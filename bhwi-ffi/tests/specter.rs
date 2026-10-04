//! Real FFI/core interpreters; frames here are synthetic protocol vectors, not firmware captures.

use base64ct::{Base64, Encoding};
use bhwi::bitcoin::{
    self, Amount, OutPoint, PublicKey, ScriptBuf, Transaction, TxIn, TxOut, absolute,
    psbt::Psbt,
    secp256k1::{Secp256k1, SecretKey},
    transaction,
};
use bhwi_ffi::{
    AddressFormat, HwiCommand, HwiError, HwiResponse, Interp, MultisigAddressFormat, Network,
    Recipient, SpecterFrameDecoder, WalletPolicy, WalletRegistration, derive_addresses,
};

const XPUB: &str = "tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP";

fn policy() -> WalletPolicy {
    WalletPolicy {
        name: "test_specter".into(),
        descriptor: format!("wpkh([f5acc2fd/84'/1'/0']{XPUB}/<0;1>/*)"),
        ledger_hmac: None,
    }
}

fn frame(payload: &[u8]) -> Vec<u8> {
    [b"ACK\r\n".as_slice(), payload, b"\r\n"].concat()
}

#[test]
fn decoder_fragmentation_coalescing_and_terminal_lifetime() {
    let reply = frame(b"success");
    for split in 0..reply.len() {
        let decoder = SpecterFrameDecoder::new();
        assert!(decoder.push(reply[..split].to_vec()).unwrap().is_none());
        assert_eq!(
            decoder.push(reply[split..].to_vec()).unwrap(),
            Some(reply.clone())
        );
        assert!(matches!(
            decoder.push(vec![]),
            Err(HwiError::BadState { .. })
        ));
    }
    let decoder = SpecterFrameDecoder::new();
    assert_eq!(decoder.push(reply.clone()).unwrap(), Some(reply));
    assert!(matches!(
        decoder.push(frame(b"delayed")),
        Err(HwiError::BadState { .. })
    ));
    for bytes in [
        b"success\r\n".to_vec(),
        b"NAK\r\nsuccess\r\n".to_vec(),
        b"ACK\r\nsuccess\r\nextra".to_vec(),
        b"ACK\r\nsuccess\r\nACK\r\nnext\r\n".to_vec(),
    ] {
        let decoder = SpecterFrameDecoder::new();
        assert!(decoder.push(bytes).is_err());
        assert!(matches!(
            decoder.push(frame(b"success")),
            Err(HwiError::BadState { .. })
        ));
    }
}

#[test]
fn decoder_enforces_exact_payload_and_frame_bounds() {
    let max = bhwi::specter::MAX_RESPONSE_SIZE;
    let reply = frame(&vec![b'x'; max]);
    assert_eq!(reply.len(), bhwi::specter::MAX_RESPONSE_FRAME_SIZE);
    let decoder = SpecterFrameDecoder::new();
    for chunk in reply[..reply.len() - 1].chunks(16 * 1024) {
        assert!(decoder.push(chunk.to_vec()).unwrap().is_none());
    }
    assert_eq!(decoder.push(vec![b'\n']).unwrap(), Some(reply));
    for bytes in [frame(&vec![b'x'; max + 1]), vec![b'x'; max + 8]] {
        let decoder = SpecterFrameDecoder::new();
        assert!(decoder.push(bytes).is_err());
        assert!(matches!(
            decoder.push(vec![]),
            Err(HwiError::BadState { .. })
        ));
    }
    let decoder = SpecterFrameDecoder::new();
    assert!(decoder.push(b"ACK\r\n".to_vec()).unwrap().is_none());
    assert!(decoder.push(vec![b'x'; max + 2]).is_err());
    assert!(matches!(
        decoder.push(vec![]),
        Err(HwiError::BadState { .. })
    ));
}

#[test]
fn incomplete_serial_chunks_are_not_interpreter_completion() {
    let interp = Interp::new_specter(Network::Testnet);
    interp.start(HwiCommand::GetMasterFingerprint).unwrap();
    let decoder = SpecterFrameDecoder::new();
    assert!(decoder.push(b"ACK\r\n".to_vec()).unwrap().is_none());
    assert!(decoder.push(b"f5acc2fd\r".to_vec()).unwrap().is_none());
    let complete = decoder.push(b"\n".to_vec()).unwrap().unwrap();
    assert!(interp.exchange(complete).unwrap().is_none());
    assert!(matches!(interp.end().unwrap(), HwiResponse::Fingerprint { hex } if hex == "f5acc2fd"));
    let invalid_driver = Interp::new_specter(Network::Testnet);
    invalid_driver
        .start(HwiCommand::GetMasterFingerprint)
        .unwrap();
    assert!(
        invalid_driver
            .exchange(b"ACK\r\n".to_vec())
            .unwrap()
            .is_none()
    );
    assert!(
        invalid_driver.end().is_err(),
        "core incomplete None is never a result"
    );
}

#[test]
fn unlock_registration_and_descriptor_display_use_actual_specter_dispatch() {
    let interp = Interp::new_specter(Network::Testnet);
    let tx = interp
        .start(HwiCommand::Unlock {
            network: Network::Testnet,
        })
        .unwrap();
    assert_eq!(tx.recipient, Recipient::Device);
    assert!(!tx.encrypted);
    assert_eq!(tx.payload, b"\r\n\r\nfingerprint\r\n");
    assert!(interp.exchange(frame(b"f5acc2fd")).unwrap().is_none());
    assert!(matches!(interp.end().unwrap(), HwiResponse::Fingerprint { hex } if hex == "f5acc2fd"));

    let wallet = policy();
    for (payload, success, refusal) in [
        ("success", true, false),
        ("true", false, false),
        ("success ", false, false),
        ("error: User cancelled", false, true),
    ] {
        let interp = Interp::new_specter(Network::Testnet);
        let tx = interp
            .start(HwiCommand::RegisterWallet {
                name: wallet.name.clone(),
                descriptor: wallet.descriptor.clone(),
            })
            .unwrap();
        assert_eq!(
            String::from_utf8(tx.payload).unwrap(),
            format!(
                "\r\n\r\naddwallet {}&{}\r\n",
                wallet.name, wallet.descriptor
            )
        );
        let result = interp.exchange(frame(payload.as_bytes()));
        if success {
            assert!(result.unwrap().is_none());
            assert!(matches!(
                interp.end().unwrap(),
                HwiResponse::WalletRegistration {
                    registration: WalletRegistration::Complete { hmac: None }
                }
            ));
        } else if refusal {
            assert!(matches!(result, Err(HwiError::UserRefused)));
        } else {
            assert!(result.is_err());
        }
    }
    for change in [false, true] {
        let interp = Interp::new_specter(Network::Testnet);
        let tx = interp
            .start(HwiCommand::DisplayDescriptorAddress {
                index: 7,
                change,
                display: true,
                wallet_policy: wallet.clone(),
            })
            .unwrap();
        assert_eq!(
            String::from_utf8(tx.payload).unwrap(),
            format!(
                "\r\n\r\nshowaddr wpkh f5acc2fd/84'/1'/0'/{}/7\r\n",
                u8::from(change)
            )
        );
        let expected = derive_addresses(wallet.descriptor.clone(), Network::Testnet, change, 7, 1)
            .unwrap()
            .remove(0)
            .address;
        assert!(
            interp
                .exchange(frame(expected.as_bytes()))
                .unwrap()
                .is_none()
        );
        assert!(
            matches!(interp.end().unwrap(), HwiResponse::Address { address } if address == expected)
        );
    }
}

#[test]
fn unsupported_commands_and_name_hmac_network_validation_are_honest() {
    let wallet = policy();
    let key = "[f5acc2fd/84'/1'/0'/0/0]0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    for command in [
        HwiCommand::GetVersion,
        HwiCommand::PromptPin,
        HwiCommand::GetXpub {
            path: "m/84'/1'/0'".into(),
            display: true,
        },
        HwiCommand::DisplayAddress {
            path: "m/84'/1'/0'/0/0".into(),
            display: false,
            format: Some(AddressFormat::NativeSegwit),
        },
        HwiCommand::DisplayAddress {
            path: "m/86'/1'/0'/0/0".into(),
            display: true,
            format: Some(AddressFormat::Taproot),
        },
        HwiCommand::DisplayDescriptorAddress {
            index: 0,
            change: false,
            display: false,
            wallet_policy: wallet.clone(),
        },
        HwiCommand::DisplayDescriptorAddress {
            index: 0,
            change: false,
            display: true,
            wallet_policy: WalletPolicy {
                descriptor: wallet.descriptor.replace("wpkh(", "tr("),
                ..wallet.clone()
            },
        },
        HwiCommand::DisplayMultisigAddress {
            threshold: 1,
            sorted: true,
            format: MultisigAddressFormat::Wit,
            keys: vec![key.into()],
        },
    ] {
        assert!(
            Interp::new_specter(Network::Testnet)
                .start(command)
                .is_err()
        );
    }
    let interp = Interp::new_specter(Network::Testnet);
    for name in ["", "bad\rname", "bad\nname", "bad&name", "bad\0name"] {
        assert!(matches!(
            interp.start(HwiCommand::RegisterWallet {
                name: name.into(),
                descriptor: wallet.descriptor.clone()
            }),
            Err(HwiError::InvalidInput { .. })
        ));
    }
    assert!(matches!(
        interp.start(HwiCommand::DisplayDescriptorAddress {
            index: 0,
            change: false,
            display: true,
            wallet_policy: WalletPolicy {
                ledger_hmac: Some(vec![0; 32]),
                ..wallet.clone()
            }
        }),
        Err(HwiError::InvalidInput { .. })
    ));
    assert_eq!(
        interp
            .start(HwiCommand::RegisterWallet {
                name: "é".repeat(80),
                descriptor: wallet.descriptor
            })
            .unwrap()
            .recipient,
        Recipient::Device
    );
    let interp = Interp::new_specter(Network::Bitcoin);
    interp
        .start(HwiCommand::GetXpub {
            path: "m/84'/1'/0'".into(),
            display: false,
        })
        .unwrap();
    assert!(matches!(
        interp.exchange(frame(XPUB.as_bytes())),
        Err(HwiError::InvalidInput { .. })
    ));
    assert!(matches!(interp.end(), Err(HwiError::BadState { .. })));
}

#[test]
fn signing_supplies_specter_context_and_preserves_existing_partials() {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[3; 32]).unwrap();
    let public = PublicKey::new(secret.public_key(&secp));
    // Synthetic signature-fidelity vector, not a funded transaction or firmware signing proof.
    let mut psbt = Psbt::from_unsigned_tx(Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            ..TxIn::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new(),
        }],
    })
    .unwrap();
    psbt.inputs[0].partial_sigs.insert(
        public,
        bitcoin::ecdsa::Signature::sighash_all(
            secp.sign_ecdsa(&bitcoin::secp256k1::Message::from_digest([42; 32]), &secret),
        ),
    );
    let original = Base64::encode_string(&psbt.serialize());
    for context in [None, Some(policy())] {
        let interp = Interp::new_specter(Network::Testnet);
        let tx = interp
            .start(HwiCommand::SignPsbt {
                psbt_base64: original.clone(),
                wallet_policy: context,
            })
            .unwrap();
        assert_eq!(
            tx.payload,
            format!("\r\n\r\nsign {original}\r\n").as_bytes()
        );
        assert!(
            interp
                .exchange(frame(original.as_bytes()))
                .unwrap()
                .is_none()
        );
        assert!(
            matches!(interp.end().unwrap(), HwiResponse::SignedPsbt { psbt_base64 } if psbt_base64 == original)
        );
    }
    let interp = Interp::new_specter(Network::Testnet);
    interp
        .start(HwiCommand::SignPsbt {
            psbt_base64: original,
            wallet_policy: Some(policy()),
        })
        .unwrap();
    // Core merges an absent original partial; a conflicting replacement must fail.
    psbt.inputs[0]
        .partial_sigs
        .get_mut(&public)
        .unwrap()
        .signature = secp.sign_ecdsa(&bitcoin::secp256k1::Message::from_digest([43; 32]), &secret);
    assert!(
        interp
            .exchange(frame(Base64::encode_string(&psbt.serialize()).as_bytes()))
            .is_err()
    );
    assert!(matches!(interp.end(), Err(HwiError::BadState { .. })));
}
