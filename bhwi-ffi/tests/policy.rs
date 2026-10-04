//! Public-input and protocol regressions through the real FFI/core interpreters.
//! Scripted replies are synthetic protocol responses. The ignored firmware module uses live firmware.

use std::str::FromStr;

use base64ct::{Base64, Encoding};
use bhwi::bitcoin::hashes::{Hash, sha256};
use bhwi::bitcoin::{
    self, Amount, OutPoint, PublicKey, ScriptBuf, Transaction, TxIn, TxOut, Txid, absolute,
    bip32::{DerivationPath, Xpriv, Xpub},
    psbt::Psbt,
    secp256k1::{Message, Secp256k1, SecretKey},
    sighash::{EcdsaSighashType, SighashCache},
    transaction,
};
use bhwi::coldcard::encrypt::Engine;
use bhwi::ledger::{LedgerWalletPolicy, Version};
use bhwi::miniscript::descriptor::WalletPolicy as CoreWalletPolicy;
use bhwi_ffi::{
    ColdcardEncryption, HwiCommand, HwiError, HwiResponse, Interp, MultisigAddressFormat, Network,
    NoiseHandle, Recipient, WalletPolicy, WalletRegistration,
};

const XPUB: &str = "tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP";
const OTHER_XPUB: &str = "tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S";

fn descriptor() -> String {
    format!(
        "wsh(sortedmulti(2,[f5acc2fd/48'/1'/0'/2']{XPUB}/<0;1>/*,[00000000/48'/1'/0'/2']{OTHER_XPUB}/<0;1>/*))"
    )
}

fn policy(hmac: Option<Vec<u8>>) -> WalletPolicy {
    WalletPolicy {
        name: "test_policy".into(),
        descriptor: descriptor(),
        ledger_hmac: hmac,
    }
}

fn display(wallet_policy: WalletPolicy) -> HwiCommand {
    HwiCommand::DisplayDescriptorAddress {
        index: 7,
        change: true,
        display: true,
        wallet_policy,
    }
}

#[test]
fn incomplete_private_and_non_account_descriptors_are_rejected_without_starting() {
    let root = bhwi::bitcoin::bip32::Xpriv::new_master(bhwi::bitcoin::Network::Testnet, &[42; 32])
        .unwrap();
    let interp = Interp::new_ledger();
    for descriptor in [
        "wpkh(@0/**)".into(),
        format!("wpkh({XPUB}/<0;1>/*)"),
        format!("wpkh([00000000]{root}/<0;1>/*)"),
        "wpkh([00000000]0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)".into(),
        "wsh(older(10))".into(),
        "not a descriptor".into(),
    ] {
        let error = interp
            .start(HwiCommand::RegisterWallet {
                name: "test_policy".into(),
                descriptor,
            })
            .unwrap_err();
        assert!(matches!(error, HwiError::InvalidInput { .. }));
        assert!(!error.to_string().contains(&root.to_string()));
    }
    assert_eq!(
        interp
            .start(HwiCommand::GetMasterFingerprint)
            .unwrap()
            .payload,
        [0xe1, 5, 0, 1, 0]
    );
}

#[test]
fn hardened_public_suffixes_fail_before_start_but_hardened_origins_remain_valid() {
    let interp = Interp::new_ledger();
    for suffix in [
        "/0'/*",
        "/<0;1>/7'/*",
        "/<0';1'>/*",
        "/<0;1>/*'",
        "/<0;1>/*h",
    ] {
        let descriptor = format!("wpkh([f5acc2fd/84'/1'/0']{XPUB}{suffix})");
        assert!(matches!(
            interp.start(HwiCommand::RegisterWallet {
                name: "test_policy".into(),
                descriptor: descriptor.clone(),
            }),
            Err(HwiError::InvalidInput { .. })
        ));
        assert!(matches!(
            interp.start(display(WalletPolicy {
                name: "test_policy".into(),
                descriptor,
                ledger_hmac: None,
            })),
            Err(HwiError::InvalidInput { .. })
        ));
    }
    // Rejected commands returned no transmit and did not consume this interpreter.
    // The accepted policy keeps its hardened BIP48 origins and normal suffixes.
    let transmit = interp
        .start(HwiCommand::RegisterWallet {
            name: "test_policy".into(),
            descriptor: descriptor(),
        })
        .unwrap();
    assert_eq!(&transmit.payload[..4], &[0xe1, 2, 0, 1]);
}

#[test]
fn ledger_and_bitbox_names_are_rejected_before_start_and_leave_interpreters_usable() {
    let noise = NoiseHandle::new(None).unwrap();
    for (interp, max_len, next, expected) in [
        (
            Interp::new_ledger(),
            64,
            HwiCommand::GetMasterFingerprint,
            vec![0xe1, 5, 0, 1, 0],
        ),
        (
            Interp::new_bitbox(noise.clone(), Network::Bitcoin).unwrap(),
            30,
            HwiCommand::Unlock {
                network: Network::Bitcoin,
            },
            b"u".to_vec(),
        ),
    ] {
        for name in [
            String::new(),
            "a".repeat(max_len + 1),
            "café".into(),
            " test_policy".into(),
            "test_policy ".into(),
            "bad\nname".into(),
        ] {
            assert!(matches!(
                interp.start(HwiCommand::RegisterWallet {
                    name,
                    descriptor: descriptor(),
                }),
                Err(HwiError::InvalidInput { .. })
            ));
        }
        assert_eq!(interp.start(next).unwrap().payload, expected);
    }
}

#[test]
fn device_specific_registration_restrictions_fail_before_any_transmit() {
    for descriptor in [
        format!("wpkh([f5acc2fd/84'/1'/0']{XPUB}/<0;1>/*)"),
        descriptor().replace("/<0;1>/*", "/<0;1;2>/*"),
    ] {
        let encryption = ColdcardEncryption::new();
        let interp = Interp::new_coldcard(encryption.clone()).unwrap();
        assert!(matches!(
            interp.start(HwiCommand::RegisterWallet {
                name: "test_policy".into(),
                descriptor
            }),
            Err(HwiError::InvalidInput { .. })
        ));
        assert!(matches!(
            Interp::new_coldcard(encryption.clone()),
            Err(HwiError::BadState { .. })
        ));
        // Pure adapter rejection neither consumes the interpreter nor releases its lease.
        assert_eq!(
            &interp
                .start(HwiCommand::Unlock {
                    network: Network::Testnet
                })
                .unwrap()
                .payload[..4],
            b"ncry"
        );
        drop(interp);
        Interp::new_coldcard(encryption).expect("lease released on drop");
    }
}

#[test]
fn hmac_is_exactly_32_bytes_and_only_accepted_by_the_actual_ledger_interpreter() {
    let ledger = Interp::new_ledger();
    for length in [0, 31, 33] {
        assert!(matches!(
            ledger.start(display(policy(Some(vec![7; length])))),
            Err(HwiError::InvalidInput { .. })
        ));
    }
    let noise = NoiseHandle::new(None).unwrap();
    let encryption = ColdcardEncryption::new();
    for interp in [
        Interp::new_jade(Network::Testnet),
        Interp::new_bitbox(noise, Network::Testnet).unwrap(),
        Interp::new_coldcard(encryption).unwrap(),
    ] {
        assert!(matches!(
            interp.start(display(policy(Some(vec![7; 32])))),
            Err(HwiError::InvalidInput { .. })
        ));
    }
    let transmit = ledger.start(display(policy(Some(vec![7; 32])))).unwrap();
    assert_eq!(&transmit.payload[..6], &[0xe1, 3, 0, 1, 70, 1]);
    let expected = LedgerWalletPolicy::new(
        "test_policy".into(),
        Version::V2,
        CoreWalletPolicy::from_str(&descriptor()).unwrap(),
    );
    assert_eq!(&transmit.payload[6..38], &expected.id().unwrap());
    assert_eq!(&transmit.payload[38..70], &[7; 32]);
    assert_eq!(&transmit.payload[70..], &[1, 0, 0, 0, 7]);
    assert!(matches!(
        ledger.exchange(vec![0x69, 0x85]),
        Err(HwiError::UserRefused)
    ));
}

#[test]
fn ledger_registration_returns_the_real_hmac_and_default_display_preserves_empty_name() {
    let ledger = Interp::new_ledger();
    let transmit = ledger
        .start(HwiCommand::RegisterWallet {
            name: "test_policy".into(),
            descriptor: descriptor(),
        })
        .unwrap();
    assert_eq!(&transmit.payload[..4], &[0xe1, 2, 0, 1]);
    let registered = LedgerWalletPolicy::new(
        "test_policy".into(),
        Version::V2,
        CoreWalletPolicy::from_str(&descriptor()).unwrap(),
    );
    let mut reply = registered.id().unwrap().to_vec();
    reply.extend([9; 32]);
    reply.extend([0x90, 0]);
    assert!(ledger.exchange(reply).unwrap().is_none());
    let HwiResponse::WalletRegistration { registration } = ledger.end().unwrap() else {
        panic!("expected registration");
    };
    assert_eq!(
        registration,
        WalletRegistration::Complete {
            hmac: Some(vec![9; 32])
        }
    );

    let standard = WalletPolicy {
        name: String::new(),
        descriptor: format!("wpkh([f5acc2fd/84'/1'/0']{XPUB}/<0;1>/*)"),
        ledger_hmac: None,
    };
    let default = LedgerWalletPolicy::new(
        String::new(),
        Version::V2,
        CoreWalletPolicy::from_str(&standard.descriptor).unwrap(),
    );
    let transmit = Interp::new_ledger().start(display(standard)).unwrap();
    assert_eq!(&transmit.payload[6..38], &default.id().unwrap());
    assert_eq!(&transmit.payload[38..70], &[0; 32]);
}

#[test]
fn ledger_registration_binds_exact_final_response_to_the_lowered_wallet_identity() {
    let registered = LedgerWalletPolicy::new(
        "test_policy".into(),
        Version::V2,
        CoreWalletPolicy::from_str(&descriptor()).unwrap(),
    );
    for mode in 0..4 {
        let interp = Interp::new_ledger();
        interp
            .start(HwiCommand::RegisterWallet {
                name: "test_policy".into(),
                descriptor: descriptor(),
            })
            .unwrap();
        // Legitimate interrupted GET_PREIMAGE request must pass to core.
        let mut interrupted = vec![0x40, 0];
        interrupted.extend(registered.id().unwrap());
        interrupted.extend([0xe0, 0]);
        let continuation = interp.exchange(interrupted).unwrap().unwrap();
        assert_eq!(&continuation.payload[..4], &[0xf8, 1, 0, 1]);
        let mut reply = registered.id().unwrap().to_vec();
        reply.extend_from_slice(b"synthetic-hmac-redaction-canary!");
        assert_eq!(reply.len(), 64);
        match mode {
            1 => reply[0] ^= 1,
            2 => reply.push(0),
            3 => {
                reply.pop();
            }
            _ => {}
        }
        reply.extend([0x90, 0]);
        if mode == 0 {
            assert!(interp.exchange(reply).unwrap().is_none());
            assert!(matches!(
                interp.end().unwrap(),
                HwiResponse::WalletRegistration { .. }
            ));
        } else {
            let error = interp.exchange(reply).unwrap_err();
            assert!(matches!(error, HwiError::Device { .. }));
            assert!(!format!("{error:?}").contains("synthetic-hmac"));
            assert!(matches!(interp.end(), Err(HwiError::BadState { .. })));
        }
    }
}

#[test]
fn wallet_debug_redacts_synthetic_hmacs_including_nested_responses() {
    let token = b"synthetic-hmac-redaction-canary!".to_vec();
    let policy = policy(Some(token.clone()));
    let registration = WalletRegistration::Complete {
        hmac: Some(token.clone()),
    };
    for rendered in [
        format!("{policy:?}"),
        format!("{registration:?}"),
        format!("{:?}", HwiResponse::WalletRegistration { registration }),
    ] {
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(&format!("{token:?}")));
        assert!(!rendered.contains("synthetic-hmac"));
    }
}

#[test]
fn jade_requires_a_valid_registered_name_and_true_registration_result() {
    for name in ["", "not a jade name", "abcdefghijklmnopq", "bad\nname"] {
        let interp = Interp::new_jade(Network::Testnet);
        assert!(matches!(
            interp.start(HwiCommand::RegisterWallet {
                name: name.into(),
                descriptor: descriptor()
            }),
            Err(HwiError::InvalidInput { .. })
        ));
        let mut input = policy(None);
        input.name = name.into();
        assert!(matches!(
            interp.start(display(input)),
            Err(HwiError::InvalidInput { .. })
        ));
    }
    for accepted in [true, false] {
        let interp = Interp::new_jade(Network::Testnet);
        let transmit = interp
            .start(HwiCommand::RegisterWallet {
                name: "test_policy".into(),
                descriptor: descriptor(),
            })
            .unwrap();
        assert!(
            transmit
                .payload
                .windows(b"register_descriptor".len())
                .any(|part| part == b"register_descriptor")
        );
        // CBOR {"id":"1","result":true/false}, matching the core's request ID.
        let mut reply = b"\xa2\x62id\x611\x66result".to_vec();
        reply.push(if accepted { 0xf5 } else { 0xf4 });
        if accepted {
            assert!(interp.exchange(reply).unwrap().is_none());
            assert!(matches!(
                interp.end().unwrap(),
                HwiResponse::WalletRegistration {
                    registration: WalletRegistration::Complete { hmac: None }
                }
            ));
        } else {
            assert!(matches!(
                interp.exchange(reply),
                Err(HwiError::Device { .. })
            ));
        }
    }
    let transmit = Interp::new_jade(Network::Testnet)
        .start(display(policy(None)))
        .unwrap();
    for expected in [
        b"get_receive_address".as_slice(),
        b"descriptor_name",
        b"test_policy",
    ] {
        assert!(
            transmit
                .payload
                .windows(expected.len())
                .any(|part| part == expected)
        );
    }
}

fn paired_coldcard() -> (std::sync::Arc<ColdcardEncryption>, Engine) {
    let encryption = ColdcardEncryption::new();
    let mut device = Engine::new(&mut rand_core::OsRng);
    let device_pubkey = device.pub_key().unwrap();
    let unlock = Interp::new_coldcard(encryption.clone()).unwrap();
    let request = unlock
        .start(HwiCommand::Unlock {
            network: Network::Testnet,
        })
        .unwrap();
    assert_eq!(&request.payload[..4], b"ncry");
    device
        .ready(request.payload[8..72].try_into().unwrap())
        .unwrap();
    let mut reply = b"mypb".to_vec();
    reply.extend(device_pubkey);
    reply.extend([0; 8]); // fingerprint followed by the empty xpub length
    assert!(unlock.exchange(reply).unwrap().is_none());
    assert!(matches!(unlock.end().unwrap(), HwiResponse::TaskDone));
    (encryption, device)
}

#[test]
fn coldcard_enrollment_acknowledgment_is_pending_not_complete() {
    let (encryption, mut device) = paired_coldcard();
    let interp = Interp::new_coldcard(encryption).unwrap();
    let transmit = interp
        .start(HwiCommand::RegisterWallet {
            name: "test_policy".into(),
            descriptor: descriptor(),
        })
        .unwrap();
    assert!(transmit.encrypted);
    let upload = device.decrypt(transmit.payload).unwrap();
    assert_eq!(&upload[..4], b"upld");
    let total = u32::from_le_bytes(upload[8..12].try_into().unwrap());
    assert_eq!(upload.len() - 12, total as usize);
    let hash = sha256::Hash::hash(&upload[12..]).to_byte_array();
    let request = interp
        .exchange(device.encrypt(b"int1\0\0\0\0".to_vec()).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(device.decrypt(request.payload).unwrap(), b"sha2");
    let mut reply = b"biny".to_vec();
    reply.extend(hash);
    let request = interp
        .exchange(device.encrypt(reply).unwrap())
        .unwrap()
        .unwrap();
    let enroll = device.decrypt(request.payload).unwrap();
    assert_eq!(&enroll[..4], b"enrl");
    assert_eq!(&enroll[4..8], &total.to_le_bytes());
    assert_eq!(&enroll[8..], &hash);
    assert!(
        interp
            .exchange(device.encrypt(b"okay".to_vec()).unwrap())
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        interp.end().unwrap(),
        HwiResponse::WalletRegistration {
            registration: WalletRegistration::PendingUserConfirmation
        }
    ));
}

#[test]
fn concrete_multisig_rejects_non_concrete_uncompressed_keys_and_invalid_thresholds() {
    const KEY: &str = "[f5acc2fd/48'/1'/0'/2'/0/7]0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let interp = Interp::new_ledger();
    for keys in [vec![], vec![KEY.into(); 16], vec![KEY[KEY.find(']').unwrap() + 1..].into()], vec![format!("[f5acc2fd]{XPUB}/0/*")], vec![format!("[f5acc2fd]{XPUB}/<0;1>/7")], vec!["[f5acc2fd]0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8".into()]] {
        assert!(matches!(interp.start(HwiCommand::DisplayMultisigAddress { threshold: 1, sorted: true, format: MultisigAddressFormat::Wit, keys }), Err(HwiError::InvalidInput { .. })));
    }
    for threshold in [0, 2] {
        assert!(matches!(
            interp.start(HwiCommand::DisplayMultisigAddress {
                threshold,
                sorted: true,
                format: MultisigAddressFormat::Legacy,
                keys: vec![KEY.into()]
            }),
            Err(HwiError::InvalidInput { .. })
        ));
    }
    // Real Coldcard lowering supports concrete compressed keys and all three wrappers.
    let (encryption, mut device) = paired_coldcard();
    for format in [
        MultisigAddressFormat::Legacy,
        MultisigAddressFormat::ShWit,
        MultisigAddressFormat::Wit,
    ] {
        let interp = Interp::new_coldcard(encryption.clone()).unwrap();
        let transmit = interp
            .start(HwiCommand::DisplayMultisigAddress {
                threshold: 1,
                sorted: true,
                format,
                keys: vec![KEY.into()],
            })
            .unwrap();
        assert_eq!(&device.decrypt(transmit.payload).unwrap()[..4], b"p2sh");
        let response = device
            .encrypt(b"asci1synthetic-protocol-address".to_vec())
            .unwrap();
        assert!(interp.exchange(response).unwrap().is_none());
        assert!(matches!(interp.end().unwrap(), HwiResponse::Address { .. }));
    }
}

fn funded_psbt(witness_script: ScriptBuf) -> Psbt {
    let destination = PublicKey::new(
        SecretKey::from_slice(&[13; 32])
            .unwrap()
            .public_key(&Secp256k1::new()),
    );
    let parent = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([3; 32]),
                vout: 0,
            },
            ..Default::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: witness_script.to_p2wsh(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            ..Default::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&destination.wpubkey_hash().unwrap()),
        }],
    })
    .unwrap();
    psbt.inputs[0].witness_utxo = Some(parent.output[0].clone());
    psbt.inputs[0].non_witness_utxo = Some(parent);
    psbt.inputs[0].witness_script = Some(witness_script);
    psbt.inputs[0].sighash_type = Some(EcdsaSighashType::All.into());
    psbt
}

fn signature_message(psbt: &Psbt, index: usize) -> Message {
    let input = &psbt.inputs[index];
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    if let Some(witness_script) = &input.witness_script {
        let hash = cache
            .p2wsh_signature_hash(
                index,
                witness_script,
                input.witness_utxo.as_ref().unwrap().value,
                EcdsaSighashType::All,
            )
            .unwrap();
        Message::from_digest(hash.to_byte_array())
    } else {
        let hash = cache
            .legacy_signature_hash(
                index,
                input.redeem_script.as_ref().unwrap(),
                EcdsaSighashType::All.to_u32(),
            )
            .unwrap();
        Message::from_digest(hash.to_byte_array())
    }
}

fn add_test_cosignature(psbt: &mut Psbt, secret: &SecretKey) -> PublicKey {
    let secp = Secp256k1::new();
    let public = PublicKey::new(secret.public_key(&secp));
    let signature = secp.sign_ecdsa(&signature_message(psbt, 0), secret);
    psbt.inputs[0]
        .partial_sigs
        .insert(public, bitcoin::ecdsa::Signature::sighash_all(signature));
    public
}

fn multisig_script(first: PublicKey, second: PublicKey) -> ScriptBuf {
    bhwi::miniscript::Descriptor::<PublicKey>::from_str(&format!(
        "wsh(sortedmulti(2,{first},{second}))"
    ))
    .unwrap()
    .explicit_script()
    .unwrap()
}

fn assert_signature(psbt: &Psbt, public: PublicKey) {
    let signature = psbt.inputs[0].partial_sigs.get(&public).unwrap();
    assert_eq!(signature.sighash_type, EcdsaSighashType::All);
    Secp256k1::verification_only()
        .verify_ecdsa(
            &signature_message(psbt, 0),
            &signature.signature,
            &public.inner,
        )
        .unwrap();
}

fn sign_command(psbt: &Psbt, wallet_policy: Option<WalletPolicy>) -> HwiCommand {
    HwiCommand::SignPsbt {
        psbt_base64: Base64::encode_string(&psbt.serialize()),
        wallet_policy,
    }
}

#[test]
fn ledger_signing_requires_exact_default_or_named_registered_policy_before_transmit() {
    let secp = Secp256k1::new();
    let first = PublicKey::new(SecretKey::from_slice(&[11; 32]).unwrap().public_key(&secp));
    let second = PublicKey::new(SecretKey::from_slice(&[12; 32]).unwrap().public_key(&secp));
    let psbt = funded_psbt(multisig_script(first, second));
    let ledger = Interp::new_ledger();
    assert!(matches!(
        ledger.start(sign_command(&psbt, None)),
        Err(HwiError::InvalidInput { .. })
    ));
    for invalid in [
        policy(None),
        policy(Some(vec![0; 32])),
        policy(Some(vec![7; 31])),
        WalletPolicy {
            name: String::new(),
            ..policy(Some(vec![7; 32]))
        },
        WalletPolicy {
            name: String::new(),
            ..policy(None)
        },
    ] {
        assert!(matches!(
            ledger.start(sign_command(&psbt, Some(invalid))),
            Err(HwiError::InvalidInput { .. })
        ));
    }
    let registered = policy(Some(vec![7; 32]));
    let expected = LedgerWalletPolicy::new(
        registered.name.clone(),
        Version::V2,
        CoreWalletPolicy::from_str(&registered.descriptor).unwrap(),
    );
    let transmit = ledger.start(sign_command(&psbt, Some(registered))).unwrap();
    assert_eq!(&transmit.payload[..4], &[0xe1, 4, 0, 1]);
    let end = transmit.payload.len();
    assert_eq!(
        &transmit.payload[end - 64..end - 32],
        &expected.id().unwrap()
    );
    assert_eq!(&transmit.payload[end - 32..], &[7; 32]);
    assert!(matches!(
        ledger.exchange(vec![0x69, 0x85]),
        Err(HwiError::UserRefused)
    ));

    for (purpose, wrapper) in [(44, "pkh"), (49, "sh(wpkh"), (84, "wpkh"), (86, "tr")] {
        let root = Xpriv::new_master(bitcoin::Network::Testnet, &[21; 32]).unwrap();
        let path = DerivationPath::from_str(&format!("m/{purpose}'/1'/100'")).unwrap();
        let xpub = Xpub::from_priv(&secp, &root.derive_priv(&secp, &path).unwrap());
        let close = if purpose == 49 { "))" } else { ")" };
        let descriptor = format!(
            "{wrapper}([{}/{path}]{xpub}/<0;1>/*{close}",
            root.fingerprint(&secp)
        );
        let default = WalletPolicy {
            name: String::new(),
            descriptor,
            ledger_hmac: None,
        };
        let expected = LedgerWalletPolicy::new(
            String::new(),
            Version::V2,
            CoreWalletPolicy::from_str(&default.descriptor).unwrap(),
        );
        let transmit = Interp::new_ledger()
            .start(sign_command(&psbt, Some(default)))
            .unwrap();
        let end = transmit.payload.len();
        assert_eq!(
            &transmit.payload[end - 64..end - 32],
            &expected.id().unwrap()
        );
        assert_eq!(&transmit.payload[end - 32..], &[0; 32]);
    }
}

#[test]
fn nonstandard_ledger_defaults_require_explicit_registration_not_guessed_rewriting() {
    let secp = Secp256k1::new();
    let root = Xpriv::new_master(bitcoin::Network::Testnet, &[21; 32]).unwrap();
    let first = PublicKey::new(SecretKey::from_slice(&[11; 32]).unwrap().public_key(&secp));
    let second = PublicKey::new(SecretKey::from_slice(&[12; 32]).unwrap().public_key(&secp));
    let psbt = funded_psbt(multisig_script(first, second));
    let ledger = Interp::new_ledger();
    for (wrapper, origin, suffix) in [
        ("wpkh", "84'/1'/101'", "/<0;1>/*"),
        ("wpkh", "49'/1'/0'", "/<0;1>/*"),
        ("wpkh", "84'/0'/0'", "/<0;1>/*"),
        ("wpkh", "84'/1'/0", "/<0;1>/*"),
        ("wpkh", "84'/1'", "/<0;1>/*"),
        ("wpkh", "84'/1'/0'/0", "/<0;1>/*"),
        ("wpkh", "84'/1'/0'", "/<1;0>/*"),
        ("wpkh", "84'/1'/0'", "/<0;2>/*"),
        ("wpkh", "84'/1'/0'", "/0/*"),
    ] {
        let path = DerivationPath::from_str(origin).unwrap();
        let xpub = Xpub::from_priv(&secp, &root.derive_priv(&secp, &path).unwrap());
        let input = WalletPolicy {
            name: String::new(),
            descriptor: format!(
                "{wrapper}([{}/{origin}]{xpub}{suffix})",
                root.fingerprint(&secp)
            ),
            ledger_hmac: None,
        };
        assert!(
            matches!(
                ledger.start(sign_command(&psbt, Some(input))),
                Err(HwiError::InvalidInput { .. })
            ),
            "{origin} {suffix}"
        );
    }
    ledger.start(HwiCommand::GetMasterFingerprint).unwrap();
}

// Synthetic protocol peer, not firmware: complete the real FFI Noise XX unlock flow.
fn paired_bitbox() -> (
    std::sync::Arc<NoiseHandle>,
    bhwi::bitbox::noise::CipherState,
    bhwi::bitbox::noise::CipherState,
) {
    use bhwi::bitbox::{
        OP_HER_COMEZ_TEH_HANDSHAEK, OP_I_CAN_HAS_HANDSHAEK, OP_I_CAN_HAS_PAIRIN_VERIFICASHUN,
        OP_UNLOCK, RESPONSE_SUCCESS, noise::HandshakeState,
    };
    let noise = NoiseHandle::new(None).unwrap();
    let unlock = Interp::new_bitbox(noise.clone(), Network::Testnet).unwrap();
    assert_eq!(
        unlock
            .start(HwiCommand::Unlock {
                network: Network::Testnet
            })
            .unwrap()
            .payload,
        [OP_UNLOCK],
    );
    assert_eq!(
        unlock.exchange(Vec::new()).unwrap().unwrap().payload,
        [OP_I_CAN_HAS_HANDSHAEK],
    );
    let request = unlock.exchange(vec![RESPONSE_SUCCESS]).unwrap().unwrap();
    assert_eq!(request.payload[0], OP_HER_COMEZ_TEH_HANDSHAEK);
    let mut device = HandshakeState::new(
        noise_protocol::patterns::noise_xx(),
        false,
        b"Noise_XX_25519_ChaChaPoly_SHA256",
        Some(noise_protocol::U8Array::from_slice(&[41; 32])),
        None,
        None,
        None,
    );
    device.read_message_vec(&request.payload[1..]).unwrap();
    let mut reply = vec![RESPONSE_SUCCESS];
    reply.extend(device.write_message_vec(b"").unwrap());
    let request = unlock.exchange(reply).unwrap().unwrap();
    assert_eq!(request.payload[0], OP_HER_COMEZ_TEH_HANDSHAEK);
    device.read_message_vec(&request.payload[1..]).unwrap();
    assert!(device.completed());
    assert_eq!(
        unlock
            .exchange(vec![RESPONSE_SUCCESS])
            .unwrap()
            .unwrap()
            .payload,
        [OP_I_CAN_HAS_PAIRIN_VERIFICASHUN],
    );
    assert!(!noise.take_pairing_code().unwrap().is_empty());
    assert!(unlock.exchange(vec![RESPONSE_SUCCESS]).unwrap().is_none());
    assert!(matches!(unlock.end().unwrap(), HwiResponse::TaskDone));
    let (receive, send) = device.get_ciphers();
    (noise, receive, send)
}

#[test]
fn signing_policy_validation_keeps_bitbox_optional_only_for_singlesig_and_full_psbt_families_context_free()
 {
    let secp = Secp256k1::new();
    let root = Xpriv::new_master(bitcoin::Network::Testnet, &[21; 32]).unwrap();
    let foreign = Xpriv::new_master(bitcoin::Network::Testnet, &[22; 32]).unwrap();
    let account = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let child = DerivationPath::from_str("m/48'/1'/0'/2'/0/0").unwrap();
    let fingerprint = root.fingerprint(&secp);
    let foreign_fingerprint = foreign.fingerprint(&secp);
    let xpub = Xpub::from_priv(&secp, &root.derive_priv(&secp, &account).unwrap());
    let foreign_xpub = Xpub::from_priv(&secp, &foreign.derive_priv(&secp, &account).unwrap());
    let first = PublicKey::new(
        root.derive_priv(&secp, &child)
            .unwrap()
            .private_key
            .public_key(&secp),
    );
    let second = PublicKey::new(
        foreign
            .derive_priv(&secp, &child)
            .unwrap()
            .private_key
            .public_key(&secp),
    );
    let mut psbt = funded_psbt(multisig_script(first, second));
    psbt.inputs[0]
        .bip32_derivation
        .insert(first.inner, (fingerprint, child.clone()));
    psbt.inputs[0]
        .bip32_derivation
        .insert(second.inner, (foreign_fingerprint, child));
    let wallet_policy = WalletPolicy {
        name: "test_policy".into(),
        descriptor: format!(
            "wsh(sortedmulti(2,[{fingerprint}/48'/1'/0'/2']{xpub}/<0;1>/*,[{foreign_fingerprint}/48'/1'/0'/2']{foreign_xpub}/<0;1>/*))"
        ),
        ledger_hmac: None,
    };
    let (noise, mut receive, mut send) = paired_bitbox();
    let bitbox = Interp::new_bitbox(noise, Network::Testnet).unwrap();
    assert!(matches!(
        bitbox.start(sign_command(&psbt, None)),
        Err(HwiError::InvalidInput { .. })
    ));
    assert!(matches!(
        bitbox.start(sign_command(&psbt, Some(policy(Some(vec![7; 32]))))),
        Err(HwiError::InvalidInput { .. })
    ));
    let request = bitbox
        .start(sign_command(&psbt, Some(wallet_policy)))
        .unwrap();
    assert!(request.encrypted);
    assert_eq!(request.payload[0], bhwi::bitbox::OP_NOISE_MSG);
    // Actual encrypted protobuf RootFingerprintRequest: field 24, zero-length message.
    assert_eq!(
        receive.decrypt_vec(&request.payload[1..]).unwrap(),
        [0xc2, 0x01, 0]
    );
    // Synthetic replies prove the native route resolves this exact BIP48 account
    // before emitting SignInit; they are not a successful firmware signing capture.
    let mut fingerprint_response = vec![0x62, 6, 0x0a, 4];
    fingerprint_response.extend(fingerprint.as_bytes());
    let mut reply = vec![bhwi::bitbox::RESPONSE_SUCCESS];
    reply.extend(send.encrypt_vec(&fingerprint_response));
    let request = bitbox.exchange(reply).unwrap().unwrap();
    assert_eq!(request.payload[0], bhwi::bitbox::OP_NOISE_MSG);
    let xpub_request = receive.decrypt_vec(&request.payload[1..]).unwrap();
    assert_eq!(xpub_request[0], 0x42); // Request field 8: BtcPub.
    let xpub_text = xpub.to_string();
    let length = u8::try_from(xpub_text.len()).unwrap();
    assert!(length < 125); // These fixed protobuf fixture lengths fit one-byte varints.
    let mut xpub_response = vec![0x2a, length + 2, 0x0a, length];
    xpub_response.extend(xpub_text.as_bytes());
    let mut reply = vec![bhwi::bitbox::RESPONSE_SUCCESS];
    reply.extend(send.encrypt_vec(&xpub_response));
    let request = bitbox.exchange(reply).unwrap().unwrap();
    assert_eq!(request.payload[0], bhwi::bitbox::OP_NOISE_MSG);
    let sign_init = receive.decrypt_vec(&request.payload[1..]).unwrap();
    assert_eq!(sign_init[0], 0x4a); // Request field 9: BtcSignInit.
    let singlesig_path = DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap();
    let singlesig_public = PublicKey::new(
        root.derive_priv(&secp, &singlesig_path)
            .unwrap()
            .private_key
            .public_key(&secp),
    );
    psbt.inputs[0].bip32_derivation.clear();
    psbt.inputs[0]
        .bip32_derivation
        .insert(singlesig_public.inner, (fingerprint, singlesig_path));
    psbt.inputs[0].witness_script = None;
    let singlesig_script = ScriptBuf::new_p2wpkh(&singlesig_public.wpubkey_hash().unwrap());
    psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey = singlesig_script.clone();
    let parent = psbt.inputs[0].non_witness_utxo.as_mut().unwrap();
    parent.output[0].script_pubkey = singlesig_script;
    psbt.unsigned_tx.input[0].previous_output.txid = parent.compute_txid();
    let (noise, mut receive, _) = paired_bitbox();
    let request = Interp::new_bitbox(noise, Network::Testnet)
        .unwrap()
        .start(sign_command(&psbt, None))
        .unwrap();
    assert!(request.encrypted);
    assert_eq!(request.payload[0], bhwi::bitbox::OP_NOISE_MSG);
    assert_eq!(
        receive.decrypt_vec(&request.payload[1..]).unwrap(),
        [0xc2, 0x01, 0]
    );
    for interp in [
        Interp::new_jade(Network::Testnet),
        Interp::new_coldcard(paired_coldcard().0).unwrap(),
    ] {
        for input in [
            policy(Some(vec![7; 32])),
            WalletPolicy {
                descriptor: "wpkh(@0/**)".into(),
                ..policy(None)
            },
        ] {
            assert!(matches!(
                interp.start(sign_command(&psbt, Some(input))),
                Err(HwiError::InvalidInput { .. })
            ));
        }
        interp
            .start(sign_command(&psbt, Some(policy(None))))
            .unwrap();
    }
}

#[test]
fn jade_full_psbt_returns_preserve_existing_signatures_or_fail_closed() {
    let secp = Secp256k1::new();
    let foreign_secret = SecretKey::from_slice(&[11; 32]).unwrap();
    let device_secret = SecretKey::from_slice(&[12; 32]).unwrap();
    let foreign = PublicKey::new(foreign_secret.public_key(&secp));
    let device = PublicKey::new(device_secret.public_key(&secp));
    let mut original = funded_psbt(multisig_script(foreign, device));
    add_test_cosignature(&mut original, &foreign_secret);
    let mut signed = original.clone();
    add_test_cosignature(&mut signed, &device_secret);
    for mode in 0..3 {
        let mut returned = signed.clone();
        match mode {
            1 => {
                returned.inputs[0].partial_sigs.remove(&foreign);
            }
            2 => {
                let changed = secp.sign_ecdsa(&Message::from_digest([99; 32]), &foreign_secret);
                returned.inputs[0]
                    .partial_sigs
                    .insert(foreign, bitcoin::ecdsa::Signature::sighash_all(changed));
            }
            _ => {}
        }
        let interp = jade_signed_return(&original, &returned);
        if mode != 0 {
            assert!(matches!(interp.end(), Err(HwiError::Device { .. })));
            continue;
        }
        let HwiResponse::SignedPsbt { psbt_base64 } = interp.end().unwrap() else {
            panic!("expected the complete signed PSBT");
        };
        let actual = Psbt::deserialize(&Base64::decode_vec(&psbt_base64).unwrap()).unwrap();
        assert_eq!(actual.unsigned_tx, original.unsigned_tx);
        assert_eq!(
            actual.inputs[0].partial_sigs[&foreign],
            original.inputs[0].partial_sigs[&foreign]
        );
        assert_signature(&actual, foreign);
        assert_signature(&actual, device);
        assert_eq!(actual, signed);
    }
}

#[test]
fn jade_accepts_signature_preserving_final_and_mixed_inputs_but_not_missing_or_conflicting_signatures()
 {
    use bitcoin::script::{Builder, PushBytesBuf};
    let secp = Secp256k1::new();
    let foreign_secret = SecretKey::from_slice(&[11; 32]).unwrap();
    let device_secret = SecretKey::from_slice(&[12; 32]).unwrap();
    let foreign = PublicKey::new(foreign_secret.public_key(&secp));
    let device = PublicKey::new(device_secret.public_key(&secp));
    let script = multisig_script(foreign, device);
    let mut ordered = [foreign, device];
    ordered.sort_unstable_by_key(|key| key.inner.serialize());
    for legacy in [false, true] {
        let mut original = funded_psbt(script.clone());
        let parent = original.inputs[0].non_witness_utxo.as_mut().unwrap();
        if legacy {
            parent.output[0].script_pubkey = script.to_p2sh();
        }
        parent.output.push(parent.output[0].clone());
        let parent = parent.clone();
        original.unsigned_tx.input[0].previous_output.txid = parent.compute_txid();
        original
            .unsigned_tx
            .input
            .push(original.unsigned_tx.input[0].clone());
        original.unsigned_tx.input[1].previous_output.vout = 1;
        original.unsigned_tx.output[0].value = Amount::from_sat(99_000);
        original.inputs[0].non_witness_utxo = Some(parent.clone());
        original.inputs[0].witness_utxo = Some(parent.output[0].clone());
        if legacy {
            original.inputs[0].redeem_script = Some(script.clone());
            original.inputs[0].witness_script = None;
        }
        original.inputs.push(original.inputs[0].clone());
        for index in 0..2 {
            let signature = bitcoin::ecdsa::Signature::sighash_all(
                secp.sign_ecdsa(&signature_message(&original, index), &foreign_secret),
            );
            original.inputs[index]
                .partial_sigs
                .insert(foreign, signature);
        }
        let mut signed = original.clone();
        for index in 0..2 {
            let signature = bitcoin::ecdsa::Signature::sighash_all(
                secp.sign_ecdsa(&signature_message(&original, index), &device_secret),
            );
            signed.inputs[index].partial_sigs.insert(device, signature);
        }
        for mode in 0..4 {
            let mut returned = signed.clone();
            let finalized = if mode == 1 { 2 } else { 1 };
            for index in 0..finalized {
                let signatures =
                    ordered.map(|key| returned.inputs[index].partial_sigs[&key].serialize());
                if legacy {
                    returned.inputs[index].final_script_sig = Some(
                        Builder::new()
                            .push_int(0)
                            .push_slice(signatures[0])
                            .push_slice(signatures[1])
                            .push_slice(
                                PushBytesBuf::try_from(script.clone().into_bytes()).unwrap(),
                            )
                            .into_script(),
                    );
                } else {
                    returned.inputs[index].final_script_witness =
                        Some(bitcoin::Witness::from_slice(&[
                            &[][..],
                            &signatures[0],
                            &signatures[1],
                            script.as_bytes(),
                        ]));
                }
                returned.inputs[index].partial_sigs.clear();
                returned.inputs[index].sighash_type = None;
                returned.inputs[index].witness_script = None;
                returned.inputs[index].redeem_script = None;
                returned.inputs[index].bip32_derivation.clear();
            }
            if mode == 2 {
                // A finalized marker plus the device signature is not proof of retention.
                let signature = signed.inputs[0].partial_sigs[&device].serialize();
                if legacy {
                    returned.inputs[0].final_script_sig = Some(
                        Builder::new()
                            .push_int(0)
                            .push_slice(signature)
                            .push_slice(
                                PushBytesBuf::try_from(script.clone().into_bytes()).unwrap(),
                            )
                            .into_script(),
                    );
                } else {
                    returned.inputs[0].final_script_witness =
                        Some(bitcoin::Witness::from_slice(&[
                            &[][..],
                            &signature,
                            script.as_bytes(),
                        ]));
                }
            } else if mode == 3 {
                // Even when the final stack retains the old bytes, conflicting partial metadata fails.
                let changed = secp.sign_ecdsa(&Message::from_digest([99; 32]), &foreign_secret);
                returned.inputs[0]
                    .partial_sigs
                    .insert(foreign, bitcoin::ecdsa::Signature::sighash_all(changed));
            }
            let interp = jade_signed_return(&original, &returned);
            if mode >= 2 {
                assert!(matches!(interp.end(), Err(HwiError::Device { .. })));
                continue;
            }
            let HwiResponse::SignedPsbt { psbt_base64 } = interp.end().unwrap() else {
                panic!("expected the complete signed PSBT");
            };
            let actual = Psbt::deserialize(&Base64::decode_vec(&psbt_base64).unwrap()).unwrap();
            assert_eq!(actual, returned);
            assert_eq!(actual.unsigned_tx, original.unsigned_tx);
            for index in 0..2 {
                let signatures = if index < finalized {
                    let stack = if legacy {
                        actual.inputs[index]
                            .final_script_sig
                            .as_ref()
                            .unwrap()
                            .instructions()
                            .map(|instruction| {
                                instruction
                                    .unwrap()
                                    .push_bytes()
                                    .unwrap()
                                    .as_bytes()
                                    .to_vec()
                            })
                            .collect::<Vec<_>>()
                    } else {
                        actual.inputs[index]
                            .final_script_witness
                            .as_ref()
                            .unwrap()
                            .to_vec()
                    };
                    assert_eq!(stack.len(), 4);
                    assert!(stack[0].is_empty());
                    assert_eq!(stack[3], script.as_bytes());
                    ordered
                        .into_iter()
                        .zip(
                            stack[1..3]
                                .iter()
                                .map(|bytes| bitcoin::ecdsa::Signature::from_slice(bytes).unwrap()),
                        )
                        .collect::<Vec<_>>()
                } else {
                    actual.inputs[index]
                        .partial_sigs
                        .iter()
                        .map(|(key, sig)| (*key, *sig))
                        .collect()
                };
                for (key, signature) in signatures {
                    assert_eq!(signature.sighash_type, EcdsaSighashType::All);
                    secp.verify_ecdsa(
                        &signature_message(&original, index),
                        &signature.signature,
                        &key.inner,
                    )
                    .unwrap();
                    if key == foreign {
                        assert_eq!(signature, original.inputs[index].partial_sigs[&foreign]);
                    }
                }
            }
        }
    }
}

// Fixture-only TCP transport: reuses the core E2E HID/HWW framing, never ships in the library.
mod firmware {
    use super::*;
    use async_trait::async_trait;
    use bhwi::bitcoin::bip32::Fingerprint;
    use bhwi::miniscript::descriptor::DescriptorPublicKey;
    use bhwi::miniscript::psbt::{PsbtInputExt, PsbtOutputExt};
    use bhwi_async::Transport;
    use bhwi_async::transport::Channel;
    use bhwi_async::transport::bitbox::hid::BitBoxTransportHID;
    use futures::executor::block_on;
    use std::cell::RefCell;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::Arc;
    use std::time::Duration;

    struct TcpChannel(RefCell<TcpStream>);

    #[async_trait(?Send)]
    impl Channel for TcpChannel {
        async fn send(&self, data: &[u8]) -> Result<usize, std::io::Error> {
            let mut stream = self.0.borrow_mut();
            stream.write_all(data)?;
            stream.flush()?;
            Ok(data.len())
        }
        async fn receive(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
            self.0.borrow_mut().read_exact(data)?;
            Ok(data.len())
        }
    }

    fn run(
        noise: &Arc<NoiseHandle>,
        transport: &mut BitBoxTransportHID<TcpChannel>,
        cmd: HwiCommand,
    ) -> HwiResponse {
        let label = match &cmd {
            HwiCommand::RegisterWallet { .. } => "register-wallet",
            HwiCommand::SignPsbt { .. } => "sign-psbt",
            _ => "policy-command",
        };
        let mut exchanges = 0;
        let interp = Interp::new_bitbox(noise.clone(), Network::Bitcoin).unwrap();
        let mut next = Some(
            interp
                .start(cmd)
                .unwrap_or_else(|error| panic!("{label} start: {error}")),
        );
        while let Some(transmit) = next {
            assert_eq!(transmit.recipient, Recipient::Device);
            let reply =
                block_on(transport.exchange(&transmit.payload, transmit.encrypted)).unwrap();
            exchanges += 1;
            next = interp
                .exchange(reply)
                .unwrap_or_else(|error| panic!("{label} exchange {exchanges}: {error}"));
            if let Some(code) = noise.take_pairing_code() {
                assert!(!code.is_empty()); // Test simulator auto-approval is not production approval.
            }
        }
        interp
            .end()
            .unwrap_or_else(|error| panic!("{label} completion: {error}"))
    }

    #[test]
    #[ignore = "requires the initialized official BitBox02 firmware simulator on 127.0.0.1:15423"]
    fn bitbox_policy_firmware_smoke() {
        const ROOT: &str = "xprv9s21ZrQH143K2qxpAMxVdyeza5dUBxY11XbJ7eKvRF51sQyhiFXgmn4P4ALi3Nf6bcG8cmPDvMMEFiAVjtXsqeZ47PJfBJif7uSYycMsx9c";
        let stream =
            TcpStream::connect_timeout(&"127.0.0.1:15423".parse().unwrap(), Duration::from_secs(5))
                .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(300)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut transport = BitBoxTransportHID::new(TcpChannel(RefCell::new(stream)));
        let noise = NoiseHandle::new(None).unwrap();
        run(
            &noise,
            &mut transport,
            HwiCommand::Unlock {
                network: Network::Bitcoin,
            },
        );
        let HwiResponse::Fingerprint { hex: fingerprint } =
            run(&noise, &mut transport, HwiCommand::GetMasterFingerprint)
        else {
            panic!("fingerprint");
        };
        let secp = Secp256k1::new();
        let root = Xpriv::from_str(ROOT).unwrap();
        assert_eq!(
            fingerprint,
            root.fingerprint(&secp).to_string(),
            "initialize the simulator with the core E2E harness first"
        );
        let account = DerivationPath::from_str("m/48'/0'/0'/2'").unwrap();
        let HwiResponse::Xpub { xpub } = run(
            &noise,
            &mut transport,
            HwiCommand::GetXpub {
                path: "m/48'/0'/0'/2'".into(),
                display: false,
            },
        ) else {
            panic!("xpub");
        };
        assert_eq!(
            xpub,
            Xpub::from_priv(&secp, &root.derive_priv(&secp, &account).unwrap()).to_string()
        );
        let foreign = Xpriv::new_master(bhwi::bitcoin::Network::Bitcoin, &[42; 32]).unwrap();
        let foreign_fp = foreign.fingerprint(&secp);
        let foreign_xpub = Xpub::from_priv(&secp, &foreign.derive_priv(&secp, &account).unwrap());
        let descriptor = format!(
            "wsh(andor(pk([{fingerprint}/48'/0'/0'/2']{xpub}/<0;1>/*),older(12960),pk([{foreign_fp}/48'/0'/0'/2']{foreign_xpub}/<0;1>/*)))"
        );
        let name = "bhwi-ffi-policy";
        assert!(matches!(
            run(
                &noise,
                &mut transport,
                HwiCommand::RegisterWallet {
                    name: name.into(),
                    descriptor: descriptor.clone()
                }
            ),
            HwiResponse::WalletRegistration {
                registration: WalletRegistration::Complete { hmac: None }
            }
        ));
        for (change, index) in [(false, 0), (true, 7)] {
            let expected =
                bhwi_ffi::derive_addresses(descriptor.clone(), Network::Bitcoin, change, index, 1)
                    .unwrap()
                    .remove(0)
                    .address;
            let HwiResponse::Address { address } = run(
                &noise,
                &mut transport,
                HwiCommand::DisplayDescriptorAddress {
                    index,
                    change,
                    display: true,
                    wallet_policy: WalletPolicy {
                        name: name.into(),
                        descriptor: descriptor.clone(),
                        ledger_hmac: None,
                    },
                },
            ) else {
                panic!("address");
            };
            assert_eq!(address, expected);
            eprintln!("BitBox02 registered-policy address ({change}, {index}): {address}");
        }

        // A separate conventional 2-of-2 policy signs disposable constructed prevouts.
        let descriptor = format!(
            "wsh(sortedmulti(2,[{fingerprint}/48'/0'/0'/2']{xpub}/<0;1>/*,[{foreign_fp}/48'/0'/0'/2']{foreign_xpub}/<0;1>/*))"
        );
        let name = "bhwi-ffi-signing";
        assert!(matches!(
            run(
                &noise,
                &mut transport,
                HwiCommand::RegisterWallet {
                    name: name.into(),
                    descriptor: descriptor.clone(),
                }
            ),
            HwiResponse::WalletRegistration {
                registration: WalletRegistration::Complete { hmac: None }
            }
        ));
        let child = DerivationPath::from_str("m/48'/0'/0'/2'/0/0").unwrap();
        let device = PublicKey::new(
            root.derive_priv(&secp, &child)
                .unwrap()
                .private_key
                .public_key(&secp),
        );
        let foreign_secret = foreign.derive_priv(&secp, &child).unwrap().private_key;
        let foreign_public = PublicKey::new(foreign_secret.public_key(&secp));
        let mut unsigned = funded_psbt(multisig_script(device, foreign_public));
        // Match the committed core E2E builder: descriptor-derived receive/change
        // metadata, a constructed previous transaction and an RBF-enabled spend.
        let descriptor_public =
            bhwi::miniscript::Descriptor::<DescriptorPublicKey>::from_str(&descriptor).unwrap();
        let mut branches = descriptor_public
            .into_single_descriptors()
            .unwrap()
            .into_iter();
        let receive = branches.next().unwrap().derive_at_index(0).unwrap();
        let change = branches.next().unwrap().derive_at_index(0).unwrap();
        let receive_script = receive.derived_descriptor(&secp).script_pubkey();
        assert_eq!(
            unsigned.inputs[0]
                .witness_utxo
                .as_ref()
                .unwrap()
                .script_pubkey,
            receive_script
        );
        let parent = unsigned.inputs[0].non_witness_utxo.as_mut().unwrap();
        parent.input[0].previous_output = OutPoint::null();
        unsigned.unsigned_tx.input[0].previous_output.txid = parent.compute_txid();
        unsigned.unsigned_tx.input[0].sequence = bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME;
        unsigned.unsigned_tx.output[0].script_pubkey =
            change.derived_descriptor(&secp).script_pubkey();
        unsigned.inputs[0]
            .update_with_descriptor_unchecked(&receive)
            .unwrap();
        unsigned.outputs[0]
            .update_with_descriptor_unchecked(&change)
            .unwrap();
        unsigned.xpub.insert(
            Xpub::from_str(&xpub).unwrap(),
            (
                Fingerprint::from_str(&fingerprint).unwrap(),
                account.clone(),
            ),
        );
        unsigned.xpub.insert(foreign_xpub, (foreign_fp, account));
        let wallet_policy = WalletPolicy {
            name: name.into(),
            descriptor: descriptor.clone(),
            ledger_hmac: None,
        };
        for foreign_first in [true, false] {
            let mut original = unsigned.clone();
            if foreign_first {
                add_test_cosignature(&mut original, &foreign_secret);
            }
            let HwiResponse::SignedPsbt { psbt_base64 } = run(
                &noise,
                &mut transport,
                sign_command(&original, Some(wallet_policy.clone())),
            ) else {
                panic!("expected full signed PSBT");
            };
            let mut returned =
                Psbt::deserialize(&Base64::decode_vec(&psbt_base64).unwrap()).unwrap();
            assert_eq!(returned.unsigned_tx, original.unsigned_tx);
            assert_eq!(
                returned.inputs[0].witness_utxo,
                original.inputs[0].witness_utxo
            );
            assert_eq!(
                returned.inputs[0].witness_script,
                original.inputs[0].witness_script
            );
            assert_signature(&returned, device);
            if foreign_first {
                assert_eq!(
                    returned.inputs[0].partial_sigs[&foreign_public],
                    original.inputs[0].partial_sigs[&foreign_public]
                );
                assert_signature(&returned, foreign_public);
                if let Some(path) = std::env::var_os("BHWI_BITBOX_SIGNING_FIXTURE") {
                    let fixture = serde_json::json!({
                        "source": "live official BitBox02 firmware; public PSBT fixture, not a Noise replay",
                        "name": name,
                        "descriptor": descriptor,
                        "original_psbt": Base64::encode_string(&original.serialize()),
                        "signed_psbt": psbt_base64,
                        "device_pubkey": device.to_string(),
                        "foreign_pubkey": foreign_public.to_string(),
                        "fingerprint": fingerprint,
                        "account_xpub": xpub,
                    });
                    std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
                }
            } else {
                let device_signature = returned.inputs[0].partial_sigs[&device];
                add_test_cosignature(&mut returned, &foreign_secret);
                assert_eq!(returned.inputs[0].partial_sigs[&device], device_signature);
                assert_signature(&returned, device);
                assert_signature(&returned, foreign_public);
            }
            eprintln!("BitBox02 full-PSBT signing verified (foreign first: {foreign_first})");
        }
    }

    #[test]
    #[ignore = "requires BHWI_BITBOX_SIGNING_FIXTURE containing a live Rust/JVM smoke result"]
    fn bitbox_signing_fixture_verifies() {
        let path = std::env::var_os("BHWI_BITBOX_SIGNING_FIXTURE").expect("fixture path");
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let parse = |field: &str| {
            Psbt::deserialize(&Base64::decode_vec(fixture[field].as_str().unwrap()).unwrap())
                .unwrap()
        };
        let original = parse("original_psbt");
        let signed = parse("signed_psbt");
        let foreign = PublicKey::from_str(fixture["foreign_pubkey"].as_str().unwrap()).unwrap();
        let device = PublicKey::from_str(fixture["device_pubkey"].as_str().unwrap()).unwrap();
        let witness_script = multisig_script(device, foreign);
        assert_eq!(
            original.inputs[0].witness_script.as_ref(),
            Some(&witness_script)
        );
        let parent = original.inputs[0].non_witness_utxo.as_ref().unwrap();
        let outpoint = original.unsigned_tx.input[0].previous_output;
        assert_eq!(parent.compute_txid(), outpoint.txid);
        let funding = &parent.output[outpoint.vout as usize];
        assert_eq!(funding.script_pubkey, witness_script.to_p2wsh());
        assert_eq!(original.inputs[0].witness_utxo.as_ref(), Some(funding));
        assert_eq!(signed.unsigned_tx, original.unsigned_tx);
        assert_eq!(
            signed.inputs[0].non_witness_utxo,
            original.inputs[0].non_witness_utxo
        );
        assert_eq!(
            signed.inputs[0].witness_utxo,
            original.inputs[0].witness_utxo
        );
        assert_eq!(
            signed.inputs[0].witness_script,
            original.inputs[0].witness_script
        );
        assert_eq!(
            signed.inputs[0].partial_sigs[&foreign],
            original.inputs[0].partial_sigs[&foreign]
        );
        assert!(!original.inputs[0].partial_sigs.contains_key(&device));
        assert_signature(&signed, foreign);
        assert_signature(&signed, device);
    }
}

#[test]
fn concrete_multisig_keys_follow_the_actual_device_family() {
    const SINGLE: &str = "[f5acc2fd/48'/1'/0'/2'/0/7]0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let xpub = format!("[f5acc2fd/48'/1'/0'/2']{XPUB}/0/7");
    let command = |keys| HwiCommand::DisplayMultisigAddress {
        threshold: 1,
        sorted: true,
        format: MultisigAddressFormat::Wit,
        keys,
    };
    for interp in [
        Interp::new_jade(Network::Testnet),
        Interp::new_trezor(Network::Testnet, None, false).unwrap(),
        Interp::new_keepkey(Network::Testnet, None).unwrap(),
    ] {
        let private = Xpriv::new_master(bitcoin::Network::Testnet, &[42; 32]).unwrap();
        for key in [
            format!("{XPUB}/0/7"),
            format!("[f5acc2fd]{XPUB}/0/*"),
            format!("[f5acc2fd]{XPUB}/<0;1>/7"),
            format!("[f5acc2fd]{XPUB}/0'/7"),
            format!("[f5acc2fd]{private}/0/7"),
            "[f5acc2fd]0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8".into(),
        ] {
            assert!(matches!(interp.start(command(vec![key])), Err(HwiError::InvalidInput { .. })));
        }
        interp
            .start(HwiCommand::GetVersion)
            .expect("rejections preserve the interpreter");
    }
    let jade = Interp::new_jade(Network::Testnet);
    assert!(matches!(
        jade.start(command(vec![SINGLE.into()])),
        Err(HwiError::InvalidInput { .. })
    ));
    let keys = vec![
        xpub.clone(),
        format!("[00000000/48'/1'/0'/2']{OTHER_XPUB}/0/7"),
    ];
    let transmit = jade
        .start(HwiCommand::DisplayMultisigAddress {
            threshold: 2,
            sorted: true,
            format: MultisigAddressFormat::Wit,
            keys,
        })
        .unwrap();
    for expected in ["register_multisig", XPUB, OTHER_XPUB] {
        assert!(
            transmit
                .payload
                .windows(expected.len())
                .any(|part| part == expected.as_bytes())
        );
    }
    let next = jade
        .exchange(b"\xa2\x62id\x611\x66result\xf5".to_vec())
        .unwrap()
        .unwrap();
    assert!(
        next.payload
            .windows(b"get_receive_address".len())
            .any(|part| part == b"get_receive_address")
    );
    assert!(
        jade.exchange(b"\xa2\x62id\x611\x66result\x64test".to_vec())
            .unwrap()
            .is_none()
    );
    assert!(matches!(jade.end().unwrap(), HwiResponse::Address { address } if address == "test"));
    for key in [SINGLE.into(), xpub.clone()] {
        Interp::new_trezor(Network::Testnet, None, false)
            .unwrap()
            .start(command(vec![key]))
            .expect("Trezor lowers both concrete public shapes");
    }
    let encryption = ColdcardEncryption::new();
    for interp in [
        Interp::new_keepkey(Network::Testnet, None).unwrap(),
        Interp::new_coldcard(encryption).unwrap(),
    ] {
        assert!(matches!(
            interp.start(command(vec![xpub.clone()])),
            Err(HwiError::InvalidInput { .. })
        ));
    }
    Interp::new_keepkey(Network::Testnet, None)
        .unwrap()
        .start(command(vec![SINGLE.into()]))
        .expect("KeepKey lowers compressed Single keys");
}

fn jade_signed_return(original: &Psbt, returned: &Psbt) -> std::sync::Arc<Interp> {
    // Synthetic CBOR with real test-key signatures, not a firmware capture.
    let interp = Interp::new_jade(Network::Testnet);
    interp.start(sign_command(original, None)).unwrap();
    let bytes = returned.serialize();
    let mut reply = b"\xa2\x62id\x611\x66result\x59".to_vec();
    reply.extend(u16::try_from(bytes.len()).unwrap().to_be_bytes());
    reply.extend(bytes);
    assert!(interp.exchange(reply).unwrap().is_none());
    interp
}

fn result_test_psbt() -> Psbt {
    let secp = Secp256k1::new();
    let keys = [11, 12].map(|byte| {
        PublicKey::new(
            SecretKey::from_slice(&[byte; 32])
                .unwrap()
                .public_key(&secp),
        )
    });
    funded_psbt(multisig_script(keys[0], keys[1]))
}

#[test]
fn signing_results_preserve_unsigned_transaction_and_existing_final_fields() {
    let mut original = result_test_psbt();
    original.inputs[0].final_script_sig = Some(ScriptBuf::from_bytes(vec![0x51]));
    original.inputs[0].final_script_witness =
        Some(bitcoin::Witness::from_slice(&[b"final-field-canary"]));
    for mode in 0..9 {
        let mut returned = original.clone();
        match mode {
            1 => returned.unsigned_tx.output[0].value = Amount::from_sat(48_999),
            2 => returned.unsigned_tx.input[0].previous_output.vout ^= 1,
            3 => returned.unsigned_tx.input[0].sequence = bitcoin::Sequence::ZERO,
            4 => returned.unsigned_tx.lock_time = absolute::LockTime::from_consensus(1),
            5 => returned.inputs[0].final_script_sig = None,
            6 => returned.inputs[0].final_script_sig = Some(ScriptBuf::from_bytes(vec![0x52])),
            7 => returned.inputs[0].final_script_witness = None,
            8 => {
                returned.inputs[0].final_script_witness =
                    Some(bitcoin::Witness::from_slice(&[b"changed"]))
            }
            _ => {}
        }
        let interp = jade_signed_return(&original, &returned);
        if mode == 0 {
            assert!(matches!(
                interp.end().unwrap(),
                HwiResponse::SignedPsbt { .. }
            ));
        } else {
            let error = interp.end().unwrap_err();
            assert!(matches!(error, HwiError::Device { .. }));
            assert!(!format!("{error:?}").contains("final-field-canary"));
        }
        assert!(matches!(interp.end(), Err(HwiError::BadState { .. })));
    }
}

#[test]
fn new_ecdsa_signatures_honor_original_sighash_requests_not_returned_metadata() {
    let secret = SecretKey::from_slice(&[11; 32]).unwrap();
    let key = PublicKey::new(secret.public_key(&Secp256k1::new()));
    let base = result_test_psbt();
    // These synthetic signatures exercise metadata/fidelity, not consensus validation.
    for (requested, generated, returned_mode, accepted) in [
        (
            None,
            EcdsaSighashType::All,
            Some(EcdsaSighashType::Single.into()),
            true,
        ),
        (
            Some(EcdsaSighashType::All.into()),
            EcdsaSighashType::All,
            None,
            true,
        ),
        (
            Some(EcdsaSighashType::Single.into()),
            EcdsaSighashType::All,
            None,
            false,
        ),
        (
            Some(EcdsaSighashType::Single.into()),
            EcdsaSighashType::All,
            Some(EcdsaSighashType::All.into()),
            false,
        ),
        (
            Some(EcdsaSighashType::Single.into()),
            EcdsaSighashType::Single,
            None,
            true,
        ),
    ] {
        let mut original = base.clone();
        original.inputs[0].sighash_type = requested;
        let mut returned = original.clone();
        add_test_cosignature(&mut returned, &secret);
        returned.inputs[0]
            .partial_sigs
            .get_mut(&key)
            .unwrap()
            .sighash_type = generated;
        returned.inputs[0].sighash_type = returned_mode;
        let interp = jade_signed_return(&original, &returned);
        if accepted {
            assert!(matches!(
                interp.end().unwrap(),
                HwiResponse::SignedPsbt { .. }
            ));
        } else {
            assert!(matches!(interp.end(), Err(HwiError::Device { .. })));
        }
        assert!(matches!(interp.end(), Err(HwiError::BadState { .. })));
    }
    // A foreign input with a nondefault request and an unchanged old signature is not rejected.
    let mut foreign = base;
    foreign.inputs[0].sighash_type = Some(EcdsaSighashType::Single.into());
    assert!(matches!(
        jade_signed_return(&foreign, &foreign).end().unwrap(),
        HwiResponse::SignedPsbt { .. }
    ));
    add_test_cosignature(&mut foreign, &secret);
    foreign.inputs[0]
        .partial_sigs
        .get_mut(&key)
        .unwrap()
        .sighash_type = EcdsaSighashType::Single;
    assert!(matches!(
        jade_signed_return(&foreign, &foreign).end().unwrap(),
        HwiResponse::SignedPsbt { .. }
    ));
}

#[test]
fn new_taproot_key_and_script_signatures_use_original_requests_and_distinct_defaults() {
    use bitcoin::sighash::TapSighashType;
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[12; 32]).unwrap();
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
    let base = result_test_psbt();
    let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest([9; 32]), &keypair);
    let script_key = (
        keypair.x_only_public_key().0,
        bitcoin::taproot::TapLeafHash::from_byte_array([5; 32]),
    );
    for script_path in [false, true] {
        for (requested, generated, returned_mode, accepted) in [
            (
                None,
                TapSighashType::Default,
                Some(TapSighashType::All.into()),
                true,
            ),
            (
                Some(TapSighashType::All.into()),
                TapSighashType::All,
                None,
                true,
            ),
            (
                Some(TapSighashType::All.into()),
                TapSighashType::Default,
                None,
                false,
            ),
            (
                Some(TapSighashType::All.into()),
                TapSighashType::Default,
                Some(TapSighashType::Default.into()),
                false,
            ),
        ] {
            let mut original = base.clone();
            original.inputs[0].sighash_type = requested;
            let mut returned = original.clone();
            let sig = bitcoin::taproot::Signature {
                signature,
                sighash_type: generated,
            };
            if script_path {
                returned.inputs[0].tap_script_sigs.insert(script_key, sig);
            } else {
                returned.inputs[0].tap_key_sig = Some(sig);
            }
            returned.inputs[0].sighash_type = returned_mode;
            let interp = jade_signed_return(&original, &returned);
            if accepted {
                assert!(matches!(
                    interp.end().unwrap(),
                    HwiResponse::SignedPsbt { .. }
                ));
            } else {
                assert!(matches!(interp.end(), Err(HwiError::Device { .. })));
            }
            assert!(matches!(interp.end(), Err(HwiError::BadState { .. })));
        }
        let mut foreign = base.clone();
        foreign.inputs[0].sighash_type = Some(TapSighashType::Single.into());
        let sig = bitcoin::taproot::Signature {
            signature,
            sighash_type: TapSighashType::Single,
        };
        if script_path {
            foreign.inputs[0].tap_script_sigs.insert(script_key, sig);
        } else {
            foreign.inputs[0].tap_key_sig = Some(sig);
        }
        assert!(matches!(
            jade_signed_return(&foreign, &foreign).end().unwrap(),
            HwiResponse::SignedPsbt { .. }
        ));
        let mut changed = foreign.clone();
        let conflicting = bitcoin::taproot::Signature {
            signature,
            sighash_type: TapSighashType::All,
        };
        if script_path {
            changed.inputs[0]
                .tap_script_sigs
                .insert(script_key, conflicting);
        } else {
            changed.inputs[0].tap_key_sig = Some(conflicting);
        }
        assert!(matches!(
            jade_signed_return(&foreign, &changed).end(),
            Err(HwiError::Device { .. })
        ));
    }
}
