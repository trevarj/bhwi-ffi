//! Transmit-level round trips: the interpreter is driven exactly as a host would drive
//! it, with scripted replies and no transport, framing or I/O anywhere.

use std::sync::Arc;

use bhwi::bitcoin::secp256k1::{Secp256k1, SecretKey};
use bhwi_ffi::{
    ColdcardEncryption, HwiCommand, HwiError, HwiResponse, Interp, Network, NoiseHandle, Recipient,
    Transmit,
};

/// Fixed test vectors; the fingerprint/xpub pair is the one used by bhwi's own tests.
const FINGERPRINT: &str = "f5acc2fd";
const ACCOUNT_PATH: &str = "m/84'/1'/0'";
const ADDRESS_PATH: &str = "m/84'/1'/0'/0/0";
const XPUB: &str = "tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP";

const SW_OK: [u8; 2] = [0x90, 0x00];
const SW_DENY: [u8; 2] = [0x69, 0x85];

fn apdu(data: &[u8], status: [u8; 2]) -> Vec<u8> {
    let mut out = data.to_vec();
    out.extend_from_slice(&status);
    out
}

fn fingerprint_reply() -> Vec<u8> {
    apdu(&hex::decode(FINGERPRINT).unwrap(), SW_OK)
}

fn xpub_reply() -> Vec<u8> {
    apdu(XPUB.as_bytes(), SW_OK)
}

/// Sends every scripted reply in turn and returns the outcome of `end`.
fn drive(
    interp: &Interp,
    command: HwiCommand,
    replies: Vec<Vec<u8>>,
) -> Result<HwiResponse, HwiError> {
    interp.start(command)?;
    for reply in replies {
        if interp.exchange(reply)?.is_none() {
            break;
        }
    }
    interp.end()
}

#[test]
fn ledger_fingerprint_round_trips_without_a_device() {
    let interp = Interp::new_ledger();
    let transmit = interp
        .start(HwiCommand::GetMasterFingerprint)
        .expect("start");
    // cla=Bitcoin(0xE1), ins=GetMasterFingerprint(0x05), p1=0, p2=protocol v1, len=0
    assert_eq!(transmit.payload, [0xE1, 0x05, 0x00, 0x01, 0x00]);
    assert!(!transmit.encrypted);
    assert_eq!(transmit.recipient, Recipient::Device);

    assert!(
        interp
            .exchange(fingerprint_reply())
            .expect("exchange")
            .is_none()
    );
    let HwiResponse::Fingerprint { hex } = interp.end().expect("end") else {
        panic!("expected a fingerprint");
    };
    assert_eq!(hex, FINGERPRINT);
}

#[test]
fn ledger_refusal_is_typed() {
    // Address display resolves the wallet policy first (fingerprint, then account xpub);
    // the device denies the final GET_WALLET_ADDRESS with 0x6985.
    let error = drive(
        &Interp::new_ledger(),
        HwiCommand::DisplayAddress {
            path: ADDRESS_PATH.to_string(),
            display: true,
            format: None,
        },
        vec![fingerprint_reply(), xpub_reply(), apdu(&[], SW_DENY)],
    )
    .expect_err("device denied");
    assert!(matches!(error, HwiError::UserRefused), "got {error:?}");
}

#[test]
fn ledger_xpub_round_trips() {
    let response = drive(
        &Interp::new_ledger(),
        HwiCommand::GetXpub {
            path: ACCOUNT_PATH.to_string(),
            display: false,
        },
        vec![xpub_reply()],
    )
    .expect("xpub");
    let HwiResponse::Xpub { xpub } = response else {
        panic!("expected an xpub, got {response:?}");
    };
    assert_eq!(xpub, XPUB);
}

#[test]
fn misuse_is_rejected_without_touching_the_device() {
    let interp = Interp::new_ledger();
    assert!(matches!(
        interp.exchange(Vec::new()),
        Err(HwiError::BadState { .. })
    ));

    interp
        .start(HwiCommand::GetMasterFingerprint)
        .expect("start");
    assert!(matches!(
        interp.start(HwiCommand::GetVersion),
        Err(HwiError::BadState { .. })
    ));

    assert!(
        interp
            .exchange(fingerprint_reply())
            .expect("exchange")
            .is_none()
    );
    assert!(
        matches!(interp.exchange(Vec::new()), Err(HwiError::BadState { .. })),
        "exchange after the machine finished"
    );

    interp.end().expect("end");
    assert!(matches!(interp.end(), Err(HwiError::BadState { .. })));
    assert!(matches!(
        interp.start(HwiCommand::GetVersion),
        Err(HwiError::BadState { .. })
    ));
}

#[test]
fn ending_mid_command_is_rejected() {
    let interp = Interp::new_ledger();
    assert!(
        matches!(interp.end(), Err(HwiError::BadState { .. })),
        "nothing was started"
    );

    let interp = Interp::new_ledger();
    interp
        .start(HwiCommand::GetMasterFingerprint)
        .expect("start");
    assert!(matches!(interp.end(), Err(HwiError::BadState { .. })));
}

#[test]
fn a_protocol_failure_retires_the_interpreter() {
    let interp = Interp::new_ledger();
    interp
        .start(HwiCommand::GetMasterFingerprint)
        .expect("start");
    // Not a status word the interpreter accepts for this command.
    let error = interp
        .exchange(apdu(&[], [0x6d, 0x00]))
        .expect_err("bad status");
    assert!(matches!(error, HwiError::Device { .. }), "got {error:?}");
    assert!(matches!(interp.end(), Err(HwiError::BadState { .. })));
}

#[test]
fn coldcard_protocol_errors_do_not_leak_and_release_the_lease() {
    let canary = "ffi-redaction-canary";
    let encryption = ColdcardEncryption::new();
    let interp = Interp::new_coldcard(encryption.clone()).expect("interpreter");
    interp
        .start(HwiCommand::Unlock {
            network: Network::Testnet,
        })
        .expect("start");
    let error = interp
        .exchange(format!("zzzz{canary}").into_bytes())
        .expect_err("unknown Coldcard response");
    let HwiError::Device { ref msg } = error else {
        panic!("expected a device error, got {error:?}");
    };
    assert!(!msg.contains(canary), "leaked error field: {error:?}");
    assert!(!error.to_string().contains(canary));
    assert!(msg.contains("Coldcard"), "missing device context");
    assert!(matches!(interp.end(), Err(HwiError::BadState { .. })));
    Interp::new_coldcard(encryption).expect("lease released after protocol failure");
}

#[test]
fn errors_after_runtime_start_are_terminal_and_release_the_lease() {
    let encryption = ColdcardEncryption::new();
    let interp = Interp::new_coldcard(encryption.clone()).unwrap();
    // Lowering succeeds; runtime encryption fails because this connection is not unlocked.
    assert!(matches!(
        interp.start(HwiCommand::GetMasterFingerprint),
        Err(HwiError::Device { .. })
    ));
    assert!(matches!(
        interp.start(HwiCommand::Unlock {
            network: Network::Testnet
        }),
        Err(HwiError::BadState { .. })
    ));
    Interp::new_coldcard(encryption).expect("runtime failure releases the lease");
}

#[test]
fn invalid_input_leaves_the_interpreter_usable() {
    let interp = Interp::new_ledger();
    assert!(matches!(
        interp.start(HwiCommand::GetXpub {
            path: "not a path".to_string(),
            display: false,
        }),
        Err(HwiError::InvalidInput { .. })
    ));
    let error = interp
        .start(HwiCommand::SignPsbt {
            psbt_base64: "cHNidP8FAN6tvu8A".to_string(),
            wallet_policy: None,
        })
        .expect_err("invalid PSBT key data");
    let HwiError::InvalidInput { ref msg } = error else {
        panic!("expected invalid input, got {error:?}");
    };
    assert!(!msg.contains("deadbeef"), "leaked PSBT key data: {error:?}");
    assert!(!error.to_string().contains("deadbeef"));
    let response = drive(
        &interp,
        HwiCommand::GetMasterFingerprint,
        vec![fingerprint_reply()],
    )
    .expect("fingerprint after invalid input");
    let HwiResponse::Fingerprint { hex } = response else {
        panic!("expected a fingerprint");
    };
    assert_eq!(hex, FINGERPRINT);
}

#[test]
fn unsupported_bitbox_command_keeps_its_input_category_and_live_lease() {
    let noise = NoiseHandle::new(None).unwrap();
    let interp = Interp::new_bitbox(noise.clone(), Network::Testnet).unwrap();
    assert!(matches!(
        interp.start(HwiCommand::PromptPin),
        Err(HwiError::InvalidInput { .. })
    ));
    assert!(matches!(noise.export(), Err(HwiError::BadState { .. })));
    assert!(
        interp
            .start(HwiCommand::Unlock {
                network: Network::Testnet,
            })
            .is_ok()
    );
}

#[test]
fn bitbox_unlock_emits_unlock_then_handshake_init() {
    let noise = NoiseHandle::new(None).expect("noise handle");
    let interp = Interp::new_bitbox(noise.clone(), Network::Testnet).expect("interpreter");

    let transmit = interp
        .start(HwiCommand::Unlock {
            network: Network::Testnet,
        })
        .expect("start");
    assert_eq!(transmit.payload, b"u");
    assert!(!transmit.encrypted);

    let next = interp
        .exchange(Vec::new())
        .expect("unlock ack")
        .expect("more");
    assert_eq!(next.payload, b"h");
}

#[test]
fn bitbox_handshake_generates_and_keeps_the_host_key() {
    const RESPONSE_SUCCESS: u8 = 0x00;
    const OP_HER_COMEZ_TEH_HANDSHAEK: u8 = b'H';

    let noise = NoiseHandle::new(None).expect("noise handle");
    assert_eq!(noise.export().expect("fresh export").privkey, None);

    let interp = Interp::new_bitbox(noise.clone(), Network::Testnet).expect("interpreter");
    interp
        .start(HwiCommand::Unlock {
            network: Network::Testnet,
        })
        .expect("start");
    interp.exchange(Vec::new()).expect("unlock ack");
    let handshake = interp
        .exchange(vec![RESPONSE_SUCCESS])
        .expect("handshake init")
        .expect("more");
    assert_eq!(handshake.payload[0], OP_HER_COMEZ_TEH_HANDSHAEK);
    // The noise XX first message is the host's 32-byte ephemeral key.
    assert_eq!(handshake.payload.len(), 33);
    // No pairing code yet: it only exists once the device answers the handshake.
    assert_eq!(noise.take_pairing_code(), None);

    // The key generated during the handshake was written through the lease, so it is
    // visible once the interpreter releases it.
    drop(interp);
    let exported = noise.export().expect("export after the lease is released");
    assert_eq!(exported.privkey.expect("generated host key").len(), 32);
}

#[test]
fn a_leased_noise_handle_refuses_a_second_interpreter() {
    let noise = NoiseHandle::new(None).expect("noise handle");
    let first = Interp::new_bitbox(noise.clone(), Network::Bitcoin).expect("first");
    assert!(matches!(
        Interp::new_bitbox(noise.clone(), Network::Bitcoin),
        Err(HwiError::BadState { .. })
    ));
    assert!(
        matches!(noise.export(), Err(HwiError::BadState { .. })),
        "export is refused while the state is leased"
    );

    // `end` releases the lease even though the command never ran.
    let _ = first.end();
    assert!(Interp::new_bitbox(noise.clone(), Network::Bitcoin).is_ok());
}

#[test]
fn dropping_an_interpreter_releases_the_lease() {
    let encryption = ColdcardEncryption::new();
    let weak = Arc::downgrade(&encryption);
    let interp = Interp::new_coldcard(encryption.clone()).expect("interpreter");
    assert!(matches!(
        Interp::new_coldcard(encryption.clone()),
        Err(HwiError::BadState { .. })
    ));
    drop(interp);
    let next = Interp::new_coldcard(encryption).expect("lease released");
    drop(next);
    assert!(weak.upgrade().is_none());
}

/// The device's answer to `ncry`: its ephemeral pubkey, the master fingerprint and an
/// empty xpub.
fn coldcard_mypub_reply() -> Vec<u8> {
    let secp = Secp256k1::new();
    let pubkey = SecretKey::from_slice(&[3u8; 32])
        .unwrap()
        .public_key(&secp)
        .serialize_uncompressed();
    let mut out = b"mypb".to_vec();
    out.extend_from_slice(&pubkey[1..]);
    out.extend_from_slice(&hex::decode(FINGERPRINT).unwrap());
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

#[test]
fn coldcard_unlock_installs_the_session_key() {
    let encryption = ColdcardEncryption::new();
    let interp = Interp::new_coldcard(encryption.clone()).expect("interpreter");
    let transmit = interp
        .start(HwiCommand::Unlock {
            network: Network::Testnet,
        })
        .expect("start");
    // `ncry` carries the host's ephemeral pubkey; the session key is derived in-protocol.
    assert_eq!(&transmit.payload[..4], b"ncry");
    assert!(!transmit.encrypted);

    assert!(
        interp
            .exchange(coldcard_mypub_reply())
            .expect("exchange")
            .is_none()
    );
    // The session key never reaches the host: `end` installs it, like `bhwi-async`'s
    // `OnUnlock` does, and reports the unlock as done.
    assert!(matches!(interp.end().expect("end"), HwiResponse::TaskDone));

    // Proof the engine is live: the next command on the same handle is encrypted.
    let next = Interp::new_coldcard(encryption).expect("second interpreter");
    let transmit = next.start(HwiCommand::GetMasterFingerprint).expect("start");
    assert!(transmit.encrypted);
}

#[test]
fn jade_unlock_starts_the_auth_handshake() {
    let interp = Interp::new_jade(Network::Testnet);
    let transmit: Transmit = interp
        .start(HwiCommand::Unlock {
            network: Network::Testnet,
        })
        .expect("start");
    assert_eq!(transmit.recipient, Recipient::Device);
    // CBOR request for `auth_user` on the testnet network.
    let payload = String::from_utf8_lossy(&transmit.payload).to_string();
    assert!(payload.contains("auth_user"), "got {payload:?}");
    assert!(payload.contains("testnet"), "got {payload:?}");
}

#[test]
fn interp_handles_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Arc<Interp>>();
    assert_send_sync::<Arc<NoiseHandle>>();
    assert_send_sync::<Arc<ColdcardEncryption>>();
}

mod trezor_keepkey {
    use super::*;
    use bhwi::trezor::api::{self, MessageType};
    use bhwi_ffi::HostPassphraseHandle;

    fn frame(kind: MessageType, body: &[u8]) -> Vec<u8> {
        api::frame(kind as u16, body)
    }

    fn device(keepkey: bool, handle: Option<Arc<HostPassphraseHandle>>) -> Arc<Interp> {
        if keepkey {
            Interp::new_keepkey(Network::Testnet, handle).unwrap()
        } else {
            Interp::new_trezor(Network::Testnet, handle, false).unwrap()
        }
    }

    fn features(keepkey: bool) -> Vec<u8> {
        let body = if keepkey {
            hex::decode("0a0b6b6565706b65792e636f6d1007180a2000380140015204746573746001800100aa01074b312d3134414db201076b6565706b6579")
        } else {
            hex::decode("1001180d2001380140015204746573746001800100aa010131")
        }.unwrap();
        frame(MessageType::Features, &body)
    }

    #[test]
    fn trezor_passphrase_modes_are_exclusive_before_cloning_the_handle() {
        let handle = HostPassphraseHandle::new("passphrase-canary".into()).unwrap();
        assert!(matches!(
            Interp::new_trezor(Network::Testnet, Some(handle.clone()), true),
            Err(HwiError::InvalidInput { .. })
        ));
        Interp::new_trezor(Network::Testnet, Some(handle.clone()), false).unwrap();
        handle.clear();
        // A cleared owner would produce BadState if cloning happened first.
        let error = Interp::new_trezor(Network::Testnet, Some(handle), true)
            .err()
            .unwrap();
        assert!(matches!(error, HwiError::InvalidInput { .. }));
        assert!(!format!("{error:?}").contains("passphrase-canary"));
    }

    #[test]
    fn raw_replies_require_one_exact_unpadded_frame_for_both_families() {
        for keepkey in [false, true] {
            let valid = features(keepkey);
            let mut wrong_magic = valid.clone();
            wrong_magic[0] = b'!';
            let mut padded = valid.clone();
            padded.extend_from_slice(b"raw-reply-canary");
            let mut truncated = valid.clone();
            truncated.pop();
            let mut excessive_length = valid.clone();
            excessive_length[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
            let mut replies = vec![wrong_magic, padded, truncated, excessive_length];
            replies.extend((0..8).map(|len| valid[..len].to_vec()));
            for reply in replies {
                let interp = device(keepkey, None);
                interp.start(HwiCommand::GetVersion).unwrap();
                let error = interp.exchange(reply).unwrap_err();
                assert!(
                    matches!(error, HwiError::Device { ref msg } if msg == "malformed device protocol reply")
                );
                assert!(!format!("{error:?}").contains("raw-reply-canary"));
                assert!(matches!(interp.end(), Err(HwiError::BadState { .. })));
                assert!(matches!(
                    interp.exchange(valid.clone()),
                    Err(HwiError::BadState { .. })
                ));
            }
            let interp = device(keepkey, None);
            interp.start(HwiCommand::GetVersion).unwrap();
            assert!(interp.exchange(valid).unwrap().is_none());
            assert!(matches!(interp.end().unwrap(), HwiResponse::Info { .. }));
        }
    }

    #[test]
    fn keepkey_profile_rejections_leave_the_same_interpreter_usable() {
        use bhwi_ffi::{AddressFormat, MultisigAddressFormat};
        let interp = device(true, None);
        for command in [
            HwiCommand::DisplayAddress {
                path: "m/84'/1'/0'/0/7".into(),
                display: true,
                format: Some(AddressFormat::Taproot),
            },
            HwiCommand::DisplayAddress {
                path: "m/86'/1'/0'/0/7".into(),
                display: true,
                format: None,
            },
            HwiCommand::DisplayMultisigAddress {
                threshold: 1,
                sorted: false,
                format: MultisigAddressFormat::Wit,
                keys: vec!["[f5acc2fd/48'/1'/0'/2'/0/7]0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into()],
            },
        ] {
            assert!(matches!(interp.start(command), Err(HwiError::InvalidInput { .. })));
        }
        interp.start(HwiCommand::GetVersion).unwrap();
        assert!(interp.exchange(features(true)).unwrap().is_none());
        assert!(matches!(interp.end().unwrap(), HwiResponse::Info { .. }));
    }

    #[test]
    fn pin_rejection_cancellation_and_invalid_positions_are_distinct_and_redacted() {
        for keepkey in [false, true] {
            for positions in ["", "0", "10", "１２", "pin-canary"] {
                let interp = device(keepkey, None);
                let cmd = HwiCommand::SendPin {
                    positions: positions.into(),
                };
                assert_eq!(format!("{cmd:?}"), "SendPin(<redacted>)");
                let error = interp.start(cmd).unwrap_err();
                assert!(matches!(error, HwiError::InvalidInput { .. }));
                assert!(!format!("{error:?}").contains(positions) || positions.is_empty());
                interp
                    .start(HwiCommand::GetVersion)
                    .expect("invalid input did not start a command");
            }
            for code in [4, 6] {
                let interp = device(keepkey, None);
                interp
                    .start(HwiCommand::SendPin {
                        positions: "1234".into(),
                    })
                    .unwrap();
                assert!(matches!(
                    interp.exchange(frame(MessageType::Failure, &[8, code])),
                    Err(HwiError::AuthRefused)
                ));
            }
            let interp = device(keepkey, None);
            interp
                .start(HwiCommand::SendPin {
                    positions: "1234".into(),
                })
                .unwrap();
            let canary = "pin-device-canary";
            let mut failure = vec![8, 7, 18, canary.len() as u8];
            failure.extend_from_slice(canary.as_bytes());
            let reply = interp.exchange(frame(MessageType::Failure, &failure));
            let error = if keepkey {
                reply.unwrap_err()
            } else {
                assert_eq!(reply.unwrap().unwrap().payload, api::get_features());
                interp.exchange(features(false)).unwrap_err()
            };
            assert!(matches!(error, HwiError::AuthRefused));
            assert!(!format!("{error:?}").contains("1234"));
            assert!(!format!("{error:?}").contains(canary));
            assert!(matches!(interp.end(), Err(HwiError::BadState { .. })));
            assert!(matches!(
                interp.start(HwiCommand::GetVersion),
                Err(HwiError::BadState { .. })
            ));
        }
    }
}
