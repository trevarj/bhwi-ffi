//! Opt-in official Specter-DIY firmware checks. Loopback serial/GUI adapters and
//! disposable-vector initialization exist only in this test, never the shipped FFI.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use base64ct::{Base64, Encoding};
use bhwi::bitcoin::{
    Address, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute,
    bip32::{DerivationPath, Xpriv, Xpub},
    hashes::Hash,
    psbt::Psbt,
    secp256k1::{Message, Secp256k1},
    sighash::{EcdsaSighashType, SighashCache},
    transaction,
};
use bhwi_ffi::{
    HwiCommand, HwiError, HwiResponse, Interp, Network, Recipient, SpecterFrameDecoder,
    WalletPolicy, WalletRegistration,
};

const DEADLINE: Duration = Duration::from_secs(30);
// BIP39 public test vector: eleven "abandon" words + "about", empty passphrase.
const SEED: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

fn connect(variable: &str) -> TcpStream {
    let target: SocketAddr = std::env::var(variable)
        .expect("explicit localhost fixture target")
        .parse()
        .unwrap();
    assert!(target.ip().is_loopback() && target.port() != 0);
    let socket = TcpStream::connect_timeout(&target, Duration::from_secs(5)).unwrap();
    socket.set_read_timeout(Some(DEADLINE)).unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
}

struct Gui(BufReader<TcpStream>);

impl Gui {
    fn connect() -> Self {
        let socket = connect("BHWI_SPECTER_GUI_ADDR");
        thread::sleep(Duration::from_millis(100)); // Core E2E's TCPHost adoption boundary.
        Self(BufReader::new(socket))
    }

    fn screen(&mut self, deadline: Instant) -> String {
        self.0
            .get_ref()
            .set_read_timeout(Some(
                deadline
                    .checked_duration_since(Instant::now())
                    .expect("GUI deadline elapsed"),
            ))
            .unwrap();
        let mut line = Vec::new();
        // Bound allocation even if a test server does not supply a newline.
        let count = self
            .0
            .by_ref()
            .take(129)
            .read_until(b'\n', &mut line)
            .unwrap();
        assert!(
            count > 0 && count <= 128 && line.ends_with(b"\r\n"),
            "incomplete/oversized GUI screen or EOF"
        );
        line.truncate(line.len() - 2);
        assert!(
            !line.is_empty() && line.iter().all(u8::is_ascii_alphanumeric),
            "GUI returned a non-screen line; verify the runner-reported GUI port",
        );
        String::from_utf8(line).unwrap()
    }

    fn reply(&mut self, value: &str) {
        self.0.get_mut().write_all(value.as_bytes()).unwrap();
        self.0.get_mut().write_all(b"\r\n").unwrap();
    }

    fn confirm<T: Send>(&mut self, approve: bool, operation: impl FnOnce() -> T + Send) -> T {
        thread::scope(|scope| {
            let pending = scope.spawn(operation);
            let deadline = Instant::now() + DEADLINE;
            loop {
                let screen = self.screen(deadline);
                if screen == "Menu" {
                    break;
                }
                // Follow the existing core's test GUI controller, confined to this opt-in test.
                self.reply(if approve { "true" } else { "false" });
            }
            pending.join().unwrap()
        })
    }
}

fn run(serial: &mut TcpStream, command: HwiCommand) -> Result<HwiResponse, HwiError> {
    let interp = Interp::new_specter(Network::Bitcoin);
    let transmit = interp.start(command)?;
    assert_eq!(transmit.recipient, Recipient::Device);
    assert!(!transmit.encrypted);
    let deadline = Instant::now() + DEADLINE;
    serial.set_write_timeout(Some(DEADLINE)).unwrap();
    serial.write_all(&transmit.payload).unwrap();
    let decoder = SpecterFrameDecoder::new();
    loop {
        serial
            .set_read_timeout(Some(
                deadline
                    .checked_duration_since(Instant::now())
                    .expect("serial deadline elapsed"),
            ))
            .unwrap();
        let mut chunk = [0; 16 * 1024];
        let count = serial.read(&mut chunk).unwrap();
        assert!(count > 0, "firmware serial EOF");
        if let Some(frame) = decoder.push(chunk[..count].to_vec())? {
            assert!(interp.exchange(frame)?.is_none());
            return interp.end();
        }
    }
}

struct Fixture {
    path: String,
    xpub: Xpub,
    policy: WalletPolicy,
    original: Psbt,
    public: PublicKey,
    receive: String,
    change: String,
}

fn fixture(account: u32) -> Fixture {
    let secp = Secp256k1::new();
    let root =
        Xpriv::new_master(bhwi::bitcoin::Network::Bitcoin, &hex::decode(SEED).unwrap()).unwrap();
    assert_eq!(root.fingerprint(&secp).to_string(), "73c5da0a");
    // Custom nondefault policy avoids the firmware's already-enrolled BIP84 default wallet.
    let path = format!("m/44'/0'/{account}'");
    let private = root
        .derive_priv(&secp, &path.parse::<DerivationPath>().unwrap())
        .unwrap();
    let xpub = Xpub::from_priv(&secp, &private);
    let receive_key = xpub
        .derive_pub(&secp, &"0/7".parse::<DerivationPath>().unwrap())
        .unwrap();
    let change_key = xpub
        .derive_pub(&secp, &"1/7".parse::<DerivationPath>().unwrap())
        .unwrap();
    let receive = Address::p2wpkh(&receive_key.to_pub(), bhwi::bitcoin::Network::Bitcoin);
    let change = Address::p2wpkh(&change_key.to_pub(), bhwi::bitcoin::Network::Bitcoin);
    let previous = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: receive.script_pubkey(),
        }],
    };
    let mut original = Psbt::from_unsigned_tx(Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: previous.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: change.script_pubkey(),
        }],
    })
    .unwrap();
    original.inputs[0].witness_utxo = Some(previous.output[0].clone());
    original.inputs[0].non_witness_utxo = Some(previous);
    original.inputs[0].bip32_derivation.insert(
        receive_key.public_key,
        (
            root.fingerprint(&secp),
            format!("{path}/0/7").parse().unwrap(),
        ),
    );
    original.outputs[0].bip32_derivation.insert(
        change_key.public_key,
        (
            root.fingerprint(&secp),
            format!("{path}/1/7").parse().unwrap(),
        ),
    );
    Fixture {
        path: path.clone(),
        xpub,
        policy: WalletPolicy {
            name: format!("test_specter_{account}_{}", std::process::id()),
            descriptor: format!(
                "wpkh([73c5da0a/{}]{xpub}/<0;1>/*)",
                path.trim_start_matches("m/")
            ),
            ledger_hmac: None,
        },
        original,
        public: PublicKey::new(receive_key.public_key),
        receive: receive.to_string(),
        change: change.to_string(),
    }
}

fn verify(fixture: &Fixture, base64: &str) {
    let signed = Psbt::deserialize(&Base64::decode_vec(base64).unwrap()).unwrap();
    assert_eq!(signed.unsigned_tx, fixture.original.unsigned_tx);
    assert_eq!(signed.outputs, fixture.original.outputs);
    assert_eq!(signed.inputs.len(), 1);
    let signature = signed.inputs[0]
        .partial_sigs
        .get(&fixture.public)
        .expect("new signature from independently derived device key");
    assert_eq!(signed.inputs[0].partial_sigs.len(), 1);
    assert_eq!(signature.sighash_type, EcdsaSighashType::All);
    let prevout = fixture.original.inputs[0].witness_utxo.as_ref().unwrap();
    let hash = SighashCache::new(&fixture.original.unsigned_tx)
        .p2wpkh_signature_hash(
            0,
            &prevout.script_pubkey,
            prevout.value,
            EcdsaSighashType::All,
        )
        .unwrap();
    Secp256k1::verification_only()
        .verify_ecdsa(
            &Message::from_digest(hash.to_byte_array()),
            &signature.signature,
            &fixture.public.inner,
        )
        .unwrap();
    let mut without_signature = signed;
    without_signature.inputs[0].partial_sigs.clear();
    assert_eq!(
        without_signature, fixture.original,
        "original construction metadata must remain unchanged"
    );
}

#[test]
#[ignore = "requires a fresh test-owned official firmware profile and explicit localhost GUI; never run against a wallet"]
fn specter_fixture_initialize() {
    assert_eq!(
        std::env::var("BHWI_SPECTER_FRESH_PROFILE").as_deref(),
        Ok("1"),
        "initialization requires an explicitly fresh, disposable, test-owned profile",
    );
    let mut gui = Gui::connect();
    // The first PinScreen was displayed before a controller existed. Bootstrap it once,
    // then consume exactly one bounded screen line per response (never whole recv chunks).
    gui.reply("\"\"");
    for (screen, value) in [
        ("PinScreen", "\"\"".to_owned()),
        ("Menu", "1".to_owned()),
        (
            "RecoverMnemonicScreen",
            serde_json::to_string(&[vec!["abandon"; 11], vec!["about"]].concat().join(" "))
                .unwrap(),
        ),
    ] {
        assert_eq!(gui.screen(Instant::now() + DEADLINE), screen);
        gui.reply(&value);
    }
    assert_eq!(gui.screen(Instant::now() + DEADLINE), "Menu");
}

#[test]
#[ignore = "requires initialized disposable official Specter-DIY firmware, explicit localhost serial/GUI targets"]
fn specter_serial_policy_firmware_smoke() {
    let mut serial = connect("BHWI_SPECTER_ADDR");
    let mut gui = Gui::connect();
    let wallet = fixture(7);
    assert!(
        matches!(run(&mut serial, HwiCommand::Unlock { network: Network::Bitcoin }).unwrap(), HwiResponse::Fingerprint { hex } if hex == "73c5da0a")
    );
    assert!(
        matches!(run(&mut serial, HwiCommand::GetXpub { path: wallet.path.clone(), display: false }).unwrap(), HwiResponse::Xpub { xpub } if xpub == wallet.xpub.to_string())
    );
    assert!(matches!(
        run(&mut serial, HwiCommand::GetVersion),
        Err(HwiError::InvalidInput { .. })
    ));
    let registration = gui
        .confirm(true, || {
            run(
                &mut serial,
                HwiCommand::RegisterWallet {
                    name: wallet.policy.name.clone(),
                    descriptor: wallet.policy.descriptor.clone(),
                },
            )
        })
        .unwrap();
    assert!(matches!(
        registration,
        HwiResponse::WalletRegistration {
            registration: WalletRegistration::Complete { hmac: None }
        }
    ));
    for (change, expected) in [(false, &wallet.receive), (true, &wallet.change)] {
        let displayed = gui
            .confirm(true, || {
                run(
                    &mut serial,
                    HwiCommand::DisplayDescriptorAddress {
                        index: 7,
                        change,
                        display: true,
                        wallet_policy: wallet.policy.clone(),
                    },
                )
            })
            .unwrap();
        assert!(matches!(displayed, HwiResponse::Address { address } if &address == expected));
    }
    let original = Base64::encode_string(&wallet.original.serialize());
    let signed = gui
        .confirm(true, || {
            run(
                &mut serial,
                HwiCommand::SignPsbt {
                    psbt_base64: original.clone(),
                    wallet_policy: Some(wallet.policy.clone()),
                },
            )
        })
        .unwrap();
    let HwiResponse::SignedPsbt { psbt_base64 } = signed else {
        panic!("expected PSBT, never raw transaction");
    };
    verify(&wallet, &psbt_base64);
    let refused = gui.confirm(false, || {
        run(
            &mut serial,
            HwiCommand::SignPsbt {
                psbt_base64: original,
                wallet_policy: Some(wallet.policy.clone()),
            },
        )
    });
    assert!(matches!(refused, Err(HwiError::UserRefused)));
    assert!(
        matches!(run(&mut serial, HwiCommand::GetMasterFingerprint).unwrap(), HwiResponse::Fingerprint { hex } if hex == "73c5da0a")
    );
    if let Ok(path) = std::env::var("BHWI_SPECTER_SIGNING_FIXTURE") {
        let jni = fixture(8);
        let json = serde_json::json!({"source": "public independently derived BIP39 fixture for live Specter-DIY Kotlin/JNI smoke", "fingerprint": "73c5da0a", "path": jni.path, "account_xpub": jni.xpub.to_string(), "name": jni.policy.name, "descriptor": jni.policy.descriptor, "receive": jni.receive, "change": jni.change, "original_psbt": Base64::encode_string(&jni.original.serialize())});
        std::fs::write(path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
    }
}

#[test]
#[ignore = "requires a Kotlin firmware smoke public result file; independently verifies its actual signature"]
fn specter_signing_fixture_verifies() {
    let path = std::env::var("BHWI_SPECTER_SIGNING_RESULT").expect("public Kotlin firmware result");
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let wallet = fixture(8);
    assert_eq!(json["fingerprint"], "73c5da0a");
    assert_eq!(json["path"], wallet.path);
    assert_eq!(json["account_xpub"], wallet.xpub.to_string());
    assert_eq!(json["descriptor"], wallet.policy.descriptor);
    assert_eq!(
        json["original_psbt"],
        Base64::encode_string(&wallet.original.serialize())
    );
    verify(
        &wallet,
        json["signed_psbt"]
            .as_str()
            .expect("actual Kotlin-returned signature"),
    );
}
