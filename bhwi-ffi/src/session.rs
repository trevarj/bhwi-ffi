//! One session == one connected device == one worker thread.
//!
//! `bhwi-async` device objects are `!Send`, so each session owns a dedicated thread that
//! builds and drives the device locally. The exported async methods only ever hold a
//! oneshot receiver, which keeps their futures `Send` for UniFFI.

use std::fmt::Debug;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::str::FromStr;
use std::sync::{Arc, Mutex, mpsc};

use base64ct::{Base64, Encoding};
use bhwi::bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use bhwi::bitcoin::psbt::Psbt;
use bhwi::bitcoin::secp256k1::ecdsa::Signature;
use bhwi::ledger::{LedgerWalletPolicy, Version, singlesig_wallet_policy};
use bhwi_async::bitbox::BitBox;
use bhwi_async::coldcard::Coldcard;
use bhwi_async::transport::bitbox::hid::BitBoxTransportHID;
use bhwi_async::transport::coldcard::hid::ColdcardTransportHID;
use bhwi_async::transport::ledger::hid::LedgerTransportHID;
use bhwi_async::{DeviceContext, DisplayAddress, HWI, Jade, Ledger};
use futures::channel::oneshot;
use futures::executor::block_on;

use crate::foreign::{
    BleChannel, DISCONNECT_MARKER, ForeignChannel, ForeignHttp, ForeignSerial, HidChannel,
    HttpBridge, LedgerBleTransport, PairingCodeListener, SerialStream,
};
use crate::{AddressFormat, DeviceInfo, HwiError, Network};

/// Which device a session is talking to. Refusal reporting is device-specific, so the
/// worker keeps this around to interpret errors.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DeviceKind {
    Ledger,
    Coldcard,
    BitBox,
    Jade,
}

/// A command already validated on the caller side, ready for the worker.
enum Job {
    Unlock(bhwi::bitcoin::Network),
    GetInfo,
    MasterFingerprint,
    Xpub {
        path: DerivationPath,
        display: bool,
    },
    Address(DisplayAddress),
    SignMessage {
        message: Vec<u8>,
        path: DerivationPath,
    },
    SignPsbt(Psbt),
}

enum Reply {
    Unit,
    Info(DeviceInfo),
    Text(String),
}

struct Request {
    job: Job,
    reply: oneshot::Sender<Result<Reply, HwiError>>,
}

/// A connected device. One command is in flight at a time; the channel serialises them.
#[derive(uniffi::Object)]
pub struct HwiSession {
    /// `None` once closed. Dropping the sender also stops the worker, so `Drop` needs no
    /// extra work beyond the implicit field drop.
    sender: Mutex<Option<mpsc::Sender<Request>>>,
}

impl HwiSession {
    async fn call(&self, job: Job) -> Result<Reply, HwiError> {
        let (reply, answer) = oneshot::channel();
        {
            // Scope the guard: a `MutexGuard` held across the await would make the future
            // `!Send` and UniFFI would reject it.
            let guard = self.sender.lock().map_err(|_| HwiError::Internal {
                msg: "session lock poisoned".to_string(),
            })?;
            let sender = guard.as_ref().ok_or(HwiError::Closed)?;
            sender
                .send(Request { job, reply })
                .map_err(|_| HwiError::Closed)?;
        }
        answer.await.map_err(|_| HwiError::Closed)?
    }

    async fn call_text(&self, job: Job) -> Result<String, HwiError> {
        match self.call(job).await? {
            Reply::Text(text) => Ok(text),
            _ => Err(HwiError::Internal {
                msg: "unexpected reply kind".to_string(),
            }),
        }
    }
}

#[uniffi::export]
impl HwiSession {
    /// Ledger: opens the Bitcoin app. Jade/BitBox/Coldcard: authenticates the device.
    pub async fn unlock(&self, network: Network) -> Result<(), HwiError> {
        self.call(Job::Unlock(network.into())).await.map(|_| ())
    }

    pub async fn get_info(&self) -> Result<DeviceInfo, HwiError> {
        match self.call(Job::GetInfo).await? {
            Reply::Info(info) => Ok(info),
            _ => Err(HwiError::Internal {
                msg: "unexpected reply kind".to_string(),
            }),
        }
    }

    pub async fn get_master_fingerprint(&self) -> Result<String, HwiError> {
        self.call_text(Job::MasterFingerprint).await
    }

    pub async fn get_extended_pubkey(
        &self,
        path: String,
        display: bool,
    ) -> Result<String, HwiError> {
        let path = parse_path(&path)?;
        self.call_text(Job::Xpub { path, display }).await
    }

    pub async fn display_address(
        &self,
        path: String,
        display: bool,
        address_format: Option<AddressFormat>,
    ) -> Result<String, HwiError> {
        let path = parse_path(&path)?;
        self.call_text(Job::Address(DisplayAddress::ByPath {
            path,
            display,
            address_format: address_format.map(Into::into),
        }))
        .await
    }

    /// Returns the standard `signmessage` base64: header byte followed by the 64-byte
    /// compact signature.
    pub async fn sign_message(&self, message: Vec<u8>, path: String) -> Result<String, HwiError> {
        let path = parse_path(&path)?;
        self.call_text(Job::SignMessage { message, path }).await
    }

    pub async fn sign_psbt(&self, psbt_base64: String) -> Result<String, HwiError> {
        let psbt = decode_psbt(&psbt_base64)?;
        self.call_text(Job::SignPsbt(psbt)).await
    }

    /// Idempotent. Stops the worker; later calls fail with `HwiError::Closed`.
    ///
    /// Exported as `disconnect` because every UniFFI object already has a generated
    /// `close()` (the handle destructor), and a second `close` collides with it in
    /// Kotlin. `disconnect()` is the deterministic one: it drops the sender even when
    /// a future still holds a reference to the session.
    #[uniffi::method(name = "disconnect")]
    pub fn close(&self) {
        if let Ok(mut guard) = self.sender.lock() {
            guard.take();
        }
    }
}

pub(crate) fn parse_path(path: &str) -> Result<DerivationPath, HwiError> {
    DerivationPath::from_str(path.trim()).map_err(|_| HwiError::invalid("invalid derivation path"))
}

pub(crate) fn decode_psbt(psbt_base64: &str) -> Result<Psbt, HwiError> {
    let raw = Base64::decode_vec(psbt_base64.trim())
        .map_err(|_| HwiError::invalid("PSBT is not valid base64"))?;
    Psbt::deserialize(&raw).map_err(|e| HwiError::invalid(format!("invalid PSBT: {e}")))
}

pub(crate) fn encode_psbt(psbt: &Psbt) -> String {
    Base64::encode_string(&psbt.serialize())
}

fn encode_signature(header: u8, signature: &Signature) -> String {
    let mut out = Vec::with_capacity(65);
    out.push(header);
    out.extend_from_slice(&signature.serialize_compact());
    Base64::encode_string(&out)
}

/// Maps a driver error to the FFI surface.
///
/// `user_action` marks the commands the user physically approves on the device
/// (display address, sign message, sign tx); only those can produce a refusal.
fn map_error<E: Debug, F: Debug>(
    error: bhwi_async::Error<E, F>,
    kind: DeviceKind,
    user_action: bool,
) -> HwiError {
    use bhwi::common::Error as CommonError;
    /// Jade reports a user-declined prompt with this CBOR-RPC code.
    const JADE_USER_CANCELLED: i32 = bhwi::jade::api::ErrorCode::UserCancelled as i32;

    match error {
        bhwi_async::Error::Transport(e) => {
            let msg = format!("{e:?}");
            // The framing transports erase `io::ErrorKind`, so recover the unplug from the
            // marker `foreign::io_err` embeds.
            if msg.contains(DISCONNECT_MARKER) {
                HwiError::Disconnected
            } else {
                HwiError::Transport { msg }
            }
        }
        bhwi_async::Error::HttpClient(e) => HwiError::Http {
            msg: format!("{e:?}"),
        },
        bhwi_async::Error::Interpreter(e) => match e {
            // BitBox `UserAbort`/pairing rejection and Jade handshake refusal land here.
            CommonError::AuthenticationRefused => HwiError::UserRefused,
            // Jade is the only device reporting the decline as a typed RPC code.
            CommonError::Rpc(code, _)
                if kind == DeviceKind::Jade && code == JADE_USER_CANCELLED =>
            {
                HwiError::UserRefused
            }
            // Ledger turns a `Deny` status word into `Response::TaskDone`, and Coldcard does
            // the same for a `refu` reply to `show_address`; neither matches the response the
            // `HWI` trait expects, so the driver reports a missing result instead.
            // Jade and BitBox use explicit errors, so an empty result there is a real fault.
            CommonError::NoErrorOrResult
                if user_action && matches!(kind, DeviceKind::Ledger | DeviceKind::Coldcard) =>
            {
                HwiError::UserRefused
            }
            CommonError::InvalidInput(msg) => HwiError::InvalidInput { msg },
            // Coldcard's `refu` reply to sign message / sign tx is not an anticipated
            // response there, so it surfaces as an unexpected-response context string.
            CommonError::UnexpectedResult(_, ref context)
                if user_action && kind == DeviceKind::Coldcard && context.contains("got Refu") =>
            {
                HwiError::UserRefused
            }
            // Deliberately drops the raw payload: errors must not carry protocol bytes.
            CommonError::UnexpectedResult(_, context) => HwiError::Device {
                msg: format!("unexpected result for {context}"),
            },
            other => HwiError::Device {
                msg: other.to_string(),
            },
        },
    }
}

async fn run_job<D, E, F>(device: &mut D, job: Job, kind: DeviceKind) -> Result<Reply, HwiError>
where
    D: HWI<Error = bhwi_async::Error<E, F>>,
    E: Debug,
    F: Debug,
{
    match job {
        Job::Unlock(network) => device
            .unlock(network)
            .await
            .map(|()| Reply::Unit)
            .map_err(|e| map_error(e, kind, false)),
        Job::GetInfo => device
            .get_info()
            .await
            .map(|info| Reply::Info(info.into()))
            .map_err(|e| map_error(e, kind, false)),
        Job::MasterFingerprint => device
            .get_master_fingerprint()
            .await
            .map(|fingerprint| Reply::Text(fingerprint.to_string()))
            .map_err(|e| map_error(e, kind, false)),
        Job::Xpub { path, display } => device
            .get_extended_pubkey(path, display)
            .await
            .map(|xpub| Reply::Text(xpub.to_string()))
            .map_err(|e| map_error(e, kind, false)),
        Job::Address(address) => device
            .display_address(address, None)
            .await
            .map(Reply::Text)
            .map_err(|e| map_error(e, kind, true)),
        Job::SignMessage { message, path } => device
            .sign_message(&message, path)
            .await
            .map(|(header, signature)| Reply::Text(encode_signature(header, &signature)))
            .map_err(|e| map_error(e, kind, true)),
        Job::SignPsbt(psbt) => sign_psbt(device, psbt, kind)
            .await
            .map(|psbt| Reply::Text(encode_psbt(&psbt))),
    }
}

async fn sign_psbt<D, E, F>(device: &mut D, psbt: Psbt, kind: DeviceKind) -> Result<Psbt, HwiError>
where
    D: HWI<Error = bhwi_async::Error<E, F>>,
    E: Debug,
    F: Debug,
{
    if kind != DeviceKind::Ledger {
        return device
            .sign_tx(psbt, None)
            .await
            .map_err(|e| map_error(e, kind, true));
    }

    // Ledger will not sign without an explicit wallet policy, even for singlesig inputs,
    // so rebuild the default policy of every standard account the PSBT spends from.
    let fingerprint = device
        .get_master_fingerprint()
        .await
        .map_err(|e| map_error(e, kind, false))?;
    let accounts = singlesig_accounts(&psbt, fingerprint);
    if accounts.is_empty() {
        return Err(HwiError::invalid(
            "no standard singlesig input in this PSBT derives from this device",
        ));
    }

    let mut signed = psbt;
    for (legacy, account_path) in accounts {
        let xpub = device
            .get_extended_pubkey(account_path.clone(), false)
            .await
            .map_err(|e| map_error(e, kind, false))?;
        let policy =
            singlesig_wallet_policy(&extend_account_path(&account_path), fingerprint, xpub)
                .map_err(|e| HwiError::invalid(e.to_string()))?;
        let context = DeviceContext::Ledger {
            wallet_policy: LedgerWalletPolicy::new(String::new(), Version::V2, policy),
            wallet_hmac: None,
        };
        let mut to_sign = signed.clone();
        if legacy {
            strip_legacy_witness_utxos(&mut to_sign, fingerprint, &account_path);
        }
        let result = device
            .sign_tx(to_sign, Some(context))
            .await
            .map_err(|e| map_error(e, kind, true))?;
        merge_psbt_signatures(&mut signed, result);
    }
    Ok(signed)
}

/// Distinct standard singlesig accounts (BIP44/49/84/86) owned by `fingerprint`.
/// The boolean marks legacy (BIP44) accounts.
fn singlesig_accounts(psbt: &Psbt, fingerprint: Fingerprint) -> Vec<(bool, DerivationPath)> {
    let mut accounts: Vec<(bool, DerivationPath)> = Vec::new();
    for input in &psbt.inputs {
        let origins = input
            .bip32_derivation
            .values()
            .map(|(fp, path)| (*fp, path))
            .chain(
                input
                    .tap_key_origins
                    .values()
                    .map(|(_, (fp, path))| (*fp, path)),
            );
        for (fp, path) in origins {
            if fp != fingerprint {
                continue;
            }
            let children: &[ChildNumber] = path.as_ref();
            // Ledger's default policies are always 5 levels: purpose/coin/account/change/index.
            if children.len() < 5 {
                continue;
            }
            let ChildNumber::Hardened { index: purpose } = children[0] else {
                continue;
            };
            if !matches!(purpose, 44 | 49 | 84 | 86) {
                continue;
            }
            let entry = (purpose == 44, DerivationPath::from(children[..3].to_vec()));
            if !accounts.contains(&entry) {
                accounts.push(entry);
            }
        }
    }
    accounts
}

/// `singlesig_wallet_policy` wants a full address path; the branch/index are irrelevant to
/// the resulting policy, so any receive address works.
fn extend_account_path(path: &DerivationPath) -> DerivationPath {
    let mut children = path.as_ref().to_vec();
    children.push(ChildNumber::from_normal_idx(0).expect("valid branch"));
    children.push(ChildNumber::from_normal_idx(0).expect("valid index"));
    DerivationPath::from(children)
}

/// Ledger rejects legacy inputs that also carry a witness UTXO.
///
/// Scoped to the legacy account currently being signed: a PSBT mixing BIP44 and BIP49
/// inputs must keep `witness_utxo` on its nested-segwit inputs for the other passes.
fn strip_legacy_witness_utxos(psbt: &mut Psbt, fingerprint: Fingerprint, account: &DerivationPath) {
    let account: &[ChildNumber] = account.as_ref();
    for (index, input) in psbt.inputs.iter_mut().enumerate() {
        let owned_by_account = input
            .bip32_derivation
            .values()
            .any(|(fp, path)| *fp == fingerprint && path.as_ref().starts_with(account));
        if !owned_by_account {
            continue;
        }
        let Some(utxo) = input.non_witness_utxo.as_ref().and_then(|tx| {
            tx.output
                .get(psbt.unsigned_tx.input[index].previous_output.vout as usize)
        }) else {
            continue;
        };
        if !utxo.script_pubkey.is_witness_program() {
            input.witness_utxo = None;
        }
    }
}

fn merge_psbt_signatures(target: &mut Psbt, signed: Psbt) {
    for (target, signed) in target.inputs.iter_mut().zip(signed.inputs) {
        target.partial_sigs.extend(signed.partial_sigs);
        target.tap_script_sigs.extend(signed.tap_script_sigs);
        if signed.tap_key_sig.is_some() {
            target.tap_key_sig = signed.tap_key_sig;
        }
    }
}

/// Spawns the worker thread that owns the `!Send` device object for this session.
fn spawn<D, E, F>(kind: DeviceKind, build: impl FnOnce() -> D + Send + 'static) -> Arc<HwiSession>
where
    D: HWI<Error = bhwi_async::Error<E, F>> + 'static,
    E: Debug + 'static,
    F: Debug + 'static,
{
    let (sender, receiver) = mpsc::channel::<Request>();
    std::thread::Builder::new()
        .name("bhwi-session".to_string())
        .spawn(move || {
            let mut device = build();
            while let Ok(Request { job, reply }) = receiver.recv() {
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    block_on(run_job(&mut device, job, kind))
                }));
                let panicked = outcome.is_err();
                let _ = reply.send(outcome.unwrap_or_else(|_| {
                    Err(HwiError::Internal {
                        msg: "device worker panicked".to_string(),
                    })
                }));
                // A panic can leave the device mid-protocol; stop instead of corrupting it.
                if panicked {
                    break;
                }
            }
        })
        .expect("spawn bhwi session worker");
    Arc::new(HwiSession {
        sender: Mutex::new(Some(sender)),
    })
}

#[uniffi::export]
pub fn connect_ledger_usb(hid: Arc<dyn HidChannel>) -> Arc<HwiSession> {
    spawn(DeviceKind::Ledger, move || {
        Ledger::new(LedgerTransportHID::new(ForeignChannel::new(hid)))
    })
}

#[uniffi::export]
pub fn connect_ledger_ble(ble: Arc<dyn BleChannel>) -> Arc<HwiSession> {
    spawn(DeviceKind::Ledger, move || {
        Ledger::new(LedgerBleTransport::new(ble))
    })
}

#[uniffi::export]
pub fn connect_coldcard_usb(hid: Arc<dyn HidChannel>) -> Arc<HwiSession> {
    spawn(DeviceKind::Coldcard, move || {
        let mut rng = rand_core::OsRng;
        Coldcard::new(
            ColdcardTransportHID::new(ForeignChannel::new(hid)),
            &mut rng,
        )
    })
}

#[uniffi::export]
pub fn connect_bitbox_usb(
    hid: Arc<dyn HidChannel>,
    network: Network,
    pairing: Arc<dyn PairingCodeListener>,
) -> Arc<HwiSession> {
    spawn(DeviceKind::BitBox, move || {
        let mut bitbox = BitBox::new(BitBoxTransportHID::new(ForeignChannel::new(hid)), None)
            .with_network(network.into());
        // Fires synchronously inside `unlock` while the user confirms the code on-device.
        bitbox.set_pairing_code_hook(Box::new(move |code| {
            pairing.on_pairing_code(code.to_string());
        }));
        bitbox
    })
}

#[uniffi::export]
pub fn connect_jade_usb(
    serial: Arc<dyn SerialStream>,
    http: Arc<dyn HttpBridge>,
    network: Network,
) -> Arc<HwiSession> {
    connect_jade(serial, http, network)
}

#[uniffi::export]
pub fn connect_jade_ble(
    serial: Arc<dyn SerialStream>,
    http: Arc<dyn HttpBridge>,
    network: Network,
) -> Arc<HwiSession> {
    connect_jade(serial, http, network)
}

/// Jade speaks the same CBOR stream over USB serial and BLE; Kotlin supplies the bytes.
fn connect_jade(
    serial: Arc<dyn SerialStream>,
    http: Arc<dyn HttpBridge>,
    network: Network,
) -> Arc<HwiSession> {
    spawn(DeviceKind::Jade, move || {
        Jade::new(
            network.into(),
            ForeignSerial::new(serial),
            ForeignHttp::new(http),
        )
    })
}

#[cfg(test)]
mod tests {
    use bhwi::bitcoin::hashes::Hash;
    use bhwi::bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bhwi::bitcoin::{
        Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        absolute::LockTime, transaction::Version,
    };
    use bhwi::common::Error as CommonError;

    use super::*;

    type DriverError = bhwi_async::Error<String, String>;

    #[test]
    fn refusal_mapping_is_device_specific() {
        let refused = |error, kind, user_action| {
            matches!(map_error(error, kind, user_action), HwiError::UserRefused)
        };

        // Jade: typed CBOR-RPC decline code, unambiguous regardless of the command.
        assert!(refused(
            DriverError::Interpreter(CommonError::Rpc(-32000, None)),
            DeviceKind::Jade,
            false
        ));
        assert!(!refused(
            DriverError::Interpreter(CommonError::Rpc(-32602, None)),
            DeviceKind::Jade,
            true
        ));

        // Coldcard: `refu` is unexpected for signing commands, so it lands in the context.
        assert!(refused(
            DriverError::Interpreter(CommonError::UnexpectedResult(
                Vec::new(),
                "coldcard unexpected response: expected [Okay, Busy, Smrx], got Refu".to_string(),
            )),
            DeviceKind::Coldcard,
            true
        ));

        // Empty result means a refusal only for Ledger/Coldcard user-approved commands.
        assert!(refused(
            DriverError::Interpreter(CommonError::NoErrorOrResult),
            DeviceKind::Ledger,
            true
        ));
        assert!(refused(
            DriverError::Interpreter(CommonError::NoErrorOrResult),
            DeviceKind::Coldcard,
            true
        ));
        assert!(!refused(
            DriverError::Interpreter(CommonError::NoErrorOrResult),
            DeviceKind::Jade,
            true
        ));
        assert!(!refused(
            DriverError::Interpreter(CommonError::NoErrorOrResult),
            DeviceKind::BitBox,
            true
        ));
        assert!(!refused(
            DriverError::Interpreter(CommonError::NoErrorOrResult),
            DeviceKind::Ledger,
            false
        ));

        // Every device reports pairing/handshake rejection the same way.
        assert!(refused(
            DriverError::Interpreter(CommonError::AuthenticationRefused),
            DeviceKind::BitBox,
            false
        ));
    }

    fn pubkey() -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::new(SecretKey::from_slice(&[1u8; 32]).unwrap().public_key(&secp))
    }

    fn funding(script: ScriptBuf) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: script,
            }],
        }
    }

    fn spend(txid: Txid) -> TxIn {
        TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    #[test]
    fn legacy_strip_leaves_other_accounts_untouched() {
        let key = pubkey();
        let legacy_script = ScriptBuf::new_p2pkh(&key.pubkey_hash());
        // A nested-segwit prevout is a bare P2SH script, so it is not a witness program
        // either: only the account check can tell the two inputs apart.
        let nested_script = ScriptBuf::new_p2sh(&legacy_script.script_hash());
        let fingerprint = Fingerprint::from([0xf5, 0xac, 0xc2, 0xfd]);

        let unsigned = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                spend(Txid::all_zeros()),
                spend(Txid::from_byte_array([1u8; 32])),
            ],
            output: vec![TxOut {
                value: Amount::from_sat(19_000),
                script_pubkey: legacy_script.clone(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned).unwrap();
        for (index, (script, path)) in [
            (legacy_script, "m/44'/1'/0'/0/0"),
            (nested_script, "m/49'/1'/0'/0/0"),
        ]
        .into_iter()
        .enumerate()
        {
            psbt.inputs[index].non_witness_utxo = Some(funding(script.clone()));
            psbt.inputs[index].witness_utxo = Some(TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: script,
            });
            psbt.inputs[index]
                .bip32_derivation
                .insert(key.inner, (fingerprint, path.parse().unwrap()));
        }

        strip_legacy_witness_utxos(&mut psbt, fingerprint, &"m/44'/1'/0'".parse().unwrap());

        assert!(
            psbt.inputs[0].witness_utxo.is_none(),
            "legacy input stripped"
        );
        assert!(
            psbt.inputs[1].witness_utxo.is_some(),
            "nested-segwit input must survive the legacy pass"
        );
    }
}
