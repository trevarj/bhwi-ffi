//! UniFFI bindings for BHWI's sans-io interpreter surface.
//!
//! There is no I/O in this crate. One device-generic API over
//! `bhwi::common::{Command, Transmit, Response, Error}` drives every supported device;
//! only the constructor is per-device. The host owns the transport, the per-device wire
//! framing, the PIN-server HTTP request and the driving loop. What crosses the FFI is
//! `(payload bytes, encrypted flag, recipient)` out and device/HTTP replies in.
//!
//! Driving model, per logical command:
//!
//! 1. Construct the device's `Interp` (including `new_trezor` / `new_keepkey` with a
//!    native passphrase handle and the chosen entry mode).
//! 2. `start(command)` -> first `Transmit`
//! 3. deliver device/HTTP payloads and call `exchange(reply)` -> next `Transmit`, or
//!    `null` when done; fail closed on unexpected host requests
//! 4. `end()` -> the typed `HwiResponse`
//!
//! An `Interp` runs exactly one command and is consumed by `end()`. Device state that
//! must survive a command (BitBox noise pairing, Coldcard link encryption) lives in a
//! separate handle the host keeps.

uniffi::setup_scaffolding!();

mod helpers;
mod interp;
mod state;
mod types;

pub use helpers::{
    AddressEntry, InputSummary, OutputSummary, PsbtSummary, build_singlesig_descriptor,
    derive_addresses, psbt_summary,
};
pub use interp::Interp;
pub use state::{
    ColdcardEncryption, HostPassphraseHandle, NoiseConfig, NoiseHandle, SpecterFrameDecoder,
};
pub use types::{
    HostRequest, HwiCommand, HwiResponse, MultisigAddressFormat, PinMatrixRequestKind, Recipient,
    Transmit, WalletPolicy, WalletRegistration,
};

/// Bitcoin network selector, mirrored from `bitcoin::Network`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Network {
    Bitcoin,
    Testnet,
    Signet,
    Regtest,
}

impl From<Network> for bhwi::bitcoin::Network {
    fn from(network: Network) -> Self {
        match network {
            Network::Bitcoin => Self::Bitcoin,
            Network::Testnet => Self::Testnet,
            Network::Signet => Self::Signet,
            Network::Regtest => Self::Regtest,
        }
    }
}

impl From<bhwi::bitcoin::Network> for Network {
    fn from(network: bhwi::bitcoin::Network) -> Self {
        match network {
            bhwi::bitcoin::Network::Bitcoin => Self::Bitcoin,
            bhwi::bitcoin::Network::Signet => Self::Signet,
            bhwi::bitcoin::Network::Regtest => Self::Regtest,
            // `bitcoin::Network` is `#[non_exhaustive]`; every remaining test network
            // (Testnet3, Testnet4, ...) is reported as Testnet.
            _ => Self::Testnet,
        }
    }
}

/// Singlesig script kind, used for address display and descriptor building.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AddressFormat {
    Legacy,
    NestedSegwit,
    NativeSegwit,
    Taproot,
}

impl From<AddressFormat> for bhwi::bitcoin::AddressType {
    fn from(format: AddressFormat) -> Self {
        match format {
            AddressFormat::Legacy => Self::P2pkh,
            AddressFormat::NestedSegwit => Self::P2sh,
            AddressFormat::NativeSegwit => Self::P2wpkh,
            AddressFormat::Taproot => Self::P2tr,
        }
    }
}

/// Structured errors surfaced to foreign-language hosts. Messages produced by this
/// crate do not carry raw protocol payloads or key material.
/// Upstream error messages/data are discarded; native variants, kinds and vendor codes determine
/// categories. Trezor/KeepKey authentication cancellation codes 4/6 and wrong-PIN
/// code 7 are `AuthRefused`, not successful `DeviceAction(false)` responses.
///
/// This guarantee applies only to `HwiError`. UniFFI catches unwinding panics and
/// reports unexpected failures separately (as Kotlin `InternalException`), whose
/// messages may retain panic text. It does not make aborts or out-of-memory failures
/// recoverable.
///
/// I/O failures have no variant here: the host owns every transport, so it reports
/// transport and HTTP problems in its own native error type.
#[derive(Clone, Debug, thiserror::Error, uniffi::Error)]
pub enum HwiError {
    #[error("device error: {msg}")]
    Device { msg: String },
    #[error("user refused the operation")]
    UserRefused,
    #[error("authentication refused")]
    AuthRefused,
    #[error("device is already unlocked")]
    DeviceAlreadyUnlocked,
    #[error("invalid input: {msg}")]
    InvalidInput { msg: String },
    #[error("bad state: {msg}")]
    BadState { msg: String },
    #[error("internal error: {msg}")]
    Internal { msg: String },
}

impl HwiError {
    pub(crate) fn invalid(msg: impl std::fmt::Display) -> Self {
        Self::InvalidInput {
            msg: msg.to_string(),
        }
    }

    pub(crate) fn bad_state(msg: impl std::fmt::Display) -> Self {
        Self::BadState {
            msg: msg.to_string(),
        }
    }

    pub(crate) fn internal(msg: impl std::fmt::Display) -> Self {
        Self::Internal {
            msg: msg.to_string(),
        }
    }
}
