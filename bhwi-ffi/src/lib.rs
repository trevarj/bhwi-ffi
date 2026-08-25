//! UniFFI (Kotlin/Android) bindings for BHWI.
//!
//! The crate is deliberately thin: device protocol work stays in `bhwi`/`bhwi-async`,
//! and everything here is either a foreign-object adapter, the session worker that owns
//! the `!Send` device objects, or a pure helper for wallet plumbing.

uniffi::setup_scaffolding!();

mod foreign;
mod helpers;
mod session;

pub use foreign::{
    BleChannel, HidChannel, HttpBridge, PairingCodeListener, SerialStream, TransportError,
};
pub use helpers::{
    AddressEntry, InputSummary, OutputSummary, PsbtSummary, build_singlesig_descriptor,
    derive_addresses, psbt_summary,
};
pub use session::{
    HwiSession, connect_bitbox_usb, connect_coldcard_usb, connect_jade_ble, connect_jade_usb,
    connect_ledger_ble, connect_ledger_usb,
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

/// Device version information returned by `HwiSession::get_info`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct DeviceInfo {
    pub version: String,
    pub firmware: Option<String>,
    pub networks: Vec<Network>,
}

impl From<bhwi_async::Info> for DeviceInfo {
    fn from(info: bhwi_async::Info) -> Self {
        Self {
            version: info.version,
            firmware: info.firmware,
            networks: info.networks.into_iter().map(Network::from).collect(),
        }
    }
}

/// Errors surfaced to Kotlin. Messages never carry raw protocol payloads or key material.
#[derive(Clone, Debug, thiserror::Error, uniffi::Error)]
pub enum HwiError {
    #[error("transport error: {msg}")]
    Transport { msg: String },
    #[error("http error: {msg}")]
    Http { msg: String },
    #[error("device error: {msg}")]
    Device { msg: String },
    #[error("user refused the operation")]
    UserRefused,
    #[error("device disconnected")]
    Disconnected,
    #[error("invalid input: {msg}")]
    InvalidInput { msg: String },
    #[error("session is closed")]
    Closed,
    #[error("internal error: {msg}")]
    Internal { msg: String },
}

impl HwiError {
    pub(crate) fn invalid(msg: impl std::fmt::Display) -> Self {
        Self::InvalidInput {
            msg: msg.to_string(),
        }
    }
}
