//! The data that crosses the FFI: commands in, transmits out, responses and errors back.
//!
//! Everything here is a plain value; the interpreter state lives in [`crate::interp`].

use std::str::FromStr;

use base64ct::{Base64, Encoding};
use bhwi::bitcoin::bip32::DerivationPath;
use bhwi::bitcoin::psbt::Psbt;
use bhwi::bitcoin::secp256k1::ecdsa::Signature;
use bhwi::common as bc;

use crate::{AddressFormat, HwiError, Network};

/// Where a payload has to be delivered.
///
/// `PinServer` only ever appears for Jade: the host must POST the payload to `url`
/// (`Content-Type: application/json`) and feed the response body back to `exchange`.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Recipient {
    Device,
    PinServer { url: String },
}

impl From<bc::Recipient> for Recipient {
    fn from(recipient: bc::Recipient) -> Self {
        match recipient {
            bc::Recipient::Device => Self::Device,
            bc::Recipient::PinServer { url } => Self::PinServer { url },
        }
    }
}

/// One payload to move. `encrypted` is the device-link encryption flag some transports
/// need for framing (BitBox U2F/HWW, Coldcard); it is not the host's business otherwise.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Transmit {
    pub payload: Vec<u8>,
    pub encrypted: bool,
    pub recipient: Recipient,
}

impl From<bc::Transmit> for Transmit {
    fn from(transmit: bc::Transmit) -> Self {
        Self {
            payload: transmit.payload,
            encrypted: transmit.encrypted,
            recipient: transmit.recipient.into(),
        }
    }
}

/// The singlesig subset of `bhwi::common::Command`.
///
/// Setup, wipe, restore, backup, wallet registration and multisig/descriptor address
/// display are out of scope for these FFI bindings.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum HwiCommand {
    /// Ledger: opens the Bitcoin app. Jade/BitBox/Coldcard: authenticates the device.
    Unlock {
        network: Network,
    },
    GetVersion,
    GetMasterFingerprint,
    GetXpub {
        path: String,
        display: bool,
    },
    DisplayAddress {
        path: String,
        display: bool,
        format: Option<AddressFormat>,
    },
    SignMessage {
        message: Vec<u8>,
        path: String,
    },
    SignPsbt {
        psbt_base64: String,
    },
}

/// The response kind a command must produce; anything else is a protocol failure or a
/// refusal. Mirrors the `if let ... else NoErrorOrResult` checks in `bhwi-async`'s `HWI`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Expect {
    /// `Unlock` is the one command whose response is device-specific (Coldcard answers
    /// with its session encryption key, the others with `TaskDone`).
    Any,
    Info,
    Fingerprint,
    Xpub,
    Address,
    Signature,
    SignedPsbt,
}

impl Expect {
    pub(crate) fn matches(self, response: &bc::Response) -> bool {
        match self {
            Self::Any => true,
            Self::Info => matches!(response, bc::Response::Info(_)),
            Self::Fingerprint => matches!(response, bc::Response::MasterFingerprint(_)),
            Self::Xpub => matches!(response, bc::Response::Xpub(_)),
            Self::Address => matches!(response, bc::Response::Address(_)),
            Self::Signature => matches!(response, bc::Response::Signature(..)),
            Self::SignedPsbt => matches!(response, bc::Response::SignedPsbt(_)),
        }
    }
}

/// What a command asks of the interpreter, once validated.
pub(crate) struct Plan {
    pub(crate) command: bc::Command,
    pub(crate) expect: Expect,
    /// Whether the user physically approves this command on the device screen; only
    /// those commands can produce a refusal.
    pub(crate) user_action: bool,
}

impl HwiCommand {
    /// Validates the string/base64 inputs and lowers the command onto `bhwi::common`.
    pub(crate) fn plan(self) -> Result<Plan, HwiError> {
        let plan = |command, expect, user_action| Plan {
            command,
            expect,
            user_action,
        };
        Ok(match self {
            Self::Unlock { network } => plan(
                bc::Command::Unlock {
                    options: bc::UnlockOptions {
                        network: Some(network.into()),
                    },
                },
                Expect::Any,
                false,
            ),
            Self::GetVersion => plan(bc::Command::GetVersion, Expect::Info, false),
            Self::GetMasterFingerprint => plan(
                bc::Command::GetMasterFingerprint,
                Expect::Fingerprint,
                false,
            ),
            Self::GetXpub { path, display } => plan(
                bc::Command::GetXpub {
                    path: parse_path(&path)?,
                    display,
                },
                Expect::Xpub,
                false,
            ),
            Self::DisplayAddress {
                path,
                display,
                format,
            } => plan(
                bc::Command::DisplayAddress(
                    bc::DisplayAddress::ByPath {
                        path: parse_path(&path)?,
                        display,
                        address_format: format.map(Into::into),
                    },
                    None,
                ),
                Expect::Address,
                true,
            ),
            Self::SignMessage { message, path } => plan(
                bc::Command::SignMessage {
                    message,
                    path: parse_path(&path)?,
                },
                Expect::Signature,
                true,
            ),
            Self::SignPsbt { psbt_base64 } => plan(
                // Ledger needs a wallet policy to sign, which this layer does not build:
                // Ledger PSBT signing is host-orchestrated and not supported here yet.
                bc::Command::SignTx(decode_psbt(&psbt_base64)?, None),
                Expect::SignedPsbt,
                true,
            ),
        })
    }
}

/// The singlesig subset of `bhwi::common::Response`.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum HwiResponse {
    TaskDone,
    Info {
        version: String,
        firmware: Option<String>,
        initialized: Option<bool>,
    },
    Fingerprint {
        hex: String,
    },
    Xpub {
        xpub: String,
    },
    Address {
        address: String,
    },
    /// Standard `signmessage` base64: the header byte followed by the 64-byte compact
    /// signature.
    MessageSignature {
        base64: String,
    },
    SignedPsbt {
        psbt_base64: String,
    },
    /// A response this API does not model (backup blobs, wallet registration, ...).
    Other,
}

impl From<bc::Response> for HwiResponse {
    fn from(response: bc::Response) -> Self {
        match response {
            bc::Response::TaskDone => Self::TaskDone,
            bc::Response::Info(info) => Self::Info {
                version: info.version,
                firmware: info.firmware,
                initialized: info.initialized,
            },
            bc::Response::MasterFingerprint(fingerprint) => Self::Fingerprint {
                hex: fingerprint.to_string(),
            },
            bc::Response::Xpub(xpub) => Self::Xpub {
                xpub: xpub.to_string(),
            },
            bc::Response::Address(address) => Self::Address { address },
            bc::Response::Signature(header, signature) => Self::MessageSignature {
                base64: encode_signature(header, &signature),
            },
            bc::Response::SignedPsbt(psbt) => Self::SignedPsbt {
                psbt_base64: encode_psbt(&psbt),
            },
            _ => Self::Other,
        }
    }
}

/// Which device an interpreter drives. Refusal reporting is device-specific.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeviceKind {
    Ledger,
    Coldcard,
    BitBox,
    Jade,
}

/// Maps an interpreter error to the FFI surface.
///
/// `user_action` marks the commands the user physically approves on the device
/// (display address, sign message, sign tx); only those can produce a refusal.
pub(crate) fn map_error(error: bc::Error, kind: DeviceKind, user_action: bool) -> HwiError {
    /// Jade reports a user-declined prompt with this CBOR-RPC code.
    const JADE_USER_CANCELLED: i32 = bhwi::jade::api::ErrorCode::UserCancelled as i32;

    match error {
        // BitBox `UserAbort`/pairing rejection, Jade handshake refusal and a Ledger app
        // that would not open all land here.
        bc::Error::AuthenticationRefused => HwiError::AuthRefused,
        // Jade is the only device reporting the decline as a typed RPC code.
        bc::Error::Rpc(code, _) if kind == DeviceKind::Jade && code == JADE_USER_CANCELLED => {
            HwiError::UserRefused
        }
        // Ledger turns a `Deny` status word into `Response::TaskDone`, and Coldcard does
        // the same for a `refu` reply to `show_address`; neither matches the response the
        // command expects, so the caller reports a missing result instead.
        // Jade and BitBox use explicit errors, so an empty result there is a real fault.
        bc::Error::NoErrorOrResult
            if user_action && matches!(kind, DeviceKind::Ledger | DeviceKind::Coldcard) =>
        {
            HwiError::UserRefused
        }
        bc::Error::InvalidInput(msg) => HwiError::InvalidInput { msg },
        // The command is missing data this API does not carry (a Ledger wallet policy).
        bc::Error::MissingCommandInfo(msg) => HwiError::InvalidInput {
            msg: msg.to_string(),
        },
        // Coldcard's `refu` reply to sign message / sign tx is not an anticipated
        // response there, so it surfaces as an unexpected-response context string.
        bc::Error::UnexpectedResult(_, ref context)
            if user_action && kind == DeviceKind::Coldcard && context.contains("got Refu") =>
        {
            HwiError::UserRefused
        }
        // Deliberately drops the raw payload: errors must not carry protocol bytes.
        bc::Error::UnexpectedResult(_, context) => HwiError::Device {
            msg: format!("unexpected result for {context}"),
        },
        other => HwiError::Device {
            msg: other.to_string(),
        },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_mapping_is_device_specific() {
        let refused = |error, kind, user_action| {
            matches!(map_error(error, kind, user_action), HwiError::UserRefused)
        };

        // Jade: typed CBOR-RPC decline code, unambiguous regardless of the command.
        assert!(refused(
            bc::Error::Rpc(-32000, None),
            DeviceKind::Jade,
            false
        ));
        assert!(!refused(
            bc::Error::Rpc(-32602, None),
            DeviceKind::Jade,
            true
        ));

        // Coldcard: `refu` is unexpected for signing commands, so it lands in the context.
        assert!(refused(
            bc::Error::UnexpectedResult(
                Vec::new(),
                "coldcard unexpected response: expected [Okay, Busy, Smrx], got Refu".to_string(),
            ),
            DeviceKind::Coldcard,
            true
        ));

        // A missing result means a refusal only for Ledger/Coldcard user-approved commands.
        assert!(refused(
            bc::Error::NoErrorOrResult,
            DeviceKind::Ledger,
            true
        ));
        assert!(refused(
            bc::Error::NoErrorOrResult,
            DeviceKind::Coldcard,
            true
        ));
        assert!(!refused(bc::Error::NoErrorOrResult, DeviceKind::Jade, true));
        assert!(!refused(
            bc::Error::NoErrorOrResult,
            DeviceKind::BitBox,
            true
        ));
        assert!(!refused(
            bc::Error::NoErrorOrResult,
            DeviceKind::Ledger,
            false
        ));

        // Pairing/handshake rejection is its own kind, on every device.
        assert!(matches!(
            map_error(bc::Error::AuthenticationRefused, DeviceKind::BitBox, false),
            HwiError::AuthRefused
        ));
    }

    #[test]
    fn errors_never_leak_protocol_bytes() {
        let error = map_error(
            bc::Error::UnexpectedResult(vec![0xde, 0xad, 0xbe, 0xef], "get_xpub".to_string()),
            DeviceKind::Jade,
            false,
        );
        let HwiError::Device { msg } = error else {
            panic!("expected a device error, got {error:?}");
        };
        assert_eq!(msg, "unexpected result for get_xpub");
    }

    #[test]
    fn bad_input_is_rejected_before_the_device() {
        assert!(matches!(
            HwiCommand::GetXpub {
                path: "not a path".to_string(),
                display: false,
            }
            .plan(),
            Err(HwiError::InvalidInput { .. })
        ));
        assert!(matches!(
            HwiCommand::SignPsbt {
                psbt_base64: "!!!".to_string(),
            }
            .plan(),
            Err(HwiError::InvalidInput { .. })
        ));
    }
}
