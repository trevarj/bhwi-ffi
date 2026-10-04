//! The data that crosses the FFI: commands in, transmits out, responses and errors back.
//!
//! Everything here is a plain value; the interpreter state lives in [`crate::interp`].

use std::str::FromStr;

use base64ct::{Base64, Encoding};
use bhwi::bitcoin::bip32::{ChildNumber, DerivationPath};
use bhwi::bitcoin::psbt::Psbt;
use bhwi::bitcoin::secp256k1::ecdsa::Signature;
use bhwi::common as bc;
use bhwi::miniscript::Descriptor;
use bhwi::miniscript::descriptor::{
    DescriptorPublicKey, SinglePubKey, WalletPolicy as CoreWalletPolicy, Wildcard,
};

use crate::{AddressFormat, HwiError, Network};

/// Where a payload has to be delivered.
///
/// `PinServer` only ever appears for Jade: the host must POST the payload to `url`
/// (`Content-Type: application/json`) and feed the response body back to `exchange`.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Recipient {
    Device,
    PinServer { url: String },
    Host { request: HostRequest },
}

impl From<bc::Recipient> for Recipient {
    fn from(recipient: bc::Recipient) -> Self {
        match recipient {
            bc::Recipient::Device => Self::Device,
            bc::Recipient::PinServer { url } => Self::PinServer { url },
            bc::Recipient::Host(request) => Self::Host {
                request: request.into(),
            },
        }
    }
}

/// An unexpected typed host prompt. This wallet-only API exposes no response route.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum HostRequest {
    PinMatrix {
        kind: PinMatrixRequestKind,
    },
    RecoveryCharacter {
        word_position: u32,
        character_position: u32,
    },
}

impl From<bc::HostRequest> for HostRequest {
    fn from(request: bc::HostRequest) -> Self {
        match request {
            bc::HostRequest::PinMatrix { kind } => Self::PinMatrix { kind: kind.into() },
            bc::HostRequest::RecoveryCharacter {
                word_position,
                character_position,
            } => Self::RecoveryCharacter {
                word_position,
                character_position,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PinMatrixRequestKind {
    Current,
    NewFirst,
    NewSecond,
    Unknown { value: i32 },
}

impl From<bc::PinMatrixRequestKind> for PinMatrixRequestKind {
    fn from(kind: bc::PinMatrixRequestKind) -> Self {
        match kind {
            bc::PinMatrixRequestKind::Current => Self::Current,
            bc::PinMatrixRequestKind::NewFirst => Self::NewFirst,
            bc::PinMatrixRequestKind::NewSecond => Self::NewSecond,
            bc::PinMatrixRequestKind::Unknown(value) => Self::Unknown { value },
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

/// Wallet-only commands. Seed administration is deliberately not exposed.
#[derive(Clone, uniffi::Enum)]
pub enum HwiCommand {
    /// Ledger: opens the Bitcoin app. Jade/BitBox/Coldcard: authenticates the device.
    Unlock {
        network: Network,
    },
    GetVersion,
    PromptPin,
    SendPin {
        positions: String,
    },
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
    RegisterWallet {
        name: String,
        descriptor: String,
    },
    DisplayDescriptorAddress {
        index: u32,
        change: bool,
        display: bool,
        wallet_policy: WalletPolicy,
    },
    DisplayMultisigAddress {
        threshold: u8,
        sorted: bool,
        format: MultisigAddressFormat,
        keys: Vec<String>,
    },
    SignMessage {
        message: Vec<u8>,
        path: String,
    },
    SignPsbt {
        psbt_base64: String,
        wallet_policy: Option<WalletPolicy>,
    },
}

impl std::fmt::Debug for HwiCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unlock { .. } => "Unlock",
            Self::GetVersion => "GetVersion",
            Self::PromptPin => "PromptPin",
            Self::SendPin { .. } => "SendPin(<redacted>)",
            Self::GetMasterFingerprint => "GetMasterFingerprint",
            Self::GetXpub { .. } => "GetXpub",
            Self::DisplayAddress { .. } => "DisplayAddress",
            Self::RegisterWallet { .. } => "RegisterWallet",
            Self::DisplayDescriptorAddress { .. } => "DisplayDescriptorAddress",
            Self::DisplayMultisigAddress { .. } => "DisplayMultisigAddress",
            Self::SignMessage { .. } => "SignMessage",
            Self::SignPsbt { .. } => "SignPsbt",
        })
    }
}

/// The response kind a command must produce; anything else is a protocol failure.
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
    WalletRegistration,
    DeviceAction,
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
            Self::WalletRegistration => matches!(response, bc::Response::WalletRegistration(_)),
            Self::DeviceAction => matches!(response, bc::Response::DeviceAction(_)),
        }
    }
}

/// What a command asks of the interpreter, once validated.
pub(crate) struct Plan {
    pub(crate) command: bc::Command,
    pub(crate) expect: Expect,
}

impl HwiCommand {
    /// Validates the string/base64 inputs and lowers the command onto `bhwi::common`.
    pub(crate) fn plan(self, kind: DeviceKind) -> Result<Plan, HwiError> {
        let plan = |command, expect| Plan { command, expect };
        Ok(match self {
            Self::Unlock { network } => plan(
                bc::Command::Unlock {
                    options: bc::UnlockOptions {
                        network: Some(network.into()),
                    },
                },
                Expect::Any,
            ),
            Self::GetVersion => plan(bc::Command::GetVersion, Expect::Info),
            Self::PromptPin => plan(bc::Command::PromptPin, Expect::DeviceAction),
            Self::SendPin { positions } => {
                if positions.is_empty()
                    || !positions.bytes().all(|byte| (b'1'..=b'9').contains(&byte))
                {
                    return Err(HwiError::invalid("PIN positions must be digits 1 to 9"));
                }
                let pin = bhwi::trezor::HostPin::new(positions)
                    .map_err(|_| HwiError::invalid("invalid PIN positions"))?;
                let context = match kind {
                    DeviceKind::Trezor => bc::DeviceContext::TrezorManagement(
                        bhwi::trezor::ManagementContext::Pin(pin),
                    ),
                    DeviceKind::KeepKey => bc::DeviceContext::KeepKeyManagement(
                        bhwi::keepkey::ManagementContext::Pin(pin),
                    ),
                    _ => return Err(HwiError::invalid("host PIN is unsupported for this device")),
                };
                plan(bc::Command::SendPin(Some(context)), Expect::DeviceAction)
            }
            Self::GetMasterFingerprint => {
                plan(bc::Command::GetMasterFingerprint, Expect::Fingerprint)
            }
            Self::GetXpub { path, display } => plan(
                bc::Command::GetXpub {
                    path: parse_path(&path)?,
                    display,
                },
                Expect::Xpub,
            ),
            Self::DisplayAddress {
                path,
                display,
                format,
            } => {
                let path = parse_path(&path)?;
                if kind == DeviceKind::KeepKey
                    && (matches!(format, Some(AddressFormat::Taproot))
                        || (format.is_none()
                            && path
                                .as_ref()
                                .first()
                                .is_some_and(|child| u32::from(*child) & 0x7fff_ffff == 86)))
                {
                    return Err(HwiError::invalid(
                        "KeepKey does not support Taproot address display",
                    ));
                }
                plan(
                    bc::Command::DisplayAddress(
                        bc::DisplayAddress::ByPath {
                            path,
                            display,
                            address_format: format.map(Into::into),
                        },
                        None,
                    ),
                    Expect::Address,
                )
            }
            Self::RegisterWallet { name, descriptor } => {
                validate_policy_name(&name, kind, true)?;
                let policy = parse_public_policy(&descriptor)?;
                plan(
                    bc::Command::RegisterWallet { name, policy },
                    Expect::WalletRegistration,
                )
            }
            Self::DisplayDescriptorAddress {
                index,
                change,
                display,
                wallet_policy,
            } => {
                if index >= (1 << 31) {
                    return Err(HwiError::invalid("address index must be unhardened"));
                }
                let context = wallet_policy.context(kind)?;
                if matches!(kind, DeviceKind::Trezor | DeviceKind::KeepKey) {
                    return Err(HwiError::invalid(
                        "descriptor address display is unsupported for this device",
                    ));
                }
                plan(
                    bc::Command::DisplayAddress(
                        bc::DisplayAddress::ByDescriptor {
                            index,
                            change,
                            display,
                            descriptor_name: wallet_policy.name,
                        },
                        context,
                    ),
                    Expect::Address,
                )
            }
            Self::DisplayMultisigAddress {
                threshold,
                sorted,
                format,
                keys,
            } => {
                if keys.is_empty()
                    || keys.len() > 15
                    || threshold == 0
                    || usize::from(threshold) > keys.len()
                {
                    return Err(HwiError::invalid(
                        "multisig requires 1 to 15 keys and a valid threshold",
                    ));
                }
                if kind == DeviceKind::KeepKey && !sorted {
                    return Err(HwiError::invalid(
                        "KeepKey requires sorted multisig address display",
                    ));
                }
                let keys = keys
                    .iter()
                    .map(|key| parse_concrete_key(key, kind))
                    .collect::<Result<_, _>>()?;
                plan(
                    bc::Command::DisplayAddress(
                        bc::DisplayAddress::ByMultisig(bc::MultisigDisplayAddress {
                            threshold,
                            sorted,
                            address_type: format.into(),
                            keys,
                        }),
                        None,
                    ),
                    Expect::Address,
                )
            }
            Self::SignMessage { message, path } => plan(
                bc::Command::SignMessage {
                    message,
                    path: parse_path(&path)?,
                },
                Expect::Signature,
            ),
            Self::SignPsbt {
                psbt_base64,
                wallet_policy,
            } => {
                let psbt = decode_psbt(&psbt_base64)?;
                let context = wallet_policy
                    .as_ref()
                    .map(|policy| policy.context(kind))
                    .transpose()?
                    .flatten();
                if kind == DeviceKind::Ledger {
                    let Some(bc::DeviceContext::Ledger {
                        wallet_policy,
                        wallet_hmac,
                    }) = &context
                    else {
                        return Err(HwiError::invalid("Ledger signing requires a wallet policy"));
                    };
                    validate_ledger_signing_policy(wallet_policy, wallet_hmac.as_ref())?;
                }
                if kind == DeviceKind::BitBox
                    && context.is_none()
                    && psbt.inputs.iter().any(|input| {
                        input.witness_script.is_some()
                            || input
                                .witness_utxo
                                .as_ref()
                                .is_some_and(|utxo| utxo.script_pubkey.is_p2wsh())
                            || input
                                .redeem_script
                                .as_ref()
                                .is_some_and(|script| !script.is_p2wpkh())
                    })
                {
                    return Err(HwiError::invalid(
                        "BitBox script signing requires its registered wallet policy",
                    ));
                }
                plan(bc::Command::SignTx(psbt, context), Expect::SignedPsbt)
            }
        })
    }
}

/// Wallet-only responses, preserving device registration state.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum HwiResponse {
    TaskDone,
    DeviceAction {
        success: bool,
    },
    Info {
        version: String,
        firmware: Option<String>,
        initialized: Option<bool>,
        networks: Vec<Network>,
        label: Option<String>,
        on_device_passphrase_entry: Option<bool>,
        needs_pin_sent: Option<bool>,
        needs_passphrase_sent: Option<bool>,
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
    WalletRegistration {
        registration: WalletRegistration,
    },
    /// A response this API does not model (backup blobs, ...).
    Other,
}

impl From<bc::Response> for HwiResponse {
    fn from(response: bc::Response) -> Self {
        match response {
            bc::Response::TaskDone => Self::TaskDone,
            bc::Response::DeviceAction(success) => Self::DeviceAction { success },
            bc::Response::Info(info) => Self::Info {
                version: info.version,
                firmware: info.firmware,
                initialized: info.initialized,
                networks: info.networks.into_iter().map(Into::into).collect(),
                label: info.label,
                on_device_passphrase_entry: info.on_device_passphrase_entry,
                needs_pin_sent: info.needs_pin_sent,
                needs_passphrase_sent: info.needs_passphrase_sent,
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
            bc::Response::WalletRegistration(registration) => Self::WalletRegistration {
                registration: registration.into(),
            },
            _ => Self::Other,
        }
    }
}

/// Which device an interpreter drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeviceKind {
    Ledger,
    Coldcard,
    BitBox,
    Jade,
    Trezor,
    KeepKey,
    Specter,
}

/// Maps typed interpreter errors to the FFI surface without inspecting device messages.
pub(crate) fn map_error(error: bc::Error, kind: DeviceKind) -> HwiError {
    match error {
        bc::Error::AuthenticationRefused => HwiError::AuthRefused,
        bc::Error::UserCancelled => HwiError::UserRefused,
        bc::Error::DeviceAlreadyUnlocked(_) => HwiError::DeviceAlreadyUnlocked,
        // The command is missing data this API does not carry (a Ledger wallet policy).
        bc::Error::MissingCommandInfo(context) => HwiError::InvalidInput {
            msg: context.to_owned(),
        },
        bc::Error::InvalidInput(_) => HwiError::InvalidInput {
            msg: format!("{kind:?}: invalid command input"),
        },
        bc::Error::Device(_) => HwiError::Device {
            msg: format!("{kind:?}: device reported an error"),
        },
        bc::Error::UnexpectedResult(_, _) => HwiError::Device {
            msg: format!("{kind:?}: unexpected response"),
        },
        bc::Error::Rpc(code, _) => HwiError::Device {
            msg: format!("{kind:?}: rpc error {code}"),
        },
        bc::Error::Serialization(_) => HwiError::Device {
            msg: format!("{kind:?}: protocol serialization failed"),
        },
        bc::Error::UnsupportedDisplayAddress(_) => HwiError::Device {
            msg: format!("{kind:?}: unsupported address display"),
        },
        bc::Error::Encryption(context) => HwiError::Device {
            msg: format!("encryption error: {context}"),
        },
        bc::Error::Request(context) => HwiError::Device {
            msg: format!("request error: {context}"),
        },
        bc::Error::NoErrorOrResult => HwiError::Device {
            msg: "no error or result returned".to_owned(),
        },
    }
}

/// A complete public descriptor and its device registration identity.
#[derive(Clone, uniffi::Record)]
pub struct WalletPolicy {
    pub name: String,
    pub descriptor: String,
    pub ledger_hmac: Option<Vec<u8>>,
}

impl std::fmt::Debug for WalletPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletPolicy")
            .field("name", &self.name)
            .field("descriptor", &self.descriptor)
            .field(
                "ledger_hmac",
                &self.ledger_hmac.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl WalletPolicy {
    pub(crate) fn context(&self, kind: DeviceKind) -> Result<Option<bc::DeviceContext>, HwiError> {
        validate_policy_name(&self.name, kind, false)?;
        let hmac = match self.ledger_hmac.as_deref() {
            Some(bytes) if kind == DeviceKind::Ledger => Some(
                bytes
                    .try_into()
                    .map_err(|_| HwiError::invalid("Ledger HMAC must contain exactly 32 bytes"))?,
            ),
            Some(_) => return Err(HwiError::invalid("wallet HMAC is only valid for Ledger")),
            None => None,
        };
        let policy = parse_public_policy(&self.descriptor)?;
        Ok(match kind {
            DeviceKind::Ledger => Some(bc::DeviceContext::Ledger {
                wallet_policy: bhwi::ledger::LedgerWalletPolicy::new(
                    self.name.clone(),
                    bhwi::ledger::Version::V2,
                    policy,
                ),
                wallet_hmac: hmac,
            }),
            DeviceKind::BitBox => Some(bc::DeviceContext::BitBox { policy }),
            DeviceKind::Specter => Some(bc::DeviceContext::Specter { policy }),
            DeviceKind::Jade | DeviceKind::Coldcard | DeviceKind::Trezor | DeviceKind::KeepKey => {
                None
            }
        })
    }
}

fn validate_ledger_signing_policy(
    wallet: &bhwi::ledger::LedgerWalletPolicy,
    hmac: Option<&[u8; 32]>,
) -> Result<(), HwiError> {
    if let Some(hmac) = hmac {
        if wallet.name.is_empty() || *hmac == [0; 32] {
            return Err(HwiError::invalid(
                "registered Ledger signing requires a name and a nonzero HMAC",
            ));
        }
        return Ok(());
    }
    if !wallet.name.is_empty() {
        return Err(HwiError::invalid(
            "Ledger signing without a HMAC requires the unnamed default policy",
        ));
    }
    let (template, keys) = bhwi::policy::extract_parts(&wallet.policy)
        .map_err(|_| HwiError::invalid("invalid Ledger default policy"))?;
    let purpose = match template.as_str() {
        "pkh(@0/**)" => 44,
        "sh(wpkh(@0/**))" => 49,
        "wpkh(@0/**)" => 84,
        "tr(@0/**)" => 86,
        _ => return Err(HwiError::invalid("Ledger policy requires registration")),
    };
    let [DescriptorPublicKey::MultiXPub(key)] = keys.as_slice() else {
        return Err(HwiError::invalid(
            "Ledger default policy requires one account xpub",
        ));
    };
    let Some((_, origin)) = &key.origin else {
        return Err(HwiError::invalid(
            "Ledger default policy requires an account origin",
        ));
    };
    let coin = if key.xkey.network == bhwi::bitcoin::NetworkKind::Main {
        0
    } else {
        1
    };
    let valid_origin = matches!(
        origin.as_ref(),
        [
            ChildNumber::Hardened { index: p },
            ChildNumber::Hardened { index: c },
            ChildNumber::Hardened { index: account },
        ] if *p == purpose && *c == coin && *account <= 100
            && key.xkey.depth == 3
            && key.xkey.child_number == (ChildNumber::Hardened { index: *account })
    );
    let paths = key.derivation_paths.paths();
    let valid_branches = paths.len() == 2
        && paths[0].as_ref() == [ChildNumber::Normal { index: 0 }]
        && paths[1].as_ref() == [ChildNumber::Normal { index: 1 }]
        && key.wildcard == Wildcard::Unhardened;
    if !valid_origin || !valid_branches {
        return Err(HwiError::invalid(
            "Ledger default policy requires a standard hardened account and receive/change branches",
        ));
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, uniffi::Enum)]
pub enum WalletRegistration {
    Complete { hmac: Option<Vec<u8>> },
    PendingUserConfirmation,
}

impl std::fmt::Debug for WalletRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Complete { hmac } => f
                .debug_struct("Complete")
                .field("hmac", &hmac.as_ref().map(|_| "<redacted>"))
                .finish(),
            Self::PendingUserConfirmation => f.write_str("PendingUserConfirmation"),
        }
    }
}

impl From<bc::WalletRegistration> for WalletRegistration {
    fn from(registration: bc::WalletRegistration) -> Self {
        match registration {
            bc::WalletRegistration::Complete { hmac } => Self::Complete {
                hmac: hmac.map(|bytes| bytes.to_vec()),
            },
            bc::WalletRegistration::PendingUserConfirmation => Self::PendingUserConfirmation,
        }
    }
}

/// Script wrappers for concrete multisig, separate from singlesig address formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MultisigAddressFormat {
    Legacy,
    ShWit,
    Wit,
}

impl From<MultisigAddressFormat> for bc::MultisigAddressType {
    fn from(format: MultisigAddressFormat) -> Self {
        match format {
            MultisigAddressFormat::Legacy => Self::Legacy,
            MultisigAddressFormat::ShWit => Self::ShWit,
            MultisigAddressFormat::Wit => Self::Wit,
        }
    }
}

fn validate_policy_name(name: &str, kind: DeviceKind, registration: bool) -> Result<(), HwiError> {
    let printable_name = |max_len| {
        (1..=max_len).contains(&name.len())
            && name.bytes().all(|byte| (b' '..=b'~').contains(&byte))
            && !name.starts_with(' ')
            && !name.ends_with(' ')
    };
    let valid = match kind {
        DeviceKind::Ledger => (!registration && name.is_empty()) || printable_name(64),
        DeviceKind::Jade => {
            !name.is_empty()
                && name.len() <= 16
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        }
        DeviceKind::Coldcard => {
            (2..=20).contains(&name.len())
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        }
        DeviceKind::BitBox => printable_name(30),
        DeviceKind::Specter => {
            !name.is_empty() && !name.contains('&') && !name.chars().any(char::is_control)
        }
        DeviceKind::Trezor | DeviceKind::KeepKey => !name.chars().any(char::is_control),
    };
    if !valid {
        return Err(HwiError::invalid(
            "invalid wallet policy name for this device",
        ));
    }
    Ok(())
}

fn parse_public_policy(text: &str) -> Result<CoreWalletPolicy, HwiError> {
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(text)
        .map_err(|_| HwiError::invalid("invalid public wallet descriptor"))?;
    if matches!(descriptor, Descriptor::Bare(_))
        || descriptor.iter_pk().next().is_none()
        || descriptor.iter_pk().any(|key| match key {
            DescriptorPublicKey::XPub(key) => {
                key.origin.is_none()
                    || key.wildcard == Wildcard::Hardened
                    || key
                        .derivation_path
                        .as_ref()
                        .iter()
                        .any(|child| child.is_hardened())
            }
            DescriptorPublicKey::MultiXPub(key) => {
                key.origin.is_none()
                    || key.wildcard == Wildcard::Hardened
                    || key
                        .derivation_paths
                        .paths()
                        .iter()
                        .any(|path| path.as_ref().iter().any(|child| child.is_hardened()))
            }
            DescriptorPublicKey::Single(_) => true,
        })
    {
        return Err(HwiError::invalid(
            "wallet descriptor requires origin-bearing public account xpubs with unhardened suffixes",
        ));
    }
    CoreWalletPolicy::from_descriptor(&descriptor)
        .map_err(|_| HwiError::invalid("unsupported public wallet descriptor"))
}

fn parse_concrete_key(text: &str, kind: DeviceKind) -> Result<DescriptorPublicKey, HwiError> {
    let key = DescriptorPublicKey::from_str(text)
        .map_err(|_| HwiError::invalid("invalid concrete multisig key"))?;
    let valid = match &key {
        DescriptorPublicKey::Single(single) => {
            kind != DeviceKind::Jade
                && single.origin.is_some()
                && matches!(&single.key, SinglePubKey::FullKey(key) if key.compressed)
        }
        DescriptorPublicKey::XPub(xpub) => {
            matches!(kind, DeviceKind::Jade | DeviceKind::Trezor)
                && xpub.origin.is_some()
                && xpub.wildcard == Wildcard::None
                && xpub
                    .derivation_path
                    .as_ref()
                    .iter()
                    .all(|child| !child.is_hardened())
        }
        DescriptorPublicKey::MultiXPub(_) => false,
    };
    if valid {
        Ok(key)
    } else {
        Err(HwiError::invalid(match kind {
            DeviceKind::Jade => {
                "Jade multisig requires origin-bearing xpubs with concrete unhardened suffixes"
            }
            DeviceKind::Trezor => {
                "Trezor multisig requires origin-bearing compressed public keys or concrete unhardened xpubs"
            }
            _ => "multisig requires origin-bearing concrete compressed public keys",
        }))
    }
}

pub(crate) fn parse_path(path: &str) -> Result<DerivationPath, HwiError> {
    DerivationPath::from_str(path.trim()).map_err(|_| HwiError::invalid("invalid derivation path"))
}

pub(crate) fn decode_psbt(psbt_base64: &str) -> Result<Psbt, HwiError> {
    let raw = Base64::decode_vec(psbt_base64.trim())
        .map_err(|_| HwiError::invalid("PSBT is not valid base64"))?;
    Psbt::deserialize(&raw).map_err(|_| HwiError::invalid("invalid PSBT"))
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
    fn refusal_mapping_uses_only_typed_errors() {
        for kind in [
            DeviceKind::Ledger,
            DeviceKind::Coldcard,
            DeviceKind::BitBox,
            DeviceKind::Jade,
            DeviceKind::Trezor,
            DeviceKind::KeepKey,
            DeviceKind::Specter,
        ] {
            assert!(matches!(
                map_error(bc::Error::UserCancelled, kind),
                HwiError::UserRefused
            ));
            assert!(matches!(
                map_error(bc::Error::AuthenticationRefused, kind),
                HwiError::AuthRefused
            ));
            for source in [
                bc::Error::NoErrorOrResult,
                bc::Error::Rpc(-32000, None),
                bc::Error::UnexpectedResult(Vec::new(), "got Refu".into()),
            ] {
                assert!(matches!(map_error(source, kind), HwiError::Device { .. }));
            }
        }
    }

    #[test]
    fn errors_never_leak_untrusted_strings() {
        let canary = "ffi-redaction-canary";
        for source in [
            bc::Error::Device(canary.into()),
            bc::Error::Serialization(canary.into()),
            bc::Error::InvalidInput(canary.into()),
            bc::Error::UnsupportedDisplayAddress(canary.into()),
            bc::Error::Rpc(-32602, Some(canary.into())),
            bc::Error::UnexpectedResult(canary.as_bytes().to_vec(), canary.into()),
        ] {
            let invalid_input = matches!(&source, bc::Error::InvalidInput(_));
            let rpc = matches!(&source, bc::Error::Rpc(..));
            let error = map_error(source, DeviceKind::Coldcard);
            let msg = match &error {
                HwiError::InvalidInput { msg } if invalid_input => msg,
                HwiError::Device { msg } if !invalid_input => msg,
                _ => panic!("unexpected error category: {error:?}"),
            };
            assert!(!msg.contains(canary), "leaked error field: {error:?}");
            assert!(!error.to_string().contains(canary));
            if rpc {
                assert!(msg.contains("-32602"), "RPC code was discarded");
            }
        }
        let error = map_error(
            bc::Error::DeviceAlreadyUnlocked("ffi-redaction-canary"),
            DeviceKind::Ledger,
        );
        assert!(matches!(error, HwiError::DeviceAlreadyUnlocked));
        assert!(!error.to_string().contains(canary));
        assert!(!format!("{error:?}").contains(canary));
    }

    #[test]
    fn bad_input_is_rejected_before_the_device() {
        assert!(matches!(
            HwiCommand::GetXpub {
                path: "not a path".to_string(),
                display: false,
            }
            .plan(DeviceKind::Ledger),
            Err(HwiError::InvalidInput { .. })
        ));
        assert!(matches!(
            HwiCommand::SignPsbt {
                psbt_base64: "!!!".to_string(),
                wallet_policy: None,
            }
            .plan(DeviceKind::Ledger),
            Err(HwiError::InvalidInput { .. })
        ));
    }

    #[test]
    fn info_preserves_model_networks_and_optional_capabilities() {
        let HwiResponse::Info {
            version,
            firmware,
            initialized,
            networks,
            label,
            on_device_passphrase_entry,
            needs_pin_sent,
            needs_passphrase_sent,
        } = HwiResponse::from(bc::Response::Info(bc::Info {
            version: "1.2.3".into(),
            firmware: Some("T".into()),
            initialized: Some(false),
            networks: vec![
                bhwi::bitcoin::Network::Bitcoin,
                bhwi::bitcoin::Network::Testnet,
            ],
            label: Some("wallet".into()),
            on_device_passphrase_entry: Some(true),
            needs_pin_sent: Some(true),
            needs_passphrase_sent: Some(false),
        }))
        else {
            panic!("expected Info");
        };
        assert_eq!(version, "1.2.3");
        assert_eq!(firmware.as_deref(), Some("T"));
        assert_eq!(initialized, Some(false));
        assert_eq!(networks, [Network::Bitcoin, Network::Testnet]);
        assert_eq!(label.as_deref(), Some("wallet"));
        assert_eq!(on_device_passphrase_entry, Some(true));
        assert_eq!(needs_pin_sent, Some(true));
        assert_eq!(needs_passphrase_sent, Some(false));

        let HwiResponse::Info {
            firmware,
            initialized,
            networks,
            label,
            on_device_passphrase_entry,
            needs_pin_sent,
            needs_passphrase_sent,
            ..
        } = HwiResponse::from(bc::Response::Info(bc::Info::default()))
        else {
            panic!("expected Info");
        };
        assert!(networks.is_empty());
        assert_eq!(firmware, None);
        assert_eq!(initialized, None);
        assert_eq!(label, None);
        assert_eq!(on_device_passphrase_entry, None);
        assert_eq!(needs_pin_sent, None);
        assert_eq!(needs_passphrase_sent, None);
    }

    #[test]
    fn policy_names_enforce_family_boundaries_and_default_name_semantics() {
        assert!(validate_policy_name("", DeviceKind::Ledger, false).is_ok());
        assert!(validate_policy_name("", DeviceKind::Ledger, true).is_err());
        assert!(validate_policy_name(&"a".repeat(64), DeviceKind::Ledger, true).is_ok());
        assert!(validate_policy_name(&"a".repeat(65), DeviceKind::Ledger, true).is_err());
        assert!(validate_policy_name(&"a".repeat(30), DeviceKind::BitBox, true).is_ok());
        assert!(validate_policy_name(&"a".repeat(31), DeviceKind::BitBox, true).is_err());
        assert!(validate_policy_name("", DeviceKind::BitBox, false).is_err());
        for kind in [DeviceKind::Ledger, DeviceKind::BitBox] {
            for name in [" leading", "trailing ", "café", "bad\nname"] {
                assert!(validate_policy_name(name, kind, true).is_err());
                assert!(validate_policy_name(name, kind, false).is_err());
            }
            assert!(validate_policy_name("valid middle space", kind, true).is_ok());
        }
        assert!(validate_policy_name("x", DeviceKind::Coldcard, true).is_err());
        assert!(validate_policy_name(&"x".repeat(21), DeviceKind::Coldcard, false).is_err());
    }
}
