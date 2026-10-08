//! The driving surface: one `Interp` runs one command against one device.

use std::sync::{Arc, Mutex};

use bhwi::Interpreter;
use bhwi::bitbox::{BitBoxCommand, BitBoxInterpreter};
use bhwi::coldcard::{ColdcardCommand, ColdcardInterpreter};
use bhwi::common as bc;
use bhwi::jade::{JadeCommand, JadeInterpreter};
use bhwi::keepkey::{KeepKeyCommand, KeepKeyInterpreter};
use bhwi::ledger::{LedgerCommand, LedgerInterpreter};
use bhwi::specter::{SpecterCommand, SpecterError, SpecterInterpreter};
use bhwi::trezor::{TrezorCommand, TrezorInterpreter};

use crate::state::{ColdcardEncryption, HostPassphraseHandle, NoiseHandle};
use crate::types::{
    DeviceKind, Expect, HwiCommand, HwiResponse, Plan, Transmit, map_command_error, map_error,
};
use crate::{HwiError, Network};

// Lower once before mutating the session; core requires a family-specific conversion error.
struct Ready<C>(C);

macro_rules! ready {
    ($command:path, $error:path) => {
        impl TryFrom<Ready<$command>> for $command {
            type Error = $error;

            fn try_from(command: Ready<Self>) -> Result<Self, Self::Error> {
                Ok(command.0)
            }
        }
    };
}

ready!(BitBoxCommand, bhwi::bitbox::error::BitBoxError);
ready!(ColdcardCommand, bhwi::coldcard::ColdcardError);
ready!(JadeCommand, bc::Error);
ready!(LedgerCommand, bhwi::ledger::LedgerError);
ready!(TrezorCommand, bhwi::trezor::TrezorError);
ready!(KeepKeyCommand, bhwi::trezor::TrezorError);
ready!(SpecterCommand, bhwi::specter::SpecterError);

/// The per-device interpreters behind one dispatch.
///
/// The two lifetimes are `'static` lies bounded by the lease held in the session
/// (`Session::lease`); see [`Interp::new_bitbox`] for the argument.
enum Inner {
    BitBox(BitBoxInterpreter<'static, Ready<BitBoxCommand>, bc::Transmit, bc::Response, bc::Error>),
    Coldcard(
        ColdcardInterpreter<'static, Ready<ColdcardCommand>, bc::Transmit, bc::Response, bc::Error>,
    ),
    Jade(JadeInterpreter<Ready<JadeCommand>, bc::Transmit, bc::Response, bc::Error>),
    Ledger(LedgerInterpreter<Ready<LedgerCommand>, bc::Transmit, bc::Response, bc::Error>),
    Trezor(TrezorInterpreter<Ready<TrezorCommand>, bc::Transmit, bc::Response, bc::Error>),
    KeepKey(KeepKeyInterpreter<Ready<KeepKeyCommand>, bc::Transmit, bc::Response, bc::Error>),
    Specter(SpecterInterpreter<Ready<SpecterCommand>, bc::Transmit, bc::Response, SpecterError>),
}

impl Inner {
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<bc::Transmit>, bc::Error> {
        match self {
            Self::BitBox(interpreter) => interpreter.exchange(data),
            Self::Coldcard(interpreter) => interpreter.exchange(data),
            Self::Jade(interpreter) => interpreter.exchange(data),
            Self::Ledger(interpreter) => interpreter.exchange(data),
            Self::Trezor(interpreter) => interpreter.exchange(data),
            Self::KeepKey(interpreter) => interpreter.exchange(data),
            Self::Specter(interpreter) => interpreter.exchange(data).map_err(specter_error),
        }
    }

    fn end(self) -> Result<bc::Response, bc::Error> {
        match self {
            Self::BitBox(interpreter) => interpreter.end(),
            Self::Coldcard(interpreter) => interpreter.end(),
            Self::Jade(interpreter) => interpreter.end(),
            Self::Ledger(interpreter) => interpreter.end(),
            Self::Trezor(interpreter) => interpreter.end(),
            Self::KeepKey(interpreter) => interpreter.end(),
            Self::Specter(interpreter) => interpreter.end().map_err(specter_error),
        }
    }
}

// Preserve the FFI payload/input distinction before upstream erases it to Serialization.
fn specter_error(error: SpecterError) -> bc::Error {
    match error {
        SpecterError::MalformedPayload(message) => {
            bc::Error::new(bc::ErrorKind::InvalidInput, message)
        }
        error => error.into(),
    }
}

/// The lease an interpreter holds on the device state it borrows, released on drop.
enum StateLease {
    /// These interpreters own their state rather than borrowing a host handle.
    None,
    Noise(Arc<NoiseHandle>),
    Coldcard(Arc<ColdcardEncryption>),
}

impl Drop for StateLease {
    fn drop(&mut self) {
        match self {
            // SAFETY: this value owns the lease taken in the matching `Interp::new_*`,
            // and the only reference derived from it lived in `Session::inner`, which is
            // declared before `Session::lease` and is therefore already dropped.
            Self::Noise(handle) => unsafe { handle.state.release() },
            Self::Coldcard(handle) => unsafe { handle.engine.release() },
            Self::None => {}
        }
    }
}

/// One in-flight command.
struct Session {
    /// Declared before `lease`: the interpreter borrows the leased state, so it has to be
    /// dropped before the lease is released.
    inner: Inner,
    lease: StateLease,
    kind: DeviceKind,
    started: bool,
    finished: bool,
    expect: Expect,
    prior_inputs: Vec<bhwi::bitcoin::psbt::Input>,
    prior_unsigned_tx: Option<bhwi::bitcoin::Wtxid>,
    ledger_registration_id: Option<[u8; 32]>,
}

impl Session {
    fn start(&mut self, plan: Plan) -> Result<Transmit, HwiError> {
        let (prior_inputs, prior_unsigned_tx) = if let bc::Command::SignTx(psbt, _) = &plan.command
        {
            (
                psbt.inputs
                    .iter()
                    .map(|input| bhwi::bitcoin::psbt::Input {
                        partial_sigs: input.partial_sigs.clone(),
                        tap_key_sig: input.tap_key_sig,
                        tap_script_sigs: input.tap_script_sigs.clone(),
                        final_script_sig: input.final_script_sig.clone(),
                        final_script_witness: input.final_script_witness.clone(),
                        sighash_type: input.sighash_type,
                        ..Default::default()
                    })
                    .collect(),
                Some(psbt.unsigned_tx.compute_wtxid()),
            )
        } else {
            (Vec::new(), None)
        };
        macro_rules! start {
            ($interpreter:expr, $command:path) => {{
                let command = <$command>::try_from(plan.command)
                    .map_err(|error| map_command_error(error.into(), self.kind))?;
                self.started = true;
                self.expect = plan.expect;
                self.prior_inputs = prior_inputs;
                self.prior_unsigned_tx = prior_unsigned_tx;
                $interpreter.start(Ready(command))
            }};
        }
        let transmit = match &mut self.inner {
            Inner::BitBox(interpreter) => start!(interpreter, BitBoxCommand),
            Inner::Coldcard(interpreter) => start!(interpreter, ColdcardCommand),
            Inner::Jade(interpreter) => start!(interpreter, JadeCommand),
            Inner::Trezor(interpreter) => start!(interpreter, TrezorCommand),
            Inner::KeepKey(interpreter) => start!(interpreter, KeepKeyCommand),
            Inner::Specter(interpreter) => {
                start!(interpreter, SpecterCommand).map_err(specter_error)
            }
            Inner::Ledger(interpreter) => {
                let command = LedgerCommand::try_from(plan.command)
                    .map_err(|error| map_command_error(error.into(), self.kind))?;
                let registration_id = match &command {
                    LedgerCommand::RegisterWallet { policy } => Some(
                        policy
                            .id()
                            .map_err(|_| HwiError::invalid("invalid Ledger wallet policy"))?,
                    ),
                    _ => None,
                };
                self.started = true;
                self.expect = plan.expect;
                self.prior_inputs = prior_inputs;
                self.prior_unsigned_tx = prior_unsigned_tx;
                self.ledger_registration_id = registration_id;
                interpreter.start(Ready(command))
            }
        }
        .map_err(|error| map_error(error, self.kind))?;
        Ok(transmit.into())
    }

    fn require_running(&self) -> Result<(), HwiError> {
        if !self.started {
            return Err(HwiError::bad_state("command has not started"));
        }
        if self.finished {
            return Err(HwiError::bad_state("command is finished"));
        }
        Ok(())
    }

    fn advance(&mut self, reply: Vec<u8>) -> Result<Option<Transmit>, HwiError> {
        if matches!(self.kind, DeviceKind::Trezor | DeviceKind::KeepKey)
            && (reply.len() < 8
                || &reply[..2] != b"##"
                || usize::try_from(u32::from_be_bytes(reply[4..8].try_into().unwrap()))
                    .ok()
                    .and_then(|len| len.checked_add(8))
                    != Some(reply.len()))
        {
            return Err(HwiError::Device {
                msg: "malformed device protocol reply".into(),
            });
        }
        if let Some(expected_id) = self.ledger_registration_id {
            use bhwi::ledger::apdu::StatusWord;
            // Interrupted-execution requests still belong to core; only final success is bound.
            if reply.len() >= 2
                && StatusWord::try_from(u16::from_be_bytes(
                    reply[reply.len() - 2..].try_into().unwrap(),
                ))
                .ok()
                    == Some(StatusWord::OK)
                && (reply.len() != 66 || reply[..32] != expected_id)
            {
                return Err(HwiError::Device {
                    msg: "invalid Ledger wallet registration response".into(),
                });
            }
        }
        match self
            .inner
            .exchange(reply)
            .map_err(|error| map_error(error, self.kind))?
        {
            Some(transmit) => Ok(Some(transmit.into())),
            None => {
                self.finished = true;
                Ok(None)
            }
        }
    }
}

/// Runs one `bhwi::common::Command` as a sequence of payload exchanges.
///
/// The object is consumed by [`Interp::end`]; any call afterwards, or after a protocol
/// failure, fails with `BadState`.
#[derive(uniffi::Object)]
pub struct Interp {
    session: Mutex<Option<Session>>,
}

impl Interp {
    fn build(inner: Inner, kind: DeviceKind, lease: StateLease) -> Arc<Self> {
        Arc::new(Self {
            session: Mutex::new(Some(Session {
                inner,
                lease,
                kind,
                started: false,
                finished: false,
                expect: Expect::Any,
                prior_inputs: Vec::new(),
                prior_unsigned_tx: None,
                ledger_registration_id: None,
            })),
        })
    }

    /// Runs `f` against the live session, retiring the interpreter on a protocol failure.
    fn with_session<R>(
        &self,
        f: impl FnOnce(&mut Session) -> Result<R, HwiError>,
    ) -> Result<R, HwiError> {
        let mut guard = self
            .session
            .lock()
            .map_err(|_| HwiError::internal("interpreter lock poisoned"))?;
        let session = guard
            .as_mut()
            .ok_or_else(|| HwiError::bad_state("interpreter is finished"))?;
        let out = f(session);
        if let Err(error) = &out {
            // A protocol failure leaves the device mid-command, so the interpreter is
            // retired, releasing the lease; that is not permission to retry the physical operation.
            // Misuse and pure preflight changed nothing, so the session survives.
            if session.started && !matches!(error, HwiError::BadState { .. }) {
                *guard = None;
            }
        }
        out
    }
}

#[uniffi::export]
impl Interp {
    /// BitBox02. Borrows `noise` until this interpreter is dropped.
    #[uniffi::constructor]
    pub fn new_bitbox(noise: Arc<NoiseHandle>, network: Network) -> Result<Arc<Self>, HwiError> {
        let pointer = noise
            .state
            .acquire()
            .ok_or_else(|| HwiError::bad_state("noise handle is already leased"))?;
        // SAFETY: the borrow is extended to `'static`, which is sound because
        // - exclusivity: the lease was just taken, and `Leased` refuses every other
        //   acquire and every `with` until it is released, so no other reference to the
        //   `NoiseState` can exist while this one lives;
        // - no aliasing through this object: every method that touches the interpreter
        //   goes through `Interp::session`'s mutex, and the pairing-code slot the host
        //   may read concurrently lives outside the leased cell;
        // - liveness: `StateLease::Noise` keeps the `Arc<NoiseHandle>` alive for at least
        //   as long as the interpreter, and the state sits in an `UnsafeCell` inside that
        //   allocation, so its address never changes;
        // - drop order: `Session::inner` is declared before `Session::lease`, so this
        //   reference is gone before the lease is released.
        let state = unsafe { &mut *pointer };
        let inner = BitBoxInterpreter::new(state).with_network(network.into());
        Ok(Self::build(
            Inner::BitBox(inner),
            DeviceKind::BitBox,
            StateLease::Noise(noise),
        ))
    }

    /// Coldcard. Borrows `encryption` until this interpreter is dropped.
    #[uniffi::constructor]
    pub fn new_coldcard(encryption: Arc<ColdcardEncryption>) -> Result<Arc<Self>, HwiError> {
        let pointer = encryption
            .engine
            .acquire()
            .ok_or_else(|| HwiError::bad_state("coldcard encryption is already leased"))?;
        // SAFETY: identical to `new_bitbox`, with the Coldcard engine in place of the
        // noise state.
        let engine = unsafe { &mut *pointer };
        Ok(Self::build(
            Inner::Coldcard(ColdcardInterpreter::new(engine)),
            DeviceKind::Coldcard,
            StateLease::Coldcard(encryption),
        ))
    }

    /// Jade. Stateless here; the PIN-server exchange is driven by the host.
    #[uniffi::constructor]
    pub fn new_jade(network: Network) -> Arc<Self> {
        Self::build(
            Inner::Jade(JadeInterpreter::default().with_network(network.into())),
            DeviceKind::Jade,
            StateLease::None,
        )
    }

    /// Ledger. Stateless; the Bitcoin app must be open (or use `Unlock` to open it).
    #[uniffi::constructor]
    pub fn new_ledger() -> Arc<Self> {
        Self::build(
            Inner::Ledger(LedgerInterpreter::default()),
            DeviceKind::Ledger,
            StateLease::None,
        )
    }

    #[uniffi::constructor]
    pub fn new_trezor(
        network: Network,
        passphrase: Option<Arc<HostPassphraseHandle>>,
        on_device_passphrase: bool,
    ) -> Result<Arc<Self>, HwiError> {
        if passphrase.is_some() && on_device_passphrase {
            return Err(HwiError::invalid(
                "host and on-device passphrases are mutually exclusive",
            ));
        }
        let passphrase = passphrase
            .as_ref()
            .map(|handle| handle.clone_passphrase())
            .transpose()?;
        Ok(Self::build(
            Inner::Trezor(
                TrezorInterpreter::default()
                    .with_network(network.into())
                    .with_passphrase(passphrase)
                    .with_on_device_passphrase(on_device_passphrase),
            ),
            DeviceKind::Trezor,
            StateLease::None,
        ))
    }

    #[uniffi::constructor]
    pub fn new_keepkey(
        network: Network,
        passphrase: Option<Arc<HostPassphraseHandle>>,
    ) -> Result<Arc<Self>, HwiError> {
        let passphrase = passphrase
            .as_ref()
            .map(|handle| handle.clone_passphrase())
            .transpose()?;
        Ok(Self::build(
            Inner::KeepKey(
                KeepKeyInterpreter::default()
                    .with_network(network.into())
                    .with_passphrase(passphrase),
            ),
            DeviceKind::KeepKey,
            StateLease::None,
        ))
    }

    /// Specter-DIY. The host supplies complete validated serial response frames.
    #[uniffi::constructor]
    pub fn new_specter(network: Network) -> Arc<Self> {
        Self::build(
            Inner::Specter(SpecterInterpreter::default().with_network(network.into())),
            DeviceKind::Specter,
            StateLease::None,
        )
    }

    /// Starts the command and returns the first payload to send. Callable once.
    pub fn start(&self, cmd: HwiCommand) -> Result<Transmit, HwiError> {
        // Validation uses the actual interpreter family, before starting its machine.
        self.with_session(|session| {
            if session.started {
                return Err(HwiError::bad_state("start was already called"));
            }
            let plan = cmd.plan(session.kind)?;
            session.start(plan)
        })
    }

    /// Feeds one reply back. Returns the next payload to send, or `None` when the
    /// machine is done and [`Interp::end`] should be called.
    pub fn exchange(&self, reply: Vec<u8>) -> Result<Option<Transmit>, HwiError> {
        self.with_session(|session| {
            session.require_running()?;
            session.advance(reply)
        })
    }

    /// Consumes the interpreter and returns the typed result.
    pub fn end(&self) -> Result<HwiResponse, HwiError> {
        let mut guard = self
            .session
            .lock()
            .map_err(|_| HwiError::internal("interpreter lock poisoned"))?;
        let session = guard
            .take()
            .ok_or_else(|| HwiError::bad_state("interpreter is finished"))?;
        // Consuming the session above already released the state lease, so an early `end`
        // still frees the handle; it just has no result to report.
        if !session.finished {
            return Err(HwiError::bad_state(
                "end called before the machine finished",
            ));
        }
        let Session {
            inner,
            lease,
            kind,
            expect,
            prior_inputs,
            prior_unsigned_tx,
            ..
        } = session;
        // Kept across the lease drop so the Coldcard session key can be installed below.
        let response = inner.end();

        // Coldcard's unlock yields the session key for the link encryption; install it
        // through the still-held lease (mirroring `bhwi-async`'s `OnUnlock`) so no other
        // interpreter can slip in between the release and the install, and so hosts never
        // see the key.
        if let (StateLease::Coldcard(encryption), Ok(bc::Response::EncryptionKey(key))) =
            (&lease, &response)
        {
            // SAFETY: `inner.end()` consumed the interpreter and with it the only other
            // reference into the leased engine, and `lease` is still held here.
            let engine = unsafe { &mut *encryption.engine.get_leased() };
            engine.ready(*key).map_err(|_| HwiError::Device {
                msg: "Coldcard: session encryption setup failed".into(),
            })?;
            drop(lease);
            return Ok(HwiResponse::TaskDone);
        }

        // The interpreter (and its borrow of the device state) is gone: release the lease
        // before anything touches that state again.
        drop(lease);
        let response = response.map_err(|e| map_error(e, kind))?;

        // An unrelated response is a protocol failure, never an inferred refusal.
        if !expect.matches(&response) {
            return Err(map_error(
                bc::Error::new(
                    bc::ErrorKind::UnexpectedResponse,
                    "command response mismatch",
                ),
                kind,
            ));
        }
        if let bc::Response::SignedPsbt(psbt) = &response {
            if prior_unsigned_tx != Some(psbt.unsigned_tx.compute_wtxid())
                || psbt.inputs.len() != prior_inputs.len()
            {
                return Err(HwiError::Device {
                    msg: "device changed the unsigned transaction".into(),
                });
            }
            for (original, returned) in prior_inputs.iter().zip(&psbt.inputs) {
                // Fidelity only: the consuming wallet must validate the complete final spend.
                let final_contains = |signature: &[u8]| {
                    returned
                        .final_script_witness
                        .as_ref()
                        .is_some_and(|witness| witness.iter().any(|item| item == signature))
                        || returned.final_script_sig.as_ref().is_some_and(|script| {
                            script
                                .instructions()
                                .try_fold(false, |found, instruction| {
                                    instruction.map(|instruction| {
                                        found
                                            || instruction
                                                .push_bytes()
                                                .is_some_and(|push| push.as_bytes() == signature)
                                    })
                                })
                                .unwrap_or(false)
                        })
                };
                let preserved = original.partial_sigs.iter().all(|(key, sig)| {
                    returned.partial_sigs.get(key).map_or_else(
                        || final_contains(&sig.serialize()),
                        |returned| returned == sig,
                    )
                }) && original.tap_script_sigs.iter().all(|(key, sig)| {
                    returned.tap_script_sigs.get(key).map_or_else(
                        || final_contains(&sig.serialize()),
                        |returned| returned == sig,
                    )
                }) && original.tap_key_sig.is_none_or(|sig| {
                    returned.tap_key_sig.map_or_else(
                        || final_contains(&sig.serialize()),
                        |returned| returned == sig,
                    )
                }) && original
                    .final_script_sig
                    .as_ref()
                    .is_none_or(|script| returned.final_script_sig.as_ref() == Some(script))
                    && original
                        .final_script_witness
                        .as_ref()
                        .is_none_or(|witness| {
                            returned.final_script_witness.as_ref() == Some(witness)
                        });
                if !preserved {
                    return Err(HwiError::Device {
                        msg: "device changed or removed an existing PSBT signature".into(),
                    });
                }
                // Check only new signatures against the original request, not returned metadata.
                let modes_match = returned
                    .partial_sigs
                    .iter()
                    .filter(|(key, _)| !original.partial_sigs.contains_key(*key))
                    .all(|(_, sig)| original.ecdsa_hash_ty().ok() == Some(sig.sighash_type))
                    && returned
                        .tap_script_sigs
                        .iter()
                        .filter(|(key, _)| !original.tap_script_sigs.contains_key(*key))
                        .all(|(_, sig)| original.taproot_hash_ty().ok() == Some(sig.sighash_type))
                    && (original.tap_key_sig.is_some()
                        || returned.tap_key_sig.is_none_or(|sig| {
                            original.taproot_hash_ty().ok() == Some(sig.sighash_type)
                        }));
                if !modes_match {
                    return Err(HwiError::Device {
                        msg: "device signature does not match the requested sighash".into(),
                    });
                }
            }
        }

        Ok(HwiResponse::from(response))
    }
}
