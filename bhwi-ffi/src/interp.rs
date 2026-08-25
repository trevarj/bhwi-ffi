//! The driving surface: one `Interp` runs one command against one device.

use std::sync::{Arc, Mutex};

use bhwi::Interpreter;
use bhwi::common as bc;
use bhwi::common::{BitBoxInterpreter, ColdcardInterpreter, JadeInterpreter, LedgerInterpreter};

use crate::state::{ColdcardEncryption, NoiseHandle};
use crate::types::{DeviceKind, Expect, HwiCommand, HwiResponse, Transmit, map_error};
use crate::{HwiError, Network};

/// The per-device interpreters behind one dispatch.
///
/// The two lifetimes are `'static` lies bounded by the lease held in the session
/// (`Session::lease`); see [`Interp::new_bitbox`] for the argument.
enum Inner {
    BitBox(BitBoxInterpreter<'static>),
    Coldcard(ColdcardInterpreter<'static>),
    Jade(JadeInterpreter),
    Ledger(LedgerInterpreter),
}

impl Inner {
    fn start(&mut self, command: bc::Command) -> Result<bc::Transmit, bc::Error> {
        match self {
            Self::BitBox(interpreter) => interpreter.start(command),
            Self::Coldcard(interpreter) => interpreter.start(command),
            Self::Jade(interpreter) => interpreter.start(command),
            Self::Ledger(interpreter) => interpreter.start(command),
        }
    }

    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<bc::Transmit>, bc::Error> {
        match self {
            Self::BitBox(interpreter) => interpreter.exchange(data),
            Self::Coldcard(interpreter) => interpreter.exchange(data),
            Self::Jade(interpreter) => interpreter.exchange(data),
            Self::Ledger(interpreter) => interpreter.exchange(data),
        }
    }

    fn end(self) -> Result<bc::Response, bc::Error> {
        match self {
            Self::BitBox(interpreter) => interpreter.end(),
            Self::Coldcard(interpreter) => interpreter.end(),
            Self::Jade(interpreter) => interpreter.end(),
            Self::Ledger(interpreter) => interpreter.end(),
        }
    }
}

/// The lease an interpreter holds on the device state it borrows, released on drop.
enum StateLease {
    /// Ledger and Jade are stateless between commands.
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
    user_action: bool,
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
                user_action: false,
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
            // retired (which releases the state lease and frees the handle for a retry).
            // Misuse (`BadState`) changed nothing, so the session survives it.
            if !matches!(error, HwiError::BadState { .. }) {
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

    /// Starts the command and returns the first payload to send. Callable once.
    pub fn start(&self, cmd: HwiCommand) -> Result<Transmit, HwiError> {
        // Input validation happens before the session is touched, so a rejected command
        // leaves the interpreter usable.
        let plan = cmd.plan()?;
        self.with_session(|session| {
            if session.started {
                return Err(HwiError::bad_state("start was already called"));
            }
            session.started = true;
            session.expect = plan.expect;
            session.user_action = plan.user_action;
            session
                .inner
                .start(plan.command)
                .map(Transmit::from)
                .map_err(|e| map_error(e, session.kind, session.user_action))
        })
    }

    /// Feeds one reply back. Returns the next payload to send, or `None` when the
    /// machine is done and [`Interp::end`] should be called.
    pub fn exchange(&self, reply: Vec<u8>) -> Result<Option<Transmit>, HwiError> {
        self.with_session(|session| {
            if !session.started {
                return Err(HwiError::bad_state("exchange called before start"));
            }
            if session.finished {
                return Err(HwiError::bad_state(
                    "exchange called after the machine finished",
                ));
            }
            match session
                .inner
                .exchange(reply)
                .map_err(|e| map_error(e, session.kind, session.user_action))?
            {
                Some(transmit) => Ok(Some(transmit.into())),
                None => {
                    session.finished = true;
                    Ok(None)
                }
            }
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
            user_action,
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
            engine
                .ready(*key)
                .map_err(|e| HwiError::Device { msg: e.to_string() })?;
            drop(lease);
            return Ok(HwiResponse::TaskDone);
        }

        // The interpreter (and its borrow of the device state) is gone: release the lease
        // before anything touches that state again.
        drop(lease);
        let response = response.map_err(|e| map_error(e, kind, user_action))?;

        // A device that refuses answers the command with an unrelated response (Ledger
        // turns a `Deny` status word into `TaskDone`), which `bhwi-async` reports as a
        // missing result. Same check, same mapping.
        if !expect.matches(&response) {
            return Err(map_error(bc::Error::NoErrorOrResult, kind, user_action));
        }

        Ok(HwiResponse::from(response))
    }
}
