//! Device state that outlives a single command: BitBox noise pairing and the Coldcard
//! link-encryption engine.
//!
//! Both interpreters borrow their state mutably (`BitBoxInterpreter<'a>`,
//! `ColdcardInterpreter<'a>`), which no FFI can express. Instead of extending the borrow
//! to `'static` behind a documented contract, exclusivity is enforced at runtime by
//! [`Leased`]: an interpreter takes the lease when it is built and releases it when it is
//! dropped, and every other accessor fails with `BadState` while a lease is out.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bhwi::bitbox::noise::{NoiseConfigData, NoiseState, PairingCodeHook};
use bhwi::coldcard::encrypt::Engine;

use crate::HwiError;

/// The two states this crate hands out `&mut` to must be `Send`, or the objects holding
/// them could not be shared with Kotlin.
const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<NoiseState>();
    assert_send::<Engine>();
};

/// A cell whose exclusivity is enforced by a lease flag instead of the borrow checker.
///
/// This is a `Mutex<T>` that refuses instead of blocking, and that can hand its pointer
/// out to a holder living in another object. A lease that is never released leaves the
/// cell permanently unavailable, exactly like a poisoned mutex.
pub(crate) struct Leased<T> {
    cell: UnsafeCell<T>,
    leased: AtomicBool,
}

// SAFETY: `Leased` grants access to the value to exactly one holder at a time. `acquire`
// only succeeds when it flips `leased` from false to true, and both `acquire` and `with`
// fail while that flag is set, so no two `&mut T` can coexist and no `&T` can overlap one.
// That is the same exclusion `Mutex<T>` provides, so it carries the same bounds.
unsafe impl<T: Send> Send for Leased<T> {}
unsafe impl<T: Send> Sync for Leased<T> {}

impl<T> Leased<T> {
    fn new(value: T) -> Self {
        Self {
            cell: UnsafeCell::new(value),
            leased: AtomicBool::new(false),
        }
    }

    /// Takes the lease out, or returns `None` when one is already out.
    ///
    /// The returned pointer stays valid until [`Leased::release`]: the value lives in
    /// this cell (never moved, since the owning handle is only ever used behind an
    /// `Arc`), and the lease holder is responsible for keeping that `Arc` alive.
    pub(crate) fn acquire(&self) -> Option<*mut T> {
        self.leased
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        Some(self.cell.get())
    }

    /// # Safety
    ///
    /// The caller must hold the lease taken by [`Leased::acquire`] and must have dropped
    /// every reference derived from the pointer it returned.
    pub(crate) unsafe fn release(&self) {
        self.leased.store(false, Ordering::Release);
    }

    /// The cell pointer for a caller that already holds the lease.
    ///
    /// # Safety
    ///
    /// The caller must hold the lease taken by [`Leased::acquire`] and must not create a
    /// reference from this pointer while any other reference derived from the lease lives.
    pub(crate) unsafe fn get_leased(&self) -> *mut T {
        self.cell.get()
    }

    /// Exclusive access for the duration of `f`; `None` while a lease is out.
    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        let pointer = self.acquire()?;
        // SAFETY: the lease is ours until `release`, so this is the only live reference
        // to the value, and it dies at the end of this statement.
        let out = f(unsafe { &mut *pointer });
        // SAFETY: the reference above is gone and the lease is the one we just took.
        unsafe { self.release() };
        Some(out)
    }
}

/// Persistable BitBox02 pairing material.
///
/// `privkey` is the host's noise static key: `None` on a fresh handle, generated during
/// the first handshake. `device_pubkeys` holds the 32-byte static key of every device
/// this host has already paired with; a device in that list skips the on-screen pairing
/// confirmation. Persist [`NoiseHandle::export`] after a successful unlock and pass it
/// back to the next [`NoiseHandle::new`].
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct NoiseConfig {
    pub privkey: Option<Vec<u8>>,
    pub device_pubkeys: Vec<Vec<u8>>,
}

impl From<&NoiseConfigData> for NoiseConfig {
    fn from(data: &NoiseConfigData) -> Self {
        Self {
            privkey: data.app_static_privkey.map(|key| key.to_vec()),
            device_pubkeys: data.device_static_pubkeys.clone(),
        }
    }
}

impl TryFrom<NoiseConfig> for NoiseConfigData {
    type Error = HwiError;

    fn try_from(config: NoiseConfig) -> Result<Self, Self::Error> {
        let mut data = NoiseConfigData::default();
        if let Some(privkey) = config.privkey {
            data.app_static_privkey = Some(
                <[u8; 32]>::try_from(privkey.as_slice())
                    .map_err(|_| HwiError::invalid("noise private key must be 32 bytes"))?,
            );
        }
        for pubkey in &config.device_pubkeys {
            if pubkey.len() != 32 {
                return Err(HwiError::invalid("noise device pubkey must be 32 bytes"));
            }
            data.add_device_static_pubkey(pubkey);
        }
        Ok(data)
    }
}

/// BitBox02 noise pairing state, shared across the commands of one host session.
#[derive(uniffi::Object)]
pub struct NoiseHandle {
    pub(crate) state: Leased<NoiseState>,
    /// The pairing-code sink lives outside the leased state on purpose: an interpreter
    /// holds the state, and the host still has to read the code while that interpreter
    /// is mid-unlock.
    pairing_code: Arc<Mutex<Option<String>>>,
}

/// The hook the interpreter fires the moment the pairing code becomes known, just before
/// it asks the device for verification.
fn pairing_hook(sink: Arc<Mutex<Option<String>>>) -> PairingCodeHook {
    Box::new(move |code| {
        if let Ok(mut slot) = sink.lock() {
            *slot = Some(code.to_string());
        }
    })
}

#[uniffi::export]
impl NoiseHandle {
    /// Builds a handle, optionally restoring previously persisted pairing material.
    #[uniffi::constructor]
    pub fn new(config: Option<NoiseConfig>) -> Result<Arc<Self>, HwiError> {
        let data = config.map(NoiseConfigData::try_from).transpose()?;
        let mut state = NoiseState::new(data);
        let pairing_code = Arc::new(Mutex::new(None));
        state.set_pairing_code_hook(pairing_hook(pairing_code.clone()));
        Ok(Arc::new(Self {
            state: Leased::new(state),
            pairing_code,
        }))
    }

    /// The pairing material to persist. Fails while an interpreter holds the state:
    /// export after `Interp.end()`, when the handshake result is in.
    pub fn export(&self) -> Result<NoiseConfig, HwiError> {
        self.state
            .with(|state| NoiseConfig::from(state.data()))
            .ok_or_else(|| HwiError::bad_state("noise handle is in use by an interpreter"))
    }

    /// Returns the pairing code once, if the device produced one since the last call.
    ///
    /// Poll it after every `exchange` during an unlock and show the code before sending
    /// the payload you just got back: the device is already waiting for the user to
    /// compare it. Works while an interpreter holds the handle.
    pub fn take_pairing_code(&self) -> Option<String> {
        self.pairing_code
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
    }
}

/// Coldcard link encryption: an ephemeral key pair before `Unlock`, the AES session
/// state afterwards.
///
/// One handle per physical connection. The key exchange happens in-protocol during
/// `Unlock`, so a handle that has already completed one cannot serve a second.
#[derive(uniffi::Object)]
pub struct ColdcardEncryption {
    pub(crate) engine: Leased<Engine>,
}

#[uniffi::export]
impl ColdcardEncryption {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            // The only randomness this crate needs: the ephemeral k256 key the Coldcard
            // session key is derived from.
            engine: Leased::new(Engine::new(&mut rand_core::OsRng)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noise_config_round_trips() {
        let config = NoiseConfig {
            privkey: Some(vec![7u8; 32]),
            device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32]],
        };
        let handle = NoiseHandle::new(Some(config.clone())).unwrap();
        assert_eq!(handle.export().unwrap(), config);
    }

    #[test]
    fn malformed_noise_config_is_rejected() {
        assert!(matches!(
            NoiseHandle::new(Some(NoiseConfig {
                privkey: Some(vec![7u8; 31]),
                device_pubkeys: Vec::new(),
            })),
            Err(HwiError::InvalidInput { .. })
        ));
        assert!(matches!(
            NoiseHandle::new(Some(NoiseConfig {
                privkey: None,
                device_pubkeys: vec![vec![1u8; 33]],
            })),
            Err(HwiError::InvalidInput { .. })
        ));
    }

    #[test]
    fn pairing_code_slot_takes_once() {
        let handle = NoiseHandle::new(None).unwrap();
        assert_eq!(handle.take_pairing_code(), None);

        // Stand in for the interpreter: fire the hook this handle installs.
        let mut hook = pairing_hook(handle.pairing_code.clone());
        hook("AAAAA BBBBB\nCCCCC DDDDD");

        assert_eq!(
            handle.take_pairing_code().as_deref(),
            Some("AAAAA BBBBB\nCCCCC DDDDD")
        );
        assert_eq!(handle.take_pairing_code(), None);
    }

    #[test]
    fn a_lease_excludes_every_other_accessor() {
        let handle = NoiseHandle::new(None).unwrap();
        let lease = handle.state.acquire().expect("first lease");
        assert!(handle.state.acquire().is_none(), "second lease refused");
        assert!(matches!(handle.export(), Err(HwiError::BadState { .. })));
        // The pairing-code slot is outside the leased state, so it stays readable.
        assert_eq!(handle.take_pairing_code(), None);

        // SAFETY: no reference was derived from `lease`.
        let _ = lease;
        unsafe { handle.state.release() };
        assert!(handle.export().is_ok());
    }
}
