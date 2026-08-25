//! Deterministic Ledger replay: drives the real `bhwi-async` Ledger device over an
//! in-memory HID channel, asserts the typed outcome, and checks in the report-level
//! transcript so the Kotlin tests can replay it without knowing any framing.
//!
//! This file doubles as the `HwiSession` lifecycle test: the replay channel is an ordinary
//! Rust implementation of the foreign `HidChannel` trait, so no FFI is involved.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bhwi_ffi::{HidChannel, HwiError, HwiSession, TransportError, connect_ledger_usb};
use futures::executor::block_on;

/// Fixed test vectors; the fingerprint/xpub pair is the one used by bhwi's own tests.
const FINGERPRINT: &str = "f5acc2fd";
const ACCOUNT_PATH: &str = "m/84'/1'/0'";
const ADDRESS_PATH: &str = "m/84'/1'/0'/0/0";
const XPUB: &str = "tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP";

const LEDGER_CHANNEL: u16 = 0x0101;
const LEDGER_TAG: u8 = 0x05;
const REPORT_LEN: usize = 64;
const SW_OK: [u8; 2] = [0x90, 0x00];
const SW_DENY: [u8; 2] = [0x69, 0x85];

/// Scripted HID channel: records every report written, serves pre-framed replies.
struct ReplayChannel {
    writes: Mutex<Vec<Vec<u8>>>,
    reads: Mutex<VecDeque<Vec<u8>>>,
    served: Mutex<Vec<Vec<u8>>>,
}

impl ReplayChannel {
    fn new(responses: &[Vec<u8>]) -> Arc<Self> {
        let reads: VecDeque<Vec<u8>> = responses.iter().flat_map(|apdu| frame(apdu)).collect();
        Arc::new(Self {
            writes: Mutex::new(Vec::new()),
            reads: Mutex::new(reads),
            served: Mutex::new(Vec::new()),
        })
    }

    fn transcript(&self) -> (Vec<String>, Vec<String>) {
        let writes = self
            .writes
            .lock()
            .unwrap()
            .iter()
            .map(hex::encode)
            .collect();
        let reads = self
            .served
            .lock()
            .unwrap()
            .iter()
            .map(hex::encode)
            .collect();
        (writes, reads)
    }
}

#[async_trait]
impl HidChannel for ReplayChannel {
    async fn send(&self, report: Vec<u8>) -> Result<u32, TransportError> {
        let written = report.len() as u32;
        self.writes.lock().unwrap().push(report);
        Ok(written)
    }

    async fn receive(&self, max_len: u32) -> Result<Vec<u8>, TransportError> {
        let mut report = self
            .reads
            .lock()
            .unwrap()
            .pop_front()
            .ok_or(TransportError::Disconnected)?;
        report.truncate(max_len as usize);
        self.served.lock().unwrap().push(report.clone());
        Ok(report)
    }
}

/// Splits an APDU response into the 64-byte HID reports a Ledger would emit.
fn frame(apdu: &[u8]) -> Vec<Vec<u8>> {
    let mut reports = Vec::new();
    let mut offset = 0usize;
    let mut sequence: u16 = 0;
    loop {
        let mut report = vec![0u8; REPORT_LEN];
        report[0..2].copy_from_slice(&LEDGER_CHANNEL.to_be_bytes());
        report[2] = LEDGER_TAG;
        report[3..5].copy_from_slice(&sequence.to_be_bytes());
        let head = if sequence == 0 {
            report[5..7].copy_from_slice(&(apdu.len() as u16).to_be_bytes());
            7
        } else {
            5
        };
        let take = (REPORT_LEN - head).min(apdu.len() - offset);
        report[head..head + take].copy_from_slice(&apdu[offset..offset + take]);
        reports.push(report);
        offset += take;
        sequence += 1;
        if offset >= apdu.len() {
            return reports;
        }
    }
}

fn response(data: &[u8], status: [u8; 2]) -> Vec<u8> {
    let mut out = data.to_vec();
    out.extend_from_slice(&status);
    out
}

fn fingerprint_response() -> Vec<u8> {
    response(&hex::decode(FINGERPRINT).unwrap(), SW_OK)
}

fn xpub_response() -> Vec<u8> {
    response(XPUB.as_bytes(), SW_OK)
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate has a parent directory")
        .join("fixtures")
}

/// Writes the fixture when missing (or when `BHWI_REGENERATE_FIXTURES` is set) and always
/// compares, so any protocol drift fails the test.
fn assert_fixture(name: &str, writes: &[String], reads: &[String], expected: &str) {
    let value = serde_json::json!({
        "writes": writes,
        "reads": reads,
        "expected": expected,
    });
    let rendered = format!("{}\n", serde_json::to_string_pretty(&value).unwrap());
    let path = fixtures_dir().join(name);
    if !path.exists() || std::env::var_os("BHWI_REGENERATE_FIXTURES").is_some() {
        std::fs::create_dir_all(fixtures_dir()).unwrap();
        std::fs::write(&path, &rendered).unwrap();
    }
    let checked_in = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        checked_in,
        rendered,
        "fixture drift in {}; re-run with BHWI_REGENERATE_FIXTURES=1 to update",
        path.display()
    );
}

#[test]
fn ledger_get_master_fingerprint() {
    let channel = ReplayChannel::new(&[fingerprint_response()]);
    let session = connect_ledger_usb(channel.clone());
    let fingerprint = block_on(session.get_master_fingerprint()).expect("fingerprint");
    session.close();

    assert_eq!(fingerprint, FINGERPRINT);
    let (writes, reads) = channel.transcript();
    assert_fixture(
        "ledger_get_master_fingerprint.json",
        &writes,
        &reads,
        &fingerprint,
    );
}

#[test]
fn ledger_get_xpub() {
    let channel = ReplayChannel::new(&[xpub_response()]);
    let session = connect_ledger_usb(channel.clone());
    let xpub =
        block_on(session.get_extended_pubkey(ACCOUNT_PATH.to_string(), false)).expect("xpub");
    session.close();

    assert_eq!(xpub, XPUB);
    let (writes, reads) = channel.transcript();
    assert_fixture("ledger_get_xpub.json", &writes, &reads, &xpub);
}

#[test]
fn ledger_refused() {
    // Address display resolves the wallet policy first (fingerprint, then account xpub);
    // the device denies the final GET_WALLET_ADDRESS with 0x6985.
    let channel = ReplayChannel::new(&[
        fingerprint_response(),
        xpub_response(),
        response(&[], SW_DENY),
    ]);
    let session = connect_ledger_usb(channel.clone());
    let error = block_on(session.display_address(ADDRESS_PATH.to_string(), true, None))
        .expect_err("device denied");
    session.close();

    assert!(
        matches!(error, HwiError::UserRefused),
        "expected UserRefused, got {error:?}"
    );
    let (writes, reads) = channel.transcript();
    assert_fixture("ledger_refused.json", &writes, &reads, "UserRefused");
}

#[test]
fn closed_session_rejects_further_commands() {
    let session = connect_ledger_usb(ReplayChannel::new(&[fingerprint_response()]));
    session.close();
    session.close(); // idempotent
    let error = block_on(session.get_master_fingerprint()).expect_err("session is closed");
    assert!(matches!(error, HwiError::Closed), "got {error:?}");
}

#[test]
fn unplug_surfaces_as_disconnected() {
    // No scripted responses: the channel reports a disconnect on the first read. The
    // marker has to survive `LedgerTransportHID` wrapping it in `LedgerHIDError::Hid`.
    let session = connect_ledger_usb(ReplayChannel::new(&[]));
    let error = block_on(session.get_master_fingerprint()).expect_err("no device");
    session.close();
    assert!(matches!(error, HwiError::Disconnected), "got {error:?}");
}

#[test]
fn other_io_failures_stay_transport_errors() {
    struct BrokenChannel;

    #[async_trait]
    impl HidChannel for BrokenChannel {
        async fn send(&self, _report: Vec<u8>) -> Result<u32, TransportError> {
            Err(TransportError::Io {
                msg: "write failed".to_string(),
            })
        }
        async fn receive(&self, _max_len: u32) -> Result<Vec<u8>, TransportError> {
            unreachable!("send fails first")
        }
    }

    let session = connect_ledger_usb(Arc::new(BrokenChannel));
    let error = block_on(session.get_master_fingerprint()).expect_err("write failed");
    session.close();
    assert!(matches!(error, HwiError::Transport { .. }), "got {error:?}");
}

#[test]
fn repeated_connect_and_close_does_not_deadlock() {
    for _ in 0..10 {
        let channel = ReplayChannel::new(&[fingerprint_response()]);
        let session: Arc<HwiSession> = connect_ledger_usb(channel);
        assert_eq!(
            block_on(session.get_master_fingerprint()).expect("fingerprint"),
            FINGERPRINT
        );
        session.close();
        assert!(matches!(
            block_on(session.get_master_fingerprint()),
            Err(HwiError::Closed)
        ));
    }
}
