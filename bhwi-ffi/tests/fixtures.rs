//! Checked-in vectors for the Kotlin side, at both levels of the split.
//!
//! * Report level: the real `bhwi-async` Ledger device driven over an in-memory HID
//!   channel. Kotlin reimplements that framing, so it needs the exact reports. This is
//!   the only place `bhwi-async` is used, and it is a dev-dependency: no I/O ships in
//!   the library.
//! * Transmit level: the same commands driven through `Interp`, the surface Kotlin
//!   actually calls, so a host loop can be replayed without a device.
//!
//! Any protocol drift fails the test instead of silently rewriting the vectors.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::rc::Rc;

use async_trait::async_trait;
use bhwi_async::transport::Channel;
use bhwi_async::transport::ledger::hid::LedgerTransportHID;
use bhwi_async::{DisplayAddress, HWI, Ledger};
use bhwi_ffi::{HwiCommand, HwiError, HwiResponse, Interp};
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
#[derive(Default)]
struct Tape {
    writes: RefCell<Vec<Vec<u8>>>,
    reads: RefCell<VecDeque<Vec<u8>>>,
    served: RefCell<Vec<Vec<u8>>>,
}

impl Tape {
    fn new(responses: &[Vec<u8>]) -> Rc<Self> {
        Rc::new(Self {
            reads: RefCell::new(responses.iter().flat_map(|apdu| frame(apdu)).collect()),
            ..Self::default()
        })
    }

    fn transcript(&self) -> (Vec<String>, Vec<String>) {
        let writes = self.writes.borrow().iter().map(hex::encode).collect();
        let reads = self.served.borrow().iter().map(hex::encode).collect();
        (writes, reads)
    }
}

/// The transport owns its channel, so the recording tape is shared through this handle.
struct Recorder(Rc<Tape>);

#[async_trait(?Send)]
impl Channel for Recorder {
    async fn send(&self, data: &[u8]) -> Result<usize, std::io::Error> {
        self.0.writes.borrow_mut().push(data.to_vec());
        Ok(data.len())
    }

    async fn receive(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
        let mut report = self
            .0
            .reads
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| std::io::Error::other("no scripted report left"))?;
        report.truncate(data.len());
        data[..report.len()].copy_from_slice(&report);
        self.0.served.borrow_mut().push(report.clone());
        Ok(report.len())
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
fn assert_fixture(name: &str, value: serde_json::Value) {
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

fn assert_report_fixture(name: &str, writes: &[String], reads: &[String], expected: &str) {
    assert_fixture(
        name,
        serde_json::json!({
            "writes": writes,
            "reads": reads,
            "expected": expected,
        }),
    );
}

// ---- report level: framed HID transcripts ----------------------------------------

#[test]
fn ledger_get_master_fingerprint() {
    let tape = Tape::new(&[fingerprint_response()]);
    let mut ledger = Ledger::new(LedgerTransportHID::new(Recorder(tape.clone())));
    let fingerprint = block_on(ledger.get_master_fingerprint()).expect("fingerprint");

    assert_eq!(fingerprint.to_string(), FINGERPRINT);
    let (writes, reads) = tape.transcript();
    assert_report_fixture(
        "ledger_get_master_fingerprint.json",
        &writes,
        &reads,
        FINGERPRINT,
    );
}

#[test]
fn ledger_get_xpub() {
    let tape = Tape::new(&[xpub_response()]);
    let mut ledger = Ledger::new(LedgerTransportHID::new(Recorder(tape.clone())));
    let xpub = block_on(ledger.get_extended_pubkey(ACCOUNT_PATH.parse().unwrap(), false))
        .expect("xpub")
        .to_string();

    assert_eq!(xpub, XPUB);
    let (writes, reads) = tape.transcript();
    assert_report_fixture("ledger_get_xpub.json", &writes, &reads, &xpub);
}

#[test]
fn ledger_refused() {
    // Address display resolves the wallet policy first (fingerprint, then account xpub);
    // the device denies the final GET_WALLET_ADDRESS with 0x6985.
    let tape = Tape::new(&[
        fingerprint_response(),
        xpub_response(),
        response(&[], SW_DENY),
    ]);
    let mut ledger = Ledger::new(LedgerTransportHID::new(Recorder(tape.clone())));
    let error = block_on(ledger.display_address(
        DisplayAddress::ByPath {
            path: ADDRESS_PATH.parse().unwrap(),
            display: true,
            address_format: None,
        },
        None,
    ))
    .expect_err("device denied");

    // A denied display answers with `TaskDone` instead of an address; `Interp` turns the
    // same mismatch into `HwiError::UserRefused` (see `interp.rs`).
    assert!(
        matches!(
            error,
            bhwi_async::Error::Interpreter(bhwi::common::Error::NoErrorOrResult)
        ),
        "expected a missing result, got {error:?}"
    );
    let (writes, reads) = tape.transcript();
    assert_report_fixture("ledger_refused.json", &writes, &reads, "UserRefused");
}

// ---- transmit level: what the Kotlin host loop sees --------------------------------

/// Drives `command` through `interp` with the scripted replies, recording each
/// `(payload, encrypted, reply)` triple, and checks the result in as a fixture.
fn assert_transmit_fixture(
    name: &str,
    label: &str,
    interp: &Interp,
    command: HwiCommand,
    replies: Vec<Vec<u8>>,
    outcome: impl FnOnce(Result<HwiResponse, HwiError>) -> String,
) {
    let mut exchanges = Vec::new();
    let mut transmit = Some(interp.start(command).expect("start"));
    let mut replies = replies.into_iter();
    let result = loop {
        let Some(current) = transmit.take() else {
            break interp.end();
        };
        let reply = replies.next().expect("a scripted reply for every payload");
        exchanges.push(serde_json::json!({
            "payload_hex": hex::encode(&current.payload),
            "encrypted": current.encrypted,
            "reply_hex": hex::encode(&reply),
        }));
        match interp.exchange(reply) {
            Ok(next) => transmit = next,
            Err(error) => break Err(error),
        }
    };

    assert_fixture(
        name,
        serde_json::json!({
            "command": label,
            "exchanges": exchanges,
            "expected": outcome(result),
        }),
    );
}

#[test]
fn transmit_ledger_fingerprint() {
    assert_transmit_fixture(
        "transmit_ledger_fingerprint.json",
        "get_master_fingerprint",
        &Interp::new_ledger(),
        HwiCommand::GetMasterFingerprint,
        vec![fingerprint_response()],
        |result| match result.expect("fingerprint") {
            HwiResponse::Fingerprint { hex } => hex,
            other => panic!("expected a fingerprint, got {other:?}"),
        },
    );
}

#[test]
fn transmit_ledger_xpub() {
    assert_transmit_fixture(
        "transmit_ledger_xpub.json",
        "get_xpub",
        &Interp::new_ledger(),
        HwiCommand::GetXpub {
            path: ACCOUNT_PATH.to_string(),
            display: false,
        },
        vec![xpub_response()],
        |result| match result.expect("xpub") {
            HwiResponse::Xpub { xpub } => xpub,
            other => panic!("expected an xpub, got {other:?}"),
        },
    );
}

#[test]
fn transmit_ledger_refused() {
    assert_transmit_fixture(
        "transmit_ledger_refused.json",
        "display_address",
        &Interp::new_ledger(),
        HwiCommand::DisplayAddress {
            path: ADDRESS_PATH.to_string(),
            display: true,
            format: None,
        },
        vec![
            fingerprint_response(),
            xpub_response(),
            response(&[], SW_DENY),
        ],
        |result| match result {
            Err(HwiError::UserRefused) => "UserRefused".to_string(),
            other => panic!("expected a refusal, got {other:?}"),
        },
    );
}
