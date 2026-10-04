//! Opt-in real Trezor One firmware smoke. UDP/debuglink exist only in this test,
//! require explicit localhost targets, and never initialize or modify a seed.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bhwi::trezor::api;
use bhwi_async::Transport;
use bhwi_async::transport::Channel;
use bhwi_async::transport::trezor::TrezorTransport;
use bhwi_ffi::{HwiCommand, HwiResponse, Interp, Network, Recipient};
use futures::executor::block_on;

struct TestUdp {
    socket: UdpSocket,
    deadline: Instant,
}

impl TestUdp {
    fn connect(target: &str) -> Self {
        let target: SocketAddr = target.parse().expect("explicit emulator socket address");
        assert_eq!(
            target.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_ne!(target.port(), 0);
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(target).unwrap();
        Self {
            socket,
            deadline: Instant::now() + Duration::from_secs(30),
        }
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "firmware command deadline exceeded",
                )
            })
    }
}

#[async_trait(?Send)]
impl Channel for &mut TestUdp {
    async fn send(&self, bytes: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.send(bytes)
    }

    async fn receive(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        let mut report = [0; 65];
        let size = self.socket.recv(&mut report)?;
        if size != 64 || bytes.len() < size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid emulator packet",
            ));
        }
        bytes[..size].copy_from_slice(&report[..size]);
        Ok(size)
    }
}

fn run(transport: &mut TestUdp, command: HwiCommand) -> HwiResponse {
    let interp = Interp::new_trezor(Network::Testnet, None, false).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    transport.deadline = deadline;
    let mut transport = TrezorTransport::new(transport);
    let mut transmit = interp.start(command).unwrap();
    loop {
        assert!(
            Instant::now() < deadline,
            "firmware command deadline exceeded"
        );
        assert_eq!(transmit.recipient, Recipient::Device);
        let reply = block_on(transport.exchange(&transmit.payload, transmit.encrypted)).unwrap();
        match interp.exchange(reply).unwrap() {
            Some(next) => transmit = next,
            None => return interp.end().unwrap(),
        }
    }
}

fn fixture_pin_positions(debug_target: &str, pin: &str) -> String {
    assert!(!pin.is_empty() && pin.bytes().all(|byte| (b'1'..=b'9').contains(&byte)));
    let mut udp = TestUdp::connect(debug_target);
    let mut debug = TrezorTransport::new(&mut udp);
    // Trezor/KeepKey's compatible DebugLinkState schema; no production FFI command.
    let reply = block_on(debug.exchange(&api::frame(101, &[]), false)).unwrap();
    let (kind, body) = api::parse_frame(&reply).unwrap();
    assert_eq!(kind, 102);
    let mut state: bhwi::keepkey::proto::DebugLinkState = api::decode(&body).unwrap();
    let matrix = state.matrix.take().expect("test fixture debug PIN matrix");
    let mut digits = matrix.as_bytes().to_vec();
    digits.sort_unstable();
    assert!(digits == b"123456789", "invalid test fixture PIN matrix");
    pin.bytes()
        .map(|digit| {
            char::from(b'1' + matrix.bytes().position(|value| value == digit).unwrap() as u8)
        })
        .collect()
}

#[test]
#[ignore = "requires an initialized disposable official One 1.13.1 emulator and explicit localhost/public-identity environment"]
fn trezor_one_public_identity_and_ordinary_pin() {
    let target = std::env::var("BHWI_TREZOR_ADDR").expect("explicit localhost emulator target");
    let expected_fingerprint =
        std::env::var("BHWI_TREZOR_FINGERPRINT").expect("fixture public fingerprint");
    let expected_xpub = std::env::var("BHWI_TREZOR_ACCOUNT_XPUB")
        .expect("fixture public BIP84 testnet account xpub");
    let mut transport = TestUdp::connect(&target);
    let HwiResponse::Info {
        version,
        firmware,
        initialized,
        networks,
        needs_pin_sent,
        needs_passphrase_sent,
        on_device_passphrase_entry,
        ..
    } = run(
        &mut transport,
        HwiCommand::Unlock {
            network: Network::Testnet,
        },
    )
    else {
        panic!("unlock must return the actual device Info");
    };
    assert_eq!(version, "1.13.1");
    assert!(firmware.is_none() || firmware.as_deref() == Some("1"));
    assert_eq!(initialized, Some(true));
    assert_eq!(networks, vec![Network::Testnet]); // Session-selected, not chain attestation.
    assert_eq!(needs_passphrase_sent, Some(false));
    assert_eq!(on_device_passphrase_entry, Some(false));
    if let Ok(pin) = std::env::var("BHWI_TREZOR_PIN") {
        assert_eq!(needs_pin_sent, Some(true), "PIN fixture must start locked");
        assert!(matches!(
            run(&mut transport, HwiCommand::PromptPin),
            HwiResponse::DeviceAction { success: true }
        ));
        let debug_target =
            std::env::var("BHWI_TREZOR_DEBUG_ADDR").expect("explicit localhost debuglink target");
        let positions = fixture_pin_positions(&debug_target, &pin);
        // A fresh command interpreter, but the same physical channel, with no Initialize in between.
        assert!(matches!(
            run(&mut transport, HwiCommand::SendPin { positions }),
            HwiResponse::DeviceAction { success: true }
        ));
    } else {
        assert_eq!(
            needs_pin_sent,
            Some(false),
            "locked fixture requires the opt-in PIN/debuglink environment"
        );
    }
    let HwiResponse::Fingerprint { hex } = run(&mut transport, HwiCommand::GetMasterFingerprint)
    else {
        panic!("expected device fingerprint");
    };
    assert_eq!(hex, expected_fingerprint);
    let HwiResponse::Xpub { xpub } = run(
        &mut transport,
        HwiCommand::GetXpub {
            path: "m/84'/1'/0'".into(),
            display: false,
        },
    ) else {
        panic!("expected public account");
    };
    assert_eq!(xpub, expected_xpub);
}

#[test]
fn expired_deadline_rejects_each_packet_without_io() {
    let mut udp = TestUdp::connect("127.0.0.1:1");
    udp.deadline = Instant::now() - Duration::from_secs(1);
    let mut channel = &mut udp;
    assert_eq!(
        block_on(channel.send(&[0; 64])).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        block_on(channel.receive(&mut [0; 64])).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}
