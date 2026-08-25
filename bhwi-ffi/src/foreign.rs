//! Foreign (Kotlin-implemented) I/O objects and the `bhwi-async` adapters over them.
//!
//! UniFFI foreign trait objects are `Arc<dyn T>` and their futures are `Send`, which is a
//! strict superset of what `bhwi-async`'s `?Send` traits require, so the adapters are
//! straight forwarding shims plus error mapping.

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use bhwi_async::transport::Channel;
use bhwi_async::transport::jade::CborStream;
use bhwi_async::{HttpClient, Transport};

/// Failure reported by a foreign I/O object.
#[derive(Clone, Debug, thiserror::Error, uniffi::Error)]
pub enum TransportError {
    #[error("io error: {msg}")]
    Io { msg: String },
    #[error("device disconnected")]
    Disconnected,
    #[error("operation cancelled")]
    Cancelled,
}

/// Raw HID report channel (Ledger / Coldcard / BitBox02 over USB).
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait HidChannel: Send + Sync {
    /// Write one HID report; returns the number of bytes written.
    async fn send(&self, report: Vec<u8>) -> Result<u32, TransportError>;
    /// Read one HID report, at most `max_len` bytes.
    async fn receive(&self, max_len: u32) -> Result<Vec<u8>, TransportError>;
}

/// Byte stream for Jade, bridged by Kotlin from either USB serial or BLE.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait SerialStream: Send + Sync {
    async fn write_all(&self, data: Vec<u8>) -> Result<(), TransportError>;
    /// Read up to `max_len` bytes. Returning fewer is fine; returning more is an error.
    ///
    /// An empty (0-byte) result means end of stream, i.e. the device is gone: it aborts
    /// the in-flight command with "stream ended before complete CBOR message". "No data
    /// yet" must **not** return empty — suspend until at least one byte is available, or
    /// throw `TransportException.Disconnected` if the link dropped.
    async fn read(&self, max_len: u32) -> Result<Vec<u8>, TransportError>;
}

/// GATT characteristic pair for a Ledger connected over BLE.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait BleChannel: Send + Sync {
    /// Write one BLE frame (already sized to `mtu`).
    async fn write(&self, data: Vec<u8>) -> Result<(), TransportError>;
    /// Await one notification payload.
    async fn read(&self) -> Result<Vec<u8>, TransportError>;
    /// Usable payload bytes per write, as negotiated by the platform BLE stack.
    fn mtu(&self) -> u16;
}

/// HTTP bridge used only for the Jade PIN server exchange.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait HttpBridge: Send + Sync {
    async fn request(&self, url: String, body: Vec<u8>) -> Result<Vec<u8>, TransportError>;
}

/// Receives the BitBox02 noise pairing code so the app can render it for confirmation.
#[uniffi::export(with_foreign)]
pub trait PairingCodeListener: Send + Sync {
    fn on_pairing_code(&self, code: String);
}

/// Marker text embedded in disconnect errors.
///
/// The framing transports in `bhwi-async` wrap our `io::Error` in their own error types,
/// which erase `ErrorKind`, so the session layer recovers the disconnect from the `Debug`
/// rendering instead. Keep it in sync with `session::map_error`.
pub(crate) const DISCONNECT_MARKER: &str = "bhwi:device-disconnected";

pub(crate) fn io_err(error: TransportError) -> io::Error {
    match error {
        TransportError::Disconnected => {
            io::Error::new(io::ErrorKind::NotConnected, DISCONNECT_MARKER)
        }
        TransportError::Cancelled => {
            io::Error::new(io::ErrorKind::Interrupted, "operation cancelled")
        }
        TransportError::Io { msg } => io::Error::other(msg),
    }
}

/// Adapts a foreign HID channel to the `bhwi-async` report-level `Channel`.
pub(crate) struct ForeignChannel(Arc<dyn HidChannel>);

impl ForeignChannel {
    pub(crate) fn new(channel: Arc<dyn HidChannel>) -> Self {
        Self(channel)
    }
}

#[async_trait(?Send)]
impl Channel for ForeignChannel {
    async fn send(&self, data: &[u8]) -> Result<usize, io::Error> {
        self.0
            .send(data.to_vec())
            .await
            .map(|written| written as usize)
            .map_err(io_err)
    }

    async fn receive(&mut self, data: &mut [u8]) -> Result<usize, io::Error> {
        let report = self.0.receive(data.len() as u32).await.map_err(io_err)?;
        // Silently truncating would desynchronise the framing layer, so refuse instead.
        if report.len() > data.len() {
            return Err(io::Error::other("HID report exceeds the requested length"));
        }
        data[..report.len()].copy_from_slice(&report);
        Ok(report.len())
    }
}

/// Adapts a foreign byte stream into the CBOR-framed transport Jade expects.
pub(crate) struct ForeignSerial(Arc<dyn SerialStream>);

impl ForeignSerial {
    pub(crate) fn new(stream: Arc<dyn SerialStream>) -> Self {
        Self(stream)
    }
}

#[async_trait(?Send)]
impl CborStream for ForeignSerial {
    async fn write_all(&mut self, command: &[u8]) -> Result<(), io::Error> {
        self.0.write_all(command.to_vec()).await.map_err(io_err)
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let chunk = self.0.read(buf.len() as u32).await.map_err(io_err)?;
        if chunk.len() > buf.len() {
            return Err(io::Error::other("serial read exceeds the requested length"));
        }
        buf[..chunk.len()].copy_from_slice(&chunk);
        Ok(chunk.len())
    }
}

#[async_trait(?Send)]
impl Transport for ForeignSerial {
    type Error = io::Error;

    async fn exchange(&mut self, command: &[u8], _encrypted: bool) -> Result<Vec<u8>, Self::Error> {
        CborStream::write_all(self, command).await?;
        self.read_cbor_message().await
    }
}

/// Adapts the foreign HTTP bridge to the Jade PIN server client.
pub(crate) struct ForeignHttp(Arc<dyn HttpBridge>);

impl ForeignHttp {
    pub(crate) fn new(bridge: Arc<dyn HttpBridge>) -> Self {
        Self(bridge)
    }
}

#[async_trait(?Send)]
impl HttpClient for ForeignHttp {
    type Error = TransportError;

    async fn request(&self, url: &str, request: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.0.request(url.to_string(), request.to_vec()).await
    }
}

const BLE_TAG_APDU: u8 = 0x05;
const BLE_TAG_MTU: u8 = 0x08;
/// Smallest usable BLE payload; also the fallback when MTU inference yields nothing sane.
const BLE_MIN_MTU: u16 = 20;
/// How many notifications to skip while waiting for the MTU answer before giving up.
const BLE_MTU_ATTEMPTS: usize = 8;

/// Ledger's BLE APDU transport.
///
/// Framing follows ledgerjs `@ledgerhq/devices`: each frame is
/// `[0x05][seq u16 BE]` plus, on `seq == 0` only, `[total apdu len u16 BE]`, followed by
/// payload; every frame is at most one MTU.
pub(crate) struct LedgerBleTransport {
    channel: Arc<dyn BleChannel>,
    /// Negotiated frame size, resolved lazily on the first exchange.
    mtu: Option<usize>,
}

impl LedgerBleTransport {
    pub(crate) fn new(channel: Arc<dyn BleChannel>) -> Self {
        Self { channel, mtu: None }
    }

    /// ledgerjs `inferMTU`: write `[0x08,0,0,0,0]`, the device answers with a 0x08-tagged
    /// notification whose sixth byte is the usable frame size.
    async fn infer_mtu(&self) -> Result<u16, io::Error> {
        self.channel
            .write(vec![BLE_TAG_MTU, 0, 0, 0, 0])
            .await
            .map_err(io_err)?;
        for _ in 0..BLE_MTU_ATTEMPTS {
            let frame = self.channel.read().await.map_err(io_err)?;
            if frame.first() == Some(&BLE_TAG_MTU) {
                return Ok(frame.get(5).copied().map_or(BLE_MIN_MTU, u16::from));
            }
        }
        Err(io::Error::other("no BLE MTU answer from the device"))
    }

    async fn frame_size(&mut self) -> Result<usize, io::Error> {
        if let Some(mtu) = self.mtu {
            return Ok(mtu);
        }
        let inferred = self.infer_mtu().await?;
        // Honour whichever bound is tighter: the device's answer or the platform's MTU.
        let mtu = inferred.min(self.channel.mtu()).max(BLE_MIN_MTU) as usize;
        self.mtu = Some(mtu);
        Ok(mtu)
    }
}

#[async_trait(?Send)]
impl Transport for LedgerBleTransport {
    // `io::Error` rather than `TransportError` so every transport in this crate carries the
    // disconnect marker the same way.
    type Error = io::Error;

    async fn exchange(&mut self, apdu: &[u8], _encrypted: bool) -> Result<Vec<u8>, Self::Error> {
        let frame_size = self.frame_size().await?;
        let total = u16::try_from(apdu.len())
            .map_err(|_| io::Error::other("APDU longer than the BLE protocol allows"))?;

        let mut seq: u16 = 0;
        let mut offset = 0usize;
        // `seq == 0` keeps the zero-length APDU case writing exactly one header frame.
        while offset < apdu.len() || seq == 0 {
            let header = if seq == 0 { 5 } else { 3 };
            let take = (frame_size - header).min(apdu.len() - offset);
            let mut frame = Vec::with_capacity(header + take);
            frame.push(BLE_TAG_APDU);
            frame.extend_from_slice(&seq.to_be_bytes());
            if seq == 0 {
                frame.extend_from_slice(&total.to_be_bytes());
            }
            frame.extend_from_slice(&apdu[offset..offset + take]);
            self.channel.write(frame).await.map_err(io_err)?;
            offset += take;
            seq += 1;
        }

        let mut expected = 0usize;
        let mut answer: Vec<u8> = Vec::new();
        let mut want: u16 = 0;
        loop {
            let frame = self.channel.read().await.map_err(io_err)?;
            // Ignore anything that is not APDU traffic (keep-alives, late MTU answers).
            if frame.len() < 3 || frame[0] != BLE_TAG_APDU {
                continue;
            }
            let index = u16::from_be_bytes([frame[1], frame[2]]);
            if index != want {
                return Err(io::Error::other(format!(
                    "BLE frame out of order: expected {want}, got {index}"
                )));
            }
            let mut payload = &frame[3..];
            if index == 0 {
                if payload.len() < 2 {
                    return Err(io::Error::other(
                        "BLE first frame is missing the length header",
                    ));
                }
                expected = u16::from_be_bytes([payload[0], payload[1]]) as usize;
                payload = &payload[2..];
            }
            let take = payload.len().min(expected - answer.len());
            answer.extend_from_slice(&payload[..take]);
            if answer.len() >= expected {
                return Ok(answer);
            }
            want += 1;
        }
    }
}
