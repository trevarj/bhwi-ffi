package com.wizardsardine.bhwi

/**
 * Failure reported by a host transport.
 *
 * The FFI has no transport error variant any more (the crate does no I/O), so this is a
 * plain Kotlin hierarchy owned by this layer. Callers see it alongside
 * `uniffi.bhwi_ffi.HwiException`, never wrapped into it.
 */
sealed class TransportException(message: String) : kotlin.Exception(message) {
    /** Anything the link could not do. [msg] is safe to show; it never carries payload bytes. */
    class Io(val msg: String) : TransportException(msg)

    /** The device went away. Distinct from [Io] because the UI reacts to it differently. */
    class Disconnected : TransportException("device disconnected")

    /** The host aborted the operation. */
    class Cancelled : TransportException("operation cancelled")
}

/** Raw HID report channel (Ledger / Coldcard / BitBox02 over USB). */
interface HidChannel {
    /**
     * Write one HID report; returns the number of bytes written.
     *
     * [report] is a scratch buffer the caller reuses between reports, so an implementation
     * must consume it before returning and must not keep a reference to it.
     */
    suspend fun send(report: ByteArray): UInt

    /** Read one HID report, at most [maxLen] bytes. Returning more is an error. */
    suspend fun receive(maxLen: UInt): ByteArray
}

/** Byte stream for Jade, bridged from either USB serial or BLE. */
interface SerialStream {
    suspend fun writeAll(data: ByteArray)

    /**
     * Read up to [maxLen] bytes. Returning fewer is fine; returning more is an error.
     *
     * An empty (0-byte) result means end of stream, i.e. the device is gone: it aborts the
     * in-flight command with "stream ended before complete CBOR message". "No data yet"
     * must **not** return empty — suspend until at least one byte is available, or throw
     * [TransportException.Disconnected] if the link dropped.
     */
    suspend fun read(maxLen: UInt): ByteArray
}

/** GATT characteristic pair for a Ledger connected over BLE. */
interface BleChannel {
    /** Write one BLE frame (already sized to [mtu]). */
    suspend fun write(data: ByteArray)

    /** Await one notification payload. */
    suspend fun read(): ByteArray

    /** Usable payload bytes per write, as negotiated by the platform BLE stack. */
    fun mtu(): UShort
}

/** HTTP bridge used only for the Jade PIN server exchange (`Content-Type: application/json`). */
interface HttpBridge {
    suspend fun request(url: String, body: ByteArray): ByteArray
}
