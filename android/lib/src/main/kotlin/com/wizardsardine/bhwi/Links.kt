package com.wizardsardine.bhwi

import java.io.ByteArrayOutputStream

/**
 * One logical request/response exchange with a device, whatever the wire framing
 * underneath. This is the only thing the driving loop ([Hwi.runCommand]) sees.
 *
 * [encrypted] is the device-link encryption flag `Transmit` carries; only the framings
 * that actually signal it on the wire (Coldcard) look at it.
 */
interface Link {
    suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray
}

private const val HID_REPORT_LEN = 64

private fun be16(buf: ByteArray, at: Int): Int =
    ((buf[at].toInt() and 0xff) shl 8) or (buf[at + 1].toInt() and 0xff)

/**
 * Ledger APDUs over 64-byte HID reports.
 *
 * Port of `bhwi-async`'s `transport/ledger/hid.rs`: channel `0x0101`, tag `0x05`, a
 * big-endian u16 sequence index in every report and a big-endian u16 total length in the
 * first one. The report-level fixtures in `fixtures/ledger_*.json` were produced by that
 * transport, so this has to match it byte for byte.
 */
class LedgerHidLink(private val channel: HidChannel) : Link {
    override suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray {
        val framed = ByteArray(payload.size + 2)
        framed[0] = ((payload.size shr 8) and 0xff).toByte()
        framed[1] = (payload.size and 0xff).toByte()
        payload.copyInto(framed, 2)

        // One reused report buffer, exactly like the reference: a final short chunk leaves
        // the tail of the previous one in place instead of zeroing it, and the recorded
        // fixtures contain those stale bytes.
        val report = ByteArray(HID_REPORT_LEN)
        report[0] = ((LEDGER_CHANNEL shr 8) and 0xff).toByte()
        report[1] = (LEDGER_CHANNEL and 0xff).toByte()
        report[2] = LEDGER_TAG.toByte()

        var seq = 0
        var offset = 0
        // `framed` is never empty (it always carries the 2-byte length), so this writes at
        // least one report, exactly like the reference's `chunks(59)`.
        while (offset < framed.size) {
            val take = minOf(HID_REPORT_LEN - 5, framed.size - offset)
            report[3] = ((seq shr 8) and 0xff).toByte()
            report[4] = (seq and 0xff).toByte()
            framed.copyInto(report, 5, offset, offset + take)
            if (channel.send(report).toInt() < report.size) {
                throw TransportException.Io("ledger: could not send the whole HID report")
            }
            offset += take
            seq++
        }

        // One reused buffer, like the reference: a short read leaves the tail of the
        // previous report in place instead of zeroing it, and the header checks below are
        // what catch a genuinely malformed report.
        val buffer = ByteArray(HID_REPORT_LEN)
        val answer = ByteArrayOutputStream()
        var want = 0
        var expected = 0
        while (true) {
            val read = channel.receive(HID_REPORT_LEN.toUInt())
            if (read.size > HID_REPORT_LEN) {
                throw TransportException.Io("ledger: HID report exceeds the requested length")
            }
            if ((want == 0 && read.size < 7) || read.size < 5) {
                throw TransportException.Io("ledger: incomplete HID header")
            }
            read.copyInto(buffer)

            if (be16(buffer, 0) != LEDGER_CHANNEL) throw TransportException.Io("ledger: invalid channel")
            if ((buffer[2].toInt() and 0xff) != LEDGER_TAG) throw TransportException.Io("ledger: invalid tag")
            if (be16(buffer, 3) != want) throw TransportException.Io("ledger: invalid sequence idx")

            var pos = 5
            if (want == 0) {
                expected = be16(buffer, 5)
                pos = 7
            }
            answer.write(buffer, pos, minOf(HID_REPORT_LEN - pos, expected - answer.size()))
            if (answer.size() >= expected) return answer.toByteArray()
            want++
        }
    }

    private companion object {
        const val LEDGER_CHANNEL = 0x0101
        const val LEDGER_TAG = 0x05
    }
}

/**
 * Coldcard over 64-byte HID reports.
 *
 * Port of `bhwi-async`'s `transport/coldcard/hid.rs`: byte 0 is the chunk length with
 * `0x80` on the last chunk and `0x40` when the link is encrypted — the one framing that
 * puts `Transmit.encrypted` on the wire.
 */
class ColdcardHidLink(private val channel: HidChannel) : Link {
    override suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray {
        // Reused across chunks for the same reason as in [LedgerHidLink].
        val report = ByteArray(HID_REPORT_LEN)
        val chunks = (payload.size + CHUNK - 1) / CHUNK
        for (i in 0 until chunks) {
            val offset = i * CHUNK
            val take = minOf(CHUNK, payload.size - offset)
            val last = i == chunks - 1
            report[0] = (take or if (last) 0x80 or (if (encrypted) 0x40 else 0x00) else 0x00).toByte()
            payload.copyInto(report, 1, offset, offset + take)
            if (channel.send(report).toInt() < report.size) {
                throw TransportException.Io("coldcard: could not send the whole HID report")
            }
        }

        val data = ByteArrayOutputStream()
        var first = true
        while (true) {
            val report = channel.receive(HID_REPORT_LEN.toUInt())
            if (report.size != HID_REPORT_LEN) {
                throw TransportException.Io("coldcard: could not read the whole HID report")
            }
            val flag = report[0].toInt() and 0xff
            // Firmware bug mitigation: `fram` responses are one packet but forget the 0x80.
            val fram = first && report.copyOfRange(1, 5).contentEquals(FRAM)
            data.write(report, 1, flag and 0x3f)
            first = false
            if (flag and 0x80 != 0 || fram) return data.toByteArray()
        }
    }

    private companion object {
        const val CHUNK = 63
        val FRAM = "fram".toByteArray(Charsets.US_ASCII)
    }
}

/**
 * U2F-HID framing, 64-byte frames.
 *
 * Init frame: big-endian u32 CID, command byte, big-endian u16 message length, 57 data
 * bytes. Continuation frames: CID, sequence byte, 59 data bytes. Port of `bhwi`'s
 * `bitbox/u2f.rs` (itself from bitbox-api-rs), cross-checked against the maintainer's
 * `u2f.zig`.
 */
internal object U2f {
    const val FRAME = 64
    const val CID = 0xff00ff00.toInt()
    const val FIRMWARE_CMD = 0xc1

    private const val INIT_DATA = FRAME - 7
    private const val CONT_DATA = FRAME - 5
    private const val MAX_MSG = INIT_DATA + 127 * CONT_DATA

    fun frameCount(len: Int): Int =
        if (len <= INIT_DATA) 1 else 1 + (len - INIT_DATA + CONT_DATA - 1) / CONT_DATA

    fun encode(msg: ByteArray): ByteArray {
        if (msg.size > MAX_MSG) throw TransportException.Io("bitbox: message needs more U2F frames than allowed")
        val out = ByteArray(frameCount(msg.size) * FRAME)
        putBe32(out, 0, CID)
        out[4] = FIRMWARE_CMD.toByte()
        out[5] = ((msg.size shr 8) and 0xff).toByte()
        out[6] = (msg.size and 0xff).toByte()

        val first = minOf(INIT_DATA, msg.size)
        msg.copyInto(out, 7, 0, first)

        var offset = first
        var frame = 1
        var seq = 0
        while (offset < msg.size) {
            val base = frame * FRAME
            putBe32(out, base, CID)
            out[base + 4] = seq.toByte()
            val take = minOf(CONT_DATA, msg.size - offset)
            msg.copyInto(out, base + 5, offset, offset + take)
            offset += take
            seq++
            frame++
        }
        return out
    }

    /** The reassembled message, or `null` while [buf] does not hold all of its frames yet. */
    fun decode(buf: ByteArray): ByteArray? {
        if (buf.size < 7) return null
        if (readBe32(buf, 0) != CID) throw TransportException.Io("bitbox: wrong U2F channel id")
        if ((buf[4].toInt() and 0xff) != FIRMWARE_CMD) throw TransportException.Io("bitbox: wrong U2F command")
        val len = be16(buf, 5)
        if (buf.size < frameCount(len) * FRAME) return null

        val out = ByteArray(len)
        var take = minOf(INIT_DATA, len)
        buf.copyInto(out, 0, 7, 7 + take)
        var written = take
        var from = 7 + take
        while (written < len) {
            take = minOf(CONT_DATA, len - written)
            buf.copyInto(out, written, from + 5, from + 5 + take)
            written += take
            from += 5 + take
        }
        return out
    }

    private fun putBe32(buf: ByteArray, at: Int, value: Int) {
        for (i in 0 until 4) buf[at + i] = ((value shr (8 * (3 - i))) and 0xff).toByte()
    }

    private fun readBe32(buf: ByteArray, at: Int): Int {
        var value = 0
        for (i in 0 until 4) value = (value shl 8) or (buf[at + i].toInt() and 0xff)
        return value
    }
}

/**
 * BitBox02 over HID: U2F frames carrying the HWW request/response layer.
 *
 * A request is `0x00 ++ payload`; the reply's first byte is a status. NOTREADY is polled
 * with a single-byte retry request. Port of `bhwi-async`'s `transport/bitbox/hid.rs`,
 * cross-checked against `hww.zig`.
 *
 * `encrypted` is deliberately unused: both reference transports ignore it, because the
 * BitBox noise encryption is inside the payload the interpreter already produced.
 */
class BitBoxHidLink(private val channel: HidChannel) : Link {
    override suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray {
        val request = ByteArray(1 + payload.size)
        request[0] = REQ_NEW
        payload.copyInto(request, 1)

        var response = query(request)
        while (true) {
            when (response.firstOrNull()) {
                RSP_ACK -> return response.copyOfRange(1, response.size)
                RSP_NOTREADY -> response = query(byteArrayOf(REQ_RETRY))
                RSP_BUSY -> throw TransportException.Io("bitbox: device busy")
                RSP_NACK -> throw TransportException.Io("bitbox: device NACK")
                else -> throw TransportException.Io("bitbox: unexpected HWW response")
            }
        }
    }

    /** Send one U2F-framed message and reassemble the framed reply. */
    private suspend fun query(msg: ByteArray): ByteArray {
        val encoded = U2f.encode(msg)
        var offset = 0
        while (offset < encoded.size) {
            val frame = encoded.copyOfRange(offset, offset + U2f.FRAME)
            if (channel.send(frame).toInt() < frame.size) {
                throw TransportException.Io("bitbox: could not send the whole HID report")
            }
            offset += U2f.FRAME
        }

        var buffer = ByteArray(0)
        while (true) {
            val report = channel.receive(U2f.FRAME.toUInt())
            if (report.size != U2f.FRAME) {
                throw TransportException.Io("bitbox: could not read the whole HID report")
            }
            buffer += report
            U2f.decode(buffer)?.let { return it }
        }
    }

    private companion object {
        const val REQ_NEW: Byte = 0x00
        const val REQ_RETRY: Byte = 0x01
        const val RSP_ACK: Byte = 0x00
        const val RSP_NOTREADY: Byte = 0x01
        const val RSP_BUSY: Byte = 0x02
        const val RSP_NACK: Byte = 0x03
    }
}

/**
 * Jade over a byte stream (USB serial or BLE): write the payload, then read until one
 * complete CBOR value has arrived.
 *
 * Mirrors `bhwi-async`'s `CborStream::read_cbor_message`, including its "everything read
 * so far" return value and its end-of-stream message.
 */
class JadeSerialLink(private val stream: SerialStream) : Link {
    override suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray {
        stream.writeAll(payload)

        val buffer = ByteArrayOutputStream()
        while (true) {
            val chunk = stream.read(CHUNK.toUInt())
            if (chunk.size > CHUNK) throw TransportException.Io("jade: serial read exceeds the requested length")
            // An empty read is EOF, which is what an unplugged Jade looks like.
            if (chunk.isEmpty()) throw TransportException.Io("stream ended before complete CBOR message")
            buffer.write(chunk)
            val message = buffer.toByteArray()
            if (Cbor.isComplete(message)) return message
        }
    }

    private companion object {
        /** Same read size the reference uses, so a chunked device behaves identically. */
        const val CHUNK = 1024
    }
}

/**
 * Ledger APDUs over BLE.
 *
 * Framing follows ledgerjs `@ledgerhq/devices`: each frame is `[0x05][seq u16 BE]` plus,
 * on `seq == 0` only, `[total apdu len u16 BE]`, followed by payload; every frame is at
 * most one MTU. The frame size is inferred once on the first exchange.
 *
 * Not safe for concurrent use; [HwiSession] serialises commands.
 */
class LedgerBleLink(private val channel: BleChannel) : Link {
    /** Negotiated frame size, resolved lazily on the first exchange. */
    private var frameSize: Int? = null

    override suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray {
        val size = frameSize()
        if (payload.size > 0xffff) throw TransportException.Io("ledger: APDU longer than the BLE protocol allows")

        var seq = 0
        var offset = 0
        // `seq == 0` keeps the zero-length APDU case writing exactly one header frame.
        while (offset < payload.size || seq == 0) {
            val header = if (seq == 0) 5 else 3
            val take = minOf(size - header, payload.size - offset)
            val frame = ByteArray(header + take)
            frame[0] = TAG_APDU.toByte()
            frame[1] = ((seq shr 8) and 0xff).toByte()
            frame[2] = (seq and 0xff).toByte()
            if (seq == 0) {
                frame[3] = ((payload.size shr 8) and 0xff).toByte()
                frame[4] = (payload.size and 0xff).toByte()
            }
            payload.copyInto(frame, header, offset, offset + take)
            channel.write(frame)
            offset += take
            seq++
        }

        val answer = ByteArrayOutputStream()
        var expected = 0
        var want = 0
        while (true) {
            val frame = channel.read()
            // Ignore anything that is not APDU traffic (keep-alives, late MTU answers).
            if (frame.size < 3 || (frame[0].toInt() and 0xff) != TAG_APDU) continue
            val index = be16(frame, 1)
            if (index != want) {
                throw TransportException.Io("ledger: BLE frame out of order: expected $want, got $index")
            }
            var from = 3
            if (index == 0) {
                if (frame.size < 5) throw TransportException.Io("ledger: BLE first frame is missing the length header")
                expected = be16(frame, 3)
                from = 5
            }
            answer.write(frame, from, minOf(frame.size - from, expected - answer.size()))
            if (answer.size() >= expected) return answer.toByteArray()
            want++
        }
    }

    private suspend fun frameSize(): Int {
        frameSize?.let { return it }
        // Honour whichever bound is tighter: the device's answer or the platform's MTU.
        val size = minOf(inferMtu(), channel.mtu().toInt()).coerceAtLeast(MIN_MTU)
        frameSize = size
        return size
    }

    /**
     * ledgerjs `inferMTU`: write `[0x08,0,0,0,0]`; the device answers with a 0x08-tagged
     * notification whose sixth byte is the usable frame size.
     */
    private suspend fun inferMtu(): Int {
        channel.write(byteArrayOf(TAG_MTU.toByte(), 0, 0, 0, 0))
        repeat(MTU_ATTEMPTS) {
            val frame = channel.read()
            if (frame.isNotEmpty() && (frame[0].toInt() and 0xff) == TAG_MTU) {
                return if (frame.size > 5) frame[5].toInt() and 0xff else MIN_MTU
            }
        }
        throw TransportException.Io("ledger: no BLE MTU answer from the device")
    }

    private companion object {
        const val TAG_APDU = 0x05
        const val TAG_MTU = 0x08

        /** Smallest usable BLE payload; also the fallback when inference yields nothing sane. */
        const val MIN_MTU = 20

        /** How many notifications to skip while waiting for the MTU answer before giving up. */
        const val MTU_ATTEMPTS = 8
    }
}
