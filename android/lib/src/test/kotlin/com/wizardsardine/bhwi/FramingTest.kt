package com.wizardsardine.bhwi

import java.util.ArrayDeque
import kotlin.test.assertFailsWith
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Records what a link writes and serves scripted reports back. */
class RecordingHidChannel(reads: List<ByteArray>) : HidChannel {
    val writes = mutableListOf<ByteArray>()
    private val reads = ArrayDeque(reads)

    override suspend fun send(report: ByteArray): UInt {
        writes += report.copyOf()
        return report.size.toUInt()
    }

    override suspend fun receive(maxLen: UInt): ByteArray =
        reads.pollFirst() ?: throw TransportException.Disconnected()
}

/** Records what a link writes and serves scripted notification payloads back. */
private class FakeBleChannel(private val mtu: Int, reads: List<ByteArray>) : BleChannel {
    val writes = mutableListOf<ByteArray>()
    private val reads = ArrayDeque(reads)

    override suspend fun write(data: ByteArray) {
        writes += data.copyOf()
    }

    override suspend fun read(): ByteArray = reads.pollFirst() ?: throw TransportException.Disconnected()

    override fun mtu(): UShort = mtu.toUShort()
}

private fun bytes(size: Int, seed: Int = 0) = ByteArray(size) { ((it + seed) % 251).toByte() }

class LedgerHidFramingTest {
    /**
     * `[0101][05][seq]` reports, 59 payload bytes each after the first two length bytes.
     *
     * [reuse] models the reference's single scratch buffer, which leaves the tail of the
     * previous chunk in a final short report; that is what the host writes, while a real
     * device sends fully formed reports.
     */
    private fun reports(apdu: ByteArray, reuse: Boolean = false): List<ByteArray> {
        val framed = byteArrayOf((apdu.size shr 8).toByte(), apdu.size.toByte()) + apdu
        val scratch = ByteArray(64)
        return framed.toList().chunked(59).mapIndexed { seq, chunk ->
            val report = if (reuse) scratch else ByteArray(64)
            report[0] = 0x01; report[1] = 0x01; report[2] = 0x05
            report[3] = (seq shr 8).toByte(); report[4] = seq.toByte()
            chunk.toByteArray().copyInto(report, 5)
            report.copyOf()
        }
    }

    @Test
    fun `a payload larger than one report is split across reports`() = runBlocking<Unit> {
        val apdu = bytes(200)
        val answer = bytes(150, seed = 7)
        val channel = RecordingHidChannel(reports(answer))

        assertEquals(answer.hex(), LedgerHidLink(channel).exchange(apdu, false).hex())

        // 202 framed bytes over 59-byte chunks: 59 + 59 + 59 + 25.
        assertEquals(4, channel.writes.size)
        assertEquals(reports(apdu, reuse = true).map { it.hex() }, channel.writes.map { it.hex() })
        assertTrue(channel.writes.all { it.size == 64 })
    }

    @Test
    fun `a short read is rejected as an incomplete header`() = runBlocking<Unit> {
        val channel = RecordingHidChannel(listOf(byteArrayOf(0x01, 0x01, 0x05, 0, 0)))
        assertFailsWith<TransportException.Io> { LedgerHidLink(channel).exchange(bytes(4), false) }
    }

    @Test
    fun `a report on another channel is rejected`() = runBlocking<Unit> {
        val bad = reports(bytes(4))[0].also { it[1] = 0x02 }
        val channel = RecordingHidChannel(listOf(bad))
        assertFailsWith<TransportException.Io> { LedgerHidLink(channel).exchange(bytes(4), false) }
    }
}

class ColdcardHidFramingTest {
    private fun reply(body: ByteArray): List<ByteArray> =
        body.toList().chunked(63).mapIndexed { i, chunk ->
            val last = i == (body.size - 1) / 63
            ByteArray(64).also {
                it[0] = (chunk.size or if (last) 0x80 else 0).toByte()
                chunk.toByteArray().copyInto(it, 1)
            }
        }

    @Test
    fun `the last chunk carries the length, the last-packet bit and the encryption bit`() = runBlocking<Unit> {
        val answer = bytes(100)
        val channel = RecordingHidChannel(reply(answer))
        val payload = bytes(70)

        assertEquals(answer.hex(), ColdcardHidLink(channel).exchange(payload, true).hex())

        assertEquals(2, channel.writes.size)
        assertEquals(63, channel.writes[0][0].toInt() and 0xff) // not last: bare length
        assertEquals(0x80 or 0x40 or 7, channel.writes[1][0].toInt() and 0xff)
    }

    @Test
    fun `an unencrypted link leaves the 0x40 bit clear`() = runBlocking<Unit> {
        val channel = RecordingHidChannel(reply(bytes(4)))
        ColdcardHidLink(channel).exchange(bytes(10), false)
        assertEquals(0x80 or 10, channel.writes[0][0].toInt() and 0xff)
    }

    /** Firmware bug: a `fram` reply is one packet but forgets the last-packet bit. */
    @Test
    fun `a fram reply without the last-packet bit still terminates`() = runBlocking<Unit> {
        val report = ByteArray(64).also {
            it[0] = 4
            "fram".toByteArray().copyInto(it, 1)
        }
        val channel = RecordingHidChannel(listOf(report))
        assertEquals("fram", ColdcardHidLink(channel).exchange(bytes(4), false).decodeToString())
    }
}

class BitBoxHidFramingTest {
    /** One U2F-framed HWW response, status byte included. */
    private fun frames(body: ByteArray): List<ByteArray> =
        U2f.encode(body).toList().chunked(64).map { it.toByteArray() }

    @Test
    fun `u2f encode and decode round trip across frame boundaries`() {
        for (size in listOf(0, 1, 56, 57, 58, 116, 117, 300)) {
            val msg = bytes(size)
            val encoded = U2f.encode(msg)
            assertEquals("frames for $size", U2f.frameCount(size) * 64, encoded.size)
            assertEquals("round trip of $size", msg.hex(), U2f.decode(encoded)!!.hex())
            // A frame short: the decoder has to ask for more, not guess.
            if (encoded.size > 64) {
                assertEquals(null, U2f.decode(encoded.copyOf(encoded.size - 64)))
            }
        }
    }

    @Test
    fun `the request is prefixed with the new-request byte and the ACK is stripped`() = runBlocking<Unit> {
        val channel = RecordingHidChannel(frames(byteArrayOf(0x00) + bytes(80)))
        assertEquals(bytes(80).hex(), BitBoxHidLink(channel).exchange(bytes(5), false).hex())

        val sent = U2f.decode(channel.writes.reduce { a, b -> a + b })!!
        assertEquals((byteArrayOf(0x00) + bytes(5)).hex(), sent.hex())
    }

    @Test
    fun `a NOTREADY status is retried with the retry request`() = runBlocking<Unit> {
        val channel = RecordingHidChannel(
            frames(byteArrayOf(0x01)) + frames(byteArrayOf(0x00) + bytes(4)),
        )
        assertEquals(bytes(4).hex(), BitBoxHidLink(channel).exchange(bytes(3), false).hex())

        assertEquals(2, channel.writes.size)
        assertEquals("01", U2f.decode(channel.writes[1])!!.hex())
    }

    @Test
    fun `a NACK status is an error`() = runBlocking<Unit> {
        val channel = RecordingHidChannel(frames(byteArrayOf(0x03)))
        assertFailsWith<TransportException.Io> { BitBoxHidLink(channel).exchange(bytes(3), false) }
    }
}

class LedgerBleFramingTest {
    /** `[05][seq]` frames, plus the total length on the first one. */
    private fun frames(apdu: ByteArray, size: Int): List<ByteArray> {
        val out = mutableListOf<ByteArray>()
        var offset = 0
        var seq = 0
        while (offset < apdu.size || seq == 0) {
            val header = if (seq == 0) 5 else 3
            val take = minOf(size - header, apdu.size - offset)
            val frame = ByteArray(header + take)
            frame[0] = 0x05
            frame[1] = (seq shr 8).toByte()
            frame[2] = seq.toByte()
            if (seq == 0) {
                frame[3] = (apdu.size shr 8).toByte()
                frame[4] = apdu.size.toByte()
            }
            apdu.copyInto(frame, header, offset, offset + take)
            out += frame
            offset += take
            seq++
        }
        return out
    }

    private fun mtuAnswer(size: Int) = byteArrayOf(0x08, 0, 0, 0, 0, size.toByte())

    @Test
    fun `the mtu is inferred once, then payloads are fragmented and reassembled`() = runBlocking<Unit> {
        val apdu = bytes(100)
        val answer = bytes(80, seed = 3)
        val channel = FakeBleChannel(
            mtu = 512,
            reads = listOf(mtuAnswer(30)) + frames(answer, 30) + frames(answer, 30),
        )
        val link = LedgerBleLink(channel)

        assertEquals(answer.hex(), link.exchange(apdu, false).hex())
        // The MTU probe plus 100 bytes over 25 + 27 + 27 + 21.
        assertEquals(
            listOf(byteArrayOf(0x08, 0, 0, 0, 0)).map { it.hex() } + frames(apdu, 30).map { it.hex() },
            channel.writes.map { it.hex() },
        )
        assertTrue(channel.writes.drop(1).all { it.size <= 30 })

        // Second exchange: no second probe.
        channel.writes.clear()
        assertEquals(answer.hex(), link.exchange(apdu, false).hex())
        assertEquals(frames(apdu, 30).map { it.hex() }, channel.writes.map { it.hex() })
    }

    @Test
    fun `the platform mtu wins when it is the tighter bound, with a floor of 20`() = runBlocking<Unit> {
        val apdu = bytes(40)
        val channel = FakeBleChannel(mtu = 5, reads = listOf(mtuAnswer(255)) + frames(bytes(2), 20))
        LedgerBleLink(channel).exchange(apdu, false)
        assertEquals(frames(apdu, 20).map { it.hex() }, channel.writes.drop(1).map { it.hex() })
    }

    @Test
    fun `non-apdu notifications are ignored`() = runBlocking<Unit> {
        val answer = bytes(10)
        val channel = FakeBleChannel(
            mtu = 64,
            reads = listOf(mtuAnswer(30), byteArrayOf(0x07, 0, 0)) + frames(answer, 30),
        )
        assertEquals(answer.hex(), LedgerBleLink(channel).exchange(bytes(4), false).hex())
    }

    @Test
    fun `an out-of-order frame is rejected`() = runBlocking<Unit> {
        val bad = frames(bytes(60), 30).reversed()
        val channel = FakeBleChannel(mtu = 64, reads = listOf(mtuAnswer(30)) + bad)
        assertFailsWith<TransportException.Io> { LedgerBleLink(channel).exchange(bytes(4), false) }
    }

    @Test
    fun `a device that never answers the mtu probe fails`() = runBlocking<Unit> {
        val channel = FakeBleChannel(mtu = 64, reads = List(8) { byteArrayOf(0x07, 0, 0) })
        assertFailsWith<TransportException.Io> { LedgerBleLink(channel).exchange(bytes(4), false) }
    }
}
