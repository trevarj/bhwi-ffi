package com.wizardsardine.bhwi

import java.util.ArrayDeque
import kotlin.test.assertFailsWith
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.bhwi_ffi.AddressFormat
import uniffi.bhwi_ffi.HwiException
import uniffi.bhwi_ffi.HwiResponse
import uniffi.bhwi_ffi.MultisigAddressFormat
import uniffi.bhwi_ffi.Network
import uniffi.bhwi_ffi.SpecterFrameDecoder
import uniffi.bhwi_ffi.WalletPolicy
import uniffi.bhwi_ffi.WalletRegistration
import uniffi.bhwi_ffi.deriveAddresses

/** Real JNI/core dispatch. All replies in this class are source-labeled synthetic frames. */
class SpecterTest {
    private val descriptor = "wpkh([f5acc2fd/84'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*)"
    private val policy = WalletPolicy("test_specter", descriptor, null)
    private val request = "\r\n\r\nfingerprint\r\n".encodeToByteArray()
    private fun frame(payload: String) = "ACK\r\n$payload\r\n".encodeToByteArray()

    private class Stream(vararg chunks: ByteArray) : SerialStream {
        val replies = ArrayDeque(chunks.toList())
        val writes = mutableListOf<ByteArray>()
        var reads = 0
        var closed = false
        override suspend fun writeAll(data: ByteArray) { writes.add(data.copyOf()) }
        override suspend fun read(maxLen: UInt): ByteArray {
            reads++
            return if (replies.isEmpty()) ByteArray(0) else replies.removeFirst()
        }
        fun close() { closed = true }
    }

    @Test
    fun `maximum payload survives JNI and the next byte fails terminally`() = runBlocking<Unit> {
        val max = 4 * 1024 * 1024
        val reply = "ACK\r\n".encodeToByteArray() + ByteArray(max) { 'x'.code.toByte() } + "\r\n".encodeToByteArray()
        val stream = Stream(*(reply.indices step 16 * 1024).map { reply.copyOfRange(it, minOf(it + 16 * 1024, reply.size)) }.toTypedArray())
        assertArrayEquals(reply, SpecterSerialLink(stream).exchange(request, false))
        for (oversized in listOf(reply.copyOf(reply.size + 1), "ACK\r\n".encodeToByteArray() + ByteArray(max + 1) { 'x'.code.toByte() } + "\r\n".encodeToByteArray())) {
            SpecterFrameDecoder().use { decoder ->
                assertFailsWith<HwiException.Device> { decoder.push(oversized) }
                assertFailsWith<HwiException.BadState> { decoder.push(frame("success")) }
            }
        }
    }

    @Test
    fun `only complete frames reach the interpreter and successful replies permit reuse`() = runBlocking<Unit> {
        val caller = Thread.currentThread()
        val expected = deriveAddresses(descriptor, Network.TESTNET, true, 7u, 1u).single().address
        val replies = ArrayDeque(listOf("A", "CK\r", "\nf5acc2fd\r", "\n", "ACK\r\nsuccess\r\n", "ACK\r\n$expected\r\n"))
        val writes = mutableListOf<String>()
        val stream = object : SerialStream {
            override suspend fun writeAll(data: ByteArray) {
                assertNotSame(caller, Thread.currentThread())
                writes.add(data.decodeToString())
            }
            override suspend fun read(maxLen: UInt): ByteArray {
                assertNotSame(caller, Thread.currentThread())
                assertEquals(16_384u, maxLen)
                return replies.removeFirst().encodeToByteArray()
            }
        }
        val session = HwiSession.specterUsb(stream, Network.TESTNET)
        try {
            assertEquals("f5acc2fd", (session.unlock(Network.TESTNET) as HwiResponse.Fingerprint).hex)
            val registration = session.registerWallet(policy.name, descriptor) as WalletRegistration.Complete
            assertEquals(null, registration.hmac)
            assertEquals(expected, session.displayDescriptorAddress(7u, true, true, policy))
        } finally {
            session.disconnect()
        }
        assertEquals(listOf(request.decodeToString(), "\r\n\r\naddwallet test_specter&$descriptor\r\n", "\r\n\r\nshowaddr wpkh f5acc2fd/84'/1'/0'/1/7\r\n"), writes)
        assertTrue(replies.isEmpty())
    }

    @Test
    fun `unsupported version raw multisig taproot hidden displays names and HMAC fail before IO`() = runBlocking<Unit> {
        val stream = Stream()
        val session = HwiSession.specterUsb(stream, Network.TESTNET)
        try {
            assertFailsWith<HwiException.InvalidInput> { session.getInfo() }
            assertFailsWith<HwiException.InvalidInput> { session.getExtendedPubkey("m/84'/1'/0'", true) }
            assertFailsWith<HwiException.Device> { session.displayAddress("m/84'/1'/0'/0/0", false, AddressFormat.NATIVE_SEGWIT) }
            assertFailsWith<HwiException.Device> { session.displayAddress("m/86'/1'/0'/0/0", true, AddressFormat.TAPROOT) }
            assertFailsWith<HwiException.Device> { session.displayDescriptorAddress(0u, false, false, policy) }
            assertFailsWith<HwiException.Device> { session.displayDescriptorAddress(0u, false, true, WalletPolicy(policy.name, descriptor.replace("wpkh(", "tr("), null)) }
            assertFailsWith<HwiException.Device> {
                session.displayMultisigAddress(1u, true, MultisigAddressFormat.WIT, listOf("[f5acc2fd/84'/1'/0'/0/0]0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
            }
            for (name in listOf("", "bad\rname", "bad\nname", "bad&name", "bad\u0000name")) {
                assertFailsWith<HwiException.InvalidInput> { session.registerWallet(name, descriptor) }
            }
            assertFailsWith<HwiException.InvalidInput> { session.displayDescriptorAddress(0u, false, true, WalletPolicy(policy.name, descriptor, ByteArray(32))) }
        } finally {
            session.disconnect()
        }
        assertTrue(stream.writes.isEmpty())
        assertEquals(0, stream.reads)
        assertFalse(stream.closed)
        stream.close() // Only the caller disposes the physical stream.
        assertTrue(stream.closed)
    }

    @Test
    fun `registration requires exact success and preserves typed user refusal`() = runBlocking<Unit> {
        for ((reply, refusal) in listOf("true" to false, "success " to false, "error: User cancelled" to true)) {
            val stream = Stream(frame(reply), frame("f5acc2fd"))
            val session = HwiSession.specterUsb(stream, Network.TESTNET)
            try {
                if (refusal) assertFailsWith<HwiException.UserRefused> { session.registerWallet(policy.name, descriptor) }
                else assertFailsWith<HwiException.InvalidInput> { session.registerWallet(policy.name, descriptor) }
                // Framing completed: a protocol-level refusal is not stale serial state.
                assertEquals("f5acc2fd", session.getMasterFingerprint())
            } finally { session.disconnect() }
        }
    }

    @Test
    fun `EOF oversized reads and parser failures retire without consuming delayed replies`() = runBlocking<Unit> {
        for (reply in listOf(ByteArray(0), ByteArray(16_385), "NAK\r\nsuccess\r\n".encodeToByteArray(), frame("success") + byteArrayOf(0))) {
            val stream = Stream(reply, frame("f5acc2fd"))
            val link = SpecterSerialLink(stream)
            assertFailsWith<Exception> { link.exchange(request, false) }
            assertFailsWith<TransportException.Disconnected> { link.exchange(request, false) }
            assertEquals(1, stream.writes.size)
            assertEquals(1, stream.reads)
            assertEquals(1, stream.replies.size)
            assertFalse(stream.closed)
        }
    }

    @Test
    fun `write and read failures cancellation and timeout permanently retire the link`() = runBlocking<Unit> {
        for (duringWrite in listOf(true, false)) {
            for (failure in listOf("io", "cancel", "timeout")) {
                val entered = CompletableDeferred<Unit>()
                var writes = 0
                var reads = 0
                suspend fun fail() {
                    entered.complete(Unit)
                    if (failure == "io") throw TransportException.Io("test-owned failure")
                    awaitCancellation()
                }
                val stream = object : SerialStream {
                    override suspend fun writeAll(data: ByteArray) { writes++; if (duringWrite) fail() }
                    override suspend fun read(maxLen: UInt): ByteArray { reads++; fail(); return frame("f5acc2fd") }
                }
                val link = SpecterSerialLink(stream, if (failure == "timeout") 30 else 300_000)
                when (failure) {
                    "io" -> assertFailsWith<TransportException.Io> { link.exchange(request, false) }
                    "timeout" -> withTimeout(2000) { assertFailsWith<TransportException.Timeout> { link.exchange(request, false) } }
                    else -> {
                        val call = async { link.exchange(request, false) }
                        withTimeout(2000) { entered.await() }
                        call.cancelAndJoin()
                        assertFailsWith<CancellationException> { call.await() }
                    }
                }
                assertFailsWith<TransportException.Disconnected> { link.exchange(request, false) }
                assertEquals(1, writes)
                assertEquals(if (duringWrite) 0 else 1, reads)
            }
        }
    }

    @Test
    fun `deadline includes write time and cannot restart after ACK or partial payload`() = runBlocking<Unit> {
        var writes = 0
        var reads = 0
        val stream = object : SerialStream {
            override suspend fun writeAll(data: ByteArray) { writes++; delay(100) }
            override suspend fun read(maxLen: UInt): ByteArray {
                reads++
                if (reads == 1) return "ACK\r\n".encodeToByteArray()
                if (reads == 2) return "f5acc".encodeToByteArray()
                awaitCancellation()
            }
        }
        val link = SpecterSerialLink(stream, 180)
        withTimeout(2000) { assertFailsWith<TransportException.Timeout> { link.exchange(request, false) } }
        val retiredReads = reads
        assertFailsWith<TransportException.Disconnected> { link.exchange(request, false) }
        assertEquals(1, writes)
        assertEquals(retiredReads, reads)
    }

    @Test
    fun `concurrent exchange is rejected before any second write`() = runBlocking<Unit> {
        val entered = CompletableDeferred<Unit>()
        var writes = 0
        val stream = object : SerialStream {
            override suspend fun writeAll(data: ByteArray) { writes++; entered.complete(Unit); awaitCancellation() }
            override suspend fun read(maxLen: UInt): ByteArray = error("unexpected read")
        }
        val link = SpecterSerialLink(stream)
        val first = async { link.exchange(request, false) }
        withTimeout(2000) { entered.await() }
        assertFailsWith<TransportException.Disconnected> { link.exchange(request, false) }
        first.cancelAndJoin()
        assertEquals(1, writes)
        assertFailsWith<TransportException.Disconnected> { link.exchange(request, false) }
    }

    @Test
    fun `cancelled facade cannot reuse a delayed reply and leaves physical closure to its owner`() = runBlocking<Unit> {
        val entered = CompletableDeferred<Unit>()
        var writes = 0
        var reads = 0
        var closed = false
        val stream = object : SerialStream, AutoCloseable {
            override suspend fun writeAll(data: ByteArray) { writes++ }
            override suspend fun read(maxLen: UInt): ByteArray {
                reads++
                if (reads == 1) { entered.complete(Unit); awaitCancellation() }
                return frame("f5acc2fd") // Delayed stale response must never be consumed.
            }
            override fun close() { closed = true }
        }
        val session = HwiSession.specterUsb(stream, Network.TESTNET)
        val call = async { session.getMasterFingerprint() }
        withTimeout(2000) { entered.await() }
        call.cancelAndJoin()
        assertFailsWith<TransportException.Disconnected> { session.getMasterFingerprint() }
        session.disconnect()
        session.disconnect()
        assertFailsWith<HwiException.BadState> { session.getMasterFingerprint() }
        assertEquals(1, writes)
        assertEquals(1, reads)
        assertFalse(closed)
        stream.close() // Test owner, not the facade, closes the transport.
        assertTrue(closed)
    }
}
