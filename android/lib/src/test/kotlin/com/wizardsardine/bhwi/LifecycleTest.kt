package com.wizardsardine.bhwi

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertFailsWith
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import uniffi.bhwi_ffi.ColdcardEncryption
import uniffi.bhwi_ffi.HwiCommand
import uniffi.bhwi_ffi.HwiException
import uniffi.bhwi_ffi.Interp
import uniffi.bhwi_ffi.Network
import uniffi.bhwi_ffi.NoiseConfig
import uniffi.bhwi_ffi.NoiseHandle

class LifecycleTest {
    private fun fingerprintFixture() = Fixture.load("ledger_get_master_fingerprint.json")

    @Test
    fun `disconnect is idempotent and closes the session`() = runBlocking<Unit> {
        val session = HwiSession.ledgerUsb(ReplayHidChannel(fingerprintFixture()))
        session.disconnect()
        session.disconnect()
        assertFailsWith<HwiException.BadState> { session.getMasterFingerprint() }
    }

    @Test
    fun `repeated connect and disconnect does not deadlock`() = runBlocking<Unit> {
        val fixture = fingerprintFixture()
        repeat(10) {
            val channel = ReplayHidChannel(fixture)
            val session = HwiSession.ledgerUsb(channel)
            assertEquals(fixture.expected, session.getMasterFingerprint())
            session.disconnect()
            assertFailsWith<HwiException.BadState> { session.getMasterFingerprint() }
            channel.check()
        }
    }

    @Test
    fun `sequential commands on one session each get a fresh interpreter`() = runBlocking<Unit> {
        val one = fingerprintFixture()
        val channel = ReplayHidChannel(Fixture(one.writes + one.writes, one.reads + one.reads, one.expected))
        val session = HwiSession.ledgerUsb(channel)
        try {
            assertEquals(one.expected, session.getMasterFingerprint())
            assertEquals(one.expected, session.getMasterFingerprint())
        } finally {
            session.disconnect()
        }
        channel.check()
    }

    @Test
    fun `two concurrent calls are serialised by the mutex`() = runBlocking<Unit> {
        val one = fingerprintFixture()
        val twice = Fixture(one.writes + one.writes, one.reads + one.reads, one.expected)
        // Identical transcripts cannot distinguish an interleaving on their own, so the
        // channel counts how many coroutines are inside it at once.
        val channel = ConcurrencyProbeChannel(twice)
        val session = HwiSession.ledgerUsb(channel)
        try {
            val first = async(Dispatchers.Default) { session.getMasterFingerprint() }
            val second = async(Dispatchers.Default) { session.getMasterFingerprint() }
            assertEquals(one.expected, first.await())
            assertEquals(one.expected, second.await())
        } finally {
            session.disconnect()
        }
        channel.check()
        assertFalse("two commands overlapped on the channel", channel.overlapped.get())
    }

    /** The lease is the runtime replacement for the borrow the FFI cannot express. */
    @Test
    fun `a second interpreter on a leased noise handle is a BadState`() {
        NoiseHandle(null).use { noise ->
            val first = Interp.newBitbox(noise, Network.TESTNET)
            try {
                assertFailsWith<HwiException.BadState> { Interp.newBitbox(noise, Network.TESTNET) }
                // Exporting is refused for the same reason; the pairing-code slot is not.
                assertFailsWith<HwiException.BadState> { noise.export() }
                assertEquals(null, noise.takePairingCode())
            } finally {
                first.close()
            }
            // Once the lease is released the handle works again.
            assertEquals(null, noise.export().privkey)
        }
    }

    @Test
    fun `runCommand destroys the interpreter even when the link fails`() = runBlocking<Unit> {
        ColdcardEncryption().use { encryption ->
            val interp = Interp.newColdcard(encryption)
            assertFailsWith<TransportException.Disconnected> {
                Hwi.runCommand(interp, HwiCommand.Unlock(Network.TESTNET), FailingLink())
            }
            // Destroyed means destroyed: the generated wrapper refuses any further call.
            assertFailsWith<IllegalStateException> { interp.end() }
            Interp.newColdcard(encryption).use { next ->
                val transmit = next.start(HwiCommand.Unlock(Network.TESTNET))
                assertEquals("ncry", transmit.payload.copyOfRange(0, 4).decodeToString())
                assertFalse(transmit.encrypted)
            }
        }
    }

    @Test
    fun `cancellation before dispatch still releases the interpreter lease`() = runBlocking<Unit> {
        NoiseHandle(null).use { noise ->
            Interp.newBitbox(noise, Network.TESTNET).use { interp ->
                var linkCalled = false
                val link = object : Link {
                    override suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray {
                        linkCalled = true
                        throw AssertionError("a cancelled command reached the link")
                    }
                }
                val call = async(start = CoroutineStart.UNDISPATCHED) {
                    cancel()
                    Hwi.runCommand(interp, HwiCommand.Unlock(Network.TESTNET), link)
                }
                assertFailsWith<CancellationException> { call.await() }
                assertFalse(linkCalled)
                assertEquals(null, noise.export().privkey)
                Interp.newBitbox(noise, Network.TESTNET).use { next ->
                    assertEquals("u", next.start(HwiCommand.Unlock(Network.TESTNET)).payload.decodeToString())
                }
            }
        }
    }

    @Test
    fun `synchronous transport cancellation stops before native handshake mutation`() = runBlocking<Unit> {
        NoiseHandle(null).use { noise ->
            val payloads = mutableListOf<String>()
            val link = object : Link {
                override suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray {
                    val request = payload.decodeToString()
                    payloads += request
                    return when (request) {
                        "u" -> ByteArray(0)
                        "h" -> {
                            currentCoroutineContext().cancel()
                            byteArrayOf(0)
                        }
                        else -> throw AssertionError("unexpected handshake payload")
                    }
                }
            }
            val call = async {
                Hwi.runCommand(
                    Interp.newBitbox(noise, Network.TESTNET),
                    HwiCommand.Unlock(Network.TESTNET),
                    link,
                )
            }
            assertFailsWith<CancellationException> { call.await() }
            assertEquals(listOf("u", "h"), payloads)
            assertEquals(null, noise.export().privkey)
        }
    }

    @Test
    fun `bitbox pairing material round trips through the session`() = runBlocking<Unit> {
        val privkey = ByteArray(32) { 7 }
        val pubkey = ByteArray(32) { 9 }
        val session = HwiSession.bitboxUsb(
            ThrowingHidChannel(TransportException.Disconnected()),
            Network.TESTNET,
            onPairingCode = {},
            noiseConfig = NoiseConfig(privkey, listOf(pubkey)),
        )
        try {
            // `NoiseConfig` holds ByteArrays, so compare the contents, not the boxes.
            val exported = session.bitboxPairing()
            assertEquals(privkey.hex(), exported.privkey?.hex())
            assertEquals(listOf(pubkey.hex()), exported.devicePubkeys.map { it.hex() })
        } finally {
            session.disconnect()
        }
        assertFailsWith<HwiException.BadState> { session.bitboxPairing() }
    }

    @Test
    fun `a non-bitbox session has no pairing material`() = runBlocking<Unit> {
        val session = HwiSession.ledgerUsb(ReplayHidChannel(fingerprintFixture()))
        try {
            assertFailsWith<HwiException.BadState> { session.bitboxPairing() }
        } finally {
            session.disconnect()
        }
    }

    @Test
    fun `a stalled call can be cancelled and disconnect does not hang`() = runBlocking<Unit> {
        val config = NoiseConfig(ByteArray(32) { 7 }, listOf(ByteArray(32) { 9 }))
        repeat(3) {
            val channel = StalledHidChannel()
            val session = HwiSession.bitboxUsb(
                channel,
                Network.TESTNET,
                onPairingCode = {},
                noiseConfig = config,
            )
            try {
                withTimeout(10_000) {
                    val call = async { session.unlock(Network.TESTNET) }
                    channel.reached.await()
                    call.cancelAndJoin()
                    val exported = session.bitboxPairing()
                    assertEquals(config.privkey?.hex(), exported.privkey?.hex())
                    assertEquals(config.devicePubkeys.map { it.hex() }, exported.devicePubkeys.map { it.hex() })
                }
                session.disconnect()
                session.disconnect()
                assertFailsWith<HwiException.BadState> { session.unlock(Network.TESTNET) }
                assertFailsWith<HwiException.BadState> { session.bitboxPairing() }
            } finally {
                session.disconnect()
            }
        }
    }
}

/** Counts how many coroutines are inside the channel at once. */
private class ConcurrencyProbeChannel(fixture: Fixture) : ReplayHidChannel(fixture) {
    val overlapped = AtomicBoolean(false)
    private val inside = AtomicInteger(0)

    // A suspension point wide enough for the other coroutine to get in if the session
    // were not serialising commands.
    override suspend fun send(report: ByteArray): UInt {
        if (inside.incrementAndGet() > 1) overlapped.set(true)
        try {
            delay(2)
            return super.send(report)
        } finally {
            inside.decrementAndGet()
        }
    }

    override suspend fun receive(maxLen: UInt): ByteArray {
        if (inside.incrementAndGet() > 1) overlapped.set(true)
        try {
            delay(2)
            return super.receive(maxLen)
        } finally {
            inside.decrementAndGet()
        }
    }
}

private class FailingLink : Link {
    override suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray =
        throw TransportException.Disconnected()
}

/** Accepts writes, then never answers: models a device that stopped responding. */
private class StalledHidChannel : HidChannel {
    val reached = CompletableDeferred<Unit>()

    override suspend fun send(report: ByteArray): UInt = report.size.toUInt()

    override suspend fun receive(maxLen: UInt): ByteArray {
        reached.complete(Unit)
        awaitCancellation()
    }
}
