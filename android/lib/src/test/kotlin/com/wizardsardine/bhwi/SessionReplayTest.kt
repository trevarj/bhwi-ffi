package com.wizardsardine.bhwi

import kotlin.test.assertFailsWith
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.bhwi_ffi.HidChannel
import uniffi.bhwi_ffi.HwiException
import uniffi.bhwi_ffi.TransportException
import uniffi.bhwi_ffi.connectLedgerUsb

/** Fixture-driven Ledger replay over the real FFI boundary, no device involved. */
class SessionReplayTest {
    private val accountPath = "m/84'/1'/0'"
    private val addressPath = "m/84'/1'/0'/0/0"

    @Test
    fun `master fingerprint replays the recorded transcript`() = runBlocking<Unit> {
        val fixture = Fixture.load("ledger_get_master_fingerprint.json")
        val channel = ReplayHidChannel(fixture)
        val session = connectLedgerUsb(channel)
        try {
            assertEquals(fixture.expected, session.getMasterFingerprint())
        } finally {
            session.disconnect()
        }
        channel.check()
    }

    @Test
    fun `extended pubkey replays the recorded transcript`() = runBlocking<Unit> {
        val fixture = Fixture.load("ledger_get_xpub.json")
        val channel = ReplayHidChannel(fixture)
        val session = connectLedgerUsb(channel)
        try {
            assertEquals(fixture.expected, session.getExtendedPubkey(accountPath, false))
        } finally {
            session.disconnect()
        }
        channel.check()
    }

    @Test
    fun `a denied address display surfaces as UserRefused`() = runBlocking<Unit> {
        val fixture = Fixture.load("ledger_refused.json")
        val channel = ReplayHidChannel(fixture)
        val session = connectLedgerUsb(channel)
        try {
            assertFailsWith<HwiException.UserRefused> {
                session.displayAddress(addressPath, true, null)
            }
        } finally {
            session.disconnect()
        }
        channel.check()
    }

    @Test
    fun `a channel io failure surfaces as Transport`() = runBlocking<Unit> {
        val session = connectLedgerUsb(ThrowingHidChannel(TransportException.Io("write failed")))
        try {
            assertFailsWith<HwiException.Transport> { session.getMasterFingerprint() }
        } finally {
            session.disconnect()
        }
    }

    @Test
    fun `an unplugged channel surfaces as Disconnected`() = runBlocking<Unit> {
        val session = connectLedgerUsb(ThrowingHidChannel(TransportException.Disconnected()))
        try {
            assertFailsWith<HwiException.Disconnected> { session.getMasterFingerprint() }
        } finally {
            session.disconnect()
        }
    }

    @Test
    fun `disconnect is idempotent and closes the session`() = runBlocking<Unit> {
        val fixture = Fixture.load("ledger_get_master_fingerprint.json")
        val session = connectLedgerUsb(ReplayHidChannel(fixture))
        session.disconnect()
        session.disconnect()
        assertFailsWith<HwiException.Closed> { session.getMasterFingerprint() }
    }

    @Test
    fun `repeated connect and disconnect does not deadlock`() = runBlocking<Unit> {
        val fixture = Fixture.load("ledger_get_master_fingerprint.json")
        repeat(10) {
            val channel = ReplayHidChannel(fixture)
            val session = connectLedgerUsb(channel)
            assertEquals(fixture.expected, session.getMasterFingerprint())
            session.disconnect()
            assertFailsWith<HwiException.Closed> { session.getMasterFingerprint() }
            channel.check()
        }
    }

    @Test
    fun `concurrent calls on one session are serialised`() = runBlocking<Unit> {
        val one = Fixture.load("ledger_get_master_fingerprint.json")
        // Two back-to-back flows against one channel: proves concurrent suspend calls are
        // safe and both transcripts are fully consumed. (Ordering itself is enforced by the
        // session's mpsc worker; identical transcripts can't distinguish interleavings.)
        val twice = Fixture(one.writes + one.writes, one.reads + one.reads, one.expected)
        val channel = ReplayHidChannel(twice)
        val session = connectLedgerUsb(channel)
        try {
            val first = async(Dispatchers.Default) { session.getMasterFingerprint() }
            val second = async(Dispatchers.Default) { session.getMasterFingerprint() }
            assertEquals(one.expected, first.await())
            assertEquals(one.expected, second.await())
        } finally {
            session.disconnect()
        }
        channel.check()
    }

    @Test
    fun `cancelling a call returns promptly and disconnect does not hang`() = runBlocking<Unit> {
        val channel = StalledHidChannel()
        val session = connectLedgerUsb(channel)
        val call = launch(Dispatchers.Default) { session.getMasterFingerprint() }
        withTimeout(10_000) { channel.stalled.await() }
        // The worker thread stays parked in the never-answered read; only the Kotlin side
        // and the session handle have to come back.
        withTimeout(10_000) { call.cancelAndJoin() }
        // Run the teardown in its own coroutine so a deadlock fails the test on the
        // timeout instead of hanging the whole JVM.
        withTimeout(10_000) { launch(Dispatchers.Default) { session.disconnect() }.join() }
    }
}

/** Fails every operation with a fixed transport error. */
private class ThrowingHidChannel(private val error: TransportException) : HidChannel {
    override suspend fun send(report: ByteArray): UInt = throw error
    override suspend fun receive(maxLen: UInt): ByteArray = throw error
}

/** Accepts writes, then never answers: models a device that stopped responding. */
private class StalledHidChannel : HidChannel {
    val stalled = CompletableDeferred<Unit>()
    private val never = CompletableDeferred<ByteArray>()

    override suspend fun send(report: ByteArray): UInt = report.size.toUInt()

    override suspend fun receive(maxLen: UInt): ByteArray {
        stalled.complete(Unit)
        return never.await()
    }
}
