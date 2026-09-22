package com.wizardsardine.bhwi.sample

import android.os.Looper
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.wizardsardine.bhwi.HidChannel
import com.wizardsardine.bhwi.HwiSession
import com.wizardsardine.bhwi.TransportException
import java.util.ArrayDeque
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The JVM replay suite, run on-device against the AAR's own `arm64-v8a`/`x86_64`
 * `libbhwi_ffi.so`. Kept to the fingerprint flow: the point is that the packaged library
 * loads under ART and that the AAR's own Kotlin host layer drives it, not to re-test the
 * framing.
 */
@RunWith(AndroidJUnit4::class)
class FingerprintReplayTest {
    @Test
    fun masterFingerprintReplaysTheRecordedTranscript() = runBlocking<Unit> {
        assertNotSame(Looper.getMainLooper().thread, Thread.currentThread())
        val json = InstrumentationRegistry.getInstrumentation()
            .context
            .assets
            .open("ledger_get_master_fingerprint.json")
            .use { it.readBytes().decodeToString() }

        val channel = ReplayHidChannel(strings("writes", json), strings("reads", json))
        val session = HwiSession.ledgerUsb(channel)
        try {
            withContext(Dispatchers.Main) {
                assertSame(Looper.getMainLooper().thread, Thread.currentThread())
                assertEquals(expected(json), session.getMasterFingerprint())
                assertSame(Looper.getMainLooper().thread, Thread.currentThread())
            }
        } finally {
            session.disconnect()
        }
        channel.check()
    }

    private fun strings(key: String, json: String): List<String> {
        val body = Regex("\"$key\"\\s*:\\s*\\[(.*?)]", RegexOption.DOT_MATCHES_ALL)
            .find(json)!!.groupValues[1]
        return Regex("\"([0-9a-fA-F]*)\"").findAll(body).map { it.groupValues[1] }.toList()
    }

    private fun expected(json: String): String =
        Regex("\"expected\"\\s*:\\s*\"([^\"]*)\"").find(json)!!.groupValues[1]
}

/** Same contract as the JVM `ReplayHidChannel`; see `lib/src/test/.../Fixtures.kt`. */
private class ReplayHidChannel(writes: List<String>, reads: List<String>) : HidChannel {
    private val writes = ArrayDeque(writes)
    private val reads = ArrayDeque(reads)
    private val lock = Any()

    override suspend fun send(report: ByteArray): UInt = synchronized(lock) {
        assertNotSame(Looper.getMainLooper().thread, Thread.currentThread())
        val actual = report.joinToString("") { "%02x".format(it) }
        val expected = writes.pollFirst()
        if (expected != actual) {
            throw AssertionError("write mismatch\n  expected: $expected\n  actual:   $actual")
        }
        report.size.toUInt()
    }

    override suspend fun receive(maxLen: UInt): ByteArray = synchronized(lock) {
        assertNotSame(Looper.getMainLooper().thread, Thread.currentThread())
        val next = reads.pollFirst() ?: throw TransportException.Disconnected()
        next.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            .copyOf(minOf(next.length / 2, maxLen.toInt()))
    }

    fun check() = synchronized(lock) {
        if (writes.isNotEmpty()) throw AssertionError("unwritten reports: ${writes.size}")
    }
}
