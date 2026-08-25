package com.wizardsardine.bhwi.sample

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.util.ArrayDeque
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.bhwi_ffi.HidChannel
import uniffi.bhwi_ffi.TransportException
import uniffi.bhwi_ffi.connectLedgerUsb

/**
 * The JVM replay suite, run on-device against the AAR's own `arm64-v8a`/`x86_64`
 * `libbhwi_ffi.so`. Kept to the fingerprint flow: the point is that the packaged
 * library loads and the callback interface works under ART, not to re-test the driver.
 */
@RunWith(AndroidJUnit4::class)
class FingerprintReplayTest {
    @Test
    fun masterFingerprintReplaysTheRecordedTranscript() = runBlocking<Unit> {
        val json = InstrumentationRegistry.getInstrumentation()
            .context
            .assets
            .open("ledger_get_master_fingerprint.json")
            .use { it.readBytes().decodeToString() }

        val channel = ReplayHidChannel(strings("writes", json), strings("reads", json))
        val session = connectLedgerUsb(channel)
        try {
            assertEquals(expected(json), session.getMasterFingerprint())
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

/** Same contract as the JVM `ReplayHidChannel`; see `lib/src/test/.../Replay.kt`. */
private class ReplayHidChannel(writes: List<String>, reads: List<String>) : HidChannel {
    private val writes = ArrayDeque(writes)
    private val reads = ArrayDeque(reads)
    private val problems = mutableListOf<String>()
    private val lock = Any()

    override suspend fun send(report: ByteArray): UInt = synchronized(lock) {
        val actual = report.joinToString("") { "%02x".format(it) }
        val expected = writes.pollFirst()
        if (expected != actual) {
            // UniFFI only catches `Exception` in foreign callbacks, so report the
            // mismatch as a transport failure and re-raise it from `check()`.
            problems += "write mismatch\n  expected: $expected\n  actual:   $actual"
            throw TransportException.Io("write mismatch")
        }
        report.size.toUInt()
    }

    override suspend fun receive(maxLen: UInt): ByteArray = synchronized(lock) {
        val next = reads.pollFirst() ?: throw TransportException.Disconnected()
        next.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            .copyOf(minOf(next.length / 2, maxLen.toInt()))
    }

    fun check() = synchronized(lock) {
        if (problems.isNotEmpty()) throw AssertionError(problems.joinToString("\n"))
        if (writes.isNotEmpty()) throw AssertionError("unwritten reports: ${writes.size}")
    }
}
