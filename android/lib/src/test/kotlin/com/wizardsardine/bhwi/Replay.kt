package com.wizardsardine.bhwi

import java.io.File
import java.util.ArrayDeque
import uniffi.bhwi_ffi.HidChannel
import uniffi.bhwi_ffi.TransportException

/** Report-level Ledger transcript, as produced by `bhwi-ffi/tests/fixtures.rs`. */
data class Fixture(val writes: List<String>, val reads: List<String>, val expected: String) {
    companion object {
        /** Directory is injected by the Gradle test task (see `lib/build.gradle.kts`). */
        private val dir = File(
            System.getProperty("bhwi.fixtures.dir")
                ?: error("bhwi.fixtures.dir is not set"),
        )

        /**
         * Hand parser: the fixtures are machine-generated and only ever contain two hex
         * string arrays plus one string, so a real JSON dependency would buy nothing.
         */
        fun load(name: String): Fixture {
            val json = File(dir, name).readText()
            fun array(key: String): List<String> {
                val body = Regex("\"$key\"\\s*:\\s*\\[(.*?)]", RegexOption.DOT_MATCHES_ALL)
                    .find(json)
                    ?.groupValues
                    ?.get(1)
                    ?: error("$name: no \"$key\" array")
                return Regex("\"([0-9a-fA-F]*)\"").findAll(body).map { it.groupValues[1] }.toList()
            }
            val expected = Regex("\"expected\"\\s*:\\s*\"([^\"]*)\"").find(json)
                ?.groupValues?.get(1)
                ?: error("$name: no \"expected\" value")
            return Fixture(array("writes"), array("reads"), expected)
        }
    }
}

fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

fun String.unhex(): ByteArray =
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()

/**
 * Replays a fixture transcript: every report the driver writes must equal the next
 * recorded write, and every read is served from the recorded replies in order.
 *
 * Mismatches are recorded and reported as `TransportException.Io` rather than thrown as
 * assertion errors: UniFFI's foreign-callback wrapper only catches `Exception`, so an
 * `AssertionError` here would escape into a `GlobalScope` coroutine and hang the call.
 * Tests call [check] afterwards to turn a recorded mismatch into a real failure.
 */
class ReplayHidChannel(fixture: Fixture) : HidChannel {
    private val writes = ArrayDeque(fixture.writes)
    private val reads = ArrayDeque(fixture.reads)
    private val problems = mutableListOf<String>()

    // UniFFI runs foreign callbacks on the default dispatcher, so the queues are touched
    // from several threads even though the session serialises the commands themselves.
    private val lock = Any()

    private fun fail(message: String): Nothing {
        problems += message
        throw TransportException.Io(message)
    }

    override suspend fun send(report: ByteArray): UInt = synchronized(lock) {
        val actual = report.hex()
        val expected = writes.pollFirst() ?: fail("unexpected extra write: $actual")
        if (actual != expected) {
            fail("write mismatch\n  expected: $expected\n  actual:   $actual\n  ${diff(expected, actual)}")
        }
        report.size.toUInt()
    }

    override suspend fun receive(maxLen: UInt): ByteArray = synchronized(lock) {
        // An exhausted script is exactly what an unplugged device looks like.
        val next = reads.pollFirst() ?: throw TransportException.Disconnected()
        next.unhex().copyOf(minOf(next.length / 2, maxLen.toInt()))
    }

    /** Fails the test if any report mismatched, or if the script was not consumed. */
    fun check(expectExhausted: Boolean = true) = synchronized(lock) {
        if (problems.isNotEmpty()) throw AssertionError(problems.joinToString("\n"))
        if (expectExhausted && writes.isNotEmpty()) {
            throw AssertionError("driver wrote fewer reports than recorded: ${writes.size} left")
        }
    }

    private fun diff(expected: String, actual: String): String {
        val at = expected.zip(actual).indexOfFirst { (a, b) -> a != b }
        return if (at < 0) "lengths differ (${expected.length} vs ${actual.length})"
        else "first difference at nibble $at (byte ${at / 2})"
    }
}
