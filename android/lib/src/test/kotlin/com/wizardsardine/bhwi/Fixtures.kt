package com.wizardsardine.bhwi

import java.io.File
import java.util.ArrayDeque

fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

fun String.unhex(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

/** Directory is injected by the Gradle test task (see `lib/build.gradle.kts`). */
private val fixtureDir = File(
    System.getProperty("bhwi.fixtures.dir") ?: error("bhwi.fixtures.dir is not set"),
)

/**
 * Hand parsers: the fixtures are machine-generated and only ever contain flat hex string
 * arrays and objects, so a real JSON dependency would buy nothing.
 */
private fun read(name: String): String = File(fixtureDir, name).readText()

private fun expected(name: String, json: String): String =
    Regex("\"expected\"\\s*:\\s*\"([^\"]*)\"").find(json)?.groupValues?.get(1)
        ?: error("$name: no \"expected\" value")

/** Report-level Ledger transcript, as produced by `bhwi-ffi/tests/fixtures.rs`. */
data class Fixture(val writes: List<String>, val reads: List<String>, val expected: String) {
    companion object {
        fun load(name: String): Fixture {
            val json = read(name)
            fun array(key: String): List<String> {
                val body = Regex("\"$key\"\\s*:\\s*\\[(.*?)]", RegexOption.DOT_MATCHES_ALL)
                    .find(json)
                    ?.groupValues
                    ?.get(1)
                    ?: error("$name: no \"$key\" array")
                return Regex("\"([0-9a-fA-F]*)\"").findAll(body).map { it.groupValues[1] }.toList()
            }
            return Fixture(array("writes"), array("reads"), expected(name, json))
        }
    }
}

/** One scripted step at the FFI boundary. */
data class Exchange(val encrypted: Boolean, val payload: String, val reply: String)

/** Transmit-level transcript: what the interpreter emits and what the device answers. */
data class TransmitFixture(val exchanges: List<Exchange>, val expected: String) {
    companion object {
        private val step = Regex(
            "\"encrypted\"\\s*:\\s*(true|false)\\s*," +
                "\\s*\"payload_hex\"\\s*:\\s*\"([0-9a-fA-F]*)\"\\s*," +
                "\\s*\"reply_hex\"\\s*:\\s*\"([0-9a-fA-F]*)\"",
            RegexOption.DOT_MATCHES_ALL,
        )

        fun load(name: String): TransmitFixture {
            val json = read(name)
            val exchanges = step.findAll(json)
                .map { Exchange(it.groupValues[1].toBoolean(), it.groupValues[2], it.groupValues[3]) }
                .toList()
            check(exchanges.isNotEmpty()) { "$name: no exchanges" }
            return TransmitFixture(exchanges, expected(name, json))
        }
    }
}

/**
 * Replays a report-level transcript: every report the link writes must equal the next
 * recorded write, and every read is served from the recorded replies in order.
 *
 * This is what proves the Kotlin framing is byte-identical to the Rust transport the
 * fixtures were generated with.
 */
open class ReplayHidChannel(fixture: Fixture) : HidChannel {
    private val writes = ArrayDeque(fixture.writes)
    private val reads = ArrayDeque(fixture.reads)

    // Commands are serialised by the session, but the queues are still touched from
    // whichever dispatcher the caller used.
    private val lock = Any()

    override suspend fun send(report: ByteArray): UInt = synchronized(lock) {
        val actual = report.hex()
        val expected = writes.pollFirst() ?: throw AssertionError("unexpected extra write: $actual")
        if (actual != expected) {
            throw AssertionError(
                "write mismatch\n  expected: $expected\n  actual:   $actual\n  ${diff(expected, actual)}",
            )
        }
        report.size.toUInt()
    }

    override suspend fun receive(maxLen: UInt): ByteArray = synchronized(lock) {
        // An exhausted script is exactly what an unplugged device looks like.
        val next = reads.pollFirst() ?: throw TransportException.Disconnected()
        next.unhex().copyOf(minOf(next.length / 2, maxLen.toInt()))
    }

    /** Fails the test if the script was not fully consumed. */
    fun check() = synchronized(lock) {
        if (writes.isNotEmpty()) {
            throw AssertionError("the link wrote fewer reports than recorded: ${writes.size} left")
        }
    }

    private fun diff(expected: String, actual: String): String {
        val at = expected.zip(actual).indexOfFirst { (a, b) -> a != b }
        return if (at < 0) "lengths differ (${expected.length} vs ${actual.length})"
        else "first difference at nibble $at (byte ${at / 2})"
    }
}
