package com.wizardsardine.bhwi

import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotSame
import org.junit.Assume.assumeTrue
import org.junit.Test
import uniffi.bhwi_ffi.Network
import uniffi.bhwi_ffi.WalletPolicy
import uniffi.bhwi_ffi.psbtSummary

/** Opt-in live firmware/JNA smoke, not a synthetic reply or encrypted Noise transcript replay. */
class BitboxSigningFirmwareTest {
    @Test
    fun `the facade signs a real policy PSBT retaining a prior foreign signature`() = runBlocking<Unit> {
        val fixturePath = System.getenv("BHWI_BITBOX_SIGNING_FIXTURE")
        assumeTrue("requires the initialized BitBox simulator and a Rust-exported public PSBT fixture", fixturePath != null)
        val outputPath = System.getenv("BHWI_BITBOX_SIGNING_RESULT")
            ?: error("BHWI_BITBOX_SIGNING_RESULT is required; independently verify the result with the Rust fixture check")
        val json = File(requireNotNull(fixturePath)).readText()
        fun field(name: String): String = Regex("\"$name\"\\s*:\\s*\"([^\"]*)\"").find(json)?.groupValues?.get(1)
            ?: error("missing public fixture field: $name")
        val caller = Thread.currentThread()
        val signed = withContext(Dispatchers.IO) {
            Socket().use { socket ->
                socket.connect(InetSocketAddress("127.0.0.1", 15423), 5_000)
                socket.soTimeout = 300_000
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                val channel = object : HidChannel {
                    override suspend fun send(report: ByteArray): UInt {
                        assertNotSame(caller, Thread.currentThread())
                        assertEquals(64, report.size)
                        output.write(report)
                        output.flush()
                        return report.size.toUInt()
                    }
                    override suspend fun receive(maxLen: UInt): ByteArray {
                        assertNotSame(caller, Thread.currentThread())
                        assertEquals(64u, maxLen)
                        val report = input.readNBytes(64)
                        check(report.size == 64) { "simulator disconnected mid-report" }
                        return report
                    }
                }
                val session = HwiSession.bitboxUsb(channel, Network.BITCOIN, onPairingCode = { code ->
                    check(code.isNotEmpty()) // Official simulator test-only auto-approval, never production UI.
                })
                try {
                    session.unlock(Network.BITCOIN)
                    assertEquals(field("fingerprint"), session.getMasterFingerprint())
                    assertEquals(field("account_xpub"), session.getExtendedPubkey("m/48'/0'/0'/2'", false))
                    session.signPsbt(field("original_psbt"), WalletPolicy(field("name"), field("descriptor"), null))
                } finally {
                    session.disconnect()
                }
            }
        }
        assertNotEquals(field("original_psbt"), signed)
        assertEquals(psbtSummary(field("original_psbt"), Network.BITCOIN), psbtSummary(signed, Network.BITCOIN))
        // Native-independent signature/unsigned-tx verification consumes this public result in policy.rs.
        val result = json.replace(Regex("\"signed_psbt\"\\s*:\\s*\"[^\"]*\"")) { "\"signed_psbt\": \"$signed\"" }
            .replace(Regex("\"source\"\\s*:\\s*\"[^\"]*\"")) {
                "\"source\": \"live official BitBox02 firmware via Kotlin/JNA; public PSBT fixture, not a Noise replay\""
            }
        File(outputPath).writeText(result)
    }
}
