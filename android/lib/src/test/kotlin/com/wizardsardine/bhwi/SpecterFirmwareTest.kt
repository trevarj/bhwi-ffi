package com.wizardsardine.bhwi

import java.io.BufferedReader
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import kotlin.test.assertFailsWith
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotSame
import org.junit.Assume.assumeTrue
import org.junit.Test
import uniffi.bhwi_ffi.HwiException
import uniffi.bhwi_ffi.HwiResponse
import uniffi.bhwi_ffi.Network
import uniffi.bhwi_ffi.WalletPolicy
import uniffi.bhwi_ffi.WalletRegistration
import uniffi.bhwi_ffi.psbtSummary

/** Opt-in actual firmware via the public JNI/facade/serial link. TCP/GUI exist only in tests. */
class SpecterFirmwareTest {
    private fun socket(variable: String): Socket {
        val target = System.getenv(variable) ?: error("explicit localhost target required: $variable")
        val match = Regex("127\\.0\\.0\\.1:([0-9]+)").matchEntire(target) ?: error("test adapter accepts only explicit loopback")
        val port = match.groupValues[1].toInt()
        require(port in 1..65535)
        return Socket().apply {
            connect(InetSocketAddress("127.0.0.1", port), 5_000)
            soTimeout = 30_000
        }
    }

    private class Gui(private val socket: Socket) {
        private val reader: BufferedReader = socket.getInputStream().bufferedReader()
        private fun screen(): String {
            val line = StringBuilder()
            while (line.length <= 128) {
                val value = reader.read()
                check(value >= 0) { "firmware GUI EOF" }
                if (value == '\n'.code) {
                    check(line.isNotEmpty() && line.last() == '\r') { "invalid GUI line delimiter" }
                    val screen = line.dropLast(1).toString()
                    check(screen.isNotEmpty() && screen.all { it.isLetterOrDigit() && it.code < 128 }) {
                        "GUI returned a non-screen line; verify the runner-reported GUI port"
                    }
                    return screen
                }
                line.append(value.toChar())
            }
            error("oversized GUI screen")
        }

        suspend fun <T> confirm(approve: Boolean = true, operation: suspend () -> T): T = coroutineScope {
            val response = async(Dispatchers.IO) { operation() }
            val menu = async(Dispatchers.IO) {
                val deadline = System.nanoTime() + 30_000_000_000L
                while (true) {
                    val remaining = (deadline - System.nanoTime()) / 1_000_000
                    check(remaining > 0) { "firmware GUI deadline elapsed" }
                    socket.soTimeout = remaining.coerceAtMost(30_000).toInt().coerceAtLeast(1)
                    if (screen() == "Menu") break
                    // Existing core E2E's disposable-firmware controller, never release approval.
                    socket.getOutputStream().write(if (approve) "true\r\n".encodeToByteArray() else "false\r\n".encodeToByteArray())
                    socket.getOutputStream().flush()
                }
            }
            val result = response.await()
            menu.await()
            result
        }
    }

    @Test
    fun `real firmware registers verifies exact addresses and signs through the Kotlin serial facade`() = runBlocking<Unit> {
        val fixturePath = System.getenv("BHWI_SPECTER_SIGNING_FIXTURE")
        assumeTrue("requires initialized official Specter-DIY and independently constructed Rust public fixture", fixturePath != null)
        val resultPath = System.getenv("BHWI_SPECTER_SIGNING_RESULT") ?: error("public result path required for independent Rust verification")
        val json = File(requireNotNull(fixturePath)).readText()
        fun field(name: String): String = Regex("\"$name\"\\s*:\\s*\"([^\"]*)\"").find(json)?.groupValues?.get(1) ?: error("missing public fixture field: $name")
        val caller = Thread.currentThread()
        val signed = withContext(Dispatchers.IO) {
            socket("BHWI_SPECTER_ADDR").use { serial ->
                socket("BHWI_SPECTER_GUI_ADDR").use { guiSocket ->
                    delay(100) // Core E2E's TCPHost client adoption boundary.
                    val gui = Gui(guiSocket)
                    val stream = object : SerialStream {
                        override suspend fun writeAll(data: ByteArray) {
                            assertNotSame(caller, Thread.currentThread())
                            runInterruptible {
                                serial.getOutputStream().write(data)
                                serial.getOutputStream().flush()
                            }
                        }
                        override suspend fun read(maxLen: UInt): ByteArray {
                            assertNotSame(caller, Thread.currentThread())
                            return runInterruptible {
                                val bytes = ByteArray(maxLen.toInt())
                                val count = serial.getInputStream().read(bytes)
                                if (count < 0) ByteArray(0) else bytes.copyOf(count)
                            }
                        }
                    }
                    val session = HwiSession.specterUsb(stream, Network.BITCOIN)
                    val policy = WalletPolicy(field("name"), field("descriptor"), null)
                    try {
                        assertEquals("73c5da0a", (session.unlock(Network.BITCOIN) as HwiResponse.Fingerprint).hex)
                        assertEquals(field("account_xpub"), session.getExtendedPubkey(field("path"), false))
                        assertFailsWith<HwiException.InvalidInput> { session.getInfo() }
                        val registration = gui.confirm { session.registerWallet(policy.name, policy.descriptor) } as WalletRegistration.Complete
                        assertEquals(null, registration.hmac)
                        assertEquals(field("receive"), gui.confirm { session.displayDescriptorAddress(7u, false, true, policy) })
                        assertEquals(field("change"), gui.confirm { session.displayDescriptorAddress(7u, true, true, policy) })
                        assertFailsWith<HwiException.UserRefused> {
                            gui.confirm(false) { session.signPsbt(field("original_psbt"), policy) }
                        }
                        assertEquals(field("fingerprint"), session.getMasterFingerprint())
                        gui.confirm { session.signPsbt(field("original_psbt"), policy) }
                    } finally {
                        session.disconnect() // The enclosing test owns socket closure.
                    }
                }
            }
        }
        assertNotEquals(field("original_psbt"), signed)
        assertEquals(psbtSummary(field("original_psbt"), Network.BITCOIN), psbtSummary(signed, Network.BITCOIN))
        // Independent Rust check verifies the actual key, ALL signature and unchanged metadata.
        File(resultPath).writeText(json.trimEnd().dropLast(1) + ",\n  \"signed_psbt\": \"$signed\"\n}\n")
    }
}
