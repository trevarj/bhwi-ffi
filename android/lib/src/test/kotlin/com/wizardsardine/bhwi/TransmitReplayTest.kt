package com.wizardsardine.bhwi

import kotlin.test.assertFailsWith
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.bhwi_ffi.HwiCommand
import uniffi.bhwi_ffi.HwiException
import uniffi.bhwi_ffi.HwiResponse
import uniffi.bhwi_ffi.Interp
import uniffi.bhwi_ffi.Recipient
import uniffi.bhwi_ffi.Transmit

/**
 * Transmit-level replay: the driving loop against a scripted [Link], with no wire framing
 * in the way. Complements [LedgerReplayTest], which covers the framing itself.
 */
class TransmitReplayTest {
    @Test
    fun `the loop drives the fingerprint transcript`() = runBlocking<Unit> {
        val fixture = TransmitFixture.load("transmit_ledger_fingerprint.json")
        val link = ScriptedLink(fixture)
        val response = Hwi.runCommand(Interp.newLedger(), HwiCommand.GetMasterFingerprint, link)
        assertEquals(fixture.expected, (response as HwiResponse.Fingerprint).hex)
        link.check()
    }

    @Test
    fun `the loop drives the xpub transcript`() = runBlocking<Unit> {
        val fixture = TransmitFixture.load("transmit_ledger_xpub.json")
        val link = ScriptedLink(fixture)
        val response = Hwi.runCommand(
            Interp.newLedger(),
            HwiCommand.GetXpub("m/84'/1'/0'", false),
            link,
        )
        assertEquals(fixture.expected, (response as HwiResponse.Xpub).xpub)
        link.check()
    }

    @Test
    fun `the loop maps a refusal to UserRefused`() = runBlocking<Unit> {
        val fixture = TransmitFixture.load("transmit_ledger_refused.json")
        val link = ScriptedLink(fixture)
        assertFailsWith<HwiException.UserRefused> {
            Hwi.runCommand(
                Interp.newLedger(),
                HwiCommand.DisplayAddress("m/84'/1'/0'/0/0", true, null),
                link,
            )
        }
        link.check()
    }

    /**
     * Jade's PIN-server payloads are the one thing that must not go to the device link.
     * Tested on the routing step itself: no real device produces such a transmit without a
     * full Jade handshake first.
     */
    @Test
    fun `a PinServer transmit is routed to the bridge`() = runBlocking<Unit> {
        var seen: Pair<String, String>? = null
        val bridge = object : HttpBridge {
            override suspend fun request(url: String, body: ByteArray): ByteArray {
                seen = url to body.hex()
                return "beef".unhex()
            }
        }
        val transmit = Transmit("0102".unhex(), false, Recipient.PinServer("http://pin.example/start"))
        assertEquals("beef", Hwi.deliver(transmit, DeadLink(), bridge).hex())
        assertEquals("http://pin.example/start" to "0102", seen)
    }

    @Test
    fun `a PinServer transmit without an HttpBridge is a BadState`() = runBlocking<Unit> {
        val transmit = Transmit("0102".unhex(), false, Recipient.PinServer("http://pin.example/start"))
        val error = assertFailsWith<HwiException.BadState> { Hwi.deliver(transmit, DeadLink(), null) }
        assertEquals(true, error.msg.contains("HttpBridge"))
    }

    @Test
    fun `a Device transmit carries the encryption flag to the link`() = runBlocking<Unit> {
        var seen: Pair<String, Boolean>? = null
        val link = object : Link {
            override suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray {
                seen = payload.hex() to encrypted
                return ByteArray(0)
            }
        }
        Hwi.deliver(Transmit("0102".unhex(), true, Recipient.Device), link, null)
        assertEquals("0102" to true, seen)
    }
}

/** Feeds the recorded replies back and asserts each payload and its encryption flag. */
private class ScriptedLink(private val fixture: TransmitFixture) : Link {
    private var index = 0

    override suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray {
        val step = fixture.exchanges.getOrNull(index)
            ?: throw AssertionError("unexpected extra exchange: ${payload.hex()}")
        assertEquals("payload of exchange $index", step.payload, payload.hex())
        assertEquals("encrypted flag of exchange $index", step.encrypted, encrypted)
        index++
        return step.reply.unhex()
    }

    fun check() {
        if (index != fixture.exchanges.size) {
            throw AssertionError("the loop ran $index of ${fixture.exchanges.size} exchanges")
        }
    }
}

/** Any use is a test failure: a PIN-server payload must never reach the device link. */
private class DeadLink : Link {
    override suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray =
        throw AssertionError("the loop sent a PIN-server payload to the device link")
}
