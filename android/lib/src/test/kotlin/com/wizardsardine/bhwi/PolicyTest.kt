package com.wizardsardine.bhwi

import java.security.MessageDigest
import kotlin.test.assertFailsWith
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.bhwi_ffi.HwiCommand
import uniffi.bhwi_ffi.HwiException
import uniffi.bhwi_ffi.HwiResponse
import uniffi.bhwi_ffi.Interp
import uniffi.bhwi_ffi.MultisigAddressFormat
import uniffi.bhwi_ffi.Network
import uniffi.bhwi_ffi.WalletPolicy
import uniffi.bhwi_ffi.WalletRegistration
import uniffi.bhwi_ffi.deriveAddresses

/** Real JNI/core interpreters with synthetic protocol replies, not firmware captures. */
class PolicyTest {
    private val xpub = "tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP"
    private val descriptor = "wpkh([f5acc2fd/84'/1'/0']$xpub/<0;1>/*)"
    // Protocol-planning vector only; never submitted to firmware for signing.
    private val unsignedPsbt =
        "cHNidP8BAFICAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////ASgjAAAAAAAAFgAU" +
            "pasSNvKjbuZXEyy+ZWhJ1coWGksAAAAAAAEBHxAnAAAAAAAAFgAUpasSNvKjbuZXEyy+ZWhJ1coWGksAAA=="
    private val noHttp = object : HttpBridge {
        override suspend fun request(url: String, body: ByteArray): ByteArray =
            throw AssertionError("wallet policy command reached HTTP")
    }

    private fun registrationId(payload: ByteArray): ByteArray {
        // This short-policy fixture has a one-byte CompactSize length after the APDU header.
        val policyLength = payload[5].toInt() and 0xff
        assertTrue(policyLength < 0xfd)
        assertEquals(policyLength, payload.size - 6)
        return MessageDigest.getInstance("SHA-256").digest(payload.copyOfRange(6, payload.size))
    }

    @Test
    fun `the facade preserves completed Jade registration and named address display`() = runBlocking<Unit> {
        val caller = Thread.currentThread()
        val expected = deriveAddresses(descriptor, Network.TESTNET, true, 7u, 1u).single().address
        var exchanges = 0
        val stream = object : SerialStream {
            override suspend fun writeAll(data: ByteArray) {
                assertNotSame(caller, Thread.currentThread())
                val request = data.decodeToString()
                assertTrue(request.contains("test_policy"))
                when (exchanges) {
                    0 -> {
                        assertTrue(request.contains("register_descriptor"))
                        assertTrue(request.contains("datavalues"))
                        assertTrue(request.contains("[f5acc2fd/84'/1'/0']$xpub"))
                    }
                    1 -> {
                        assertTrue(request.contains("get_receive_address"))
                        assertTrue(request.contains("descriptor_name"))
                    }
                    else -> throw AssertionError("unexpected extra exchange")
                }
            }
            override suspend fun read(maxLen: UInt): ByteArray = when (exchanges++) {
                0 -> "a2626964613166726573756c74f5".unhex()
                1 -> "a2626964613166726573756c7478".unhex() + byteArrayOf(expected.length.toByte()) + expected.encodeToByteArray()
                else -> throw AssertionError("unexpected extra read")
            }
        }
        val session = HwiSession.jadeUsb(stream, noHttp, Network.TESTNET)
        try {
            val registration = session.registerWallet("test_policy", descriptor)
            assertTrue(registration is WalletRegistration.Complete)
            assertEquals(null, (registration as WalletRegistration.Complete).hmac)
            assertEquals(expected, session.displayDescriptorAddress(7u, true, true, WalletPolicy("test_policy", descriptor, null)))
        } finally {
            session.disconnect()
        }
        assertEquals(2, exchanges)
    }

    @Test
    fun `Jade false registration is never reported as success`() = runBlocking<Unit> {
        val link = object : Link {
            override suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray {
                assertTrue(payload.decodeToString().contains("register_descriptor"))
                return "a2626964613166726573756c74f4".unhex()
            }
        }
        assertFailsWith<HwiException.Device> {
            Hwi.runCommand(Interp.newJade(Network.TESTNET), HwiCommand.RegisterWallet("test_policy", descriptor), link)
        }
    }

    @Test
    fun `Ledger registration returns its HMAC and descriptor display transmits it`() = runBlocking<Unit> {
        val hmac = ByteArray(32) { 9 }
        var expectedId: ByteArray? = null
        val registerLink = object : Link {
            override suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray {
                assertFalse(encrypted)
                assertEquals("e1020001", payload.copyOfRange(0, 4).hex())
                assertTrue(payload.decodeToString().contains("test_policy"))
                val id = registrationId(payload).also { expectedId = it }
                return id + hmac + "9000".unhex()
            }
        }
        val response = Hwi.runCommand(Interp.newLedger(), HwiCommand.RegisterWallet("test_policy", descriptor), registerLink)
        val registration = (response as HwiResponse.WalletRegistration).registration as WalletRegistration.Complete
        assertEquals(hmac.hex(), registration.hmac?.hex())
        val displayLink = object : Link {
            override suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray {
                assertEquals("e10300014601", payload.copyOfRange(0, 6).hex())
                assertEquals(requireNotNull(expectedId).hex(), payload.copyOfRange(6, 38).hex())
                assertEquals(hmac.hex(), payload.copyOfRange(38, 70).hex())
                assertEquals("0100000007", payload.copyOfRange(70, 75).hex())
                return "6985".unhex()
            }
        }
        assertFailsWith<HwiException.UserRefused> {
            Hwi.runCommand(
                Interp.newLedger(),
                HwiCommand.DisplayDescriptorAddress(7u, true, true, WalletPolicy("test_policy", descriptor, hmac)),
                displayLink,
            )
        }
    }

    @Test
    fun `Ledger mismatched registration identity retires the interpreter`() {
        Interp.newLedger().use { interp ->
            val transmit = interp.start(HwiCommand.RegisterWallet("test_policy", descriptor))
            val id = registrationId(transmit.payload)
            id[0] = (id[0].toInt() xor 1).toByte()
            assertFailsWith<HwiException.Device> {
                interp.exchange(id + ByteArray(32) { 9 } + "9000".unhex())
            }
            assertFailsWith<HwiException.BadState> { interp.end() }
        }
    }

    @Test
    fun `public input HMAC and concrete multisig validation happens before platform IO`() = runBlocking<Unit> {
        val stream = object : SerialStream {
            override suspend fun writeAll(data: ByteArray): Unit = throw AssertionError("invalid input reached the device")
            override suspend fun read(maxLen: UInt): ByteArray = throw AssertionError("invalid input read the device")
        }
        val session = HwiSession.jadeUsb(stream, noHttp, Network.TESTNET)
        try {
            for ((name, input) in listOf(
                "bad name" to descriptor,
                "test_policy" to "wpkh(@0/**)",
                "test_policy" to "wpkh($xpub/<0;1>/*)",
                "test_policy" to "wpkh([f5acc2fd/84'/1'/0']$xpub/0'/*)",
                "test_policy" to "wpkh([f5acc2fd/84'/1'/0']$xpub/<0;1>/7'/*)",
            )) {
                assertFailsWith<HwiException.InvalidInput> { session.registerWallet(name, input) }
            }
            assertFailsWith<HwiException.InvalidInput> {
                session.displayDescriptorAddress(7u, true, true, WalletPolicy("test_policy", descriptor, ByteArray(32)))
            }
            assertFailsWith<HwiException.InvalidInput> {
                session.displayDescriptorAddress(0x80000000u, false, true, WalletPolicy("test_policy", descriptor, null))
            }
            assertFailsWith<HwiException.InvalidInput> {
                session.displayMultisigAddress(1u, true, MultisigAddressFormat.WIT, listOf("[f5acc2fd]$xpub/<0;1>/*"))
            }
            assertFailsWith<HwiException.InvalidInput> {
                session.displayMultisigAddress(0u, true, MultisigAddressFormat.SH_WIT, emptyList())
            }
        } finally {
            session.disconnect()
        }
    }

    @Test
    fun `signing requires an exact Ledger policy and forwards its V2 identity and HMAC`() = runBlocking<Unit> {
        suspend fun firstPayload(policy: WalletPolicy): ByteArray {
            var request: ByteArray? = null
            val link = object : Link {
                override suspend fun exchange(payload: ByteArray, encrypted: Boolean): ByteArray {
                    assertFalse(encrypted)
                    request = payload
                    return "6985".unhex() // Synthetic refusal, not a successful signing capture.
                }
            }
            assertFailsWith<HwiException.UserRefused> {
                Hwi.runCommand(Interp.newLedger(), HwiCommand.SignPsbt(unsignedPsbt, policy), link)
            }
            return requireNotNull(request)
        }
        for (hmac in listOf(null, ByteArray(32) { 7 })) {
            val name = if (hmac == null) "" else "test_policy"
            val policy = WalletPolicy(name, descriptor, hmac)
            val signing = firstPayload(policy)
            assertEquals("e1040001", signing.copyOfRange(0, 4).hex())
            Interp.newLedger().use { display ->
                val addressRequest = display.start(HwiCommand.DisplayDescriptorAddress(0u, false, false, policy)).payload
                assertEquals(
                    addressRequest.copyOfRange(6, 38).hex(),
                    signing.copyOfRange(signing.size - 64, signing.size - 32).hex(),
                )
            }
            assertEquals((hmac ?: ByteArray(32)).hex(), signing.takeLast(32).toByteArray().hex())
        }
        val stream = object : SerialStream {
            override suspend fun writeAll(data: ByteArray): Unit = throw AssertionError("invalid signing policy reached IO")
            override suspend fun read(maxLen: UInt): ByteArray = throw AssertionError("invalid signing policy read IO")
        }
        val session = HwiSession.jadeUsb(stream, noHttp, Network.TESTNET)
        try {
            assertFailsWith<HwiException.InvalidInput> {
                session.signPsbt(unsignedPsbt, WalletPolicy("test_policy", descriptor, ByteArray(32) { 7 }))
            }
            assertFailsWith<HwiException.InvalidInput> {
                session.signPsbt(unsignedPsbt, WalletPolicy("test_policy", "wpkh(@0/**)", null))
            }
        } finally {
            session.disconnect()
        }
    }
}
