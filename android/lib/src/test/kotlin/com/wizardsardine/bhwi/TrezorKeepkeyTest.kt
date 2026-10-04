package com.wizardsardine.bhwi

import java.io.ByteArrayOutputStream
import java.util.ArrayDeque
import kotlin.test.assertFailsWith
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.bhwi_ffi.HostPassphraseHandle
import uniffi.bhwi_ffi.HwiCommand
import uniffi.bhwi_ffi.HwiException
import uniffi.bhwi_ffi.HwiResponse
import uniffi.bhwi_ffi.Interp
import uniffi.bhwi_ffi.MultisigAddressFormat
import uniffi.bhwi_ffi.Network
import uniffi.bhwi_ffi.WalletPolicy

/** Test-only protobuf field reader for synthetic ACK assertions. */
private fun protobufField(body: ByteArray, field: Int): Any? {
    var offset = 0
    fun varint(): Int {
        var value = 0
        for (shift in 0..28 step 7) {
            check(offset < body.size)
            val byte = body[offset++].toInt() and 0xff
            value = value or ((byte and 0x7f) shl shift)
            if (byte and 0x80 == 0) return value
        }
        error("invalid test protobuf varint")
    }
    while (offset < body.size) {
        val tag = varint()
        when (tag and 7) {
            0 -> {
                val value = varint()
                if (tag shr 3 == field) return value
            }
            1 -> offset += 8
            2 -> {
                val length = varint()
                check(length >= 0 && length <= body.size - offset)
                if (tag shr 3 == field) return body.copyOfRange(offset, offset + length)
                offset += length
            }
            5 -> offset += 4
            else -> error("unsupported test protobuf field")
        }
        check(offset <= body.size)
    }
    return null
}

private const val TREZOR_XPUB = "tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP"

private fun v1Frame(kind: Int, body: ByteArray = byteArrayOf()): ByteArray =
    byteArrayOf(0x23, 0x23, (kind shr 8).toByte(), kind.toByte(), 0, (body.size shr 16).toByte(),
        (body.size shr 8).toByte(), body.size.toByte()) + body

private fun v1Reports(frame: ByteArray): List<ByteArray> = frame.toList().chunked(63).map { chunk ->
    ByteArray(64).also { it[0] = 0x3f; chunk.toByteArray().copyInto(it, 1) }
}

private fun publicKeyReply(): ByteArray = v1Frame(12,
    byteArrayOf(0x0a, 0, 0x12, TREZOR_XPUB.length.toByte()) + TREZOR_XPUB.encodeToByteArray() +
        "1884868808".unhex()) // PublicKey.root_fingerprint = 01020304

private fun featuresReply(keepkey: Boolean, model: String?, capability: Boolean = false): ByteArray {
    val vendorVersion = if (keepkey) "0a0b6b6565706b65792e636f6d1007180a2000" else "1001180d2001"
    val flags = "380140015204746573746001800100" // PIN/passphrase protected, initialized, locked, label=test.
    val modelField = model?.let { "aa01".unhex() + byteArrayOf(it.length.toByte()) + it.encodeToByteArray() } ?: byteArrayOf()
    return v1Frame(17, (vendorVersion + flags).unhex() + modelField + if (capability) "f00111".unhex() else byteArrayOf())
}

/** Synthetic protobuf responses driven through JNI and the actual core, not command echoes. */
private class V1ScriptChannel(steps: List<Pair<Int, ByteArray>>) : HidChannel {
    private val steps = ArrayDeque(steps)
    private val replies = ArrayDeque<ByteArray>()
    private val request = ByteArrayOutputStream()
    val requests = mutableListOf<ByteArray>()

    override suspend fun send(report: ByteArray): UInt {
        assertEquals(64, report.size)
        assertEquals(0x3f.toByte(), report[0])
        request.write(report, 1, 63)
        return 64u
    }

    override suspend fun receive(maxLen: UInt): ByteArray {
        assertEquals(64u, maxLen)
        if (replies.isEmpty()) {
            val bytes = request.toByteArray()
            request.reset()
            check(bytes.size >= 8)
            val length = (4..7).fold(0) { value, i -> (value shl 8) or (bytes[i].toInt() and 0xff) }
            val frame = bytes.copyOf(8 + length)
            val (expectedKind, reply) = steps.removeFirst()
            assertEquals(expectedKind, ((frame[2].toInt() and 0xff) shl 8) or (frame[3].toInt() and 0xff))
            requests += frame
            replies.addAll(v1Reports(reply))
        }
        return replies.removeFirst()
    }

    fun checkComplete() {
        assertTrue(steps.isEmpty())
        assertTrue(replies.isEmpty())
        assertEquals(0, request.size())
    }
}

class TrezorKeepkeyTest {
    private fun session(keepkey: Boolean, channel: HidChannel): HwiSession =
        if (keepkey) HwiSession.keepkeyUsb(channel, Network.TESTNET) else HwiSession.trezorUsb(channel, Network.TESTNET)

    @Test
    fun `unlock preserves actual model and all flags independently of host keypad support`() = runBlocking<Unit> {
        for (keepkey in listOf(false, true)) {
            for (model in if (keepkey) listOf("K1-14AM") else listOf(null, "1", "T", "future")) {
                for (capability in listOf(false, true)) {
                    val channel = V1ScriptChannel(listOf(0 to featuresReply(keepkey, model, capability)))
                    val session = session(keepkey, channel)
                    try {
                        val info = session.unlock(Network.TESTNET) as HwiResponse.Info
                        assertEquals(if (keepkey) "7.10.0" else "1.13.1", info.version)
                        assertEquals(model, info.firmware)
                        assertEquals(true, info.initialized)
                        assertEquals(listOf(Network.TESTNET), info.networks)
                        assertEquals("test", info.label)
                        assertEquals(true, info.needsPinSent) // A locked T also has this flag.
                        assertEquals(capability && !keepkey, info.onDevicePassphraseEntry)
                        assertEquals(!capability || keepkey, info.needsPassphraseSent)
                        if (!keepkey && model == "future") {
                            assertFailsWith<HwiException.InvalidInput> { session.supportsHostPin(info) }
                        } else {
                            assertEquals(keepkey || model == null || model == "1", session.supportsHostPin(info))
                        }
                    } finally { session.disconnect() }
                    channel.checkComplete()
                }
            }
        }
    }

    @Test
    fun `prompt and send PIN use one channel and retain the chosen host passphrase across commands`() = runBlocking<Unit> {
        for (keepkey in listOf(false, true)) {
            val channel = V1ScriptChannel(listOf(
                0 to featuresReply(keepkey, if (keepkey) "K1-14AM" else "1"),
                11 to v1Frame(18, byteArrayOf(8, 1)),
                19 to v1Frame(41), 42 to publicKeyReply(),
                11 to v1Frame(41), 42 to publicKeyReply(),
            ))
            HostPassphraseHandle("café").use { handle ->
                val session = session(keepkey, channel)
                try {
                    session.configurePassphrase(handle, false)
                    assertTrue(session.promptPin())
                    assertTrue(session.sendPin("796"))
                    assertEquals("01020304", session.getMasterFingerprint())
                    assertEquals(v1Frame(19, "0a03373936".unhex()).hex(), channel.requests[2].hex())
                    for (request in listOf(channel.requests[3], channel.requests[5])) {
                        val body = request.copyOfRange(8, request.size)
                        val passphrase = protobufField(body, 1) as? ByteArray
                        assertEquals("cafe\u0301", passphrase?.decodeToString())
                        assertFalse(protobufField(body, 3) == 1)
                    }
                } finally { session.disconnect() }
                assertFailsWith<HwiException.BadState> { Interp.newKeepkey(Network.TESTNET, handle) }
            }
            channel.checkComplete()
        }
    }

    @Test
    fun `send PIN command-local host mode does not overwrite future on-device mode`() = runBlocking<Unit> {
        val channel = V1ScriptChannel(listOf(19 to publicKeyReply(), 11 to v1Frame(41), 42 to publicKeyReply()))
        val session = session(false, channel)
        try {
            session.configurePassphrase(null, true)
            assertTrue(session.sendPin("1234"))
            assertEquals("01020304", session.getMasterFingerprint())
            val body = channel.requests[2].copyOfRange(8, channel.requests[2].size)
            assertEquals(1, protobufField(body, 3))
            assertEquals(null, protobufField(body, 1))
        } finally { session.disconnect() }
        channel.checkComplete()
    }

    @Test
    fun `PIN false rejection and typed cancellation are not success`() = runBlocking<Unit> {
        for (keepkey in listOf(false, true)) {
            val steps = if (keepkey) listOf(19 to v1Frame(3, byteArrayOf(8, 7))) else listOf(
                19 to v1Frame(3, byteArrayOf(8, 7)), 55 to featuresReply(false, "1"),
            )
            val rejectedChannel = V1ScriptChannel(steps)
            val rejected = session(keepkey, rejectedChannel)
            try {
                rejected.configurePassphrase(null, false)
                assertFalse(rejected.sendPin("1234"))
            } finally { rejected.disconnect() }
            rejectedChannel.checkComplete()
            for (code in listOf(4, 6)) {
                val channel = V1ScriptChannel(listOf(19 to v1Frame(3, byteArrayOf(8, code.toByte()))))
                val refused = session(keepkey, channel)
                try {
                    refused.configurePassphrase(null, false)
                    assertFailsWith<HwiException.AuthRefused> { refused.sendPin("1234") }
                }
                finally { refused.disconnect() }
                channel.checkComplete()
            }
            // A separate explicit no-PIN Features fixture avoids treating AlreadyUnlocked as generic success.
            val unlockedBody = if (keepkey) "0a0b6b6565706b65792e636f6d1007180a20003800" else "1001180d20013800"
            val channel = V1ScriptChannel(listOf(0 to v1Frame(17, unlockedBody.unhex())))
            val unlocked = session(keepkey, channel)
            try { assertFailsWith<HwiException.DeviceAlreadyUnlocked> { unlocked.promptPin() } }
            finally { unlocked.disconnect() }
            channel.checkComplete()
        }
    }

    @Test
    fun `native normalized handle limits clear and independent interpreter clones cross JNI`() {
        for (text in listOf("a".repeat(50), "é".repeat(16))) HostPassphraseHandle(text).use { }
        for (text in listOf("a".repeat(51), "é".repeat(17), "ﬃ".repeat(17))) {
            assertFailsWith<HwiException.InvalidInput> { HostPassphraseHandle(text) }
        }
        HostPassphraseHandle("café").use { handle ->
            Interp.newTrezor(Network.TESTNET, handle, false).use { first ->
                Interp.newKeepkey(Network.TESTNET, handle).use { second ->
                    handle.clear()
                    handle.clear()
                    assertFailsWith<HwiException.BadState> { Interp.newTrezor(Network.TESTNET, handle, false) }
                    assertFailsWith<HwiException.BadState> { Interp.newKeepkey(Network.TESTNET, handle) }
                    for (interp in listOf(first, second)) {
                        interp.start(HwiCommand.GetMasterFingerprint)
                        val ack = requireNotNull(interp.exchange(v1Frame(41))).payload
                        val body = ack.copyOfRange(8, ack.size)
                        assertEquals("cafe\u0301", (protobufField(body, 1) as? ByteArray)?.decodeToString())
                        assertFalse(protobufField(body, 3) == 1)
                        assertEquals(null, interp.exchange(publicKeyReply()))
                        assertEquals("01020304", (interp.end() as HwiResponse.Fingerprint).hex)
                    }
                }
            }
        }
    }

    @Test
    fun `cleared and closed passphrase replacements preserve the configured native owner`() = runBlocking<Unit> {
        for (keepkey in listOf(false, true)) {
            for (closed in listOf(false, true)) {
                val channel = V1ScriptChannel(listOf(11 to v1Frame(41), 42 to publicKeyReply()))
                HostPassphraseHandle("café").use { original ->
                    HostPassphraseHandle("replacement").use { candidate ->
                        val session = session(keepkey, channel)
                        try {
                            session.configurePassphrase(original, false)
                            if (closed) {
                                candidate.close()
                                assertFailsWith<IllegalStateException> { session.configurePassphrase(candidate, false) }
                            } else {
                                candidate.clear()
                                assertFailsWith<HwiException.BadState> { session.configurePassphrase(candidate, false) }
                            }
                            original.validate()
                            assertEquals("01020304", session.getMasterFingerprint())
                            val ack = channel.requests[1]
                            assertEquals("cafe\u0301", (protobufField(ack.copyOfRange(8, ack.size), 1) as ByteArray).decodeToString())
                        } finally { session.disconnect() }
                    }
                }
                channel.checkComplete()
            }
        }
    }

    @Test
    fun `passphrase configuration rejects busy closed and unsupported modes and cancellation can join`() = runBlocking<Unit> {
        val reached = CompletableDeferred<Unit>()
        var writes = 0
        var reads = 0
        val channel = object : HidChannel {
            override suspend fun send(report: ByteArray): UInt { writes++; return report.size.toUInt() }
            override suspend fun receive(maxLen: UInt): ByteArray {
                reads++
                if (reads == 1) { reached.complete(Unit); awaitCancellation() }
                return v1Reports(publicKeyReply()).first() // Delayed stale reply must never be consumed.
            }
        }
        HostPassphraseHandle("native-only").use { handle ->
            val session = session(false, channel)
            session.configurePassphrase(handle, false)
            val call = async { session.getMasterFingerprint() }
            withTimeout(2000) { reached.await() }
            assertFailsWith<HwiException.BadState> { session.configurePassphrase(null, false) }
            call.cancelAndJoin()
            assertFailsWith<CancellationException> { call.await() }
            // The canceled command's owned clone is gone; the owner remains usable until teardown.
            Interp.newTrezor(Network.TESTNET, handle, false).close()
            session.configurePassphrase(null, true)
            assertFailsWith<HwiException.BadState> { Interp.newTrezor(Network.TESTNET, handle, false) }
            assertFailsWith<TransportException.Disconnected> { session.getMasterFingerprint() }
            assertEquals(1, writes)
            assertEquals(1, reads)
            session.disconnect()
            assertFailsWith<HwiException.BadState> { session.configurePassphrase(null, false) }
            assertFailsWith<HwiException.BadState> { session.getMasterFingerprint() }
        }
        val keepkey = session(true, channel)
        try { assertFailsWith<HwiException.InvalidInput> { keepkey.configurePassphrase(null, true) } }
        finally { keepkey.disconnect() }
    }

    @Test
    fun `registration descriptor display PIN positions and policy HMAC fail before device IO`() = runBlocking<Unit> {
        val channel = object : HidChannel {
            override suspend fun send(report: ByteArray): UInt = error("unsupported command reached device IO")
            override suspend fun receive(maxLen: UInt): ByteArray = error("unsupported command read device IO")
        }
        val descriptor = "wpkh([01020304/84'/1'/0']$TREZOR_XPUB/<0;1>/*)"
        for (keepkey in listOf(false, true)) {
            val session = session(keepkey, channel)
            try {
                assertFailsWith<HwiException.BadState> { session.getMasterFingerprint() }
                assertFailsWith<HwiException.BadState> { session.sendPin("1234") }
                session.configurePassphrase(null, false)
                assertFailsWith<HwiException.InvalidInput> { session.registerWallet("test_policy", descriptor) }
                assertFailsWith<HwiException.InvalidInput> {
                    session.displayDescriptorAddress(0u, false, true, WalletPolicy("test_policy", descriptor, null))
                }
                for (positions in listOf("", "0", "10", "１２", "pin-canary")) {
                    assertFailsWith<HwiException.InvalidInput> { session.sendPin(positions) }
                }
            } finally { session.disconnect() }
            fun interpreter() = if (keepkey) Interp.newKeepkey(Network.TESTNET, null)
                else Interp.newTrezor(Network.TESTNET, null, false)
            val psbt = "cHNidP8BAFICAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////ASgjAAAAAAAAFgAU" +
                "pasSNvKjbuZXEyy+ZWhJ1coWGksAAAAAAAEBHxAnAAAAAAAAFgAUpasSNvKjbuZXEyy+ZWhJ1coWGksAAA=="
            for (policy in listOf(WalletPolicy("test_policy", "invalid", null), WalletPolicy("test_policy", descriptor, ByteArray(32)))) {
                interpreter().use { interp ->
                    assertFailsWith<HwiException.InvalidInput> { interp.start(HwiCommand.SignPsbt(psbt, policy)) }
                }
            }
            interpreter().use { interp ->
                // A valid supplied policy is validated, but Trezor/KeepKey receive no foreign context.
                assertEquals(11, interp.start(HwiCommand.SignPsbt(psbt, WalletPolicy("test_policy", descriptor, null))).payload[3].toInt())
            }
        }
    }

    @Test
    fun `concrete origin keys reach the native multisig display route`() = runBlocking<Unit> {
        val keys = listOf(
            "[01020304/48'/1'/0'/2'/0/0]0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "[05060708/48'/1'/0'/2'/0/0]02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        )
        val address = "tb1qsynthetic_multisig_protocol_response"
        for (keepkey in listOf(false, true)) {
            val channel = V1ScriptChannel(listOf(29 to v1Frame(30, byteArrayOf(0x0a, address.length.toByte()) + address.encodeToByteArray())))
            val session = session(keepkey, channel)
            try {
                session.configurePassphrase(null, false)
                assertEquals(address, session.displayMultisigAddress(2u, true, MultisigAddressFormat.WIT, keys))
            }
            finally { session.disconnect() }
            channel.checkComplete()
        }
    }
}

class TrezorV1FramingTest {
    @Test
    fun `invalid requests preserve readiness and complete responses permit reuse`() = runBlocking<Unit> {
        val request = v1Frame(11)
        val answer = v1Frame(12, ByteArray(100))
        val channel = RecordingHidChannel(v1Reports(answer) + v1Reports(answer))
        val link = TrezorV1Link(channel)
        assertFailsWith<TransportException.Io> { link.exchange(ByteArray(0), false) }
        assertTrue(channel.writes.isEmpty())
        repeat(2) { assertEquals(answer.hex(), link.exchange(request, false).hex()) }
        assertEquals(2, channel.writes.size)
    }

    @Test
    fun `partial writes malformed packets and truncated replies retire before further channel IO`() = runBlocking<Unit> {
        val request = v1Frame(11)
        val response = v1Reports(v1Frame(12, ByteArray(100)))
        for (failure in listOf("partial-write", "malformed", "truncated")) {
            var writes = 0
            var reads = 0
            val replies = ArrayDeque(response)
            val channel = object : HidChannel {
                override suspend fun send(report: ByteArray): UInt {
                    writes++
                    return if (failure == "partial-write") 63u else 64u
                }
                override suspend fun receive(maxLen: UInt): ByteArray {
                    reads++
                    if (failure == "malformed") return ByteArray(64)
                    if (failure == "truncated" && reads == 2) return response[1].copyOf(63)
                    return replies.removeFirst()
                }
            }
            val link = TrezorV1Link(channel)
            assertFailsWith<TransportException.Io> { link.exchange(request, false) }
            val retiredReads = reads
            assertFailsWith<TransportException.Disconnected> { link.exchange(request, false) }
            assertEquals(1, writes)
            assertEquals(retiredReads, reads)
        }
    }

    @Test
    fun `interrupted write and concurrent exchange fail closed before a delayed reply`() = runBlocking<Unit> {
        val entered = CompletableDeferred<Unit>()
        var writes = 0
        var reads = 0
        val channel = object : HidChannel {
            override suspend fun send(report: ByteArray): UInt {
                writes++
                entered.complete(Unit)
                awaitCancellation()
            }
            override suspend fun receive(maxLen: UInt): ByteArray { reads++; return v1Reports(v1Frame(12)).single() }
        }
        val link = TrezorV1Link(channel)
        val first = async { link.exchange(v1Frame(11), false) }
        withTimeout(2000) { entered.await() }
        assertFailsWith<TransportException.Disconnected> { link.exchange(v1Frame(11), false) }
        first.cancelAndJoin()
        assertFailsWith<CancellationException> { first.await() }
        assertFailsWith<TransportException.Disconnected> { link.exchange(v1Frame(11), false) }
        assertEquals(1, writes)
        assertEquals(0, reads)
    }

    @Test
    fun `V1 framing strips padding and zero pads every outgoing packet at all boundaries`() = runBlocking<Unit> {
        for (size in listOf(0, 1, 55, 56, 63, 64, 200, 65_536)) {
            val request = v1Frame(11, ByteArray(size) { (it % 251).toByte() })
            val answer = v1Frame(12, ByteArray(size) { ((it + 7) % 251).toByte() })
            val channel = RecordingHidChannel(v1Reports(answer))
            assertEquals(answer.hex(), TrezorV1Link(channel).exchange(request, false).hex())
            assertEquals(v1Reports(request).map { it.hex() }, channel.writes.map { it.hex() })
        }
    }

    @Test
    fun `V1 rejects short oversized wrong-prefix wrong-magic oversized-body and truncated packets`() = runBlocking<Unit> {
        val request = v1Frame(11)
        val first = v1Reports(v1Frame(12)).single()
        val oversized = first.copyOf().also { "00010001".unhex().copyInto(it, 5) }
        val unsignedOverflow = first.copyOf().also { "ffffffff".unhex().copyInto(it, 5) }
        for (packet in listOf(first.copyOf(63), first.copyOf(65), first.copyOf().also { it[0] = 0 },
            first.copyOf().also { it[1] = 0 }, oversized, unsignedOverflow)) {
            assertFailsWith<TransportException.Io> { TrezorV1Link(RecordingHidChannel(listOf(packet))).exchange(request, false) }
        }
        val chunks = v1Reports(v1Frame(12, ByteArray(100)))
        assertFailsWith<TransportException.Io> {
            TrezorV1Link(RecordingHidChannel(listOf(chunks[0], chunks[1].also { it[0] = 0 }))).exchange(request, false)
        }
        assertFailsWith<TransportException.Disconnected> {
            TrezorV1Link(RecordingHidChannel(chunks.take(1))).exchange(request, false)
        }
        for (written in listOf(0u, 63u, 65u)) {
            val partial = object : HidChannel {
                override suspend fun send(report: ByteArray): UInt = written
                override suspend fun receive(maxLen: UInt): ByteArray = error("incomplete write attempted a read")
            }
            assertFailsWith<TransportException.Io> { TrezorV1Link(partial).exchange(request, false) }
        }
        for (bad in listOf(byteArrayOf(), v1Frame(11).also { it[0] = 0 }, v1Frame(11).also { it[7] = 1 }, v1Frame(11, ByteArray(65_537)))) {
            val channel = RecordingHidChannel(emptyList())
            assertFailsWith<TransportException.Io> { TrezorV1Link(channel).exchange(bad, false) }
            assertTrue(channel.writes.isEmpty())
        }
    }
}

