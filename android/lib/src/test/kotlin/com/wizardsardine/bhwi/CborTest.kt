package com.wizardsardine.bhwi

import java.util.ArrayDeque
import kotlin.test.assertFailsWith
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The completeness scanner Jade's stream framing runs on every read. It has to agree with
 * `serde_cbor`'s "is this an EOF or a real error" answer, which is what `bhwi-async` uses.
 */
class CborTest {
    private fun complete(hex: String) =
        assertTrue("expected complete: $hex", Cbor.isComplete(hex.unhex()))

    private fun incomplete(hex: String) =
        assertFalse("expected incomplete: $hex", Cbor.isComplete(hex.unhex()))

    @Test
    fun `definite lengths`() {
        complete("00") // 0
        complete("182a") // 42 in one extra byte
        complete("1a0000002a") // 42 in four extra bytes
        complete("43010203") // bytes(3)
        complete("63616263") // "abc"
        complete("83010203") // [1, 2, 3]
        complete("a10102") // {1: 2}
        complete("80") // []
        complete("a0") // {}
    }

    @Test
    fun `truncated values are incomplete, not malformed`() {
        incomplete("") // nothing at all
        incomplete("18") // header announces one more byte
        incomplete("1b00000000000000") // eight-byte header, seven bytes there
        incomplete("430102") // bytes(3) with two bytes
        incomplete("830102") // [1, 2, 3] with two items
        incomplete("a101") // {1: 2} with the value missing
        incomplete("c0") // a tag with nothing to tag
    }

    @Test
    fun `header payloads are not mistaken for lengths`() {
        // The regression these guard: a `u64` or a float carries eight bytes of *value*,
        // which must not be range-checked against what is left in the buffer.
        complete("1bffffffffffffffff") // 18446744073709551615
        complete("fbffffffffffffffff") // a float64
        complete("f97e00") // a float16
        complete("f5") // true
    }

    @Test
    fun `indefinite lengths`() {
        complete("9f010203ff") // [_ 1, 2, 3]
        incomplete("9f010203") // ... missing the break
        complete("bf616101616202ff") // {_ "a": 1, "b": 2}
        incomplete("bf616101") // ... mid-pair
        complete("5f42010243030405ff") // (_ h'0102', h'030405')
        incomplete("5f420102") // ... missing the break
    }

    @Test
    fun `nested containers`() {
        complete("a161619f8101ff") // {"a": [_ [1]]}
        incomplete("a161619f8101") // ... missing the break
        complete("826161a1616201") // ["a", {"b": 1}]
        incomplete("826161a16162") // ... missing the map value
        complete("c1821a514b67b01a514b67b0") // a tagged array of two u32
    }

    @Test
    fun `a value is complete even with trailing bytes`() {
        // `read_cbor_message` returns everything it read, so a value followed by the start
        // of the next one still counts as complete.
        complete("0018")
    }

    @Test
    fun `structurally invalid cbor is rejected outright`() {
        // Reserved additional information, and indefinite lengths where they are illegal.
        for (hex in listOf("1c", "1f", "3f", "df")) {
            assertFailsWith<Cbor.MalformedException>("expected malformed: $hex") {
                Cbor.isComplete(hex.unhex())
            }
        }
    }

    @Test
    fun `every prefix of a value is incomplete and the whole value is complete`() {
        val value = "a2646e616d656570692d5f5f656974656d739f0102182aff".unhex()
        for (length in 1 until value.size) {
            assertFalse("prefix of $length bytes", Cbor.isComplete(value.copyOf(length)))
        }
        assertTrue(Cbor.isComplete(value))
    }
}

/** The Jade link on top of the scanner: read until the value is whole, EOF is fatal. */
class JadeSerialLinkTest {
    private class ScriptedSerial(chunks: List<ByteArray>) : SerialStream {
        val written = mutableListOf<ByteArray>()
        private val chunks = ArrayDeque(chunks)

        override suspend fun writeAll(data: ByteArray) {
            written += data.copyOf()
        }

        override suspend fun read(maxLen: UInt): ByteArray = chunks.pollFirst() ?: ByteArray(0)
    }

    @Test
    fun `a message split across reads is reassembled`() = runBlocking<Unit> {
        val message = "a16269641a0000002a".unhex() // {"id": 42}, delivered in three pieces
        val stream = ScriptedSerial(
            listOf(message.copyOfRange(0, 3), message.copyOfRange(3, 6), message.copyOfRange(6, 9)),
        )
        assertEquals(message.hex(), JadeSerialLink(stream).exchange("0102".unhex(), false).hex())
        assertEquals(listOf("0102"), stream.written.map { it.hex() })
    }

    @Test
    fun `an empty read before the message is complete is end of stream`() = runBlocking<Unit> {
        val stream = ScriptedSerial(listOf("a26269".unhex()))
        val error = assertFailsWith<TransportException.Io> {
            JadeSerialLink(stream).exchange("0102".unhex(), false)
        }
        assertEquals("stream ended before complete CBOR message", error.msg)
    }
}
