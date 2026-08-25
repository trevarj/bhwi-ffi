package com.wizardsardine.bhwi

/**
 * Just enough CBOR to tell a complete top-level value from a truncated one, which is all
 * Jade's stream framing needs: a structural walk over headers, never a decode.
 *
 * `bhwi-async` gets the same answer by handing the buffer to `serde_cbor` and treating an
 * EOF error as "read more"; the semantics mirrored here are exactly that, including
 * tolerating trailing bytes after the first complete value.
 */
internal object Cbor {
    /** [endOfValue] could not finish: more bytes are needed. */
    const val INCOMPLETE = -1

    /** Structurally invalid CBOR — reading more bytes cannot fix it. */
    class MalformedException(message: String) : TransportException("jade: malformed CBOR, $message")

    /** Whether [buf] starts with one complete CBOR value. */
    fun isComplete(buf: ByteArray): Boolean = endOfValue(buf, 0, buf.size) != INCOMPLETE

    /** Index just past the value starting at [at], or [INCOMPLETE]. */
    fun endOfValue(buf: ByteArray, at: Int, end: Int): Int {
        if (at >= end) return INCOMPLETE
        val initial = buf[at].toInt() and 0xff
        val major = initial shr 5
        val info = initial and 0x1f
        var pos = at + 1
        val value: Long

        when {
            info < 24 -> value = info.toLong()
            info <= 27 -> {
                val width = 1 shl (info - 24)
                if (pos + width > end) return INCOMPLETE
                var read = 0L
                for (i in 0 until width) read = (read shl 8) or (buf[pos + i].toLong() and 0xff)
                pos += width
                value = read
            }
            info == 31 -> return when (major) {
                // Strings are a run of definite chunks; arrays and maps a run of values.
                // Both end at a break, and both are only legal for these major types.
                2, 3 -> endOfChunks(buf, pos, end, major)
                4, 5 -> endOfItems(buf, pos, end)
                else -> throw MalformedException("indefinite length for major type $major")
            }
            else -> throw MalformedException("reserved additional information $info")
        }

        // For the length-carrying major types, every remaining byte or item needs at least
        // one byte of input, so anything past the end of the buffer is unreachable with what
        // we have. The guard also keeps the 64-bit header values (and a `u64` length that
        // reads back negative) out of the Int arithmetic below.
        fun bounded(next: (Int) -> Int): Int =
            if (value < 0 || value > end - pos) INCOMPLETE else next(value.toInt())

        return when (major) {
            // Integers and simple/float values are header-only; `value` is their payload,
            // not a length, so it must not be range-checked.
            0, 1, 7 -> pos
            2, 3 -> bounded { length -> pos + length }
            4 -> bounded { items -> endOfItems(buf, pos, end, items) }
            5 -> bounded { pairs -> endOfItems(buf, pos, end, pairs * 2) }
            else -> endOfValue(buf, pos, end) // major 6: a tag wraps exactly one value
        }
    }

    /** Definite-length chunks of major type [major] up to a break byte. */
    private fun endOfChunks(buf: ByteArray, from: Int, end: Int, major: Int): Int {
        var pos = from
        while (true) {
            if (pos >= end) return INCOMPLETE
            val initial = buf[pos].toInt() and 0xff
            if (initial == BREAK) return pos + 1
            if ((initial shr 5) != major) throw MalformedException("chunk of the wrong major type")
            if ((initial and 0x1f) == 31) throw MalformedException("nested indefinite string")
            pos = endOfValue(buf, pos, end)
            if (pos == INCOMPLETE) return INCOMPLETE
        }
    }

    /** [count] values, or — when [count] is negative — values up to a break byte. */
    private fun endOfItems(buf: ByteArray, from: Int, end: Int, count: Int = -1): Int {
        var pos = from
        var left = count
        while (left != 0) {
            if (pos >= end) return INCOMPLETE
            if (count < 0 && (buf[pos].toInt() and 0xff) == BREAK) return pos + 1
            pos = endOfValue(buf, pos, end)
            if (pos == INCOMPLETE) return INCOMPLETE
            left--
        }
        return pos
    }

    private const val BREAK = 0xff
}
