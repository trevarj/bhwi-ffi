package com.wizardsardine.bhwi

import kotlin.test.assertFailsWith
import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.bhwi_ffi.AddressFormat
import uniffi.bhwi_ffi.HwiException
import uniffi.bhwi_ffi.Network
import uniffi.bhwi_ffi.buildSinglesigDescriptor
import uniffi.bhwi_ffi.deriveAddresses
import uniffi.bhwi_ffi.psbtSummary

/**
 * Device-free helpers. The expected values are the vectors the Rust unit tests in
 * `bhwi-ffi/src/helpers.rs` build from the same xpub, so any drift fails on both sides.
 */
class HelpersTest {
    private val xpub =
        "tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP"
    private val fingerprint = "f5acc2fd"
    private val descriptor =
        "wpkh([f5acc2fd/84'/1'/0']$xpub/<0;1>/*)#lyhjujaa"

    /** One P2WPKH input worth 10_000 sat, one 9_000 sat output: 1_000 sat fee. */
    private val psbt =
        "cHNidP8BAFICAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////ASgjAAAAAAAAFgAU" +
            "pasSNvKjbuZXEyy+ZWhJ1coWGksAAAAAAAEBHxAnAAAAAAAAFgAUpasSNvKjbuZXEyy+ZWhJ1coWGksAAA=="

    @Test
    fun `descriptor matches the rust vector`() {
        assertEquals(
            descriptor,
            buildSinglesigDescriptor(
                xpub,
                fingerprint,
                "m/84'/1'/0'",
                AddressFormat.NATIVE_SEGWIT,
                Network.TESTNET,
            ),
        )
    }

    @Test
    fun `descriptor rejects a network mismatch`() {
        assertFailsWith<HwiException.InvalidInput> {
            buildSinglesigDescriptor(
                xpub,
                fingerprint,
                "m/84'/0'/0'",
                AddressFormat.NATIVE_SEGWIT,
                Network.BITCOIN,
            )
        }
    }

    @Test
    fun `derives both branches`() {
        assertEquals(
            listOf(
                "tb1q5k43ydhj5dhwv4cn9jlx26zf6h9pvxjtz54x2r",
                "tb1qzr9ck7ftmxy53n6j0vyc6whu6t4l3pekepj0kl",
                "tb1qqpz363h2zgm8acq8c5sss9ek58w9da7v9lsr7e",
            ),
            deriveAddresses(descriptor, Network.TESTNET, false, 0u, 3u).map { it.address },
        )
        assertEquals(
            listOf(
                "tb1qg48n3y5zr0k4fvp03wfa9w6kfuuc3jy0au8mc2",
                "tb1qswhr3nt6kn4794fywgjynp3h4f9ua3xmhzwk68",
                "tb1q64gulf8mkuxschy82a6pe05t5laljtdt5w7ehf",
            ),
            deriveAddresses(descriptor, Network.TESTNET, true, 0u, 3u).map { it.address },
        )
        assertEquals(listOf(0u, 1u, 2u), deriveAddresses(descriptor, Network.TESTNET, false, 0u, 3u).map { it.index })
    }

    @Test
    fun `derive rejects an oversized count`() {
        assertFailsWith<HwiException.InvalidInput> {
            deriveAddresses(descriptor, Network.TESTNET, false, 0u, 1001u)
        }
    }

    @Test
    fun `psbt summary reports amounts and fee`() {
        val summary = psbtSummary(psbt, Network.TESTNET)
        assertEquals(1, summary.inputs.size)
        assertEquals(
            "0000000000000000000000000000000000000000000000000000000000000000",
            summary.inputs[0].prevTxid,
        )
        assertEquals(0u, summary.inputs[0].vout)
        assertEquals(10_000uL, summary.inputs[0].amountSat)
        assertEquals(1, summary.outputs.size)
        assertEquals("tb1q5k43ydhj5dhwv4cn9jlx26zf6h9pvxjtz54x2r", summary.outputs[0].address)
        assertEquals(9_000uL, summary.outputs[0].amountSat)
        assertEquals(1_000uL, summary.feeSat)
    }

    @Test
    fun `psbt summary rejects garbage`() {
        assertFailsWith<HwiException.InvalidInput> { psbtSummary("not base64!", Network.TESTNET) }
    }
}
