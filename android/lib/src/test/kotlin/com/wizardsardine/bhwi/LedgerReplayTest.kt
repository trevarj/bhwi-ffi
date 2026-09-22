package com.wizardsardine.bhwi

import kotlin.test.assertFailsWith
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.bhwi_ffi.HwiException

/**
 * Report-level replay: the Kotlin Ledger HID framing plus the real interpreter, against
 * transcripts recorded from `bhwi-async`'s own transport. Any framing drift shows up as a
 * write mismatch, so this is the parity gate for [LedgerHidLink].
 */
class LedgerReplayTest {
    private val accountPath = "m/84'/1'/0'"
    private val addressPath = "m/84'/1'/0'/0/0"

    @Test
    fun `master fingerprint replays the recorded transcript`() = runBlocking<Unit> {
        val fixture = Fixture.load("ledger_get_master_fingerprint.json")
        val channel = ReplayHidChannel(fixture)
        val session = HwiSession.ledgerUsb(channel)
        try {
            assertEquals(fixture.expected, session.getMasterFingerprint())
        } finally {
            session.disconnect()
        }
        channel.check()
    }

    @Test
    fun `extended pubkey replays the recorded transcript`() = runBlocking<Unit> {
        val fixture = Fixture.load("ledger_get_xpub.json")
        val channel = ReplayHidChannel(fixture)
        val session = HwiSession.ledgerUsb(channel)
        try {
            assertEquals(fixture.expected, session.getExtendedPubkey(accountPath, false))
        } finally {
            session.disconnect()
        }
        channel.check()
    }

    /** Also the multi-report case: the address APDU spans two 64-byte writes. */
    @Test
    fun `a denied address display surfaces as UserRefused`() = runBlocking<Unit> {
        val fixture = Fixture.load("ledger_refused.json")
        val channel = ReplayHidChannel(fixture)
        val session = HwiSession.ledgerUsb(channel)
        try {
            assertFailsWith<HwiException.UserRefused> {
                session.displayAddress(addressPath, true, null)
            }
        } finally {
            session.disconnect()
        }
        channel.check()
    }

    @Test
    fun `a channel io failure surfaces as TransportException`() = runBlocking<Unit> {
        val session = HwiSession.ledgerUsb(ThrowingHidChannel(TransportException.Io("write failed")))
        try {
            assertFailsWith<TransportException.Io> { session.getMasterFingerprint() }
        } finally {
            session.disconnect()
        }
    }

    @Test
    fun `an unplugged channel surfaces as Disconnected`() = runBlocking<Unit> {
        val session = HwiSession.ledgerUsb(ThrowingHidChannel(TransportException.Disconnected()))
        try {
            assertFailsWith<TransportException.Disconnected> { session.getMasterFingerprint() }
        } finally {
            session.disconnect()
        }
    }
}

/** Fails every operation with a fixed transport error. */
class ThrowingHidChannel(private val error: TransportException) : HidChannel {
    override suspend fun send(report: ByteArray): UInt = throw error
    override suspend fun receive(maxLen: UInt): ByteArray = throw error
}
