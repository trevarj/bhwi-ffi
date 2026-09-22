package com.wizardsardine.bhwi

import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import uniffi.bhwi_ffi.AddressFormat
import uniffi.bhwi_ffi.ColdcardEncryption
import uniffi.bhwi_ffi.HwiCommand
import uniffi.bhwi_ffi.HwiException
import uniffi.bhwi_ffi.HwiResponse
import uniffi.bhwi_ffi.Interp
import uniffi.bhwi_ffi.Network
import uniffi.bhwi_ffi.NoiseConfig
import uniffi.bhwi_ffi.NoiseHandle

/**
 * A connected device: one command at a time, over one [Link].
 *
 * Convenience over the raw interpreter API — each call builds a fresh `Interp`, drives it
 * with [Hwi.runCommand] and unwraps the typed response. The device state that has to
 * survive a command (BitBox02 noise pairing, Coldcard link encryption) is owned here, and
 * the mutex is what keeps a second command from trying to lease it mid-flight.
 *
 * Errors come through as they are: `HwiException` from the protocol layer,
 * [TransportException] from the host transport.
 */
class HwiSession private constructor(
    private val newInterp: () -> Interp,
    private val link: Link,
    private val http: HttpBridge? = null,
    private val noise: NoiseHandle? = null,
    private val coldcard: ColdcardEncryption? = null,
    private val onPairingCode: ((String) -> Unit)? = null,
) {
    /** Serialises commands: the state handles can only be leased by one `Interp` at a time. */
    private val lock = Mutex()
    private val closed = AtomicBoolean(false)

    /** Ledger: opens the Bitcoin app. Jade/BitBox/Coldcard: authenticates the device. */
    suspend fun unlock(network: Network) {
        run(HwiCommand.Unlock(network))
    }

    suspend fun getInfo(): HwiResponse.Info =
        run(HwiCommand.GetVersion) as? HwiResponse.Info ?: unexpected()

    suspend fun getMasterFingerprint(): String =
        (run(HwiCommand.GetMasterFingerprint) as? HwiResponse.Fingerprint)?.hex ?: unexpected()

    suspend fun getExtendedPubkey(path: String, display: Boolean): String =
        (run(HwiCommand.GetXpub(path, display)) as? HwiResponse.Xpub)?.xpub ?: unexpected()

    suspend fun displayAddress(path: String, display: Boolean, addressFormat: AddressFormat?): String =
        (run(HwiCommand.DisplayAddress(path, display, addressFormat)) as? HwiResponse.Address)?.address
            ?: unexpected()

    /**
     * Returns the standard `signmessage` base64: header byte followed by the 64-byte
     * compact signature.
     */
    suspend fun signMessage(message: ByteArray, path: String): String =
        (run(HwiCommand.SignMessage(message, path)) as? HwiResponse.MessageSignature)?.base64 ?: unexpected()

    suspend fun signPsbt(psbtBase64: String): String =
        (run(HwiCommand.SignPsbt(psbtBase64)) as? HwiResponse.SignedPsbt)?.psbtBase64 ?: unexpected()

    /**
     * The BitBox02 pairing material to persist, so the next session skips the on-screen
     * confirmation. Call it after a successful [unlock]; pass it back as `noiseConfig`.
     */
    suspend fun bitboxPairing(): NoiseConfig = lock.withLock {
        requireOpen()
        val handle = noise ?: throw HwiException.BadState("this session has no BitBox02 pairing state")
        handle.export()
    }

    /**
     * Idempotent. Releases the device state handles; later calls fail with
     * `HwiException.BadState`.
     *
     * The transport itself belongs to the caller and is left alone. Deliberately not
     * suspending and not behind the mutex, so it never blocks on an in-flight command.
     */
    fun disconnect() {
        if (closed.compareAndSet(false, true)) {
            noise?.close()
            coldcard?.close()
        }
    }

    private suspend fun run(cmd: HwiCommand): HwiResponse = lock.withLock {
        requireOpen()
        val pairing = noise?.let { handle -> onPairingCode?.let { Hwi.Pairing(handle, it) } }
        try {
            Hwi.runCommand(newInterp(), cmd, link, http, pairing)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e // extends IllegalStateException; must not be remapped
        } catch (e: IllegalStateException) {
            // disconnect() racing an in-flight command destroys the state handles under
            // the loop; surface that as the typed post-disconnect error, not a uniffi ISE.
            if (closed.get()) throw HwiException.BadState("session is disconnected") else throw e
        }
    }

    private fun requireOpen() {
        if (closed.get()) throw HwiException.BadState("session is disconnected")
    }

    /** The crate validates the response kind per command, so this is a bindings bug. */
    private fun unexpected(): Nothing =
        throw HwiException.Internal("the device answered with an unexpected response kind")

    companion object {
        fun ledgerUsb(hid: HidChannel): HwiSession =
            HwiSession({ Interp.newLedger() }, LedgerHidLink(hid))

        fun ledgerBle(ble: BleChannel): HwiSession =
            HwiSession({ Interp.newLedger() }, LedgerBleLink(ble))

        fun coldcardUsb(hid: HidChannel): HwiSession {
            // One encryption engine per physical connection; the session key is installed
            // inside it by `unlock`.
            val encryption = ColdcardEncryption()
            return HwiSession(
                { Interp.newColdcard(encryption) },
                ColdcardHidLink(hid),
                coldcard = encryption,
            )
        }

        /**
         * [noiseConfig] restores previously persisted pairing material (see
         * [bitboxPairing]); pass `null` to pair from scratch.
         */
        fun bitboxUsb(
            hid: HidChannel,
            network: Network,
            onPairingCode: (String) -> Unit,
            noiseConfig: NoiseConfig? = null,
        ): HwiSession {
            val noise = NoiseHandle(noiseConfig)
            return HwiSession(
                { Interp.newBitbox(noise, network) },
                BitBoxHidLink(hid),
                noise = noise,
                onPairingCode = onPairingCode,
            )
        }

        fun jadeUsb(serial: SerialStream, http: HttpBridge, network: Network): HwiSession =
            HwiSession({ Interp.newJade(network) }, JadeSerialLink(serial), http)

        /** Jade over BLE speaks the same CBOR stream as over USB serial. */
        fun jadeBle(serial: SerialStream, http: HttpBridge, network: Network): HwiSession =
            HwiSession({ Interp.newJade(network) }, JadeSerialLink(serial), http)
    }
}
