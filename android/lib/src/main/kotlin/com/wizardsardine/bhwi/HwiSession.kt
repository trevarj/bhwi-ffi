package com.wizardsardine.bhwi

import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import uniffi.bhwi_ffi.AddressFormat
import uniffi.bhwi_ffi.ColdcardEncryption
import uniffi.bhwi_ffi.HostPassphraseHandle
import uniffi.bhwi_ffi.HwiCommand
import uniffi.bhwi_ffi.HwiException
import uniffi.bhwi_ffi.HwiResponse
import uniffi.bhwi_ffi.Interp
import uniffi.bhwi_ffi.MultisigAddressFormat
import uniffi.bhwi_ffi.Network
import uniffi.bhwi_ffi.NoiseConfig
import uniffi.bhwi_ffi.NoiseHandle
import uniffi.bhwi_ffi.WalletPolicy
import uniffi.bhwi_ffi.WalletRegistration

/**
 * A connected device: one command at a time, over one [Link].
 *
 * Convenience over the raw interpreter API — each call builds a fresh `Interp`, drives it
 * with [Hwi.runCommand] and unwraps the typed response. The device state that has to
 * survive a command (BitBox02 noise pairing, Coldcard link encryption) is owned here, and
 * the mutex is what keeps a second command from trying to lease it mid-flight.
 *
 * Suspend commands and pairing export are main-safe. The synchronous factories remain
 * worker-only, as do generated UniFFI constructors, methods and helpers.
 *
 * Errors come through as they are: `HwiException` from the protocol layer,
 * [TransportException] from the host transport. Coroutine cancellation remains
 * `CancellationException`; [TransportException.Cancelled] is a separate adapter error.
 */
class HwiSession private constructor(
    private val newInterp: (() -> Interp)?,
    private val link: Link,
    private val http: HttpBridge? = null,
    private val noise: NoiseHandle? = null,
    private val coldcard: ColdcardEncryption? = null,
    private val onPairingCode: ((String) -> Unit)? = null,
    private val pinFamily: PinFamily? = null,
    private val network: Network? = null,
) {
    /** Serialises commands: the state handles can only be leased by one `Interp` at a time. */
    private val lock = Mutex()
    private val closed = AtomicBoolean(false)
    private var passphrase: HostPassphraseHandle? = null
    private var onDevicePassphrase = false
    private var passphraseConfigured = false

    private enum class PinFamily { TREZOR, KEEPKEY }

    /**
     * Worker-only. Choose the passphrase mode before requesting an account. Null/false
     * means an explicitly selected Standard wallet, not an unanswered passphrase choice.
     * The session clears the supplied native owner on replacement/disconnect; the caller
     * must not share, clear or close it while configured. Managed input Strings are not erased.
     */
    @Synchronized
    fun configurePassphrase(handle: HostPassphraseHandle?, onDevice: Boolean) {
        if (!lock.tryLock()) throw HwiException.BadState("a command is running")
        try {
            requireOpen()
            val family = pinFamily ?: throw HwiException.BadState("this session has no passphrase options")
            if (family == PinFamily.KEEPKEY && onDevice) {
                throw HwiException.InvalidInput("KeepKey does not support on-device passphrase entry")
            }
            if (onDevice && handle != null) {
                throw HwiException.InvalidInput("choose host or on-device passphrase entry")
            }
            // Generated method calls guard destroyed wrappers; constructor argument lowering does not.
            handle?.validate()
            if (passphrase !== handle) passphrase?.clear()
            passphrase = handle
            onDevicePassphrase = onDevice
            passphraseConfigured = true
        } finally {
            lock.unlock()
        }
    }

    /** Model capability, not the generic locked flag or passphrase-entry capability. */
    fun supportsHostPin(info: HwiResponse.Info): Boolean = when (pinFamily) {
        PinFamily.KEEPKEY -> true
        PinFamily.TREZOR -> when (info.firmware) {
            null, "1" -> true
            "T" -> false
            else -> throw HwiException.InvalidInput("unsupported Trezor model")
        }
        null -> false
    }

    /** Keep the physical channel open between the prompt and its positions acknowledgment. */
    suspend fun promptPin(): Boolean =
        (run(HwiCommand.PromptPin) as? HwiResponse.DeviceAction)?.success ?: unexpected()

    /** Positions 1–9 on a blank keypad; rejected PINs and authentication cancellation throw AuthRefused. */
    suspend fun sendPin(positions: String): Boolean =
        (run(HwiCommand.SendPin(positions)) as? HwiResponse.DeviceAction)?.success ?: unexpected()

    /** Trezor/KeepKey return their actual Info; other unlock results remain device-specific. */
    suspend fun unlock(network: Network): HwiResponse = try {
        run(HwiCommand.Unlock(network))
    } catch (_: HwiException.DeviceAlreadyUnlocked) {
        // This typed outcome is benign only for unlock; do not invent an Info response.
        HwiResponse.TaskDone
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

    suspend fun registerWallet(name: String, descriptor: String): WalletRegistration =
        (run(HwiCommand.RegisterWallet(name, descriptor)) as? HwiResponse.WalletRegistration)?.registration
            ?: unexpected()

    suspend fun displayDescriptorAddress(
        index: UInt,
        change: Boolean,
        display: Boolean,
        walletPolicy: WalletPolicy,
    ): String =
        (run(HwiCommand.DisplayDescriptorAddress(index, change, display, walletPolicy)) as? HwiResponse.Address)?.address
            ?: unexpected()

    suspend fun displayMultisigAddress(
        threshold: UByte,
        sorted: Boolean,
        format: MultisigAddressFormat,
        keys: List<String>,
    ): String =
        (run(HwiCommand.DisplayMultisigAddress(threshold, sorted, format, keys)) as? HwiResponse.Address)?.address
            ?: unexpected()

    /**
     * Returns the standard `signmessage` base64: header byte followed by the 64-byte
     * compact signature.
     */
    suspend fun signMessage(message: ByteArray, path: String): String =
        (run(HwiCommand.SignMessage(message, path)) as? HwiResponse.MessageSignature)?.base64 ?: unexpected()

    /** Returns the complete PSBT, retaining partial signatures; never finalizes or broadcasts. */
    suspend fun signPsbt(psbtBase64: String, walletPolicy: WalletPolicy?): String =
        (run(HwiCommand.SignPsbt(psbtBase64, walletPolicy)) as? HwiResponse.SignedPsbt)?.psbtBase64 ?: unexpected()

    /**
     * The BitBox02 pairing material to persist, so the next session skips the on-screen
     * confirmation. Call it after a successful [unlock]; pass it back as `noiseConfig`.
     */
    suspend fun bitboxPairing(): NoiseConfig = withContext(Dispatchers.IO) {
        lock.withLock {
            ensureActive()
            requireOpen()
            val handle = noise ?: throw HwiException.BadState("this session has no BitBox02 pairing state")
            handle.export()
        }
    }

    /**
     * Idempotent. Closes the facade and releases its state-handle references; later calls
     * fail with `HwiException.BadState`.
     *
     * The transport belongs to the caller and is left alone. This synchronous method is
     * outside the command mutex: it does not own/cancel an operation Job, unblock platform
     * I/O, or guarantee that an in-flight command cannot finish.
     *
     * For teardown, cancel the operation, unblock caller-owned platform I/O if needed,
     * join the operation, disconnect (clearing its native passphrase owner), then dispose
     * the transport. Managed input Strings and already-running clones are not erased here.
     */
    @Synchronized
    fun disconnect() {
        if (closed.compareAndSet(false, true)) {
            noise?.close()
            coldcard?.close()
            passphrase?.clear()
            passphrase = null
        }
    }

    private suspend fun run(cmd: HwiCommand): HwiResponse = withContext(Dispatchers.IO) {
        lock.withLock {
            ensureActive()
            requireOpen()
            val pairing = noise?.let { handle -> onPairingCode?.let { Hwi.Pairing(handle, it) } }
            try {
                Hwi.runCommand(createInterp(cmd), cmd, link, http, pairing)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e // extends IllegalStateException; must not be remapped
            } catch (e: IllegalStateException) {
                // disconnect() racing an in-flight command destroys the state handles under
                // the loop; surface that as the typed post-disconnect error, not a uniffi ISE.
                if (closed.get()) throw HwiException.BadState("session is disconnected") else throw e
            }
        }
    }

    @Synchronized
    private fun createInterp(cmd: HwiCommand): Interp {
        requireOpen()
        if (pinFamily != null && !passphraseConfigured && when (cmd) {
            is HwiCommand.SendPin, HwiCommand.GetMasterFingerprint, is HwiCommand.GetXpub,
            is HwiCommand.DisplayAddress, is HwiCommand.DisplayMultisigAddress,
            is HwiCommand.SignMessage, is HwiCommand.SignPsbt -> true
            else -> false
        }) throw HwiException.BadState("choose a passphrase mode before requesting an account")
        return when (pinFamily) {
            PinFamily.TREZOR -> Interp.newTrezor(requireNotNull(network), passphrase, onDevicePassphrase)
            PinFamily.KEEPKEY -> Interp.newKeepkey(requireNotNull(network), passphrase)
            null -> requireNotNull(newInterp).invoke()
        }
    }

    private fun requireOpen() {
        if (closed.get()) throw HwiException.BadState("session is disconnected")
    }

    /** The crate validates the response kind per command, so this is a bindings bug. */
    private fun unexpected(): Nothing =
        throw HwiException.Internal("the device answered with an unexpected response kind")

    /**
     * Synchronous, worker-only factories. [coldcardUsb] generates native key material and
     * [bitboxUsb] restores native state; the other factories defer native initialization.
     */
    companion object {
        fun ledgerUsb(hid: HidChannel): HwiSession =
            HwiSession({ Interp.newLedger() }, LedgerHidLink(hid))

        fun ledgerBle(ble: BleChannel): HwiSession =
            HwiSession({ Interp.newLedger() }, LedgerBleLink(ble))

        /** HID and vendor-class WebUSB both supply the same physical packet channel. */
        fun trezorUsb(channel: HidChannel, network: Network): HwiSession =
            HwiSession(null, TrezorV1Link(channel), pinFamily = PinFamily.TREZOR, network = network)

        fun keepkeyUsb(channel: HidChannel, network: Network): HwiSession =
            HwiSession(null, TrezorV1Link(channel), pinFamily = PinFamily.KEEPKEY, network = network)

        fun specterUsb(stream: SerialStream, network: Network): HwiSession =
            HwiSession({ Interp.newSpecter(network) }, SpecterSerialLink(stream))

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
