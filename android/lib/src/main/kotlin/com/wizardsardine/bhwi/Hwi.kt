package com.wizardsardine.bhwi

import uniffi.bhwi_ffi.HwiCommand
import uniffi.bhwi_ffi.HwiException
import uniffi.bhwi_ffi.HwiResponse
import uniffi.bhwi_ffi.Interp
import uniffi.bhwi_ffi.NoiseHandle
import uniffi.bhwi_ffi.Recipient
import uniffi.bhwi_ffi.Transmit

/**
 * The driving loop over the sans-io interpreter: `start` -> (send / receive / `exchange`)*
 * -> `end`.
 *
 * This is the raw layer. Use it when you want to own the `Interp` and the state handles
 * yourself; [HwiSession] is the same loop with the per-device wiring already done.
 */
object Hwi {
    /**
     * BitBox02 pairing-code plumbing: the handle to poll and where to deliver a new code.
     *
     * Bundled so the two can never be passed apart — polling without a sink would silently
     * swallow the code, and a sink without the handle could never fire.
     */
    class Pairing(val noise: NoiseHandle, val onCode: (String) -> Unit)

    /**
     * Runs one command to completion. Consumes [interp]: it is destroyed on every path,
     * which releases the state lease it holds.
     *
     * [http] is required only for Jade, whose PIN-server payloads are not device traffic.
     */
    suspend fun runCommand(
        interp: Interp,
        cmd: HwiCommand,
        link: Link,
        http: HttpBridge? = null,
        pairing: Pairing? = null,
    ): HwiResponse = interp.use {
        var transmit = interp.start(cmd)
        while (true) {
            val reply = deliver(transmit, link, http)
            val next = interp.exchange(reply)
            // During a first-time BitBox pair the code becomes known just before the
            // verification payload goes out, so surface it before sending that payload:
            // the device is already waiting for the user to compare it.
            pairing?.let { p -> p.noise.takePairingCode()?.let(p.onCode) }
            transmit = next ?: break
        }
        interp.end()
    }

    /** Internal so the routing decision can be tested without a device. */
    internal suspend fun deliver(transmit: Transmit, link: Link, http: HttpBridge?): ByteArray =
        when (val recipient = transmit.recipient) {
            is Recipient.Device -> link.exchange(transmit.payload, transmit.encrypted)
            is Recipient.PinServer -> {
                val bridge = http
                    ?: throw HwiException.BadState("this command needs an HttpBridge for the Jade PIN server")
                bridge.request(recipient.url, transmit.payload)
            }
        }
}
