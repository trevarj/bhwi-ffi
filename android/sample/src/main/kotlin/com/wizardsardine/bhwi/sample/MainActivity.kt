package com.wizardsardine.bhwi.sample

import android.app.Activity
import android.os.Bundle
import android.widget.TextView
import uniffi.bhwi_ffi.AddressFormat
import uniffi.bhwi_ffi.Network
import uniffi.bhwi_ffi.buildSinglesigDescriptor

/**
 * Smallest possible consumer of the published AAR: calling one exported helper is enough
 * to prove the library loads and links on-device.
 */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val descriptor = buildSinglesigDescriptor(
            "tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP",
            "f5acc2fd",
            "m/84'/1'/0'",
            AddressFormat.NATIVE_SEGWIT,
            Network.TESTNET,
        )
        setContentView(TextView(this).apply { text = descriptor })
    }
}
