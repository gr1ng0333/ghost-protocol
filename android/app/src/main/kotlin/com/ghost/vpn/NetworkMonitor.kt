package com.ghost.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Handler
import android.os.HandlerThread

/**
 * Monitors underlying network changes (WiFi↔Mobile) and triggers VPN
 * transport reconnection when the physical network changes.
 *
 * Design decisions:
 * - Uses registerDefaultNetworkCallback (Ghost process is excluded from VPN
 *   via addDisallowedApplication, so default = physical network)
 * - Debounces events by 1500ms to avoid reconnect storms from flapping
 * - Does NOT recreate TUN — only triggers transport reconnect
 * - Checks NET_CAPABILITY_VALIDATED before triggering reconnect
 */
class NetworkMonitor(
    context: Context,
    private val onNetworkChanged: () -> Unit,
    private val onNetworkLost: () -> Unit,
    private val onCaptivePortal: () -> Unit
) {
    private val connectivityManager = context.getSystemService(ConnectivityManager::class.java)
    private val handlerThread = HandlerThread("GhostNetworkMonitor").apply { start() }
    private val handler = Handler(handlerThread.looper)

    @Volatile
    private var currentNetwork: Network? = null
    @Volatile
    private var isValidated: Boolean = false

    private var pendingReconnect: Runnable? = null
    private val debounceMs = 1500L

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {

        override fun onAvailable(network: Network) {
            // Don't act here — wait for onCapabilitiesChanged per Android docs
            // (race condition: capabilities not yet stable)
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            val validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            val captivePortal = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)

            if (captivePortal) {
                onCaptivePortal()
                return
            }

            val networkChanged = network != currentNetwork
            currentNetwork = network
            isValidated = validated

            if (networkChanged && validated) {
                scheduleReconnect()
            }
        }

        override fun onLost(network: Network) {
            if (network == currentNetwork) {
                currentNetwork = null
                isValidated = false
                cancelPendingReconnect()
                onNetworkLost()
            }
        }
    }

    private fun scheduleReconnect() {
        cancelPendingReconnect()
        val runnable = Runnable { onNetworkChanged() }
        pendingReconnect = runnable
        handler.postDelayed(runnable, debounceMs)
    }

    private fun cancelPendingReconnect() {
        pendingReconnect?.let { handler.removeCallbacks(it) }
        pendingReconnect = null
    }

    fun start() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            connectivityManager.registerDefaultNetworkCallback(networkCallback, handler)
        } else {
            connectivityManager.registerDefaultNetworkCallback(networkCallback)
        }
    }

    fun stop() {
        cancelPendingReconnect()
        try {
            connectivityManager.unregisterNetworkCallback(networkCallback)
        } catch (_: IllegalArgumentException) {
            // Callback was not registered or already unregistered
        }
        handlerThread.quitSafely()
    }
}
