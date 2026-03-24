package com.ghost.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Starts Ghost VPN service after device boot if auto-connect is enabled.
 *
 * This handles the case where the user wants auto-connect but hasn't enabled
 * Android's system-level always-on VPN setting. When always-on IS enabled,
 * the system starts VpnService automatically and this receiver is redundant
 * (but harmless).
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return

        val prefs = context.getSharedPreferences("ghost_config", Context.MODE_PRIVATE)
        val autoConnect = prefs.getBoolean("auto_connect_on_boot", false)

        if (autoConnect) {
            val configStore = ConfigStore(context)
            if (configStore.isConfigured()) {
                val vpnIntent = Intent(context, GhostVpnService::class.java)
                    .setAction(GhostVpnService.ACTION_CONNECT)
                context.startForegroundService(vpnIntent)
            }
        }
    }
}
