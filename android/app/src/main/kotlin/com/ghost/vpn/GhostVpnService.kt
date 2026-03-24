package com.ghost.vpn

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.content.ComponentCallbacks2
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat

/**
 * Foreground [VpnService] that owns the TUN interface and Ghost tunnel.
 *
 * Communication with the UI layer happens through the [companion object] fields
 * ([client], [isRunning], [lastError]) and the Intent actions
 * [ACTION_CONNECT] / [ACTION_DISCONNECT].
 */
class GhostVpnService : VpnService() {

    companion object {
        private const val TAG = "GhostVPN"

        /** Intent action to initiate a VPN connection. */
        const val ACTION_CONNECT = "com.ghost.vpn.CONNECT"

        /** Intent action to tear down the VPN connection. */
        const val ACTION_DISCONNECT = "com.ghost.vpn.DISCONNECT"

        const val NOTIFICATION_ID = 1001
        const val CHANNEL_ID = "ghost_vpn"

        /** The active Ghost client instance, or `null` when disconnected. */
        var client: ghost.Client? = null

        /** `true` between a successful [ghost.Ghost.start] and [disconnect]. */
        var isRunning: Boolean = false

        /** The last error message if the connection attempt failed. */
        var lastError: String? = null

        /** Current traffic-shaping mode. */
        var currentMode: String = "balanced"
    }

    /** Saved mode before battery saver switched us to "performance". */
    private var previousMode: String? = null

    /** Monitors underlying network changes to trigger transport reconnect. */
    private var networkMonitor: NetworkMonitor? = null

    private val powerReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == PowerManager.ACTION_POWER_SAVE_MODE_CHANGED) {
                val pm = getSystemService(PowerManager::class.java)
                if (pm.isPowerSaveMode) {
                    previousMode = currentMode
                    client?.let { ghost.Ghost.setMode("performance") }
                    currentMode = "performance"
                    Log.i(TAG, "Battery saver ON — switched to performance mode")
                } else {
                    previousMode?.let { mode ->
                        client?.let { ghost.Ghost.setMode(mode) }
                        currentMode = mode
                        previousMode = null
                        Log.i(TAG, "Battery saver OFF — restored $mode mode")
                    }
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> connect()
            ACTION_DISCONNECT -> disconnect()
            null -> {
                // System-initiated start (always-on VPN or restart after crash)
                if (!isRunning) {
                    val configStore = ConfigStore(this)
                    if (configStore.isConfigured()) {
                        connect()
                    } else {
                        Log.w(TAG, "System-initiated start but no config — stopping")
                        stopSelf()
                    }
                }
            }
        }
        return START_STICKY
    }

    private fun connect() {
        // Idempotent: skip if already running
        if (isRunning && client != null) {
            Log.d(TAG, "Already connected — ignoring duplicate connect()")
            return
        }

        // 0. Verify configuration exists
        val configStore = ConfigStore(applicationContext)
        if (!configStore.isConfigured()) {
            Log.e(TAG, "Cannot connect — not configured")
            lastError = "Not configured — open Settings"
            isRunning = false
            stopSelf()
            return
        }

        // 1. Start foreground immediately (required before any long work on Android 14+)
        val notification = buildNotification(getString(R.string.vpn_connecting))
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            notification,
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        )

        // 2. Build VPN interface
        val builder = Builder()
            .setSession("Ghost VPN")
            .setBlocking(true)
            .setMtu(1500)
            .addAddress("10.0.85.1", 24)
            .addRoute("0.0.0.0", 0)
            // Block IPv6 to prevent leaks (Ghost tunnel is IPv4-only)
            .addRoute("::", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")

        // TODO: Remove addDisallowedApplication once SocketProtector is integrated
        // into the Go transport layer (requires internal/transport API change).
        // For now, keep as defense-in-depth fallback.
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to exclude self from VPN", e)
        }

        // 3. Establish TUN
        val pfd: ParcelFileDescriptor? = try {
            builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "VPN establish failed", e)
            null
        }

        // Tell Android to use default network as VPN underlay (WireGuard pattern)
        setUnderlyingNetworks(null)

        if (pfd == null) {
            Log.e(TAG, "VPN establish returned null — permission revoked?")
            lastError = "VPN establish failed — permission may have been revoked"
            isRunning = false
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // 4. Transfer fd ownership to Go
        val fd = pfd.detachFd()

        // 5. Load config from ConfigStore
        val configJSON = configStore.toConfigJSON()

        // 6. Set up Go log callback and socket protector
        ghost.Ghost.setLogCallback(object : ghost.LogCallback {
            override fun log(level: String?, message: String?) {
                Log.d("GhostGo", "[${level ?: "?"} ] ${message ?: ""}")
            }
        })

        // Register socket protector so Go transport sockets bypass VPN
        ghost.Ghost.setSocketProtector(object : ghost.SocketProtector {
            override fun protect(fd: Int): Boolean {
                return this@GhostVpnService.protect(fd)
            }
        })

        // 7. Start Ghost
        try {
            client = ghost.Ghost.start(fd.toLong(), configJSON)
            isRunning = true
            lastError = null
            updateNotification(getString(R.string.vpn_connected))
            registerReceiver(
                powerReceiver,
                IntentFilter(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED)
            )

            // 8. Start network monitor for WiFi↔Mobile transitions
            networkMonitor = NetworkMonitor(
                context = this,
                onNetworkChanged = {
                    Log.i(TAG, "Network changed — ConnManager will detect dead socket and reconnect")
                    updateNotification(getString(R.string.vpn_connecting))
                },
                onNetworkLost = {
                    Log.w(TAG, "All networks lost — waiting for connectivity")
                    updateNotification("Waiting for network…")
                },
                onCaptivePortal = {
                    Log.w(TAG, "Captive portal detected — authentication required")
                }
            ).also { it.start() }

            Log.i(TAG, "Ghost VPN connected")
        } catch (e: Exception) {
            Log.e(TAG, "Ghost start failed", e)
            lastError = e.message
            isRunning = false
            // Go didn't take ownership — close fd manually
            try {
                ParcelFileDescriptor.adoptFd(fd).close()
            } catch (closeErr: Exception) {
                Log.w(TAG, "Failed to close fd after error", closeErr)
            }
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun disconnect() {
        networkMonitor?.stop()
        networkMonitor = null
        try {
            unregisterReceiver(powerReceiver)
        } catch (_: Exception) { /* not registered */ }
        try {
            client?.stop()
        } catch (e: Exception) {
            Log.e(TAG, "Ghost stop error", e)
        }
        client = null
        isRunning = false
        previousMode = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "Ghost VPN disconnected")
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked")
        disconnect()
        super.onRevoke()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // User swiped app from recents — VPN should continue running.
        super.onTaskRemoved(rootIntent)
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= ComponentCallbacks2.TRIM_MEMORY_RUNNING_CRITICAL) {
            Log.w(TAG, "System memory critical, VPN service continuing")
        }
    }

    override fun onDestroy() {
        networkMonitor?.stop()
        networkMonitor = null
        try {
            unregisterReceiver(powerReceiver)
        } catch (_: Exception) { /* not registered */ }
        disconnect()
        super.onDestroy()
    }

    private fun buildNotification(text: String): android.app.Notification {
        val disconnectIntent = Intent(this, GhostVpnService::class.java)
            .setAction(ACTION_DISCONNECT)
        val disconnectPendingIntent = PendingIntent.getService(
            this, 0, disconnectIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val tapIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openPendingIntent = PendingIntent.getActivity(
            this, 1, tapIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setOngoing(true)
            .setContentIntent(openPendingIntent)
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "Disconnect",
                disconnectPendingIntent
            )
            .build()
    }

    fun updateNotification(text: String) {
        val notification = buildNotification(text)
        val manager = getSystemService(android.app.NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, notification)
    }

}
