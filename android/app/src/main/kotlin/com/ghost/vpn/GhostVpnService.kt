package com.ghost.vpn

import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.ParcelFileDescriptor
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
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> connect()
            ACTION_DISCONNECT -> disconnect()
        }
        return START_STICKY
    }

    private fun connect() {
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
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")

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

        // 6. Set up Go log callback
        ghost.Ghost.setLogCallback(object : ghost.LogCallback {
            override fun log(level: String?, message: String?) {
                Log.d("GhostGo", "[${level ?: "?"}] ${message ?: ""}")
            }
        })

        // 7. Start Ghost
        try {
            client = ghost.Ghost.start(fd.toLong(), configJSON)
            isRunning = true
            lastError = null
            updateNotification(getString(R.string.vpn_connected))
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
        try {
            client?.stop()
        } catch (e: Exception) {
            Log.e(TAG, "Ghost stop error", e)
        }
        client = null
        isRunning = false
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "Ghost VPN disconnected")
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked")
        disconnect()
        super.onRevoke()
    }

    override fun onDestroy() {
        disconnect()
        super.onDestroy()
    }

    private fun buildNotification(text: String): android.app.Notification {
        val tapIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, tapIntent, PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .build()
    }

    private fun updateNotification(text: String) {
        val notification = buildNotification(text)
        val manager = getSystemService(android.app.NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, notification)
    }

}
