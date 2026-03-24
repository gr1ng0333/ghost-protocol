package com.ghost.vpn

import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat

class GhostVpnService : VpnService() {

    companion object {
        private const val TAG = "GhostVPN"
        const val ACTION_CONNECT = "com.ghost.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.ghost.vpn.DISCONNECT"
        const val NOTIFICATION_ID = 1001
        const val CHANNEL_ID = "ghost_vpn"
        private const val PREFS_NAME = "ghost_prefs"
        private const val PREFS_KEY_CONFIG = "ghost_config"
    }

    private var client: ghost.Client? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> connect()
            ACTION_DISCONNECT -> disconnect()
        }
        return START_STICKY
    }

    private fun connect() {
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
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // 4. Transfer fd ownership to Go
        val fd = pfd.detachFd()

        // 5. Load config
        val configJSON = loadConfig()

        // 6. Set up Go log callback
        ghost.Ghost.setLogCallback(object : ghost.LogCallback {
            override fun log(level: String?, message: String?) {
                Log.d("GhostGo", "[${level ?: "?"}] ${message ?: ""}")
            }
        })

        // 7. Start Ghost
        try {
            client = ghost.Ghost.start(fd.toLong(), configJSON)
            updateNotification(getString(R.string.vpn_connected))
            Log.i(TAG, "Ghost VPN connected")
        } catch (e: Exception) {
            Log.e(TAG, "Ghost start failed", e)
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

    private fun loadConfig(): String {
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        val config = prefs.getString(PREFS_KEY_CONFIG, null)
        if (!config.isNullOrBlank()) {
            return config
        }
        // Return placeholder config that will fail — user must configure
        return """
            {
                "server_addr": "CONFIGURE_ME:443",
                "server_sni": "example.com",
                "server_public_key": "0000000000000000000000000000000000000000000000000000000000000000",
                "client_private_key": "0000000000000000000000000000000000000000000000000000000000000000",
                "shaping_mode": "balanced",
                "auto_mode": true,
                "log_level": "info"
            }
        """.trimIndent()
    }
}
