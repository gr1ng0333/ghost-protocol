package com.ghost.vpn

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.util.Log

class GhostApp : Application() {
    override fun onCreate() {
        try {
            super.onCreate()
            createNotificationChannel()
            // Pre-load native library early so failures are caught before UI
            loadNativeLibrary()
        } catch (e: Throwable) {
            Log.e(TAG, "FATAL: Application.onCreate crashed", e)
        }
    }

    private fun loadNativeLibrary() {
        try {
            // Trigger ghost class loading → go.Seq → System.loadLibrary("gojni")
            ghost.Ghost.touch()
            nativeLoaded = true
            Log.i(TAG, "Native library loaded successfully")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load native library (wrong ABI or corrupt .so)", e)
            nativeError = e.message
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to load native library", e)
            nativeError = e.message
        }
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.notification_channel_desc)
        }
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }

    companion object {
        const val TAG = "GhostVPN"
        const val CHANNEL_ID = "ghost_vpn"

        /** True if libgojni.so loaded without error. Check before any ghost.* call. */
        @Volatile
        var nativeLoaded: Boolean = false
            private set

        /** Error message if native library failed to load. */
        var nativeError: String? = null
            private set
    }
}
