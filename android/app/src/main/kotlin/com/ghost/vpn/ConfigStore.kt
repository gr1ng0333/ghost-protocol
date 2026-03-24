package com.ghost.vpn

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import org.json.JSONObject

/**
 * Manages Ghost VPN configuration persistence.
 *
 * Non-sensitive values (server address, SNI, shaping mode, auto mode, log level) are
 * stored in regular [SharedPreferences]. Sensitive cryptographic keys (server public key,
 * client private key) are stored in [EncryptedSharedPreferences] backed by the Android
 * Keystore.
 *
 * If the device's Keystore is broken or unavailable, encrypted storage falls back to
 * regular [SharedPreferences] with a logged warning — the app will not crash.
 *
 * @param context Application or Activity context used to open preference files.
 */
class ConfigStore(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val securePrefs: SharedPreferences = createSecurePrefs(context)

    /** Server address in "host:port" format (e.g. "example.com:443"). */
    var serverAddr: String
        get() = prefs.getString(KEY_SERVER_ADDR, "") ?: ""
        set(value) = prefs.edit().putString(KEY_SERVER_ADDR, value).apply()

    /** TLS SNI hostname. If empty, derived from [serverAddr] at JSON-build time. */
    var serverSni: String
        get() = prefs.getString(KEY_SERVER_SNI, "") ?: ""
        set(value) = prefs.edit().putString(KEY_SERVER_SNI, value).apply()

    /** Server x25519 public key as a 64-character hex string. Stored encrypted. */
    var serverPublicKey: String
        get() = securePrefs.getString(KEY_SERVER_PUBLIC_KEY, "") ?: ""
        set(value) = securePrefs.edit().putString(KEY_SERVER_PUBLIC_KEY, value).apply()

    /** Client x25519 private key as a 64-character hex string. Stored encrypted. */
    var clientPrivateKey: String
        get() = securePrefs.getString(KEY_CLIENT_PRIVATE_KEY, "") ?: ""
        set(value) = securePrefs.edit().putString(KEY_CLIENT_PRIVATE_KEY, value).apply()

    /** Traffic-shaping mode: "stealth", "balanced", or "performance". */
    var shapingMode: String
        get() = prefs.getString(KEY_SHAPING_MODE, "balanced") ?: "balanced"
        set(value) = prefs.edit().putString(KEY_SHAPING_MODE, value).apply()

    /** Whether adaptive mode switching is enabled. */
    var autoMode: Boolean
        get() = prefs.getBoolean(KEY_AUTO_MODE, true)
        set(value) = prefs.edit().putBoolean(KEY_AUTO_MODE, value).apply()

    /** Logging verbosity: "debug", "info", "warn", or "error". */
    var logLevel: String
        get() = prefs.getString(KEY_LOG_LEVEL, "info") ?: "info"
        set(value) = prefs.edit().putString(KEY_LOG_LEVEL, value).apply()

    /**
     * Returns `true` if the minimum required fields are populated:
     * server address, server public key, and client private key.
     */
    fun isConfigured(): Boolean {
        return serverAddr.isNotBlank() &&
            serverPublicKey.isNotBlank() &&
            clientPrivateKey.isNotBlank()
    }

    /**
     * Builds the JSON configuration string expected by `ghost.Start()`.
     *
     * If [serverSni] is empty, the host portion of [serverAddr] (with port stripped)
     * is used as the SNI value.
     *
     * @return A JSON string matching the Ghost Go API config format.
     */
    fun toConfigJSON(): String {
        val sni = serverSni.ifBlank {
            serverAddr.substringBefore(":")
        }
        return JSONObject().apply {
            put("server_addr", serverAddr)
            put("server_sni", sni)
            put("server_public_key", serverPublicKey)
            put("client_private_key", clientPrivateKey)
            put("shaping_mode", shapingMode)
            put("auto_mode", autoMode)
            put("log_level", logLevel)
        }.toString()
    }

    companion object {
        private const val TAG = "ConfigStore"
        private const val PREFS_NAME = "ghost_prefs"
        private const val SECURE_PREFS_NAME = "ghost_secure_prefs"

        private const val KEY_SERVER_ADDR = "server_addr"
        private const val KEY_SERVER_SNI = "server_sni"
        private const val KEY_SERVER_PUBLIC_KEY = "server_public_key"
        private const val KEY_CLIENT_PRIVATE_KEY = "client_private_key"
        private const val KEY_SHAPING_MODE = "shaping_mode"
        private const val KEY_AUTO_MODE = "auto_mode"
        private const val KEY_LOG_LEVEL = "log_level"

        /**
         * Attempts to create [EncryptedSharedPreferences]. On failure (broken Keystore,
         * unsupported device, etc.) falls back to regular [SharedPreferences] and logs
         * a warning.
         */
        private fun createSecurePrefs(context: Context): SharedPreferences {
            return try {
                val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
                EncryptedSharedPreferences.create(
                    SECURE_PREFS_NAME,
                    masterKeyAlias,
                    context,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                )
            } catch (e: Exception) {
                Log.w(TAG, "EncryptedSharedPreferences unavailable, falling back to plain storage", e)
                context.getSharedPreferences(SECURE_PREFS_NAME, Context.MODE_PRIVATE)
            }
        }
    }
}
