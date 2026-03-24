package com.ghost.vpn

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Represents the current state of the VPN connection.
 */
sealed class VpnState {
    /** No active VPN connection. */
    object Disconnected : VpnState()

    /** A connection attempt is in progress. */
    object Connecting : VpnState()

    /**
     * The VPN tunnel is established and carrying traffic.
     *
     * @property mode       Current shaping mode ("stealth", "balanced", or "performance").
     * @property bytesSent  Total bytes sent through the tunnel.
     * @property bytesRecv  Total bytes received through the tunnel.
     * @property activeStreams Number of active HTTP/2 streams.
     * @property uptimeSec  Seconds since the tunnel was established.
     */
    data class Connected(
        val mode: String,
        val bytesSent: Long,
        val bytesRecv: Long,
        val activeStreams: Int,
        val uptimeSec: Long
    ) : VpnState()

    /** The tunnel lost connectivity and is attempting to recover. */
    object Reconnecting : VpnState()

    /**
     * An error prevented or interrupted the VPN connection.
     *
     * @property message Human-readable error description.
     */
    data class Error(val message: String) : VpnState()
}

/**
 * ViewModel that drives the VPN UI by exposing connection [state] and [logs].
 *
 * It communicates with [GhostVpnService] via its companion-object fields and
 * Intent actions, and polls tunnel statistics while connected.
 */
class VpnViewModel : ViewModel() {

    private val _state = MutableStateFlow<VpnState>(VpnState.Disconnected)

    /** Observable connection state for the UI layer. */
    val state: StateFlow<VpnState> = _state.asStateFlow()

    private val _logs = MutableStateFlow<List<String>>(emptyList())

    /** Last 200 log entries in "[LEVEL] message" format. */
    val logs: StateFlow<List<String>> = _logs.asStateFlow()

    private var pollingJob: Job? = null

    /**
     * Initiates a VPN connection by sending [GhostVpnService.ACTION_CONNECT]
     * to the foreground service.
     *
     * @param context Android context used to build and send the service Intent.
     */
    fun connect(context: Context) {
        _state.value = VpnState.Connecting
        GhostVpnService.lastError = null
        val intent = Intent(context, GhostVpnService::class.java).apply {
            action = GhostVpnService.ACTION_CONNECT
        }
        ContextCompat.startForegroundService(context, intent)
    }

    /**
     * Tears down the VPN by sending [GhostVpnService.ACTION_DISCONNECT]
     * and cancelling stats polling.
     *
     * @param context Android context used to build and send the service Intent.
     */
    fun disconnect(context: Context) {
        stopStatsPolling()
        val intent = Intent(context, GhostVpnService::class.java).apply {
            action = GhostVpnService.ACTION_DISCONNECT
        }
        context.startService(intent)
        _state.value = VpnState.Disconnected
    }

    /**
     * Requests a shaping-mode change on the active tunnel.
     *
     * @param mode One of "stealth", "balanced", or "performance".
     */
    fun setMode(mode: String) {
        try {
            GhostVpnService.client?.setMode(mode)
        } catch (e: Exception) {
            _state.value = VpnState.Error(e.message ?: "Failed to set mode")
        }
    }

    /**
     * Appends a log entry, keeping the list trimmed to the most recent 200 entries.
     *
     * @param level Log severity (e.g. "INFO", "ERROR").
     * @param msg   Log message body.
     */
    fun addLog(level: String, msg: String) {
        _logs.value = (_logs.value + "[$level] $msg").takeLast(200)
    }

    /**
     * Begins polling [GhostVpnService.client] for tunnel statistics every 1.5 seconds.
     *
     * While the client reports [ghost.Client.healthy] as `true`, the state is updated
     * to [VpnState.Connected]. If the health check fails, the state moves to
     * [VpnState.Reconnecting].
     */
    fun startStatsPolling() {
        stopStatsPolling()
        pollingJob = viewModelScope.launch {
            while (true) {
                delay(1500L)
                val c = GhostVpnService.client
                if (c == null) {
                    val err = GhostVpnService.lastError
                    if (err != null) {
                        _state.value = VpnState.Error(err)
                        break
                    }
                    continue
                }
                try {
                    if (!c.healthy()) {
                        _state.value = VpnState.Reconnecting
                        continue
                    }
                    val statsJson = c.stats()
                    val json = JSONObject(statsJson)
                    _state.value = VpnState.Connected(
                        mode = json.optString("mode", "stealth"),
                        bytesSent = json.optLong("bytes_sent", 0),
                        bytesRecv = json.optLong("bytes_recv", 0),
                        activeStreams = json.optInt("active_streams", 0),
                        uptimeSec = json.optLong("uptime_sec", 0)
                    )
                } catch (e: Exception) {
                    _state.value = VpnState.Error(e.message ?: "Stats polling failed")
                }
            }
        }
    }

    /**
     * Cancels the active stats-polling coroutine, if any.
     */
    fun stopStatsPolling() {
        pollingJob?.cancel()
        pollingJob = null
    }
}
