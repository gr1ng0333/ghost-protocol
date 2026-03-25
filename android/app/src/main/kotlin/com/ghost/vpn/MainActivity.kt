package com.ghost.vpn

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.ghost.vpn.theme.GhostTheme
import kotlinx.coroutines.delay

/**
 * Main entry point for the Ghost VPN Android application.
 *
 * Handles VPN permission acquisition via [ActivityResultContracts] and hosts the
 * Jetpack Compose UI rooted in [ConnectionScreen].
 */
class MainActivity : ComponentActivity() {

    private lateinit var viewModel: VpnViewModel

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            viewModel.connect(this)
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* proceed regardless */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestNotificationPermission()
        setContent {
            val vm: VpnViewModel = viewModel()
            viewModel = vm
            val configStore = remember { ConfigStore(applicationContext) }
            var showSettings by remember { mutableStateOf(false) }

            // Route Go log messages into ViewModel log buffer
            LaunchedEffect(Unit) {
                ghost.Ghost.setLogCallback(object : ghost.LogCallback {
                    override fun log(level: String, message: String) {
                        vm.addLog(level, message)
                    }
                })
            }

            GhostTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    if (showSettings) {
                        SettingsScreen(
                            configStore = configStore,
                            onBack = { showSettings = false }
                        )
                    } else {
                        ConnectionScreen(
                            viewModel = vm,
                            onConnectClick = ::onConnectClick,
                            onSettingsClick = { showSettings = true },
                            isConfigured = configStore.isConfigured()
                        )
                    }
                }
            }
        }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun onConnectClick() {
        requestBatteryOptimizationExemption()
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            viewModel.connect(this)
        }
    }

    private fun requestBatteryOptimizationExemption() {
        val pm = getSystemService(PowerManager::class.java)
        if (!pm.isIgnoringBatteryOptimizations(packageName)) {
            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                data = Uri.parse("package:$packageName")
            }
            startActivity(intent)
        }
    }
}

// ---------------------------------------------------------------------------
// ConnectionScreen
// ---------------------------------------------------------------------------

/**
 * Primary VPN UI screen displaying connection status, traffic stats,
 * mode selector, connect/disconnect button, and a scrollable log viewer.
 *
 * @param viewModel      The [VpnViewModel] driving UI state.
 * @param onConnectClick  Callback invoked when the user taps "Connect" (triggers VPN permission flow).
 * @param onSettingsClick Callback invoked when the settings gear icon is tapped.
 * @param isConfigured    Whether the VPN has a valid server configuration.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectionScreen(
    viewModel: VpnViewModel,
    onConnectClick: () -> Unit,
    onSettingsClick: () -> Unit,
    isConfigured: Boolean = true
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val logs by viewModel.logs.collectAsStateWithLifecycle()
    val context = LocalContext.current

    // Bridge: poll service companion to transition Connecting → Connected / Error
    LaunchedEffect(state) {
        if (state is VpnState.Connecting) {
            while (true) {
                delay(500L)
                val err = GhostVpnService.lastError
                if (err != null) {
                    viewModel.addLog("ERROR", err)
                    break // ViewModel polling will pick up the error
                }
                if (GhostVpnService.isRunning) {
                    viewModel.startStatsPolling()
                    break
                }
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Ghost") },
                actions = {
                    IconButton(onClick = onSettingsClick) {
                        Icon(
                            imageVector = Icons.Default.Settings,
                            contentDescription = "Settings"
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(24.dp))

            // Status indicator circle
            StatusIndicator(state = state)

            Spacer(modifier = Modifier.height(12.dp))

            // Status text
            Text(
                text = when (state) {
                    is VpnState.Disconnected -> "Disconnected"
                    is VpnState.Connecting -> "Connecting…"
                    is VpnState.Connected -> "Connected"
                    is VpnState.Reconnecting -> "Reconnecting…"
                    is VpnState.Disconnecting -> "Disconnecting…"
                    is VpnState.Error -> "Error"
                },
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground
            )

            // Uptime (only when connected)
            if (state is VpnState.Connected) {
                val connected = state as VpnState.Connected
                Text(
                    text = "Uptime: ${formatUptime(connected.uptimeSec)}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // Error message
            if (state is VpnState.Error) {
                Text(
                    text = (state as VpnState.Error).message,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Traffic stats (only when connected)
            if (state is VpnState.Connected) {
                val connected = state as VpnState.Connected
                StatsRow(
                    bytesSent = connected.bytesSent,
                    bytesRecv = connected.bytesRecv
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "${connected.activeStreams} active stream${if (connected.activeStreams != 1) "s" else ""}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(16.dp))
            }

            // Connect / Disconnect button
            ConnectButton(
                state = state,
                onConnect = onConnectClick,
                onDisconnect = { viewModel.disconnect(context) },
                isConfigured = isConfigured
            )

            // Helper text when config is missing
            if (!isConfigured) {
                Text(
                    text = "Configure server in Settings first",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Mode selector
            ModeSelector(
                state = state,
                onModeSelected = { viewModel.setMode(it) }
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Logs section
            Text(
                text = "Logs",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onBackground,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(4.dp))

            LogViewer(
                logs = logs,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
            )
        }
    }
}

// ---------------------------------------------------------------------------
// StatusIndicator
// ---------------------------------------------------------------------------

/**
 * Large colored circle indicating the current VPN connection state.
 *
 * - Green (#4DB6AC) when connected
 * - Gray when disconnected
 * - Amber when connecting or reconnecting
 * - Red when in error state
 *
 * @param state Current [VpnState].
 */
@Composable
fun StatusIndicator(state: VpnState) {
    val color = when (state) {
        is VpnState.Connected -> Color(0xFF4DB6AC)
        is VpnState.Disconnected -> Color(0xFF757575)
        is VpnState.Connecting, is VpnState.Reconnecting, is VpnState.Disconnecting -> Color(0xFFFFA726)
        is VpnState.Error -> Color(0xFFCF6679)
    }
    Canvas(modifier = Modifier.size(80.dp)) {
        drawCircle(color = color)
    }
}

// ---------------------------------------------------------------------------
// StatsRow
// ---------------------------------------------------------------------------

/**
 * Displays upload and download byte counters in a horizontal row.
 *
 * @param bytesSent Total bytes transmitted.
 * @param bytesRecv Total bytes received.
 */
@Composable
fun StatsRow(bytesSent: Long, bytesRecv: Long) {
    Row(
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(
            text = "▲ ${formatBytes(bytesSent)}",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onBackground
        )
        Spacer(modifier = Modifier.width(24.dp))
        Text(
            text = "▼ ${formatBytes(bytesRecv)}",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onBackground
        )
    }
}

// ---------------------------------------------------------------------------
// ConnectButton
// ---------------------------------------------------------------------------

/**
 * Primary action button that toggles VPN connection.
 *
 * Shows "CONNECT" when disconnected/error, "DISCONNECT" when connected,
 * and a progress indicator with label when transitioning.
 *
 * @param state        Current [VpnState].
 * @param onConnect    Callback to initiate connection.
 * @param onDisconnect Callback to tear down connection.
 * @param isConfigured Whether server configuration is present.
 */
@Composable
fun ConnectButton(
    state: VpnState,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    isConfigured: Boolean = true
) {
    val isTransitioning = state is VpnState.Connecting || state is VpnState.Reconnecting || state is VpnState.Disconnecting
    val isConnected = state is VpnState.Connected

    val buttonColors = if (isConnected) {
        ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
    } else {
        ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary)
    }

    Button(
        onClick = if (isConnected) onDisconnect else onConnect,
        enabled = !isTransitioning && (isConnected || isConfigured),
        colors = buttonColors,
        modifier = Modifier
            .fillMaxWidth()
            .height(52.dp)
    ) {
        if (isTransitioning) {
            CircularProgressIndicator(
                modifier = Modifier.size(20.dp),
                strokeWidth = 2.dp,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = when (state) {
                    is VpnState.Connecting -> "CONNECTING…"
                    is VpnState.Disconnecting -> "DISCONNECTING…"
                    else -> "RECONNECTING…"
                }
            )
        } else {
            Text(text = if (isConnected) "DISCONNECT" else "CONNECT")
        }
    }
}

// ---------------------------------------------------------------------------
// ModeSelector
// ---------------------------------------------------------------------------

private val MODES = listOf(
    "Stealth" to "stealth",
    "Balanced" to "balanced",
    "Performance" to "performance"
)

/**
 * Row of [FilterChip]s for selecting the traffic-shaping mode.
 *
 * Only interactable when the VPN is in the [VpnState.Connected] state.
 *
 * @param state          Current [VpnState] — the active mode is read from [VpnState.Connected.mode].
 * @param onModeSelected Callback with the API mode value (e.g. "stealth").
 */
@Composable
fun ModeSelector(state: VpnState, onModeSelected: (String) -> Unit) {
    val isConnected = state is VpnState.Connected
    val currentMode = (state as? VpnState.Connected)?.mode

    Row(
        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(
            text = "Mode:",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.align(Alignment.CenterVertically)
        )
        MODES.forEach { (label, value) ->
            FilterChip(
                selected = currentMode == value,
                onClick = { onModeSelected(value) },
                label = { Text(label, style = MaterialTheme.typography.labelMedium) },
                enabled = isConnected,
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                    selectedLabelColor = MaterialTheme.colorScheme.onPrimaryContainer
                )
            )
        }
    }
}

// ---------------------------------------------------------------------------
// LogViewer
// ---------------------------------------------------------------------------

/** Amber color used for WARN-level log entries. */
private val WarnColor = Color(0xFFFFA726)

/**
 * Scrollable log viewer that auto-scrolls to the latest entry.
 *
 * Log entries are color-coded by severity level:
 * - INFO → default text color
 * - WARN → amber
 * - ERROR → theme error color
 *
 * @param logs     List of formatted log strings (e.g. "[INFO] message").
 * @param modifier Modifier applied to the outer container.
 */
@Composable
fun LogViewer(logs: List<String>, modifier: Modifier = Modifier) {
    val listState = rememberLazyListState()

    // Auto-scroll to bottom when new entries arrive
    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) {
            listState.animateScrollToItem(logs.size - 1)
        }
    }

    Surface(
        modifier = modifier,
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.small
    ) {
        LazyColumn(
            state = listState,
            modifier = Modifier.padding(8.dp)
        ) {
            items(logs) { entry ->
                val textColor = when {
                    entry.startsWith("[ERROR]") -> MaterialTheme.colorScheme.error
                    entry.startsWith("[WARN]") -> WarnColor
                    else -> MaterialTheme.colorScheme.onSurfaceVariant
                }
                Text(
                    text = entry,
                    style = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp
                    ),
                    color = textColor,
                    modifier = Modifier.padding(vertical = 1.dp)
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/**
 * Formats a byte count into a human-readable string with appropriate unit.
 *
 * Examples: "123 B", "4.5 KB", "12.5 MB", "1.2 GB".
 */
private fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024) return "%.1f KB".format(kb)
    val mb = kb / 1024.0
    if (mb < 1024) return "%.1f MB".format(mb)
    val gb = mb / 1024.0
    return "%.1f GB".format(gb)
}

/**
 * Formats a duration in seconds into a compact human-readable string.
 *
 * Examples: "30s", "5m 30s", "2h 15m 30s".
 */
private fun formatUptime(seconds: Long): String {
    val h = seconds / 3600
    val m = (seconds % 3600) / 60
    val s = seconds % 60
    return buildString {
        if (h > 0) append("${h}h ")
        if (h > 0 || m > 0) append("${m}m ")
        append("${s}s")
    }
}
