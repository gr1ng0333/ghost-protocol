package com.ghost.vpn

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp

/** Regex that matches exactly 64 hexadecimal characters. */
private val HEX_64 = Regex("^[0-9a-fA-F]{64}$")

/** Mode options: display label to API value. */
private val MODE_OPTIONS = listOf(
    "Stealth" to "stealth",
    "Balanced" to "balanced",
    "Performance" to "performance"
)

/** Log-level options: display label to API value. */
private val LOG_LEVEL_OPTIONS = listOf(
    "Debug" to "debug",
    "Info" to "info",
    "Warn" to "warn",
    "Error" to "error"
)

/**
 * Settings screen for editing Ghost VPN configuration.
 *
 * Loads current values from [configStore] on entry. On save, validates all fields
 * and writes them back to the store before navigating back via [onBack].
 *
 * @param configStore The [ConfigStore] used to read and persist settings.
 * @param onBack      Callback invoked after a successful save or when the back arrow is tapped.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    configStore: ConfigStore,
    onBack: () -> Unit
) {
    // Local mutable state seeded from persisted config
    var serverAddr by remember { mutableStateOf(configStore.serverAddr) }
    var serverSni by remember { mutableStateOf(configStore.serverSni) }
    var serverPublicKey by remember { mutableStateOf(configStore.serverPublicKey) }
    var clientPrivateKey by remember { mutableStateOf(configStore.clientPrivateKey) }
    var shapingMode by remember { mutableStateOf(configStore.shapingMode) }
    var autoMode by remember { mutableStateOf(configStore.autoMode) }
    var logLevel by remember { mutableStateOf(configStore.logLevel) }

    var showPrivateKey by remember { mutableStateOf(false) }
    var validationError by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back"
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
                .padding(horizontal = 24.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Spacer(modifier = Modifier.height(8.dp))

            // ---- Server section ----
            SectionHeader("Server")

            OutlinedTextField(
                value = serverAddr,
                onValueChange = { serverAddr = it },
                label = { Text("Server Address") },
                placeholder = { Text("host:port") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(8.dp))

            OutlinedTextField(
                value = serverSni,
                onValueChange = { serverSni = it },
                label = { Text("Server SNI (optional)") },
                placeholder = { Text("defaults to address host") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(20.dp))

            // ---- Keys section ----
            SectionHeader("Keys")

            OutlinedTextField(
                value = serverPublicKey,
                onValueChange = { serverPublicKey = it },
                label = { Text("Server Public Key") },
                placeholder = { Text("64 hex characters") },
                singleLine = true,
                textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(8.dp))

            OutlinedTextField(
                value = clientPrivateKey,
                onValueChange = { clientPrivateKey = it },
                label = { Text("Client Private Key") },
                placeholder = { Text("64 hex characters") },
                singleLine = true,
                textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                visualTransformation = if (showPrivateKey) {
                    VisualTransformation.None
                } else {
                    PasswordVisualTransformation()
                },
                trailingIcon = {
                    IconButton(onClick = { showPrivateKey = !showPrivateKey }) {
                        Icon(
                            imageVector = if (showPrivateKey) {
                                Icons.Filled.VisibilityOff
                            } else {
                                Icons.Filled.Visibility
                            },
                            contentDescription = if (showPrivateKey) "Hide key" else "Show key"
                        )
                    }
                },
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(20.dp))

            // ---- Preferences section ----
            SectionHeader("Preferences")

            DropdownField(
                label = "Default Mode",
                options = MODE_OPTIONS,
                selectedValue = shapingMode,
                onSelected = { shapingMode = it }
            )
            Spacer(modifier = Modifier.height(8.dp))

            // Auto mode switch
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "Auto Mode",
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onBackground,
                    modifier = Modifier.weight(1f)
                )
                Switch(
                    checked = autoMode,
                    onCheckedChange = { autoMode = it }
                )
            }
            Spacer(modifier = Modifier.height(8.dp))

            DropdownField(
                label = "Log Level",
                options = LOG_LEVEL_OPTIONS,
                selectedValue = logLevel,
                onSelected = { logLevel = it }
            )

            Spacer(modifier = Modifier.height(24.dp))

            // ---- Save button ----
            Button(
                onClick = {
                    val error = validate(serverAddr, serverPublicKey, clientPrivateKey)
                    if (error != null) {
                        validationError = error
                    } else {
                        validationError = null
                        configStore.serverAddr = serverAddr.trim()
                        configStore.serverSni = serverSni.trim()
                        configStore.serverPublicKey = serverPublicKey.trim()
                        configStore.clientPrivateKey = clientPrivateKey.trim()
                        configStore.shapingMode = shapingMode
                        configStore.autoMode = autoMode
                        configStore.logLevel = logLevel
                        onBack()
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp)
            ) {
                Text("SAVE")
            }

            // Validation feedback
            if (validationError != null) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = validationError!!,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error
                )
            }

            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

// ---------------------------------------------------------------------------
// Internal composables
// ---------------------------------------------------------------------------

/**
 * Styled section header text.
 *
 * @param title Section title to display.
 */
@Composable
private fun SectionHeader(title: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(bottom = 8.dp)
    )
}

/**
 * Dropdown selector built on [ExposedDropdownMenuBox].
 *
 * @param label        Label shown above the field.
 * @param options      List of (display label, API value) pairs.
 * @param selectedValue Currently selected API value.
 * @param onSelected   Callback with the newly selected API value.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DropdownField(
    label: String,
    options: List<Pair<String, String>>,
    selectedValue: String,
    onSelected: (String) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    val displayText = options.firstOrNull { it.second == selectedValue }?.first ?: selectedValue

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it }
    ) {
        OutlinedTextField(
            value = displayText,
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(MenuAnchorType.PrimaryNotEditable)
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false }
        ) {
            options.forEach { (displayLabel, value) ->
                DropdownMenuItem(
                    text = { Text(displayLabel) },
                    onClick = {
                        onSelected(value)
                        expanded = false
                    }
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * Validates the required configuration fields.
 *
 * @return An error message string if validation fails, or `null` if all fields are valid.
 */
private fun validate(
    serverAddr: String,
    serverPublicKey: String,
    clientPrivateKey: String
): String? {
    if (serverAddr.isBlank()) return "Server address is required"
    if (!HEX_64.matches(serverPublicKey.trim())) return "Server public key must be exactly 64 hex characters"
    if (!HEX_64.matches(clientPrivateKey.trim())) return "Client private key must be exactly 64 hex characters"
    return null
}
