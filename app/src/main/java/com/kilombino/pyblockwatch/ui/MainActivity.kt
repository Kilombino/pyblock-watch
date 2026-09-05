package com.kilombino.pyblockwatch.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import com.kilombino.pyblockwatch.chain.Chain
import com.kilombino.pyblockwatch.crypto.ScriptType
import com.kilombino.pyblockwatch.data.AddressRow
import com.kilombino.pyblockwatch.data.TxConf
import com.kilombino.pyblockwatch.data.WatchService

class MainActivity : ComponentActivity() {

    private val notifPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* result handled by the switch state itself */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            PyBlockWatchTheme {
                val vm: WalletViewModel = viewModel()
                val state by vm.state.collectAsState()
                // Notifications are on by default: start the watcher (and ask for the
                // POST_NOTIFICATIONS permission on Android 13+) as soon as there is a wallet.
                LaunchedEffect(state.hasWallet, state.notificationsEnabled) {
                    if (state.hasWallet && state.notificationsEnabled) toggleNotifications(vm, true)
                }
                Box(Modifier.fillMaxSize().background(Ink)) {
                    if (state.hasWallet) {
                        WalletScreen(
                            state = state, vm = vm,
                            onToggleNotifications = { on -> toggleNotifications(vm, on) },
                        )
                    } else {
                        OnboardingScreen(state, vm)
                    }
                }
            }
        }
    }

    private fun toggleNotifications(vm: WalletViewModel, enable: Boolean) {
        if (enable && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        vm.setNotificationsEnabled(enable)
        val intent = Intent(this, WatchService::class.java)
        if (enable) ContextCompat.startForegroundService(this, intent) else stopService(intent)
    }
}

// ---------------------------------------------------------------- onboarding

@Composable
private fun OnboardingScreen(state: UiState, vm: WalletViewModel) {
    var xpub by remember { mutableStateOf("") }
    var label by remember { mutableStateOf("") }
    var showScanner by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val cameraPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted -> if (granted) showScanner = true }

    if (showScanner) {
        QrScannerDialog(
            onResult = { raw ->
                xpub = Regex("(?:[xyz]pub)[1-9A-HJ-NP-Za-km-z]+").find(raw)?.value ?: raw.trim()
                showScanner = false
                if (state.inputError != null) vm.clearError()
            },
            onDismiss = { showScanner = false },
        )
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Spacer(Modifier.height(40.dp))
        Text("PyBLØCK", style = MaterialTheme.typography.displayLarge, color = Purple)
        Text("WATCH", style = MaterialTheme.typography.titleLarge, color = TextSoft)

        Panel(accent = Purple) {
            SectionLabel("Solo lectura, por diseño")
            Spacer(Modifier.height(8.dp))
            Explain(
                "Esta app mira, no gasta. No contiene código de firma: aunque quisiera, " +
                    "no podría mover una sola moneda. Por eso solo le das tu clave PÚBLICA " +
                    "extendida — la xpub — que sirve para calcular tus direcciones y " +
                    "consultar sus saldos, pero nunca para gastar."
            )
            Spacer(Modifier.height(10.dp))
            Explain(
                "Cuidado con la privacidad: una xpub revela TODAS tus direcciones, " +
                    "presentes y futuras. Guárdala como guardarías tu extracto bancario."
            )
        }

        OutlinedTextField(
            value = xpub,
            onValueChange = { xpub = it; if (state.inputError != null) vm.clearError() },
            label = { Text("xpub / ypub / zpub", style = MaterialTheme.typography.bodySmall) },
            textStyle = MaterialTheme.typography.bodySmall,
            isError = state.inputError != null,
            minLines = 3,
            modifier = Modifier.fillMaxWidth(),
        )
        state.inputError?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = Bad) }

        TextButton(onClick = {
            if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
            ) showScanner = true else cameraPermission.launch(Manifest.permission.CAMERA)
        }) { Text("📷  Escanear QR con la cámara", color = Purple,
                  style = MaterialTheme.typography.bodySmall) }

        OutlinedTextField(
            value = label,
            onValueChange = { label = it },
            label = { Text("Nombre (opcional)", style = MaterialTheme.typography.bodySmall) },
            textStyle = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.fillMaxWidth(),
        )

        Button(
            onClick = { vm.setXpub(xpub, label) },
            enabled = xpub.isNotBlank(),
            colors = ButtonDefaults.buttonColors(containerColor = Purple, contentColor = Ink),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth(),
        ) { Text("MIRAR LAS DOS CADENAS", style = MaterialTheme.typography.titleMedium) }

        Panel(accent = Orange) {
            SectionLabel("Qué va a pasar", Orange)
            Spacer(Modifier.height(8.dp))
            Explain(
                "Se consultará la MISMA xpub en las dos cadenas: la bifurcación BLAKE2b y " +
                    "la SHA-256 clásica. Comparten el mismo bloque génesis y el mismo sistema " +
                    "de direcciones, así que tus llaves existen en ambas — pero los saldos " +
                    "divergieron el día de la bifurcación. Verás las dos cifras por separado."
            )
        }
    }
}

// ---------------------------------------------------------------- wallet

@Composable
private fun WalletScreen(state: UiState, vm: WalletViewModel, onToggleNotifications: (Boolean) -> Unit) {
    val chain = state.selected
    val cs = state.current
    val accent by animateColorAsState(Color(chain.accent), tween(400), label = "accent")
    var showSettings by remember { mutableStateOf(false) }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Spacer(Modifier.height(28.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("PyBLØCK WATCH", style = MaterialTheme.typography.titleMedium, color = accent)
                Text(
                    state.label.ifBlank { "monedero solo lectura" },
                    style = MaterialTheme.typography.bodySmall, color = TextFaint,
                )
            }
            TextButton(onClick = { showSettings = !showSettings }) {
                Text(if (showSettings) "cerrar" else "ajustes",
                     style = MaterialTheme.typography.bodySmall, color = TextSoft)
            }
        }

        ChainSwitcher(state.selected, state.chains, vm::select)

        BalanceCard(chain, cs, accent, state.scriptType)

        ScanStatus(cs, accent, onRetry = { vm.scan(chain) })

        if (cs.transactions.isNotEmpty()) MovementsCard(cs.transactions, accent)

        if (cs.fingerprintChanged) {
            Panel(accent = Bad) {
                SectionLabel("El certificado del servidor ha CAMBIADO", Bad)
                Spacer(Modifier.height(8.dp))
                Explain(
                    "La huella no coincide con la que vimos la primera vez. Puede ser un " +
                        "cambio legítimo (certificado renovado) o alguien interponiéndose. " +
                        "No lo aceptes sin comprobarlo por otra vía."
                )
                Spacer(Modifier.height(6.dp))
                cs.fingerprint?.let {
                    SelectionContainer { Text(it, style = MaterialTheme.typography.bodySmall, color = Bad) }
                }
                TextButton(onClick = { vm.trustCurrentCertificate(chain) }) {
                    Text("He comprobado la huella: confiar", color = Warn,
                         style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        Reveal(showSettings) {
            SettingsPanel(state, vm, accent, onToggleNotifications) { vm.forget() }
        }

        if (cs.rows.isNotEmpty()) AddressList(cs.rows, accent)

        Panel(accent = accent) {
            SectionLabel("Cómo se encuentran tus monedas", accent)
            Spacer(Modifier.height(8.dp))
            Explain(
                "Tu xpub no guarda una lista de direcciones: las genera. La app deriva " +
                    "m/0/0, m/0/1, m/0/2… y pregunta al servidor por cada una. Cuando " +
                    "encuentra ${'$'}{20} vacías seguidas, asume que no hay más y para. Eso es " +
                    "el «límite de hueco», y es lo que dibuja el círculo de arriba mientras escanea."
            )
        }
        Spacer(Modifier.height(30.dp))
    }
}

@Composable
private fun ChainSwitcher(selected: Chain, chains: Map<Chain, ChainState>, onSelect: (Chain) -> Unit) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(PanelSoft).padding(4.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Chain.entries.forEach { c ->
            val active = c == selected
            val bg by animateColorAsState(
                if (active) Color(c.accent).copy(alpha = 0.18f) else Color.Transparent,
                tween(300), label = "tabbg",
            )
            Column(
                Modifier.weight(1f).clip(RoundedCornerShape(11.dp)).background(bg)
                    .clickable { onSelect(c) }.padding(vertical = 10.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    c.display,
                    style = MaterialTheme.typography.titleMedium,
                    color = if (active) Color(c.accent) else TextFaint,
                )
                val st = chains[c]
                val sats = st?.total ?: 0L
                Text(
                    if (st?.phase is ScanPhase.Complete) "${formatSats(sats).first} ₿" else "…",
                    style = MaterialTheme.typography.bodySmall,
                    color = if (active) TextSoft else TextFaint,
                )
            }
        }
    }
}

@Composable
private fun BalanceCard(chain: Chain, cs: ChainState, accent: Color, scriptType: ScriptType?) {
    // Count the balance up rather than snapping: the movement is what tells the
    // user a number just changed, and it makes the two chains feel comparable.
    val target = cs.total / 100_000_000f
    val shown by animateFloatAsState(target, tween(900), label = "balance")

    Panel(accent = accent) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            SectionLabel("saldo ${chain.display}", accent)
            Spacer(Modifier.weight(1f))
            if (cs.phase is ScanPhase.Complete) PulseDot(Good, 7)
        }
        Spacer(Modifier.height(6.dp))
        Row(verticalAlignment = Alignment.Bottom) {
            Text("%.8f".format(shown), style = MaterialTheme.typography.displayLarge, color = accent)
            Spacer(Modifier.width(8.dp))
            Text("₿", style = MaterialTheme.typography.titleLarge, color = accent.copy(alpha = 0.7f))
        }
        Text("${cs.total} sats", style = MaterialTheme.typography.bodySmall, color = TextFaint)

        if (cs.unconfirmed != 0L) {
            Spacer(Modifier.height(4.dp))
            Text("sin confirmar: ${cs.unconfirmed} sats",
                 style = MaterialTheme.typography.bodySmall, color = Warn)
        }
        Spacer(Modifier.height(10.dp))
        Text(
            "${cs.usedAddresses} direcciones con uso · altura ${cs.height}",
            style = MaterialTheme.typography.bodySmall, color = TextSoft,
        )
        scriptType?.let {
            Text("${it.label} — ${it.explain}",
                 style = MaterialTheme.typography.bodySmall, color = TextFaint)
        }
        Spacer(Modifier.height(6.dp))
        Explain(chain.blurb)
    }
}

@Composable
private fun ScanStatus(cs: ChainState, accent: Color, onRetry: () -> Unit) {
    Panel(accent = accent) {
        AnimatedContent(
            targetState = cs.phase,
            transitionSpec = { fadeIn(tween(200)) togetherWith fadeOut(tween(120)) },
            label = "phase",
        ) { phase ->
            when (phase) {
                is ScanPhase.Idle -> Text("en espera", style = MaterialTheme.typography.bodySmall, color = TextFaint)

                is ScanPhase.Connecting -> Row(verticalAlignment = Alignment.CenterVertically) {
                    PulseDot(accent); Spacer(Modifier.width(10.dp))
                    Column {
                        Text("conectando con ${phase.endpoint}",
                             style = MaterialTheme.typography.bodyMedium, color = accent)
                        Explain("El primer saludo TLS con Frigate puede tardar hasta 40 s.")
                    }
                }

                is ScanPhase.Scanning -> Row(verticalAlignment = Alignment.CenterVertically) {
                    GapRing(phase.gapUsed, phase.gapLimit, accent)
                    Spacer(Modifier.width(14.dp))
                    Column(Modifier.weight(1f)) {
                        DerivationTicker(phase.path, accent)
                        Text(
                            if (phase.chainIndex == 0) "cadena de recepción" else "cadena de cambio",
                            style = MaterialTheme.typography.bodySmall, color = TextFaint,
                        )
                        Text("${phase.gapUsed}/${phase.gapLimit} vacías seguidas",
                             style = MaterialTheme.typography.bodySmall, color = TextSoft)
                    }
                }

                is ScanPhase.Complete -> Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        PulseDot(Good); Spacer(Modifier.width(10.dp))
                        Text("escaneo completo", style = MaterialTheme.typography.bodyMedium, color = Good)
                    }
                    cs.server?.let {
                        Spacer(Modifier.height(6.dp))
                        Text("servidor: $it", style = MaterialTheme.typography.bodySmall, color = TextSoft)
                    }
                    cs.fingerprint?.let {
                        Text("huella fijada: ${it.take(16)}…",
                             style = MaterialTheme.typography.bodySmall, color = TextFaint)
                    }
                }

                is ScanPhase.Error -> Column {
                    Text("no se pudo completar", style = MaterialTheme.typography.bodyMedium, color = Bad)
                    Spacer(Modifier.height(4.dp))
                    Explain(phase.message)
                    TextButton(onClick = onRetry) {
                        Text("reintentar", color = accent, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

@Composable
private fun AddressList(rows: List<AddressRow>, accent: Color) {
    Panel(accent = accent) {
        SectionLabel("direcciones con actividad", accent)
        Spacer(Modifier.height(10.dp))
        rows.forEach { row ->
            Row(Modifier.fillMaxWidth().padding(vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(shortAddress(row.address),
                         style = MaterialTheme.typography.bodyMedium, color = TextMain)
                    Text(
                        "${row.path}  ·  ${if (row.chainIndex == 0) "recepción" else "cambio"}",
                        style = MaterialTheme.typography.bodySmall, color = TextFaint,
                    )
                }
                Text(
                    "%.8f".format(row.total / 100_000_000f),
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (row.total > 0) accent else TextFaint,
                    fontWeight = FontWeight.Bold,
                )
            }
        }
    }
}

@Composable
private fun SettingsPanel(
    state: UiState,
    vm: WalletViewModel,
    accent: Color,
    onToggleNotifications: (Boolean) -> Unit,
    onForget: () -> Unit,
) {
    val chain = state.selected
    var host by remember(chain) { mutableStateOf(vm.endpointFor(chain).let { if (it.isCustom) it.host else "" }) }
    var port by remember(chain) { mutableStateOf(vm.endpointFor(chain).port.toString()) }

    Panel(accent = accent) {
        SectionLabel("ajustes", accent)
        Spacer(Modifier.height(10.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Avisarme si cambia el saldo",
                     style = MaterialTheme.typography.bodyMedium, color = TextMain)
                Explain("Un servicio comprueba las direcciones ya descubiertas cada 15 minutos. " +
                    "Sin servidor de push, sin Google: la consulta la hace tu teléfono.")
            }
            Switch(
                checked = state.notificationsEnabled,
                onCheckedChange = onToggleNotifications,
                colors = SwitchDefaults.colors(checkedThumbColor = accent),
            )
        }

        Spacer(Modifier.height(14.dp))
        Text("Tipo de dirección (derivación)",
             style = MaterialTheme.typography.bodyMedium, color = TextMain)
        Explain("Cómo se leen las claves de tu xpub. Por defecto BIP84 (bc1q). " +
            "Cámbialo si tu monedero usa otro formato; se reescanean las dos cadenas.")
        Spacer(Modifier.height(4.dp))
        DerivationSelector(state.scriptType, accent) { vm.setScriptType(it) }

        Spacer(Modifier.height(14.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Límite de hueco (gap): ${state.gapLimit}",
                     style = MaterialTheme.typography.bodyMedium, color = TextMain)
                Explain("Cuántas direcciones vacías seguidas se revisan antes de parar. " +
                    "Súbelo si usas muchas direcciones; bájalo para escanear más rápido.")
            }
            TextButton(onClick = { vm.setGapLimit(state.gapLimit - 5) }) {
                Text("−5", color = accent, style = MaterialTheme.typography.bodyMedium)
            }
            TextButton(onClick = { vm.setGapLimit(state.gapLimit + 5) }) {
                Text("+5", color = accent, style = MaterialTheme.typography.bodyMedium)
            }
        }

        Spacer(Modifier.height(14.dp))
        if (chain.allowsCustomNode) {
            Text("Tu propio nodo ${chain.display}",
                 style = MaterialTheme.typography.bodyMedium, color = TextMain)
            Explain("Déjalo vacío para usar ${chain.defaultHost}:${chain.defaultPort}.")
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = host, onValueChange = { host = it },
                    label = { Text("host", style = MaterialTheme.typography.bodySmall) },
                    textStyle = MaterialTheme.typography.bodySmall,
                    singleLine = true, modifier = Modifier.weight(2f),
                )
                OutlinedTextField(
                    value = port, onValueChange = { port = it.filter(Char::isDigit).take(5) },
                    label = { Text("puerto", style = MaterialTheme.typography.bodySmall) },
                    textStyle = MaterialTheme.typography.bodySmall,
                    singleLine = true, modifier = Modifier.weight(1f),
                )
            }
            TextButton(onClick = {
                vm.setCustomNode(chain, host.ifBlank { null }, port.toIntOrNull() ?: chain.defaultPort)
            }) { Text("aplicar y reescanear", color = accent, style = MaterialTheme.typography.bodySmall) }
        } else {
            Explain(
                "La cadena SHA-256 es solo consulta: sirve para encontrar tus monedas con la " +
                    "xpub, y por eso no ofrece nodo propio."
            )
        }

        Spacer(Modifier.height(10.dp))
        SelectionContainer {
            Text(
                state.xpub?.let { "${it.take(24)}…${it.takeLast(10)}" } ?: "",
                style = MaterialTheme.typography.bodySmall, color = TextFaint,
            )
        }
        TextButton(onClick = onForget) {
            Text("olvidar esta xpub", color = Bad, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun DerivationSelector(current: ScriptType?, accent: Color, onSelect: (ScriptType) -> Unit) {
    fun purpose(t: ScriptType) = when (t) {
        ScriptType.P2PKH -> 44; ScriptType.P2SH_P2WPKH -> 49
        ScriptType.P2WPKH -> 84; ScriptType.P2TR -> 86
    }
    Column {
        ScriptType.entries.forEach { t ->
            val sel = t == current
            TextButton(onClick = { onSelect(t) }, modifier = Modifier.fillMaxWidth()) {
                Text(
                    (if (sel) "● " else "○ ") + "BIP${purpose(t)} · ${t.label}  (m/${purpose(t)}'/0'/0')",
                    color = if (sel) accent else TextMain,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

@Composable
private fun MovementsCard(txs: List<TxConf>, accent: Color) {
    Panel(accent = accent) {
        SectionLabel("movimientos · confirmaciones", accent)
        Spacer(Modifier.height(8.dp))
        txs.take(15).forEach { t ->
            Row(
                Modifier.fillMaxWidth().padding(vertical = 3.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "${t.txid.take(8)}…${t.txid.takeLast(6)}",
                    style = MaterialTheme.typography.bodySmall, color = TextSoft,
                    modifier = Modifier.weight(1f),
                )
                if (t.pending) {
                    Text("en mempool · 0 conf",
                         style = MaterialTheme.typography.bodySmall, color = Warn)
                } else {
                    Text(
                        "${t.confirmations} conf" + if (t.confirmations >= 6) "  ✓" else "",
                        style = MaterialTheme.typography.bodySmall,
                        color = if (t.confirmations >= 6) Good else TextSoft,
                    )
                }
            }
        }
        if (txs.size > 15) {
            Text("… y ${txs.size - 15} más",
                 style = MaterialTheme.typography.bodySmall, color = TextFaint)
        }
    }
}
