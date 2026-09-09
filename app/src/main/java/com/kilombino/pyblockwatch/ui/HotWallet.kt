package com.kilombino.pyblockwatch.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.kilombino.pyblockwatch.crypto.Bip39
import java.security.SecureRandom

// ------------------------------------------------------------------- create with dice

/**
 * Generate a seed the SeedSigner way: roll a physical die and tap what it shows, 50 times for
 * 12 words or 99 for 24. The rolls become entropy by SHA-256 (so the same rolls reproduce the
 * same seed on air-gapped hardware); the app never sees a network or the device RNG unless the
 * user picks the shortcut. The mnemonic is shown once to write down, then encrypted behind the
 * biometric gate on "create".
 */
@Composable
fun DiceScreen(vm: WalletViewModel, onBack: () -> Unit) {
    val activity = LocalContext.current as FragmentActivity
    var strength by remember { mutableStateOf(256) }          // 24 words by default
    var rolls by remember { mutableStateOf("") }
    var mnemonic by remember { mutableStateOf<List<String>?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val needed = if (strength == 128) 50 else 99

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Spacer(Modifier.height(30.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("New wallet", style = MaterialTheme.typography.titleLarge, color = Purple,
                 modifier = Modifier.weight(1f))
            TextButton(onClick = onBack) { Text("back", color = TextSoft,
                style = MaterialTheme.typography.bodySmall) }
        }

        val words = mnemonic
        if (words == null) {
            Panel(accent = Purple) {
                SectionLabel("Roll dice for your seed")
                Spacer(Modifier.height(8.dp))
                Explain("Tap the number each roll of a real die shows. $needed rolls become your " +
                    "seed by SHA-256 — the same rolls give the same seed on a SeedSigner, so you " +
                    "can verify this offline. Nothing leaves the phone.")
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                WordCountChip("12 words", strength == 128, Modifier.weight(1f)) { strength = 128; rolls = "" }
                WordCountChip("24 words", strength == 256, Modifier.weight(1f)) { strength = 256; rolls = "" }
            }

            Panel(accent = Orange) {
                Text("${rolls.length} / $needed rolls",
                     style = MaterialTheme.typography.titleMedium, color = Orange)
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.fillMaxWidth()) {
                    for (n in 1..6) {
                        DieButton(n, enabled = rolls.length < needed, modifier = Modifier.weight(1f)) {
                            if (rolls.length < needed) rolls += n.toString()
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                Row {
                    TextButton(onClick = { if (rolls.isNotEmpty()) rolls = rolls.dropLast(1) }) {
                        Text("⌫ undo", color = TextSoft, style = MaterialTheme.typography.bodySmall)
                    }
                    TextButton(onClick = { rolls = "" }) {
                        Text("clear", color = TextFaint, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }

            error?.let { Text(it, color = Bad, style = MaterialTheme.typography.bodySmall) }

            Button(
                onClick = {
                    error = null
                    runCatching { Bip39.fromEntropy(Bip39.entropyFromDiceRolls(rolls, strength)) }
                        .onSuccess { mnemonic = it }
                        .onFailure { error = it.message }
                },
                enabled = rolls.length == needed,
                colors = ButtonDefaults.buttonColors(containerColor = Purple, contentColor = Ink),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("GENERATE SEED", style = MaterialTheme.typography.titleMedium) }

            TextButton(onClick = {
                error = null
                val bytes = ByteArray(strength / 8).also { SecureRandom().nextBytes(it) }
                runCatching { Bip39.fromEntropy(bytes) }
                    .onSuccess { mnemonic = it }.onFailure { error = it.message }
            }, modifier = Modifier.fillMaxWidth()) {
                Text("or use the phone's secure randomness", color = TextFaint,
                     style = MaterialTheme.typography.bodySmall)
            }
        } else {
            SeedBackup(
                words = words,
                onDiscard = { mnemonic = null; rolls = "" },
                onConfirm = {
                    error = null
                    runCatching { vm.seedEncryptCipher() }
                        .onSuccess { cipher ->
                            Biometric.authenticate(
                                activity, "Protect your seed",
                                "Unlock to encrypt and store it",
                                cipher,
                                onSuccess = { authed -> vm.createHotWallet(words, authed) { error = it } },
                                onError = { error = it },
                            )
                        }
                        .onFailure { error = it.message }
                },
            )
            error?.let { Text(it, color = Bad, style = MaterialTheme.typography.bodySmall) }
        }
    }
}

@Composable
private fun WordCountChip(label: String, selected: Boolean, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Column(
        modifier.clip(RoundedCornerShape(11.dp))
            .background(if (selected) Purple.copy(alpha = 0.18f) else PanelSoft)
            .clickable(onClick = onClick).padding(vertical = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(label, color = if (selected) Purple else TextSoft,
             style = MaterialTheme.typography.titleMedium)
    }
}

@Composable
private fun DieButton(n: Int, enabled: Boolean, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Column(
        modifier.clip(RoundedCornerShape(10.dp))
            .background(if (enabled) Orange.copy(alpha = 0.16f) else PanelSoft)
            .clickable(enabled = enabled, onClick = onClick).padding(vertical = 14.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("$n", color = if (enabled) Orange else TextFaint,
             style = MaterialTheme.typography.titleLarge)
    }
}

@Composable
private fun SeedBackup(words: List<String>, onDiscard: () -> Unit, onConfirm: () -> Unit) {
    Panel(accent = Bad) {
        SectionLabel("Write these ${words.size} words down", Bad)
        Spacer(Modifier.height(6.dp))
        Explain("This is the ONLY backup of your money. Anyone who sees it can take your coins; " +
            "if you lose it, no one can recover them. Write it on paper — never a photo or the cloud.")
    }
    Spacer(Modifier.height(10.dp))
    Panel(accent = Purple) {
        SelectionContainer {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                words.chunked(2).forEachIndexed { rowIdx, pair ->
                    Row(Modifier.fillMaxWidth()) {
                        pair.forEachIndexed { colIdx, w ->
                            val n = rowIdx * 2 + colIdx + 1
                            Text(
                                "$n. $w",
                                style = MaterialTheme.typography.bodyMedium,
                                fontFamily = FontFamily.Monospace, color = TextMain,
                                modifier = Modifier.weight(1f),
                            )
                        }
                    }
                }
            }
        }
    }
    Spacer(Modifier.height(12.dp))
    Button(
        onClick = onConfirm,
        colors = ButtonDefaults.buttonColors(containerColor = Purple, contentColor = Ink),
        shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxWidth(),
    ) { Text("I'VE WRITTEN IT DOWN — CREATE", style = MaterialTheme.typography.titleMedium) }
    TextButton(onClick = onDiscard, modifier = Modifier.fillMaxWidth()) {
        Text("start over", color = TextFaint, style = MaterialTheme.typography.bodySmall)
    }
}

// ------------------------------------------------------------------- restore from words

@Composable
fun RestoreScreen(vm: WalletViewModel, onBack: () -> Unit) {
    val activity = LocalContext.current as FragmentActivity
    var phrase by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Spacer(Modifier.height(30.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Restore wallet", style = MaterialTheme.typography.titleLarge, color = Purple,
                 modifier = Modifier.weight(1f))
            TextButton(onClick = onBack) { Text("back", color = TextSoft,
                style = MaterialTheme.typography.bodySmall) }
        }
        Panel(accent = Purple) {
            SectionLabel("Enter your seed words")
            Spacer(Modifier.height(8.dp))
            Explain("Type your 12 or 24 BIP-39 words, separated by spaces. They are checked before " +
                "anything is stored, and then encrypted behind your biometric.")
        }
        OutlinedTextField(
            value = phrase, onValueChange = { phrase = it; error = null },
            label = { Text("seed words", style = MaterialTheme.typography.bodySmall) },
            textStyle = MaterialTheme.typography.bodyMedium,
            minLines = 3, modifier = Modifier.fillMaxWidth(),
        )
        error?.let { Text(it, color = Bad, style = MaterialTheme.typography.bodySmall) }
        Button(
            onClick = {
                val words = phrase.trim().lowercase().split(Regex("\\s+"))
                if (!Bip39.isValid(words)) { error = "Those words are not a valid BIP-39 seed."; return@Button }
                runCatching { vm.seedEncryptCipher() }.onSuccess { cipher ->
                    Biometric.authenticate(
                        activity, "Protect your seed", "Unlock to encrypt and store it", cipher,
                        onSuccess = { authed -> vm.createHotWallet(words, authed) { error = it } },
                        onError = { error = it },
                    )
                }.onFailure { error = it.message }
            },
            enabled = phrase.isNotBlank(),
            colors = ButtonDefaults.buttonColors(containerColor = Purple, contentColor = Ink),
            shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxWidth(),
        ) { Text("RESTORE", style = MaterialTheme.typography.titleMedium) }
    }
}

// ------------------------------------------------------------------- send

@Composable
fun SendSheet(vm: WalletViewModel, accent: Color, onClose: () -> Unit) {
    val activity = LocalContext.current as FragmentActivity
    val state by vm.state.collectAsState()
    var to by remember { mutableStateOf("") }
    var amount by remember { mutableStateOf("") }
    var feeRate by remember { mutableStateOf("2") }

    Panel(accent = accent) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            SectionLabel("send", accent)
            Spacer(Modifier.weight(1f))
            TextButton(onClick = { vm.resetSend(); onClose() }) {
                Text("close", color = TextSoft, style = MaterialTheme.typography.bodySmall)
            }
        }
        Spacer(Modifier.height(8.dp))

        when (val phase = state.sendPhase) {
            is SendPhase.Sent -> {
                Text("Broadcast ✓", color = Good, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(6.dp))
                SelectionContainer { Text(phase.txid, color = TextSoft,
                    style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace) }
                Spacer(Modifier.height(8.dp))
                Button(onClick = { vm.resetSend(); onClose() },
                    colors = ButtonDefaults.buttonColors(containerColor = accent, contentColor = Ink),
                    shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxWidth()) {
                    Text("DONE", style = MaterialTheme.typography.titleMedium)
                }
            }

            is SendPhase.Review -> {
                val d = phase.draft
                RowLine("To", shortAddress(d.toAddress), accent)
                RowLine("Amount", "${groupSats(d.amount)} sats", accent)
                RowLine("Fee", "${groupSats(d.fee)} sats", accent)
                RowLine("Change", if (d.change > 0) "${groupSats(d.change)} sats" else "—", accent)
                RowLine("Inputs", "${d.inputs.size}", accent)
                Spacer(Modifier.height(10.dp))
                Button(
                    onClick = {
                        runCatching { vm.seedDecryptCipher() }.onSuccess { cipher ->
                            Biometric.authenticate(
                                activity, "Confirm payment", "Unlock to sign and send", cipher,
                                onSuccess = { authed -> vm.confirmSend(authed) },
                                onError = { /* stays on review; user can retry */ },
                            )
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = accent, contentColor = Ink),
                    shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxWidth(),
                ) { Text("CONFIRM & SIGN", style = MaterialTheme.typography.titleMedium) }
                TextButton(onClick = { vm.resetSend() }, modifier = Modifier.fillMaxWidth()) {
                    Text("edit", color = TextFaint, style = MaterialTheme.typography.bodySmall)
                }
            }

            SendPhase.Preparing, SendPhase.Broadcasting -> {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    PulseDot(accent); Spacer(Modifier.width(10.dp))
                    Text(if (phase is SendPhase.Broadcasting) "signing & broadcasting…" else "choosing coins…",
                         color = accent, style = MaterialTheme.typography.bodyMedium)
                }
            }

            else -> { // Editing or Failed
                if (state.sendPhase is SendPhase.Failed) {
                    Text((state.sendPhase as SendPhase.Failed).message, color = Bad,
                         style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(6.dp))
                }
                OutlinedTextField(
                    value = to, onValueChange = { to = it },
                    label = { Text("recipient address", style = MaterialTheme.typography.bodySmall) },
                    textStyle = MaterialTheme.typography.bodySmall, singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = amount, onValueChange = { amount = it.filter(Char::isDigit) },
                        label = { Text("amount (sats)", style = MaterialTheme.typography.bodySmall) },
                        textStyle = MaterialTheme.typography.bodySmall, singleLine = true,
                        modifier = Modifier.weight(2f),
                    )
                    OutlinedTextField(
                        value = feeRate,
                        onValueChange = { feeRate = it.filter { c -> c.isDigit() || c == '.' } },
                        label = { Text("sat/vB", style = MaterialTheme.typography.bodySmall) },
                        textStyle = MaterialTheme.typography.bodySmall, singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                }
                Spacer(Modifier.height(10.dp))
                Button(
                    onClick = {
                        vm.prepareSend(
                            to.trim(),
                            amount.toLongOrNull() ?: 0L,
                            feeRate.toDoubleOrNull() ?: 1.0,
                        )
                    },
                    enabled = to.isNotBlank() && (amount.toLongOrNull() ?: 0L) > 0,
                    colors = ButtonDefaults.buttonColors(containerColor = accent, contentColor = Ink),
                    shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxWidth(),
                ) { Text("REVIEW", style = MaterialTheme.typography.titleMedium) }
            }
        }
    }
}

@Composable
private fun RowLine(label: String, value: String, accent: Color) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(label, color = TextFaint, style = MaterialTheme.typography.bodySmall,
             modifier = Modifier.weight(1f))
        Text(value, color = accent, style = MaterialTheme.typography.bodyMedium,
             fontWeight = FontWeight.Bold)
    }
}
