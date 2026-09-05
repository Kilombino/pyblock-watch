package com.kilombino.pyblockwatch.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.kilombino.pyblockwatch.chain.Chain
import com.kilombino.pyblockwatch.chain.NodeEndpoint
import com.kilombino.pyblockwatch.crypto.ScriptType
import com.kilombino.pyblockwatch.data.AddressRow
import com.kilombino.pyblockwatch.data.ScanEvent
import com.kilombino.pyblockwatch.data.Scanner
import com.kilombino.pyblockwatch.data.Store
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** What the scan is doing right now, so the UI can narrate rather than spin. */
sealed interface ScanPhase {
    data object Idle : ScanPhase
    data class Connecting(val endpoint: NodeEndpoint) : ScanPhase
    data class Scanning(val path: String, val chainIndex: Int, val gapUsed: Int, val gapLimit: Int) : ScanPhase
    data object Complete : ScanPhase
    data class Error(val message: String) : ScanPhase
}

data class ChainState(
    val phase: ScanPhase = ScanPhase.Idle,
    val rows: List<AddressRow> = emptyList(),
    val height: Int = 0,
    val server: String? = null,
    val fingerprint: String? = null,
    val fingerprintChanged: Boolean = false,
    val endpoint: NodeEndpoint? = null,
) {
    val confirmed: Long get() = rows.sumOf { it.confirmed }
    val unconfirmed: Long get() = rows.sumOf { it.unconfirmed }
    val total: Long get() = confirmed + unconfirmed
    val usedAddresses: Int get() = rows.size
}

data class UiState(
    val xpub: String? = null,
    val label: String = "",
    val scriptType: ScriptType? = null,
    val selected: Chain = Chain.BLAKE2B,
    val chains: Map<Chain, ChainState> = Chain.entries.associateWith { ChainState() },
    val notificationsEnabled: Boolean = false,
    val inputError: String? = null,
) {
    val current: ChainState get() = chains[selected] ?: ChainState()
    val hasWallet: Boolean get() = !xpub.isNullOrBlank()
}

class WalletViewModel(app: Application) : AndroidViewModel(app) {

    private val store = Store(app)
    private val scanner = Scanner()
    private val jobs = mutableMapOf<Chain, Job>()

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    init {
        val xpub = store.xpub
        _state.update {
            it.copy(
                xpub = xpub,
                label = store.label,
                scriptType = store.scriptType,
                selected = store.lastChain,
                notificationsEnabled = store.notificationsEnabled,
            )
        }
        if (xpub != null) Chain.entries.forEach { scan(it) }
    }

    /** Validate and store a pasted extended public key, then scan both chains. */
    fun setXpub(raw: String, label: String) {
        val trimmed = raw.trim().replace("\\s".toRegex(), "")
        val type = Scanner.scriptTypeOf(trimmed)
        if (type == null) {
            // Re-derive the real reason so the user sees something actionable.
            val why = runCatching { com.kilombino.pyblockwatch.crypto.Bip32.parseExtendedPubKey(trimmed) }
                .exceptionOrNull()?.message ?: "No se reconoce como xpub, ypub o zpub."
            _state.update { it.copy(inputError = why) }
            return
        }
        store.xpub = trimmed
        store.label = label
        // Default derivation: honour a specific prefix (ypub → nested, zpub → native),
        // but a plain xpub defaults to BIP-84 native segwit rather than legacy. The user
        // can still switch it afterwards with the type selector.
        val chosen = when (type) {
            ScriptType.P2SH_P2WPKH, ScriptType.P2WPKH -> type
            else -> ScriptType.P2WPKH
        }
        store.scriptType = chosen
        _state.update {
            it.copy(
                xpub = trimmed, label = label, scriptType = chosen, inputError = null,
                chains = Chain.entries.associateWith { ChainState() },
            )
        }
        Chain.entries.forEach { scan(it) }
    }

    /** Change the address type (BIP-84/49/44/86) and re-scan both chains. */
    fun setScriptType(type: ScriptType) {
        if (type == store.scriptType) return
        store.scriptType = type
        _state.update {
            it.copy(scriptType = type, chains = Chain.entries.associateWith { ChainState() })
        }
        if (!_state.value.xpub.isNullOrBlank()) Chain.entries.forEach { scan(it) }
    }

    fun clearError() = _state.update { it.copy(inputError = null) }

    fun select(chain: Chain) {
        store.lastChain = chain
        _state.update { it.copy(selected = chain) }
    }

    fun forget() {
        jobs.values.forEach(Job::cancel); jobs.clear()
        store.clearWallet()
        _state.value = UiState(notificationsEnabled = store.notificationsEnabled)
    }

    fun endpointFor(chain: Chain): NodeEndpoint = store.endpoint(chain)

    fun setCustomNode(chain: Chain, host: String?, port: Int) {
        store.setCustomEndpoint(chain, host, port)
        scan(chain)
    }

    fun setNotificationsEnabled(enabled: Boolean) {
        store.notificationsEnabled = enabled
        _state.update { it.copy(notificationsEnabled = enabled) }
    }

    /** Accept a changed certificate — only ever from an explicit user action. */
    fun trustCurrentCertificate(chain: Chain) {
        val st = _state.value.chains[chain] ?: return
        val ep = st.endpoint ?: return
        val fp = st.fingerprint ?: return
        store.pinFingerprint(ep, fp)
        _state.update { s ->
            s.copy(chains = s.chains + (chain to st.copy(fingerprintChanged = false)))
        }
        scan(chain)
    }

    fun scan(chain: Chain) {
        val xpub = _state.value.xpub ?: return
        jobs[chain]?.cancel()
        val endpoint = store.endpoint(chain)
        val pin = store.pinnedFingerprint(endpoint)

        jobs[chain] = viewModelScope.launch {
            val found = mutableListOf<AddressRow>()
            scanner.scan(xpub, chain, endpoint, pin, store.scriptType).collect { ev ->
                update(chain) { st ->
                    when (ev) {
                        is ScanEvent.Connecting ->
                            st.copy(phase = ScanPhase.Connecting(ev.endpoint), endpoint = ev.endpoint,
                                    rows = emptyList())
                        is ScanEvent.Connected -> {
                            // First sight of this server's certificate: pin it silently.
                            // A CHANGE is never auto-accepted — the UI asks.
                            if (pin == null && ev.fingerprint != null) store.pinFingerprint(endpoint, ev.fingerprint)
                            st.copy(server = ev.server, height = ev.height, fingerprint = ev.fingerprint,
                                    fingerprintChanged = ev.fingerprintChanged)
                        }
                        is ScanEvent.Deriving ->
                            st.copy(phase = ScanPhase.Scanning(ev.path, ev.chainIndex, 0, 20))
                        is ScanEvent.GapProgress ->
                            st.copy(phase = (st.phase as? ScanPhase.Scanning)
                                ?.copy(gapUsed = ev.consecutiveEmpty, gapLimit = ev.gapLimit) ?: st.phase)
                        is ScanEvent.Found -> {
                            found += ev.row
                            st.copy(rows = found.toList())
                        }
                        is ScanEvent.Done -> {
                            store.setLastTotal(chain, ev.rows.sumOf { it.total })
                            st.copy(phase = ScanPhase.Complete, rows = ev.rows, height = ev.height)
                        }
                        is ScanEvent.Failed -> st.copy(phase = ScanPhase.Error(ev.message))
                    }
                }
            }
        }
    }

    private fun update(chain: Chain, f: (ChainState) -> ChainState) {
        _state.update { s ->
            s.copy(chains = s.chains + (chain to f(s.chains[chain] ?: ChainState())))
        }
    }
}
