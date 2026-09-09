package com.kilombino.pyblockwatch.data

import com.kilombino.pyblockwatch.chain.Chain
import com.kilombino.pyblockwatch.chain.ElectrumClient
import com.kilombino.pyblockwatch.chain.ScriptHashBalance
import com.kilombino.pyblockwatch.chain.NodeEndpoint
import com.kilombino.pyblockwatch.crypto.Address
import com.kilombino.pyblockwatch.crypto.Bip32
import com.kilombino.pyblockwatch.crypto.ScriptType
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn

/** One derived address and what the chain says about it. */
data class AddressRow(
    val chainIndex: Int,       // 0 = receive, 1 = change
    val index: Int,
    val address: String,
    val path: String,          // e.g. "m/0/3", shown so the user can follow along
    val scriptHash: String,
    val confirmed: Long = 0,
    val unconfirmed: Long = 0,
    val txCount: Int = 0,
) {
    val total: Long get() = confirmed + unconfirmed
    val isUsed: Boolean get() = txCount > 0 || total > 0
}

/**
 * Progress events, emitted one at a time so the UI can narrate the scan instead of
 * showing an opaque spinner. Someone watching should be able to see that a wallet
 * is a sequence of derived keys, each asked about independently.
 */
sealed interface ScanEvent {
    data class Connecting(val endpoint: NodeEndpoint) : ScanEvent
    data class Connected(val server: String, val height: Int, val fingerprint: String?,
                         val fingerprintChanged: Boolean) : ScanEvent
    data class Deriving(val chainIndex: Int, val index: Int, val path: String) : ScanEvent
    data class Found(val row: AddressRow) : ScanEvent
    data class GapProgress(val chainIndex: Int, val consecutiveEmpty: Int, val gapLimit: Int) : ScanEvent
    data class Done(val rows: List<AddressRow>, val height: Int, val txs: List<TxConf>) : ScanEvent
    data class Failed(val message: String) : ScanEvent
}

/** A wallet transaction and how deep it is: pending (in the mempool) or N confirmations. */
data class TxConf(val txid: String, val confirmations: Int, val pending: Boolean)

/**
 * Walks an xpub the way every wallet does: derive `chain/index`, ask the server
 * whether anything ever touched it, and stop after [gapLimit] consecutive unused
 * addresses.
 *
 * The gap limit is the whole reason a watch-only wallet can find your coins without
 * knowing how many addresses you used: BIP-44 promises you never skip more than 20
 * in a row, so 20 consecutive empties means the end.
 */
class Scanner(
    private val gapLimit: Int = 20,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) {

    fun scan(
        xpub: String,
        chain: Chain,
        endpoint: NodeEndpoint,
        pinnedFingerprint: String?,
        scriptType: ScriptType,
        gap: Int = gapLimit,
    ): Flow<ScanEvent> = flow {
        val purpose = purposeFor(scriptType)
        val txHeights = HashMap<String, Int>()
        val parsed = try {
            Bip32.parseExtendedPubKey(xpub)
        } catch (e: IllegalArgumentException) {
            emit(ScanEvent.Failed(e.message ?: "Invalid extended key")); return@flow
        }

        emit(ScanEvent.Connecting(endpoint))
        val client = ElectrumClient(endpoint, pinnedFingerprint)
        try {
            client.connect()
        } catch (e: Exception) {
            emit(ScanEvent.Failed(e.message ?: "No se pudo conectar")); return@flow
        }

        val rows = mutableListOf<AddressRow>()
        try {
            val height = client.blockHeight()
            emit(ScanEvent.Connected(
                client.serverVersion ?: "desconocido", height,
                client.serverFingerprint, client.fingerprintChanged,
            ))

            // Receive chain then change chain. Both are scanned: a wallet's balance
            // lives on both, and showing only the receive side under-reports funds.
            for (chainIndex in 0..1) {
                val branch = Bip32.deriveChild(parsed, chainIndex)
                var index = 0
                var consecutiveEmpty = 0
                while (consecutiveEmpty < gap) {
                    val path = "m/$purpose'/0'/0'/$chainIndex/$index"
                    emit(ScanEvent.Deriving(chainIndex, index, path))

                    val child = Bip32.deriveChild(branch, index)
                    val scriptHash = Address.scriptHashFor(child.pubkey(), scriptType)
                    val address = Address.encode(child.pubkey(), scriptType)

                    // History first, balance only when there IS history. Most addresses
                    // in a scan are unused, and asking for a balance we already know is
                    // zero doubles the round trips on the common path.
                    val hist = client.history(scriptHash)
                    val txs = hist.size
                    val bal = if (txs > 0) client.balance(scriptHash) else ScriptHashBalance(0, 0)

                    val row = AddressRow(
                        chainIndex = chainIndex, index = index, address = address,
                        path = path, scriptHash = scriptHash,
                        confirmed = bal.confirmed, unconfirmed = bal.unconfirmed, txCount = txs,
                    )
                    if (row.isUsed) {
                        rows += row
                        hist.forEach { txHeights[it.txid] = it.height }
                        consecutiveEmpty = 0
                        emit(ScanEvent.Found(row))
                    } else {
                        consecutiveEmpty++
                        emit(ScanEvent.GapProgress(chainIndex, consecutiveEmpty, gap))
                    }
                    index++
                }
            }
            // Confirmations from the tip: height <= 0 is still in the mempool (0 conf).
            val txs = txHeights.map { (id, h) ->
                TxConf(id, if (h <= 0) 0 else height - h + 1, pending = h <= 0)
            }.sortedWith(compareBy({ !it.pending }, { it.confirmations }))
            emit(ScanEvent.Done(rows, height, txs))
        } catch (e: Exception) {
            emit(ScanEvent.Failed(e.message ?: "Fallo durante el escaneo"))
        } finally {
            client.close()
        }
    }.flowOn(dispatcher)

    /**
     * Cheap refresh of already-discovered addresses for the notification service.
     * Returns confirmed and unconfirmed apart so the watcher can distinguish a mempool
     * arrival, a confirmation and a spend.
     */
    suspend fun refreshBalance(
        rows: List<AddressRow>, endpoint: NodeEndpoint, pinnedFingerprint: String?,
    ): ScriptHashBalance {
        val client = ElectrumClient(endpoint, pinnedFingerprint)
        return try {
            client.connect()
            var confirmed = 0L; var unconfirmed = 0L
            for (r in rows) {
                val b = client.balance(r.scriptHash)
                confirmed += b.confirmed; unconfirmed += b.unconfirmed
            }
            ScriptHashBalance(confirmed, unconfirmed)
        } finally {
            client.close()
        }
    }

    /**
     * Silent refresh of the addresses a scan already found: re-query balance and history
     * for each known scripthash and recompute confirmations against the tip. No gap walk,
     * so it's cheap enough to run on a foreground timer without flickering the UI.
     */
    suspend fun refreshDetails(
        rows: List<AddressRow>, endpoint: NodeEndpoint, pinnedFingerprint: String?,
    ): Triple<List<AddressRow>, List<TxConf>, Int> {
        val client = ElectrumClient(endpoint, pinnedFingerprint)
        return try {
            client.connect()
            val tip = client.blockHeight()
            val txHeights = HashMap<String, Int>()
            val updated = rows.map { r ->
                val hist = client.history(r.scriptHash)
                hist.forEach { txHeights[it.txid] = it.height }
                val bal = client.balance(r.scriptHash)
                r.copy(confirmed = bal.confirmed, unconfirmed = bal.unconfirmed, txCount = hist.size)
            }
            val txs = txHeights.map { (id, h) ->
                TxConf(id, if (h <= 0) 0 else tip - h + 1, pending = h <= 0)
            }.sortedWith(compareBy({ !it.pending }, { it.confirmations }))
            Triple(updated, txs, tip)
        } finally {
            client.close()
        }
    }

    companion object {
        /** The script type the xpub prefix implies (SLIP-132), or null for a plain xpub. */
        fun scriptTypeOf(xpub: String): ScriptType? =
            runCatching { Bip32.parseExtendedPubKey(xpub).scriptType }.getOrNull()

        /** BIP purpose for a script type: 44 legacy, 49 nested, 84 native segwit, 86 taproot. */
        fun purposeFor(type: ScriptType): Int = when (type) {
            ScriptType.P2PKH -> 44
            ScriptType.P2SH_P2WPKH -> 49
            ScriptType.P2WPKH -> 84
            ScriptType.P2TR -> 86
        }
    }
}
