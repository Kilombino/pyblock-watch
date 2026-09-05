package com.kilombino.pyblockwatch.data

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import com.kilombino.pyblockwatch.chain.Chain
import com.kilombino.pyblockwatch.crypto.Address
import com.kilombino.pyblockwatch.crypto.Bip32
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlin.math.absoluteValue

/**
 * Balance-change notifications, without a push server.
 *
 * The upstream PyBLØCK app routes notifications through UnifiedPush, which is a
 * good degoogled answer but still means a server knows your device and your npub.
 * A watch-only wallet does not need that: the phone can simply ask the Electrum
 * server itself. Nothing about this wallet leaves the device except the scripthash
 * queries the wallet already makes.
 *
 * The cost is honesty about battery: this is a visible foreground service on a
 * 15-minute loop, not a free push wake-up. The user opts in and can see it running.
 */
class WatchService : Service() {

    private var job: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(ONGOING_ID, ongoingNotification())
        if (job?.isActive != true) job = scope.launch { loop() }
        return START_STICKY
    }

    override fun onDestroy() {
        job?.cancel(); scope.cancel()
        super.onDestroy()
    }

    private suspend fun loop() {
        val store = Store(this)
        val scanner = Scanner()
        while (scope.isActive) {
            val xpub = store.xpub
            if (xpub == null || !store.notificationsEnabled) { delay(INTERVAL_MS); continue }

            for (chain in Chain.entries) {
                runCatching {
                    val rows = deriveKnownAddresses(xpub, chain, store)
                    if (rows.isEmpty()) return@runCatching
                    val endpoint = store.endpoint(chain)
                    val bal = scanner.refreshBalance(rows, endpoint, store.pinnedFingerprint(endpoint))
                    val prevConf = store.lastConfirmed(chain)
                    val prevUnconf = store.lastUnconfirmed(chain)
                    store.setLastBalance(chain, bal.confirmed, bal.unconfirmed)
                    // prevConf == -1 means "never scanned", so the first observation is not a change.
                    if (prevConf >= 0 && (bal.confirmed != prevConf || bal.unconfirmed != prevUnconf)) {
                        notifyChange(chain, prevConf, prevUnconf, bal.confirmed, bal.unconfirmed)
                    }
                }
            }
            delay(INTERVAL_MS)
        }
    }

    /**
     * Re-derive the addresses a scan already found. We keep only the count in
     * storage, not the address list, so this walks the same deterministic path the
     * scanner did — cheap, and it keeps a single source of truth for derivation.
     */
    private fun deriveKnownAddresses(xpub: String, chain: Chain, store: Store): List<AddressRow> {
        val account = runCatching { Bip32.parseExtendedPubKey(xpub) }.getOrNull() ?: return emptyList()
        val type = store.scriptType
        val depth = store.gapLimit
        val out = mutableListOf<AddressRow>()
        for (chainIndex in 0..1) {
            val branch = Bip32.deriveChild(account, chainIndex)
            for (i in 0 until depth) {
                val child = Bip32.deriveChild(branch, i)
                val sh = Address.scriptHashFor(child.pubkey(), type)
                out += AddressRow(
                    chainIndex = chainIndex, index = i,
                    address = Address.encode(child.pubkey(), type),
                    path = "m/$chainIndex/$i", scriptHash = sh,
                )
            }
        }
        return out
    }

    private fun notifyChange(
        chain: Chain, prevConf: Long, prevUnconf: Long, newConf: Long, newUnconf: Long,
    ) {
        fun btc(sats: Long) = "%.8f".format(sats.absoluteValue / 100_000_000f)
        val prevTotal = prevConf + prevUnconf
        val newTotal = newConf + newUnconf
        val delta = newTotal - prevTotal
        val (title, text) = when {
            delta > 0 && newUnconf > prevUnconf ->
                "Recibiendo +${btc(delta)} ₿" to "En la mempool · 0 confirmaciones (aún no confirmado)"
            delta > 0 ->
                "Recibido +${btc(delta)} ₿" to "Confirmado · saldo ${btc(newTotal)} ₿"
            delta < 0 && newUnconf != 0L ->
                "Enviando −${btc(delta)} ₿" to "En la mempool · 0 confirmaciones"
            delta < 0 ->
                "Enviado −${btc(delta)} ₿" to "Confirmado · saldo ${btc(newTotal)} ₿"
            else -> // total unchanged but a pending tx moved: it just confirmed
                "Confirmado" to "${btc(newConf - prevConf)} ₿ ya tienen confirmaciones"
        }
        val n = Notification.Builder(this, CHANNEL_ALERTS)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("${chain.display}: $title")
            .setContentText(text)
            .setAutoCancel(true)
            .setContentIntent(openApp())
            .build()
        manager().notify(chain.ordinal + 100, n)
    }

    private fun ongoingNotification(): Notification {
        ensureChannels()
        return Notification.Builder(this, CHANNEL_ONGOING)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("Vigilando tus saldos")
            .setContentText("Consulta cada 15 min · sin servidor de push")
            .setOngoing(true)
            .setContentIntent(openApp())
            .build()
    }

    private fun openApp(): PendingIntent {
        val intent = packageManager.getLaunchIntentForPackage(packageName)
        return PendingIntent.getActivity(
            this, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    private fun manager() = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    private fun ensureChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val m = manager()
        m.createNotificationChannel(
            NotificationChannel(CHANNEL_ONGOING, "Vigilancia", NotificationManager.IMPORTANCE_MIN)
        )
        m.createNotificationChannel(
            NotificationChannel(CHANNEL_ALERTS, "Cambios de saldo", NotificationManager.IMPORTANCE_DEFAULT)
        )
    }

    private companion object {
        const val CHANNEL_ONGOING = "watch_ongoing"
        const val CHANNEL_ALERTS = "watch_alerts"
        const val ONGOING_ID = 1
        const val INTERVAL_MS = 15 * 60 * 1000L
        /** How far down each branch the background check looks. */
        const val WATCH_DEPTH = 20
    }
}
