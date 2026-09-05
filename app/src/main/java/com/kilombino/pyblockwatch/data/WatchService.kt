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
                    val total = scanner.refreshTotal(rows, endpoint, store.pinnedFingerprint(endpoint))
                    val previous = store.lastTotal(chain)
                    store.setLastTotal(chain, total)
                    // -1 means "never scanned", so the first observation is not a change.
                    if (previous >= 0 && total != previous) notifyChange(chain, previous, total)
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
        val out = mutableListOf<AddressRow>()
        for (chainIndex in 0..1) {
            val branch = Bip32.deriveChild(account, chainIndex)
            for (i in 0 until WATCH_DEPTH) {
                val child = Bip32.deriveChild(branch, i)
                val sh = Address.scriptHashFor(child.pubkey(), account.scriptType)
                out += AddressRow(
                    chainIndex = chainIndex, index = i,
                    address = Address.encode(child.pubkey(), account.scriptType),
                    path = "m/$chainIndex/$i", scriptHash = sh,
                )
            }
        }
        return out
    }

    private fun notifyChange(chain: Chain, before: Long, after: Long) {
        val delta = after - before
        val sign = if (delta > 0) "+" else "−"
        val amount = "%.8f".format(delta.absoluteValue / 100_000_000f)
        val n = Notification.Builder(this, CHANNEL_ALERTS)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("${chain.display}: $sign$amount ₿")
            .setContentText("Nuevo saldo: %.8f ₿".format(after / 100_000_000f))
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
