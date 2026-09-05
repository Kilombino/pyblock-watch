package com.kilombino.pyblockwatch.data

import android.content.Context
import com.kilombino.pyblockwatch.chain.Chain
import com.kilombino.pyblockwatch.chain.NodeEndpoint
import com.kilombino.pyblockwatch.crypto.ScriptType

/**
 * Everything this app remembers.
 *
 * Plain app-private SharedPreferences on purpose. A watch-only wallet holds NO
 * secrets — an xpub cannot spend, and this app has no signing code to misuse one
 * with — so wrapping it in EncryptedSharedPreferences would buy nothing except a
 * dependency on `androidx.security:security-crypto`, which is both an alpha and
 * deprecated by Google. An xpub IS privacy-sensitive (it reveals every address you
 * will ever use), so `allowBackup=false` keeps it off cloud backups, and Android's
 * per-app sandbox does the rest.
 */
class Store(context: Context) {

    private val prefs = context.applicationContext
        .getSharedPreferences("pyblockwatch", Context.MODE_PRIVATE)

    var xpub: String?
        get() = prefs.getString(KEY_XPUB, null)
        set(v) = prefs.edit().apply { if (v == null) remove(KEY_XPUB) else putString(KEY_XPUB, v) }.apply()

    var label: String
        get() = prefs.getString(KEY_LABEL, "") ?: ""
        set(v) = prefs.edit().putString(KEY_LABEL, v).apply()

    /** Which chain the user last looked at, so the app reopens where they left it. */
    var lastChain: Chain
        get() = Chain.entries.firstOrNull { it.id == prefs.getString(KEY_CHAIN, null) } ?: Chain.BLAKE2B
        set(v) = prefs.edit().putString(KEY_CHAIN, v.id).apply()

    fun endpoint(chain: Chain): NodeEndpoint {
        if (!chain.allowsCustomNode) return NodeEndpoint.default(chain)
        val host = prefs.getString(keyHost(chain), null) ?: return NodeEndpoint.default(chain)
        val port = prefs.getInt(keyPort(chain), chain.defaultPort)
        return NodeEndpoint(host, port, isCustom = true)
    }

    fun setCustomEndpoint(chain: Chain, host: String?, port: Int) {
        prefs.edit().apply {
            if (host.isNullOrBlank()) { remove(keyHost(chain)); remove(keyPort(chain)) }
            else { putString(keyHost(chain), host.trim()); putInt(keyPort(chain), port) }
        }.apply()
    }

    /**
     * Trust-on-first-use certificate pinning.
     *
     * Electrum servers use self-signed certificates — Frigate's literally says
     * `CN=localhost` — so CA validation says nothing. Remembering the fingerprint we
     * first saw, and shouting when it changes, is the security property that is
     * actually available here.
     */
    fun pinnedFingerprint(endpoint: NodeEndpoint): String? =
        prefs.getString(keyPin(endpoint), null)

    fun pinFingerprint(endpoint: NodeEndpoint, fingerprint: String) {
        prefs.edit().putString(keyPin(endpoint), fingerprint).apply()
    }

    fun forgetPin(endpoint: NodeEndpoint) {
        prefs.edit().remove(keyPin(endpoint)).apply()
    }

    /** Last known total per chain, so the service can tell "changed" from "first run". */
    fun lastTotal(chain: Chain): Long = prefs.getLong(keyTotal(chain), -1L)
    fun setLastTotal(chain: Chain, sats: Long) {
        prefs.edit().putLong(keyTotal(chain), sats).apply()
    }

    // Confirmed and unconfirmed tracked apart so the watcher can tell "arrived in the
    // mempool" from "just confirmed" from "sent", and word the notification accordingly.
    fun lastConfirmed(chain: Chain): Long = prefs.getLong(keyConf(chain), -1L)
    fun lastUnconfirmed(chain: Chain): Long = prefs.getLong(keyUnconf(chain), 0L)
    fun setLastBalance(chain: Chain, confirmed: Long, unconfirmed: Long) {
        prefs.edit().putLong(keyConf(chain), confirmed).putLong(keyUnconf(chain), unconfirmed).apply()
    }

    /** How many consecutive empty addresses end a branch scan. Configurable; sane bounds. */
    var gapLimit: Int
        get() = prefs.getInt(KEY_GAP, 20).coerceIn(5, 100)
        set(v) = prefs.edit().putInt(KEY_GAP, v.coerceIn(5, 100)).apply()

    // On by default: the whole point is to be told when coins arrive without opening the app.
    var notificationsEnabled: Boolean
        get() = prefs.getBoolean(KEY_NOTIFY, true)
        set(v) = prefs.edit().putBoolean(KEY_NOTIFY, v).apply()

    /**
     * Which address type to derive from the xpub. Defaults to native SegWit (BIP-84,
     * m/84'/0'/0', bc1q); the user can switch to Nested (BIP-49), Legacy (BIP-44) or
     * Taproot (BIP-86). Independent of the xpub prefix, so a plain `xpub` still works.
     */
    var scriptType: ScriptType
        get() = prefs.getString(KEY_SCRIPT, null)
            ?.let { runCatching { ScriptType.valueOf(it) }.getOrNull() } ?: ScriptType.P2WPKH
        set(v) = prefs.edit().putString(KEY_SCRIPT, v.name).apply()

    fun clearWallet() {
        prefs.edit().apply {
            remove(KEY_XPUB); remove(KEY_LABEL)
            Chain.entries.forEach { remove(keyTotal(it)) }
        }.apply()
    }

    private companion object {
        const val KEY_XPUB = "xpub"
        const val KEY_LABEL = "label"
        const val KEY_CHAIN = "chain"
        const val KEY_NOTIFY = "notify"
        const val KEY_SCRIPT = "scripttype"
        const val KEY_GAP = "gaplimit"
        fun keyHost(c: Chain) = "host_${c.id}"
        fun keyPort(c: Chain) = "port_${c.id}"
        fun keyTotal(c: Chain) = "total_${c.id}"
        fun keyConf(c: Chain) = "conf_${c.id}"
        fun keyUnconf(c: Chain) = "unconf_${c.id}"
        fun keyPin(e: NodeEndpoint) = "pin_${e.host}_${e.port}"
    }
}
