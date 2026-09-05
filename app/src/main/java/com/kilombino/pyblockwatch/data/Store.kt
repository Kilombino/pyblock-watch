package com.kilombino.pyblockwatch.data

import android.content.Context
import com.kilombino.pyblockwatch.chain.Chain
import com.kilombino.pyblockwatch.chain.NodeEndpoint

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

    var notificationsEnabled: Boolean
        get() = prefs.getBoolean(KEY_NOTIFY, false)
        set(v) = prefs.edit().putBoolean(KEY_NOTIFY, v).apply()

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
        fun keyHost(c: Chain) = "host_${c.id}"
        fun keyPort(c: Chain) = "port_${c.id}"
        fun keyTotal(c: Chain) = "total_${c.id}"
        fun keyPin(e: NodeEndpoint) = "pin_${e.host}_${e.port}"
    }
}
