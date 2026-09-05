package com.kilombino.pyblockwatch.chain

import com.kilombino.pyblockwatch.crypto.Hashes
import com.kilombino.pyblockwatch.crypto.Hashes.toHex
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/** What the server said about one scripthash. */
data class ScriptHashBalance(val confirmed: Long, val unconfirmed: Long) {
    val total: Long get() = confirmed + unconfirmed
}

class ElectrumException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * A minimal Electrum protocol 1.4 client.
 *
 * Three things here are not obvious and were established by probing the real
 * servers rather than read from a spec:
 *
 *  1. **`jsonrpc: "2.0"` is mandatory.** Frigate (the SHA-256 server) rejects any
 *     request without that field with `-32600 Invalid Request`. Fulcrum tolerates
 *     its absence, so a client tested only against Fulcrum breaks on Frigate.
 *
 *  2. **Certificates are self-signed** — Frigate's even says `CN=localhost`. That
 *     is normal for Electrum servers and it means CA validation is meaningless
 *     here. Instead we pin: the SHA-256 fingerprint is remembered on first connect
 *     and any later change is surfaced to the user rather than silently accepted.
 *
 *  3. **The first TLS handshake can take ~40 seconds.** Frigate is slow to respond
 *     on a cold connection, so the timeouts are deliberately generous; a 10-second
 *     timeout looks like "server down" when it is merely slow.
 */
class ElectrumClient(
    private val endpoint: NodeEndpoint,
    private val pinnedFingerprint: String?,
) {
    companion object {
        private const val CONNECT_TIMEOUT_MS = 20_000
        private const val READ_TIMEOUT_MS = 60_000
    }

    private var socket: SSLSocket? = null
    private var reader: BufferedReader? = null
    private var writer: BufferedWriter? = null
    private var nextId = 0

    /** SHA-256 fingerprint of the certificate this connection actually presented. */
    var serverFingerprint: String? = null
        private set

    /** True when a pin was supplied and the server presented a different certificate. */
    var fingerprintChanged: Boolean = false
        private set

    var serverVersion: String? = null
        private set

    /**
     * Connect, capturing the certificate. We do not reject on mismatch here — the
     * caller decides how to present that to the user, because silently failing and
     * silently accepting are both wrong.
     */
    fun connect() {
        val raw = connectRaw()
        val ctx = SSLContext.getInstance("TLS")
        val capture = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                val fp = Hashes.sha256(chain[0].encoded).toHex()
                serverFingerprint = fp
                if (pinnedFingerprint != null && !pinnedFingerprint.equals(fp, ignoreCase = true)) {
                    fingerprintChanged = true
                }
            }
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        ctx.init(null, arrayOf(capture), java.security.SecureRandom())

        val ssl = ctx.socketFactory.createSocket(raw, endpoint.host, endpoint.port, true) as SSLSocket
        ssl.soTimeout = READ_TIMEOUT_MS
        try {
            ssl.startHandshake()
        } catch (e: Exception) {
            throw ElectrumException("No se pudo establecer TLS con ${endpoint}: ${e.message}", e)
        }
        socket = ssl
        reader = BufferedReader(InputStreamReader(ssl.inputStream, Charsets.UTF_8))
        writer = BufferedWriter(OutputStreamWriter(ssl.outputStream, Charsets.UTF_8))

        val version = call("server.version", JSONArray().put("PyBlockWatch").put("1.4"))
        serverVersion = (version as? JSONArray)?.optString(0) ?: version?.toString()
    }

    /**
     * Open the TCP socket, trying every resolved address.
     *
     * Both hostnames publish AAAA records through AirVPN's dynamic DNS, and a host
     * with no IPv6 default route will hang on those until the connect timeout. So we
     * walk all addresses and keep the first that answers instead of trusting the
     * resolver's ordering.
     */
    private fun connectRaw(): Socket {
        val addresses = try {
            InetAddress.getAllByName(endpoint.host)
        } catch (e: Exception) {
            throw ElectrumException("No se pudo resolver ${endpoint.host}: ${e.message}", e)
        }
        // IPv4 first: when IPv6 is advertised but unroutable, this avoids a stall.
        val ordered = addresses.sortedBy { it.address.size }
        var last: Exception? = null
        for (addr in ordered) {
            try {
                val s = Socket()
                s.connect(InetSocketAddress(addr, endpoint.port), CONNECT_TIMEOUT_MS)
                s.soTimeout = READ_TIMEOUT_MS
                s.tcpNoDelay = true
                return s
            } catch (e: Exception) {
                last = e
            }
        }
        throw ElectrumException("No se pudo conectar con $endpoint: ${last?.message}", last)
    }

    /** One JSON-RPC round trip. Requests are newline-delimited. */
    @Synchronized
    private fun call(method: String, params: JSONArray): Any? {
        val w = writer ?: throw ElectrumException("cliente no conectado")
        val r = reader ?: throw ElectrumException("cliente no conectado")
        val id = nextId++
        val req = JSONObject()
            .put("jsonrpc", "2.0")   // Frigate rejects the request without this.
            .put("id", id)
            .put("method", method)
            .put("params", params)
        try {
            w.write(req.toString()); w.write("\n"); w.flush()
        } catch (e: Exception) {
            throw ElectrumException("Se perdió la conexión al enviar $method: ${e.message}", e)
        }

        // Skip any subscription notification that arrives before our reply.
        while (true) {
            val line = try {
                r.readLine()
            } catch (e: Exception) {
                throw ElectrumException("Se perdió la conexión esperando $method: ${e.message}", e)
            } ?: throw ElectrumException("El servidor cerró la conexión durante $method")

            val obj = try { JSONObject(line) } catch (e: Exception) { continue }
            if (obj.has("error") && !obj.isNull("error")) {
                throw ElectrumException("$method: ${obj.get("error")}")
            }
            if (obj.optInt("id", -1) != id) continue   // notification, not our answer
            return obj.opt("result")
        }
    }

    fun blockHeight(): Int {
        val r = call("blockchain.headers.subscribe", JSONArray()) as? JSONObject
            ?: throw ElectrumException("respuesta inesperada de headers.subscribe")
        return r.getInt("height")
    }

    fun balance(scriptHash: String): ScriptHashBalance {
        val r = call("blockchain.scripthash.get_balance", JSONArray().put(scriptHash)) as? JSONObject
            ?: throw ElectrumException("respuesta inesperada de get_balance")
        return ScriptHashBalance(r.optLong("confirmed"), r.optLong("unconfirmed"))
    }

    /** Number of transactions touching this scripthash — how we detect a used address. */
    fun historyCount(scriptHash: String): Int {
        val r = call("blockchain.scripthash.get_history", JSONArray().put(scriptHash)) as? JSONArray
        return r?.length() ?: 0
    }

    fun close() {
        runCatching { socket?.close() }
        socket = null; reader = null; writer = null
    }
}
