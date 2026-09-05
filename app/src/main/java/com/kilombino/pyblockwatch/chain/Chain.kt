package com.kilombino.pyblockwatch.chain

/**
 * The two chains this wallet can watch.
 *
 * They share a genesis block and Bitcoin's whole address scheme — the BLAKE2b fork
 * changed the proof-of-work, not key derivation — so ONE xpub is meaningful on both
 * sides, and the interesting question the app answers is "what does this key hold on
 * each side of the fork?".
 *
 * Both are WATCH-ONLY by construction. There is no signing code anywhere in this
 * app, so neither chain can spend; the distinction the user cares about is which
 * server answers, not which one is trusted with keys.
 */
enum class Chain(
    val id: String,
    val display: String,
    val ticker: String,
    val defaultHost: String,
    val defaultPort: Int,
    val accent: Long,
    val blurb: String,
) {
    BLAKE2B(
        id = "blake2b",
        display = "BLAKE2b",
        ticker = "₿",
        defaultHost = "fulcrum.kilombino.com",
        defaultPort = 17717,
        accent = 0xFFB96BFF,
        blurb = "La bifurcación con prueba de trabajo BLAKE2b. Cabeceras de 164 bytes.",
    ),
    SHA256(
        id = "sha256",
        display = "SHA-256",
        ticker = "₿",
        defaultHost = "nobip110fulcrum.kilombino.com",
        defaultPort = 50002,
        accent = 0xFFF7931A,
        blurb = "La cadena SHA-256 clásica. Solo lectura: busca tus monedas con la xpub.",
    );

    /** Only BLAKE2b offers pointing at your own node; SHA-256 is a lookup service. */
    val allowsCustomNode: Boolean get() = this == BLAKE2B
}

/** Where to reach a chain: the bundled default, or a node the user typed in. */
data class NodeEndpoint(val host: String, val port: Int, val isCustom: Boolean = false) {
    override fun toString() = "$host:$port"
    companion object {
        fun default(chain: Chain) = NodeEndpoint(chain.defaultHost, chain.defaultPort, false)
    }
}
