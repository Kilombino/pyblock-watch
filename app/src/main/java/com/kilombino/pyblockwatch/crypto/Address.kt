package com.kilombino.pyblockwatch.crypto

/**
 * Address and scriptPubKey derivation, plus the Electrum "scripthash" both of our
 * servers index by.
 *
 * Both chains share Bitcoin's address formats and the same genesis block — the
 * BLAKE2b fork changed the proof-of-work, not the key derivation — so one code
 * path serves both and the same xpub is meaningful on either side.
 */
object Address {

    private const val HRP_MAINNET = "bc"
    private const val P2PKH_VERSION = 0x00
    private const val P2SH_VERSION = 0x05

    /** The scriptPubKey a given public key locks coins to, under [type]. */
    fun scriptPubKey(pubkey: ByteArray, type: ScriptType): ByteArray {
        val h160 = Hashes.hash160(pubkey)
        return when (type) {
            // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
            ScriptType.P2PKH ->
                byteArrayOf(0x76, 0xa9.toByte(), 0x14) + h160 + byteArrayOf(0x88.toByte(), 0xac.toByte())
            // OP_HASH160 <20 = hash160(redeemScript)> OP_EQUAL, redeemScript = OP_0 <20>
            ScriptType.P2SH_P2WPKH -> {
                val redeem = byteArrayOf(0x00, 0x14) + h160
                byteArrayOf(0xa9.toByte(), 0x14) + Hashes.hash160(redeem) + byteArrayOf(0x87.toByte())
            }
            // OP_0 <20>
            ScriptType.P2WPKH -> byteArrayOf(0x00, 0x14) + h160
        }
    }

    /** The human-readable address for a public key under [type]. */
    fun encode(pubkey: ByteArray, type: ScriptType): String {
        val h160 = Hashes.hash160(pubkey)
        return when (type) {
            ScriptType.P2PKH -> Base58.encodeChecked(byteArrayOf(P2PKH_VERSION.toByte()) + h160)
            ScriptType.P2SH_P2WPKH -> {
                val redeem = byteArrayOf(0x00, 0x14) + h160
                Base58.encodeChecked(byteArrayOf(P2SH_VERSION.toByte()) + Hashes.hash160(redeem))
            }
            ScriptType.P2WPKH -> Bech32.encodeSegwit(HRP_MAINNET, 0, h160)
        }
    }

    /**
     * Electrum indexes by `sha256(scriptPubKey)` **reversed** — the byte order trips
     * up nearly everyone implementing this the first time.
     */
    fun electrumScriptHash(scriptPubKey: ByteArray): String {
        val digest = Hashes.sha256(scriptPubKey)
        digest.reverse()
        return with(Hashes) { digest.toHex() }
    }

    /** Convenience: pubkey → the scripthash to ask the server about. */
    fun scriptHashFor(pubkey: ByteArray, type: ScriptType): String =
        electrumScriptHash(scriptPubKey(pubkey, type))
}
