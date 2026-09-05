package com.kilombino.pyblockwatch.crypto

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The hash primitives Bitcoin address derivation needs.
 *
 * SHA-256 and HMAC-SHA512 come from the platform (present on every Android API
 * level we support). RIPEMD-160 does not exist in Android's providers, so it
 * lives in [Ripemd160] inside this repo — see the note there.
 */
object Hashes {

    fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    /** Bitcoin's double-SHA256, used for Base58Check checksums. */
    fun doubleSha256(data: ByteArray): ByteArray = sha256(sha256(data))

    /** HASH160 = RIPEMD160(SHA256(x)) — the payload of every P2PKH/P2WPKH address. */
    fun hash160(data: ByteArray): ByteArray = Ripemd160.digest(sha256(data))

    fun hmacSha512(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA512")
        mac.init(SecretKeySpec(key, "HmacSHA512"))
        return mac.doFinal(data)
    }

    fun ByteArray.toHex(): String {
        val sb = StringBuilder(size * 2)
        for (b in this) sb.append("%02x".format(b.toInt() and 0xFF))
        return sb.toString()
    }

    fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "hex string must have even length" }
        return ByteArray(hex.length / 2) {
            ((Character.digit(hex[it * 2], 16) shl 4) or Character.digit(hex[it * 2 + 1], 16)).toByte()
        }
    }
}
