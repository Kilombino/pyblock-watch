package com.kilombino.pyblockwatch.crypto

import java.math.BigInteger

/** Base58 and Base58Check — the encoding behind xpub/ypub/zpub and legacy `1…` addresses. */
object Base58 {

    private const val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private val INDEX = IntArray(128) { -1 }.also {
        ALPHABET.forEachIndexed { i, c -> it[c.code] = i }
    }

    fun encode(input: ByteArray): String {
        if (input.isEmpty()) return ""
        // Leading zero bytes are encoded as leading '1's, outside the base conversion.
        var zeros = 0
        while (zeros < input.size && input[zeros].toInt() == 0) zeros++

        var num = BigInteger(1, input)
        val sb = StringBuilder()
        val fifty8 = BigInteger.valueOf(58)
        while (num.signum() > 0) {
            val (q, r) = num.divideAndRemainder(fifty8)
            sb.append(ALPHABET[r.toInt()])
            num = q
        }
        repeat(zeros) { sb.append(ALPHABET[0]) }
        return sb.reverse().toString()
    }

    fun decode(input: String): ByteArray {
        if (input.isEmpty()) return ByteArray(0)
        var num = BigInteger.ZERO
        val fifty8 = BigInteger.valueOf(58)
        for (c in input) {
            val d = if (c.code < 128) INDEX[c.code] else -1
            require(d >= 0) { "invalid base58 character '$c'" }
            num = num.multiply(fifty8).add(BigInteger.valueOf(d.toLong()))
        }
        var bytes = num.toByteArray()
        // BigInteger may prepend a zero sign byte; drop it.
        if (bytes.size > 1 && bytes[0].toInt() == 0) bytes = bytes.copyOfRange(1, bytes.size)

        var zeros = 0
        while (zeros < input.length && input[zeros] == ALPHABET[0]) zeros++
        return ByteArray(zeros) + bytes
    }

    /** Decode and verify the 4-byte double-SHA256 checksum, returning the payload. */
    fun decodeChecked(input: String): ByteArray {
        val raw = decode(input)
        require(raw.size >= 5) { "base58check string too short" }
        val payload = raw.copyOfRange(0, raw.size - 4)
        val checksum = raw.copyOfRange(raw.size - 4, raw.size)
        val expected = Hashes.doubleSha256(payload).copyOfRange(0, 4)
        require(checksum.contentEquals(expected)) { "bad base58check checksum" }
        return payload
    }

    fun encodeChecked(payload: ByteArray): String =
        encode(payload + Hashes.doubleSha256(payload).copyOfRange(0, 4))
}
