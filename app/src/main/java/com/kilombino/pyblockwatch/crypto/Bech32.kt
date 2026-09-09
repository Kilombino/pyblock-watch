package com.kilombino.pyblockwatch.crypto

/**
 * Bech32 (BIP-173) and Bech32m (BIP-350) — the encoding for `bc1…` addresses.
 * Witness v0 uses Bech32, v1+ (Taproot) uses Bech32m; the only difference is the
 * checksum constant.
 */
object Bech32 {

    private const val CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private const val BECH32_CONST = 1
    private const val BECH32M_CONST = 0x2bc830a3

    private fun polymod(values: IntArray): Int {
        val gen = intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
        var chk = 1
        for (v in values) {
            val b = chk ushr 25
            chk = ((chk and 0x1ffffff) shl 5) xor v
            for (i in 0 until 5) if (((b ushr i) and 1) != 0) chk = chk xor gen[i]
        }
        return chk
    }

    private fun hrpExpand(hrp: String): IntArray {
        val out = IntArray(hrp.length * 2 + 1)
        hrp.forEachIndexed { i, c ->
            out[i] = c.code ushr 5
            out[i + hrp.length + 1] = c.code and 31
        }
        out[hrp.length] = 0
        return out
    }

    /** Regroup bits, e.g. 8→5 when encoding or 5→8 when decoding a witness program. */
    private fun convertBits(data: IntArray, from: Int, to: Int, pad: Boolean): IntArray? {
        var acc = 0
        var bits = 0
        val out = ArrayList<Int>()
        val maxv = (1 shl to) - 1
        for (value in data) {
            if (value < 0 || (value ushr from) != 0) return null
            acc = (acc shl from) or value
            bits += from
            while (bits >= to) {
                bits -= to
                out.add((acc ushr bits) and maxv)
            }
        }
        if (pad) {
            if (bits > 0) out.add((acc shl (to - bits)) and maxv)
        } else if (bits >= from || ((acc shl (to - bits)) and maxv) != 0) {
            return null
        }
        return out.toIntArray()
    }

    /**
     * Encode a SegWit address. [witnessVersion] 0 gives P2WPKH/P2WSH (Bech32),
     * 1 gives Taproot (Bech32m).
     */
    fun encodeSegwit(hrp: String, witnessVersion: Int, program: ByteArray): String {
        val data = convertBits(IntArray(program.size) { program[it].toInt() and 0xFF }, 8, 5, true)
            ?: error("cannot regroup witness program bits")
        val payload = intArrayOf(witnessVersion) + data
        val const = if (witnessVersion == 0) BECH32_CONST else BECH32M_CONST
        val values = hrpExpand(hrp) + payload + IntArray(6)
        val mod = polymod(values) xor const
        val checksum = IntArray(6) { (mod ushr (5 * (5 - it))) and 31 }
        val sb = StringBuilder(hrp).append('1')
        for (v in payload + checksum) sb.append(CHARSET[v])
        return sb.toString()
    }

    data class Segwit(val witnessVersion: Int, val program: ByteArray)

    /**
     * Decode a SegWit address under [hrp] (e.g. "bc"). Returns null on any malformed input —
     * bad checksum, mixed case, wrong witness-version/length, or a v0 program that is not
     * 20 or 32 bytes. Used to turn a recipient's `bc1…` into a scriptPubKey.
     */
    fun decodeSegwit(hrp: String, addr: String): Segwit? {
        if (addr != addr.lowercase() && addr != addr.uppercase()) return null // no mixed case
        val a = addr.lowercase()
        val pos = a.lastIndexOf('1')
        if (pos < 1 || pos + 7 > a.length || a.substring(0, pos) != hrp) return null
        val dataPart = a.substring(pos + 1)
        val values = IntArray(dataPart.length)
        for (i in dataPart.indices) {
            val idx = CHARSET.indexOf(dataPart[i])
            if (idx < 0) return null
            values[i] = idx
        }
        if (values.size < 7) return null
        val witnessVersion = values[0]
        if (witnessVersion < 0 || witnessVersion > 16) return null
        val expected = if (witnessVersion == 0) BECH32_CONST else BECH32M_CONST
        if (polymod(hrpExpand(hrp) + values) != expected) return null
        val program = convertBits(values.copyOfRange(1, values.size - 6), 5, 8, false) ?: return null
        if (program.size < 2 || program.size > 40) return null
        if (witnessVersion == 0 && program.size != 20 && program.size != 32) return null
        return Segwit(witnessVersion, ByteArray(program.size) { program[it].toByte() })
    }
}
