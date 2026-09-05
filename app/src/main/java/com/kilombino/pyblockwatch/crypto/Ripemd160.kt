package com.kilombino.pyblockwatch.crypto

/**
 * RIPEMD-160, in-tree.
 *
 * Android's default security providers ship SHA-family digests and HMAC, but NOT
 * RIPEMD-160 — and Bitcoin's HASH160 (`RIPEMD160(SHA256(x))`) needs it for every
 * address we derive. Pulling in BouncyCastle just for this would add a large
 * third-party jar to the reproducible-build surface for ~120 lines of very
 * well-specified, fully deterministic code with published test vectors.
 *
 * This is a hash function: no secrets pass through it, and correctness is settled
 * entirely by the vectors in `Ripemd160Test`. Implemented from the Dobbertin–
 * Bosselaers–Preneel specification (1996).
 */
object Ripemd160 {

    // Message-word selection order, left and right lines.
    private val RL = intArrayOf(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    )
    private val RR = intArrayOf(
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    )

    // Per-round rotation amounts, left and right lines.
    private val SL = intArrayOf(
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    )
    private val SR = intArrayOf(
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    )

    // Round constants: left line uses the first row, right line the second.
    private val KL = intArrayOf(0x00000000, 0x5A827999, 0x6ED9EBA1, -0x70E44324, -0x56AC02B2)
    private val KR = intArrayOf(0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)

    /** The five nonlinear round functions, selected by round block j/16. */
    private fun f(j: Int, x: Int, y: Int, z: Int): Int = when (j / 16) {
        0 -> x xor y xor z
        1 -> (x and y) or (x.inv() and z)
        2 -> (x or y.inv()) xor z
        3 -> (x and z) or (y and z.inv())
        else -> x xor (y or z.inv())
    }

    private fun rol(v: Int, n: Int): Int = (v shl n) or (v ushr (32 - n))

    fun digest(input: ByteArray): ByteArray {
        // Padding: 0x80, then zeros, then the bit length as little-endian u64.
        val bitLen = input.size.toLong() * 8
        val padLen = ((55 - input.size) % 64 + 64) % 64 + 1
        val msg = ByteArray(input.size + padLen + 8)
        input.copyInto(msg)
        msg[input.size] = 0x80.toByte()
        for (i in 0 until 8) msg[msg.size - 8 + i] = (bitLen ushr (8 * i)).toByte()

        var h0 = 0x67452301
        var h1 = -0x10325477  // 0xEFCDAB89
        var h2 = -0x67452302  // 0x98BADCFE
        var h3 = 0x10325476
        var h4 = -0x3c2d1e10  // 0xC3D2E1F0

        val x = IntArray(16)
        var off = 0
        while (off < msg.size) {
            for (i in 0 until 16) {
                val b = off + i * 4
                x[i] = (msg[b].toInt() and 0xFF) or
                    ((msg[b + 1].toInt() and 0xFF) shl 8) or
                    ((msg[b + 2].toInt() and 0xFF) shl 16) or
                    ((msg[b + 3].toInt() and 0xFF) shl 24)
            }

            var al = h0; var bl = h1; var cl = h2; var dl = h3; var el = h4
            var ar = h0; var br = h1; var cr = h2; var dr = h3; var er = h4

            for (j in 0 until 80) {
                var t = al + f(j, bl, cl, dl) + x[RL[j]] + KL[j / 16]
                t = rol(t, SL[j]) + el
                al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = t

                t = ar + f(79 - j, br, cr, dr) + x[RR[j]] + KR[j / 16]
                t = rol(t, SR[j]) + er
                ar = er; er = dr; dr = rol(cr, 10); cr = br; br = t
            }

            // The two lines cross over when folded back into the state.
            val tmp = h1 + cl + dr
            h1 = h2 + dl + er
            h2 = h3 + el + ar
            h3 = h4 + al + br
            h4 = h0 + bl + cr
            h0 = tmp

            off += 64
        }

        val out = ByteArray(20)
        intArrayOf(h0, h1, h2, h3, h4).forEachIndexed { i, h ->
            for (k in 0 until 4) out[i * 4 + k] = (h ushr (8 * k)).toByte()
        }
        return out
    }
}
