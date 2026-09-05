package com.kilombino.pyblockwatch

import com.kilombino.pyblockwatch.crypto.Address
import com.kilombino.pyblockwatch.crypto.Base58
import com.kilombino.pyblockwatch.crypto.Bip32
import com.kilombino.pyblockwatch.crypto.Hashes
import com.kilombino.pyblockwatch.crypto.Hashes.toHex
import com.kilombino.pyblockwatch.crypto.Ripemd160
import com.kilombino.pyblockwatch.crypto.ScriptType
import com.kilombino.pyblockwatch.crypto.Secp256k1
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Everything cryptographic in this app is implemented in-tree, so these vectors are
 * what stands between us and silently wrong addresses. They are the published ones:
 * RIPEMD-160 from the original spec, and the BIP-49/84 account vectors that every
 * wallet is expected to reproduce.
 */
class CryptoTest {

    @Test
    fun `ripemd160 matches the specification vectors`() {
        val vectors = mapOf(
            "" to "9c1185a5c5e9fc54612808977ee8f548b2258d31",
            "a" to "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
            "abc" to "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
            "message digest" to "5d0689ef49d2fae572b881b123a85ffa21595f36",
            "abcdefghijklmnopqrstuvwxyz" to "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
        )
        for ((input, expected) in vectors) {
            assertEquals("RIPEMD160(\"$input\")", expected, Ripemd160.digest(input.toByteArray()).toHex())
        }
    }

    @Test
    fun `ripemd160 handles a multi-block input`() {
        // 8 × "1234567890" = 80 bytes, forcing a second compression block.
        val input = "1234567890".repeat(8)
        assertEquals("9b752e45573d4b39f4dbd3323cab82bf63326bfb", Ripemd160.digest(input.toByteArray()).toHex())
    }

    @Test
    fun `secp256k1 generator is on the curve and compresses round-trip`() {
        val g = Secp256k1.G
        // y² == x³ + 7 (mod p)
        val lhs = g.y!!.modPow(java.math.BigInteger.TWO, Secp256k1.P)
        val rhs = (g.x!!.modPow(java.math.BigInteger.valueOf(3), Secp256k1.P) +
            java.math.BigInteger.valueOf(7)).mod(Secp256k1.P)
        assertEquals(lhs, rhs)

        val round = Secp256k1.decompress(Secp256k1.compress(g))
        assertEquals(g, round)
    }

    @Test
    fun `secp256k1 scalar multiplication matches known public keys`() {
        // k = 1 must give G itself; k = 2 the published doubling of G.
        assertEquals(Secp256k1.G, Secp256k1.multiply(java.math.BigInteger.ONE, Secp256k1.G))
        val two = Secp256k1.multiply(java.math.BigInteger.TWO, Secp256k1.G)
        assertEquals(
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            two.x!!.toString(16).padStart(64, '0'),
        )
    }

    @Test
    fun `base58check round-trips and rejects a corrupted checksum`() {
        val payload = Hashes.hexToBytes("00010966776006953d5567439e5e39f86a0d273bee")
        val encoded = Base58.encodeChecked(payload)
        assertEquals("16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM", encoded)
        assertTrue(Base58.decodeChecked(encoded).contentEquals(payload))

        val corrupted = encoded.dropLast(1) + if (encoded.last() == 'M') 'N' else 'M'
        var threw = false
        try { Base58.decodeChecked(corrupted) } catch (e: IllegalArgumentException) { threw = true }
        assertTrue("a bad checksum must be rejected", threw)
    }

    /**
     * BIP-84 test vector: the canonical `abandon…about` account zpub must yield the
     * published bech32 addresses. This exercises the whole stack at once — Base58
     * decode, point decompression, CKDpub, HASH160 (so RIPEMD-160) and Bech32.
     */
    @Test
    fun `bip84 zpub derives the published native segwit addresses`() {
        val zpub = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3Ef" +
            "H1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
        val account = Bip32.parseExtendedPubKey(zpub)
        assertEquals(ScriptType.P2WPKH, account.scriptType)

        val receive = Bip32.deriveChild(account, 0)
        assertEquals(
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            Address.encode(Bip32.deriveChild(receive, 0).pubkey(), ScriptType.P2WPKH),
        )
        assertEquals(
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
            Address.encode(Bip32.deriveChild(receive, 1).pubkey(), ScriptType.P2WPKH),
        )
        val change = Bip32.deriveChild(account, 1)
        assertEquals(
            "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
            Address.encode(Bip32.deriveChild(change, 0).pubkey(), ScriptType.P2WPKH),
        )
    }

    /** BIP-49 test vector: the same seed as a ypub must give the wrapped-SegWit address. */
    @Test
    fun `bip49 ypub derives the published nested segwit address`() {
        val ypub = "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxo" +
            "JwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP"
        val account = Bip32.parseExtendedPubKey(ypub)
        assertEquals(ScriptType.P2SH_P2WPKH, account.scriptType)
        val first = Bip32.deriveChild(Bip32.deriveChild(account, 0), 0)
        assertEquals("37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
            Address.encode(first.pubkey(), ScriptType.P2SH_P2WPKH))
    }

    /**
     * The Electrum scripthash of the genesis coinbase address. This exact value was
     * confirmed against both live servers — Fulcrum and Frigate each answered it with
     * a real balance — so it pins our byte order, which is the classic place to get
     * Electrum wrong (the digest is REVERSED).
     */
    @Test
    fun `electrum scripthash matches what the live servers index`() {
        val addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        val h160 = Base58.decodeChecked(addr).copyOfRange(1, 21)
        val spk = byteArrayOf(0x76, 0xa9.toByte(), 0x14) + h160 +
            byteArrayOf(0x88.toByte(), 0xac.toByte())
        assertEquals(
            "8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161",
            Address.electrumScriptHash(spk),
        )
    }

    @Test
    fun `an xprv is refused with an explanation instead of being parsed`() {
        val xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiCh" +
            "kVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        var message: String? = null
        try { Bip32.parseExtendedPubKey(xprv) } catch (e: IllegalArgumentException) { message = e.message }
        assertTrue("must refuse an xprv, said: $message", message != null)
    }
}
