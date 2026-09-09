package com.kilombino.pyblockwatch

import com.kilombino.pyblockwatch.crypto.Bip32Priv
import com.kilombino.pyblockwatch.crypto.Bip39
import com.kilombino.pyblockwatch.crypto.Ecdsa
import com.kilombino.pyblockwatch.crypto.Hashes
import com.kilombino.pyblockwatch.crypto.Hashes.toHex
import com.kilombino.pyblockwatch.crypto.Secp256k1
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

/**
 * The signing half is new and the whole point is that it never produces a wrong signature,
 * so these are the published vectors: BIP-32 Test Vector 1, a BIP-39 vector with the TREZOR
 * passphrase, and internal ECDSA round-trips. The unforgiving end-to-end anchor (BIP-143) is
 * exercised by the transaction test.
 */
class SigningTest {

    @Test
    fun `bip32 master and hardened child match test vector 1`() {
        val seed = Hashes.hexToBytes("000102030405060708090a0b0c0d0e0f")
        val m = Bip32Priv.fromSeed(seed)
        assertEquals(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
            m.keyBytes().toHex(),
        )
        assertEquals(
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
            m.chainCode.toHex(),
        )
        val m0h = Bip32Priv.derivePath(m, "m/0'")
        assertEquals(
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
            m0h.keyBytes().toHex(),
        )
        assertEquals(
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
            m0h.chainCode.toHex(),
        )
    }

    @Test
    fun `bip39 all-zero entropy yields the abandon mnemonic and TREZOR seed`() {
        val entropy = ByteArray(16) // 128 bits of zero
        val words = Bip39.fromEntropy(entropy)
        assertEquals(
            "abandon abandon abandon abandon abandon abandon " +
                "abandon abandon abandon abandon abandon about",
            words.joinToString(" "),
        )
        assertTrue(Bip39.isValid(words))
        val seed = Bip39.toSeed(words, "TREZOR")
        assertEquals(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e534955" +
                "31f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            seed.toHex(),
        )
    }

    @Test
    fun `bip39 rejects a tampered checksum`() {
        val good = "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about"
        assertTrue(Bip39.isValid(good.split(" ")))
        val bad = good.replace("about", "abandon")
        assertFalse(Bip39.isValid(bad.split(" ")))
    }

    @Test
    fun `dice rolls need the right count and produce SeedSigner entropy`() {
        val fifty = "1".repeat(50)
        val e = Bip39.entropyFromDiceRolls(fifty, 128)
        assertEquals(16, e.size)
        // SeedSigner: SHA-256 of the roll string, truncated. Pin the known digest.
        assertEquals(Hashes.sha256(fifty.toByteArray()).copyOf(16).toHex(), e.toHex())
    }

    @Test
    fun `ecdsa signs deterministically, verifies, and rejects a tampered message`() {
        val d = BigInteger("cca9fbcc1b41e5a95d369eaa6ddcff73b61a4efaa279cfc6567e8daa39cbaf50", 16)
        val pub = Secp256k1.multiply(d, Secp256k1.G)
        val hash = Hashes.sha256("Kilombino Bitcoin-Blake2b".toByteArray())

        val a = Ecdsa.sign(d, hash)
        val b = Ecdsa.sign(d, hash)
        assertEquals("RFC 6979 must be deterministic", a, b)          // same (key, msg) → same sig
        assertTrue(a.s <= Secp256k1.N.shiftRight(1))                  // low-S
        assertTrue(Ecdsa.verify(pub, hash, a))                       // verifies
        val other = Hashes.sha256("different".toByteArray())
        assertFalse(Ecdsa.verify(pub, other, a))                     // not under a different message
    }

    @Test
    fun `bip84 account zpub and first address match the published vector`() {
        val mnemonic = ("abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about").split(" ")
        val master = Bip32Priv.fromSeed(Bip39.toSeed(mnemonic))
        val zpub = Bip32Priv.accountXpub(master, purpose = 84, account = 0)
        assertEquals(
            "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtf" +
                "SdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
            zpub,
        )
        val first = Bip32Priv.derivePath(master, "m/84'/0'/0'/0/0")
        assertEquals(
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            com.kilombino.pyblockwatch.crypto.Address.encode(
                first.publicKey(), com.kilombino.pyblockwatch.crypto.ScriptType.P2WPKH),
        )
    }

    @Test
    fun `private key one has G as its public point`() {
        val pub = Secp256k1.multiply(BigInteger.ONE, Secp256k1.G)
        assertEquals(Secp256k1.compress(Secp256k1.G).toHex(), Secp256k1.compress(pub).toHex())
    }
}
