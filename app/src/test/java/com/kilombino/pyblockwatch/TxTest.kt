package com.kilombino.pyblockwatch

import com.kilombino.pyblockwatch.crypto.Address
import com.kilombino.pyblockwatch.crypto.Bip32Priv
import com.kilombino.pyblockwatch.crypto.Ecdsa
import com.kilombino.pyblockwatch.crypto.Hashes
import com.kilombino.pyblockwatch.crypto.Hashes.toHex
import com.kilombino.pyblockwatch.crypto.ScriptType
import com.kilombino.pyblockwatch.crypto.Secp256k1
import com.kilombino.pyblockwatch.crypto.TxBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

/**
 * The BIP-143 worked example is the anchor: if the P2WPKH sighash and its witness signature
 * come out byte-for-byte, then prevout/sequence/output commitments, the scriptCode, the
 * segwit preimage, RFC-6979 ECDSA and DER are all correct at once. Plus address decoding,
 * which turns a recipient string into the scriptPubKey a send pays to.
 */
class TxTest {

    // The two inputs and two outputs of the BIP-143 native-P2WPKH example.
    private val in0 = TxBuilder.Input(
        txid = "9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff",
        vout = 0, value = 625000000L,
        privateKey = BigInteger.ONE, pubkey = ByteArray(33), // input 0 is not ours; only its outpoint/seq matter here
        sequence = 0xffffffeeL,
    )
    private val in1 = TxBuilder.Input(
        txid = "8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef",
        vout = 1, value = 600000000L,
        privateKey = BigInteger("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9", 16),
        pubkey = Hashes.hexToBytes("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"),
        sequence = 0xffffffffL,
    )
    private val outs = listOf(
        TxBuilder.Output(Hashes.hexToBytes("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac"), 112340000L),
        TxBuilder.Output(Hashes.hexToBytes("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac"), 223450000L),
    )

    @Test
    fun `bip143 p2wpkh sighash matches the worked example`() {
        val h = TxBuilder.sighash(version = 1, inputs = listOf(in0, in1), outputs = outs, index = 1, locktime = 17)
        assertEquals("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670", h.toHex())
    }

    @Test
    fun `bip143 witness signature matches the worked example`() {
        val sig = TxBuilder.witnessSignature(version = 1, inputs = listOf(in0, in1), outputs = outs, index = 1, locktime = 17)
        assertEquals(
            "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a" +
                "0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01",
            sig.toHex(),
        )
    }

    @Test
    fun `bech32 v0 address decodes to the witness program script`() {
        // BIP-173 test vector.
        val spk = Address.decodeToScriptPubKey("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        assertEquals("0014751e76e8199196d454941c45d1b3a323f1433bd6", spk.toHex())
    }

    @Test
    fun `decode is the inverse of encode for our own key`() {
        val seed = Hashes.hexToBytes("000102030405060708090a0b0c0d0e0f")
        val node = Bip32Priv.derivePath(Bip32Priv.fromSeed(seed), "m/84'/0'/0'/0/0")
        val pub = node.publicKey()
        val address = Address.encode(pub, ScriptType.P2WPKH)
        assertEquals(
            Address.scriptPubKey(pub, ScriptType.P2WPKH).toHex(),
            Address.decodeToScriptPubKey(address).toHex(),
        )
    }

    @Test
    fun `a built transaction has a verifiable witness for every input`() {
        val seed = Hashes.hexToBytes("000102030405060708090a0b0c0d0e0f")
        val n0 = Bip32Priv.derivePath(Bip32Priv.fromSeed(seed), "m/84'/0'/0'/0/0")
        val n1 = Bip32Priv.derivePath(Bip32Priv.fromSeed(seed), "m/84'/0'/0'/0/1")
        val inputs = listOf(
            TxBuilder.Input("a".repeat(64), 0, 100_000L, n0.key, n0.publicKey()),
            TxBuilder.Input("b".repeat(64), 1, 60_000L, n1.key, n1.publicKey()),
        )
        val to = Address.decodeToScriptPubKey("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        val change = Address.scriptPubKey(n0.publicKey(), ScriptType.P2WPKH)
        val outputs = listOf(TxBuilder.Output(to, 120_000L), TxBuilder.Output(change, 39_500L))
        val signed = TxBuilder.build(inputs, outputs)

        assertTrue(signed.rawHex.startsWith("02000000000102")) // version 2 + segwit marker/flag
        assertEquals(64, signed.txid.length)
        for (i in inputs.indices) {
            val h = TxBuilder.sighash(2, inputs, outputs, i, 0)
            val der = TxBuilder.witnessSignature(2, inputs, outputs, i, 0)
            // strip the trailing sighash byte, parse DER back to (r,s), verify under the input's key.
            val point = Secp256k1.decompress(inputs[i].pubkey)
            assertTrue("witness $i must verify", Ecdsa.verify(point, h, parseDer(der.copyOf(der.size - 1))))
        }
    }

    /** Minimal DER (r,s) parser, for the round-trip check only. */
    private fun parseDer(der: ByteArray): Ecdsa.Signature {
        var p = 2 // skip 0x30, total-len
        require(der[p].toInt() == 0x02); p++
        val rlen = der[p].toInt() and 0xFF; p++
        val r = BigInteger(1, der.copyOfRange(p, p + rlen)); p += rlen
        require(der[p].toInt() == 0x02); p++
        val slen = der[p].toInt() and 0xFF; p++
        val s = BigInteger(1, der.copyOfRange(p, p + slen))
        return Ecdsa.Signature(r, s)
    }
}
