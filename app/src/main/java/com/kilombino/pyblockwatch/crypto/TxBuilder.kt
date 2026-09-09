package com.kilombino.pyblockwatch.crypto

import com.kilombino.pyblockwatch.crypto.Hashes.toHex
import java.io.ByteArrayOutputStream
import java.math.BigInteger

/**
 * Build and sign native-SegWit (P2WPKH) transactions.
 *
 * Every input this wallet spends is P2WPKH, so signing is the BIP-143 segwit sighash and
 * nothing else — no legacy sighash, no script trees. The BIP-143 worked example is the
 * anchor in the tests: the sighash and the witness signature it publishes must come out of
 * this code byte for byte, which pins the whole path (prevout/sequence/output commitments,
 * scriptCode, RFC-6979 ECDSA, DER).
 *
 * Amounts are satoshis. Fee is (sum of inputs − sum of outputs); the caller does coin
 * selection and change, this class does the bytes.
 */
object TxBuilder {

    const val SIGHASH_ALL = 0x01

    /** A coin being spent, with the key that unlocks it. */
    data class Input(
        val txid: String,          // display (big-endian) txid, as an explorer shows it
        val vout: Int,
        val value: Long,           // satoshis locked in this output
        val privateKey: BigInteger,
        val pubkey: ByteArray,     // 33-byte compressed, must hash to this input's address
        val sequence: Long = 0xffffffffL,
    )

    data class Output(val scriptPubKey: ByteArray, val value: Long)

    data class Signed(val rawHex: String, val txid: String, val weight: Int) {
        /** Virtual size in vbytes, rounded up — what fee rate is quoted against. */
        val vbytes: Int get() = (weight + 3) / 4
    }

    // ---- little-endian / varint writers ---------------------------------------------

    private fun u32le(v: Long): ByteArray = byteArrayOf(
        v.toByte(), (v ushr 8).toByte(), (v ushr 16).toByte(), (v ushr 24).toByte(),
    )

    private fun u64le(v: Long): ByteArray = ByteArray(8) { ((v ushr (8 * it)) and 0xFF).toByte() }

    private fun varint(n: Long): ByteArray = when {
        n < 0xfd -> byteArrayOf(n.toByte())
        n <= 0xffff -> byteArrayOf(0xfd.toByte(), n.toByte(), (n ushr 8).toByte())
        n <= 0xffffffffL -> byteArrayOf(0xfe.toByte()) + u32le(n)
        else -> byteArrayOf(0xff.toByte()) + u64le(n)
    }

    private fun varBytes(b: ByteArray): ByteArray = varint(b.size.toLong()) + b

    /** The internal (little-endian) outpoint: reversed txid ‖ vout. */
    private fun outpoint(txid: String, vout: Int): ByteArray =
        Hashes.hexToBytes(txid).reversedArray() + u32le(vout.toLong())

    // ---- BIP-143 sighash ------------------------------------------------------------

    /**
     * The BIP-143 sighash for input [index], SIGHASH_ALL. [inputs] supplies every
     * outpoint/sequence (all inputs are committed to), and [index]'s own value + pubkey.
     */
    fun sighash(version: Long, inputs: List<Input>, outputs: List<Output>, index: Int, locktime: Long): ByteArray {
        val prevouts = ByteArrayOutputStream()
        val sequences = ByteArrayOutputStream()
        for (i in inputs) {
            prevouts.write(outpoint(i.txid, i.vout))
            sequences.write(u32le(i.sequence))
        }
        val outs = ByteArrayOutputStream()
        for (o in outputs) { outs.write(u64le(o.value)); outs.write(varBytes(o.scriptPubKey)) }

        val hashPrevouts = Hashes.doubleSha256(prevouts.toByteArray())
        val hashSequence = Hashes.doubleSha256(sequences.toByteArray())
        val hashOutputs = Hashes.doubleSha256(outs.toByteArray())

        val inp = inputs[index]
        // scriptCode for P2WPKH is the P2PKH script of the same key hash.
        val scriptCode = byteArrayOf(0x76, 0xa9.toByte(), 0x14) +
            Hashes.hash160(inp.pubkey) + byteArrayOf(0x88.toByte(), 0xac.toByte())

        val pre = ByteArrayOutputStream()
        pre.write(u32le(version))
        pre.write(hashPrevouts)
        pre.write(hashSequence)
        pre.write(outpoint(inp.txid, inp.vout))
        pre.write(varBytes(scriptCode))
        pre.write(u64le(inp.value))
        pre.write(u32le(inp.sequence))
        pre.write(hashOutputs)
        pre.write(u32le(locktime))
        pre.write(u32le(SIGHASH_ALL.toLong()))
        return Hashes.doubleSha256(pre.toByteArray())
    }

    /** The DER signature + sighash byte that goes in input [index]'s witness. */
    fun witnessSignature(version: Long, inputs: List<Input>, outputs: List<Output>, index: Int, locktime: Long): ByteArray {
        val h = sighash(version, inputs, outputs, index, locktime)
        return Ecdsa.der(Ecdsa.sign(inputs[index].privateKey, h)) + byteArrayOf(SIGHASH_ALL.toByte())
    }

    /** Build, sign and serialise the whole SegWit transaction. */
    fun build(inputs: List<Input>, outputs: List<Output>, version: Long = 2, locktime: Long = 0): Signed {
        require(inputs.isNotEmpty()) { "a transaction needs at least one input" }
        require(outputs.isNotEmpty()) { "a transaction needs at least one output" }

        val witnesses = ArrayList<ByteArray>(inputs.size)
        for (i in inputs.indices) {
            witnesses.add(witnessSignature(version, inputs, outputs, i, locktime))
        }

        fun writeInputsOutputs(out: ByteArrayOutputStream) {
            out.write(varint(inputs.size.toLong()))
            for (i in inputs) {
                out.write(outpoint(i.txid, i.vout))
                out.write(byteArrayOf(0x00)) // empty scriptSig (witness carries the proof)
                out.write(u32le(i.sequence))
            }
            out.write(varint(outputs.size.toLong()))
            for (o in outputs) { out.write(u64le(o.value)); out.write(varBytes(o.scriptPubKey)) }
        }

        // Non-witness serialisation, for the txid.
        val legacy = ByteArrayOutputStream()
        legacy.write(u32le(version))
        writeInputsOutputs(legacy)
        legacy.write(u32le(locktime))
        val legacyBytes = legacy.toByteArray()
        val txid = Hashes.doubleSha256(legacyBytes).reversedArray().toHex()

        // Full segwit serialisation, with marker/flag and the witness stack.
        val full = ByteArrayOutputStream()
        full.write(u32le(version))
        full.write(byteArrayOf(0x00, 0x01)) // segwit marker + flag
        writeInputsOutputs(full)
        for (i in inputs.indices) {
            full.write(varint(2))                       // two witness items: signature, pubkey
            full.write(varBytes(witnesses[i]))
            full.write(varBytes(inputs[i].pubkey))
        }
        full.write(u32le(locktime))
        val fullBytes = full.toByteArray()

        // weight = base*3 + total (BIP-141): base = non-witness, total = full serialisation.
        val weight = legacyBytes.size * 3 + fullBytes.size
        return Signed(fullBytes.toHex(), txid, weight)
    }
}
