package com.kilombino.pyblockwatch

import com.kilombino.pyblockwatch.crypto.Hashes
import com.kilombino.pyblockwatch.crypto.Hashes.toHex
import com.kilombino.pyblockwatch.crypto.Secp256k1
import com.kilombino.pyblockwatch.crypto.SilentPayment
import org.junit.Assert.assertEquals
import org.junit.Test
import java.math.BigInteger

/**
 * BIP-352 "Simple send: two inputs" published vector. Building the wrong output would send
 * coins where no one can find them, so the sender maths is pinned to the spec's own case.
 */
class SilentPaymentTest {

    private val address =
        "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"

    @Test
    fun `sp address decodes to its scan and spend keys`() {
        val r = SilentPayment.decodeAddress(address)
        assertEquals("0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4",
            Secp256k1.compress(r.scan).toHex())
        assertEquals("025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36",
            Secp256k1.compress(r.spend).toHex())
    }

    @Test
    fun `output scriptPubKey matches the BIP-352 simple-send vector`() {
        val inputs = listOf(
            SilentPayment.Input(
                BigInteger("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1", 16),
                "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 0,
            ),
            SilentPayment.Input(
                BigInteger("93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16", 16),
                "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 0,
            ),
        )
        val script = SilentPayment.outputScript(SilentPayment.decodeAddress(address), inputs)
        // OP_1 (0x51) OP_PUSH32 (0x20) <x-only>
        assertEquals("5120" + "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1",
            script.toHex())
    }
}
