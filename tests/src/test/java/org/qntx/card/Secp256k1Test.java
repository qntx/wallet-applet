// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import javacard.framework.ISOException;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Crypto;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/** {@link Secp256k1} primitives against BouncyCastle: mul, compress, onCurve, DER codec. */
final class Secp256k1Test {
    private static final SecureRandom RND = new SecureRandom();

    private static Secp256k1 secp() {
        Card card = Vecs.factory();
        return Internals.secp(card.applet(Spec.WALLET_AID));
    }

    @Test
    void mulMatchesBouncyCastle() {
        Secp256k1 s = secp();
        byte[] out = new byte[65];
        for (int i = 0; i < 25; i++) {
            BigInteger k;
            do {
                k = new BigInteger(256, RND);
            } while (k.signum() == 0 || k.compareTo(Crypto.N) >= 0);
            byte[] scalar = new byte[32];
            byte[] kb = k.toByteArray();
            System.arraycopy(
                    kb,
                    Math.max(0, kb.length - 32),
                    scalar,
                    Math.max(0, 32 - kb.length),
                    Math.min(32, kb.length));
            s.mul(scalar, (short) 0, Secp256k1.G, (short) 0, out, (short) 0);
            byte[] expect = Crypto.DOMAIN.getG().multiply(k).getEncoded(false);
            assertArrayEquals(expect, out, "k=" + k.toString(16));
        }
    }

    @Test
    void mulRejectsScalarZeroAndN() {
        Secp256k1 s = secp();
        byte[] out = new byte[65];
        // k = 0 or k = n both leave [1,n): the platform refuses the multiplication
        assertThrows(
                RuntimeException.class,
                () -> s.mul(new byte[32], (short) 0, Secp256k1.G, (short) 0, out, (short) 0));
        byte[] n = Crypto.N.toByteArray();
        byte[] nn = new byte[32];
        System.arraycopy(
                n,
                Math.max(0, n.length - 32),
                nn,
                Math.max(0, 32 - n.length),
                Math.min(32, n.length));
        assertThrows(
                RuntimeException.class,
                () -> s.mul(nn, (short) 0, Secp256k1.G, (short) 0, out, (short) 0));
    }

    @Test
    void compressMatchesBouncyCastle() {
        Secp256k1 s = secp();
        byte[] out = new byte[33];
        for (int i = 0; i < 10; i++) {
            BigInteger k = new BigInteger(255, RND).add(BigInteger.ONE);
            ECPoint p = Crypto.DOMAIN.getG().multiply(k.mod(Crypto.N));
            byte[] point = p.getEncoded(false);
            s.compress(point, (short) 0, out, (short) 0);
            assertArrayEquals(p.getEncoded(true), out);
        }
    }

    @Test
    void onCurveChecks() {
        Secp256k1 s = secp();
        byte[] g = Secp256k1.G;
        assertEquals(Const.CHECK_OK, s.onCurve(g, (short) 0));
        byte[] bad = g.clone();
        bad[64] ^= 1;
        assertEquals(Const.CHECK_FAIL, s.onCurve(bad, (short) 0));
        bad = g.clone();
        bad[0] = 0x03;
        assertEquals(Const.CHECK_FAIL, s.onCurve(bad, (short) 0));
        bad = g.clone();
        Arrays.fill(bad, 1, 33, (byte) 0xFF); // x = 2^256-1 >= p
        assertEquals(Const.CHECK_FAIL, s.onCurve(bad, (short) 0));
    }

    @Test
    void derCodecRoundTripsAgainstBouncyCastle() throws Exception {
        Secp256k1 s = secp();
        ECDSASigner signer = new ECDSASigner();
        signer.init(
                true,
                new org.bouncycastle.crypto.params.ECPrivateKeyParameters(
                        new BigInteger("7"), Crypto.DOMAIN));
        byte[] rs = new byte[64];
        byte[] der = new byte[80];
        for (int i = 0; i < 10; i++) {
            byte[] hash = new byte[32];
            RND.nextBytes(hash);
            BigInteger[] sig = signer.generateSignature(hash);
            byte[] r = fixed(sig[0]);
            byte[] t = fixed(sig[1]);
            // applet DER encode, then compare against a strict re-decode
            System.arraycopy(r, 0, rs, 0, 32);
            System.arraycopy(t, 0, rs, 32, 32);
            short derLen = s.rsToDer(rs, (short) 0, der, (short) 0);
            ASN1Sequence seq = ASN1Sequence.getInstance(Arrays.copyOf(der, derLen));
            assertEquals(sig[0], ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
            assertEquals(sig[1], ASN1Integer.getInstance(seq.getObjectAt(1)).getValue());
            // and the BC-encoded DER decodes back to the same r ‖ s
            byte[] bcDer =
                    new org.bouncycastle.asn1.DERSequence(
                                    new org.bouncycastle.asn1.ASN1Encodable[] {
                                        new ASN1Integer(sig[0]), new ASN1Integer(sig[1])
                                    })
                            .getEncoded();
            byte[] back = new byte[64];
            s.derToRs(bcDer, (short) 0, (short) bcDer.length, back, (short) 0);
            assertArrayEquals(rs, back);
        }
    }

    private static byte[] fixed(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        System.arraycopy(
                b,
                Math.max(0, b.length - 32),
                out,
                Math.max(0, 32 - b.length),
                Math.min(32, b.length));
        return out;
    }

    /**
     * {@link Secp256k1#verifyHash} returns exactly the coded results: {@code CHECK_OK} on a valid
     * signature, {@code CHECK_FAIL} on an invalid one, {@code CHECK_MALFORMED} on an out-of-range
     * scalar. Exact values — the two-conditional derivation must not let one skipped branch pass a
     * {@code FAIL ^ CHECK_STEP_i} off as a result (§16.2 item 4).
     */
    @Test
    void verifyHashReturnsExactCodedResults() {
        Secp256k1 s = secp();
        ECPublicKey pub =
                (ECPublicKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256k1.setDomain(pub);
        BigInteger d = new BigInteger("7");
        byte[] w = Crypto.publicKey(d);
        pub.setW(w, (short) 0, (short) w.length);
        byte[] hash = new byte[32];
        hash[0] = 1;
        byte[] rs = Crypto.sign(d, hash);
        assertEquals(Const.CHECK_OK, s.verifyHash(pub, hash, (short) 0, rs, (short) 0), "valid");
        rs[63] ^= 0x01;
        assertEquals(
                Const.CHECK_FAIL, s.verifyHash(pub, hash, (short) 0, rs, (short) 0), "invalid");
        byte[] bad = new byte[64];
        byte[] n = fixed(Crypto.N);
        System.arraycopy(n, 0, bad, 0, 32);
        bad[63] = 1;
        assertEquals(
                Const.CHECK_MALFORMED,
                s.verifyHash(pub, hash, (short) 0, bad, (short) 0),
                "r = n out of range");
    }

    @Test
    void malformedDerIsAFault() {
        Secp256k1 s = secp();
        byte[] out = new byte[64];
        assertThrows(
                ISOException.class,
                () -> s.derToRs(new byte[8], (short) 0, (short) 8, out, (short) 0));
    }

    @Test
    void randomScalarsAreInRangeAndVary() {
        Secp256k1 s = secp();
        byte[] first = new byte[32];
        s.randomScalar(first, (short) 0);
        BigInteger v0 = new BigInteger(1, first);
        assertTrue(v0.signum() > 0 && v0.compareTo(Crypto.N) < 0);
        for (int i = 0; i < 20; i++) {
            byte[] x = new byte[32];
            s.randomScalar(x, (short) 0);
            BigInteger v = new BigInteger(1, x);
            assertTrue(v.signum() > 0 && v.compareTo(Crypto.N) < 0, "scalar out of [1,n)");
            assertNotEquals(v0, v, "randomScalar repeated its output");
        }
    }
}
