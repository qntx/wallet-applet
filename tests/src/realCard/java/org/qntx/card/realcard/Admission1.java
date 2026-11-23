// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

/**
 * Admission 1 (architecture §10, protocol §3 item 1): {@code ALG_RSA_NOPAD} with zero-extended
 * 512-bit moduli, exponents {@code 2} and a 32-byte exponent — results equal BigInteger for 1,000
 * random inputs per modulus, and every input {@code ≥ m} is rejected.
 */
final class Admission1 extends Suite {
    private static final int INPUTS = 1000;

    /** The four modulus/exponent pairs of the row, as {@code (m, e)}. */
    private static final BigInteger[][] KEYS;

    static {
        BigInteger l = Curve.WEI25519.n;
        BigInteger n = Curve.SECP256K1.n;
        BigInteger p = Curve.SECP256K1.p;
        BigInteger sqrtExp = p.add(BigInteger.ONE).shiftRight(2);
        KEYS =
                new BigInteger[][] {
                    {l, BigInteger.TWO},
                    {n, BigInteger.TWO},
                    {p, BigInteger.TWO},
                    {p, sqrtExp},
                };
    }

    @Test
    void modPowEqualsBigInteger() {
        Probe probe = Suite.prepareProbe();
        SecureRandom rng = new SecureRandom();
        int compared = 0;
        for (int slot = 0; slot < KEYS.length; slot++) {
            BigInteger m = KEYS[slot][0];
            BigInteger e = KEYS[slot][1];
            probe.rsaSetModulus(slot, Curve.u64(m));
            probe.rsaSetExponent(slot, exponentBytes(e));
            for (int i = 0; i < INPUTS; i++) {
                BigInteger x = new BigInteger(m.bitLength(), rng).mod(m);
                Probe.Rsp r = probe.rsa(slot, Curve.u64(x));
                assertEquals(0x9000, r.sw(), "rsa slot " + slot + " sw");
                int len = Apdu.u16(r.data(), 0);
                byte[] out = new byte[64];
                System.arraycopy(r.data(), 2, out, 64 - len, len);
                assertArrayEquals(Curve.u64(x.modPow(e, m)), out, "x^e mod m, slot " + slot);
                compared++;
            }
        }
        Results.row("Admission 1", "modPow", "pass", compared + " inputs on 4 moduli");
    }

    @Test
    void rejectsInputGeModulus() {
        Probe probe = Suite.prepareProbe();
        SecureRandom rng = new SecureRandom();
        StringBuilder accepted = new StringBuilder();
        for (int slot = 0; slot < KEYS.length; slot++) {
            BigInteger m = KEYS[slot][0];
            probe.rsaSetModulus(slot, Curve.u64(m));
            probe.rsaSetExponent(slot, exponentBytes(KEYS[slot][1]));
            BigInteger[] inputs = {
                m,
                m.add(BigInteger.ONE),
                m.add(new BigInteger(64, rng)),
                BigInteger.ONE.shiftLeft(511),
                BigInteger.ONE.shiftLeft(512).subtract(BigInteger.ONE),
            };
            for (BigInteger x : inputs) {
                if (probe.rsa(slot, Curve.u64(x)).sw() == 0x9000) {
                    accepted.append(" slot").append(slot);
                }
            }
            for (int i = 0; i < 20; i++) {
                BigInteger x = m.add(new BigInteger(511, rng));
                if (x.bitLength() > 512) {
                    continue;
                }
                if (probe.rsa(slot, Curve.u64(x)).sw() == 0x9000) {
                    accepted.append(" slot").append(slot).append("r");
                }
            }
        }
        if (accepted.length() != 0 && reader.isSim()) {
            Results.row(
                    "Admission 1",
                    "reject >= m",
                    "skip",
                    "simulator does not reject input >= modulus (jcardsim RSA_NOPAD)");
            org.junit.jupiter.api.Assumptions.abort(
                    "simulator does not reject input >= modulus (jcardsim RSA_NOPAD)");
        }
        assertEquals("", accepted.toString(), "inputs >= m must be rejected");
        Results.row("Admission 1", "reject >= m", "pass", "all inputs >= m rejected");
    }

    /** The exponent in the shortest big-endian form, 32-byte aligned when it is a big one. */
    private static byte[] exponentBytes(BigInteger e) {
        if (e.bitLength() > 8) {
            return Curve.u32(e);
        }
        return new byte[] {e.byteValue()};
    }
}
