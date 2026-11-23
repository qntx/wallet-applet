// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Crypto;

/**
 * Admission 4 (protocol §3 item 4): {@code signPreComputedHash} and {@code verifyPreComputedHash}
 * on 32-byte hashes — the card's signature verifies under the BouncyCastle oracle, and the card
 * verifier accepts a correct signature and rejects a wrong hash.
 */
final class Admission4 extends Suite {
    @Test
    void signAndVerifyPreComputed() {
        Probe probe = Suite.prepareProbe();
        SecureRandom rng = new SecureRandom();
        Curve c = Curve.SECP256K1;
        for (int i = 0; i < 6; i++) {
            BigInteger d = c.scalar(rng);
            byte[] pub = c.enc(c.mul(d, c.g));
            byte[] hash = new byte[32];
            rng.nextBytes(hash);

            byte[] in = new byte[64];
            System.arraycopy(Curve.u32(d), 0, in, 0, 32);
            System.arraycopy(hash, 0, in, 32, 32);
            Probe.Rsp sig = probe.sign(0, in);
            assertEquals(0x9000, sig.sw(), "signPreComputedHash sw");
            BigInteger[] rs = derDecode(sig.data());
            byte[] flat = new byte[64];
            System.arraycopy(Curve.u32(rs[0]), 0, flat, 0, 32);
            System.arraycopy(Curve.u32(rs[1]), 0, flat, 32, 32);
            assertTrue(Crypto.verify(pub, hash, flat), "card signature must verify (BouncyCastle)");

            byte[] vIn = new byte[65 + 32 + sig.data().length];
            System.arraycopy(pub, 0, vIn, 0, 65);
            System.arraycopy(hash, 0, vIn, 65, 32);
            System.arraycopy(sig.data(), 0, vIn, 97, sig.data().length);
            Probe.Rsp ok = probe.verify(0, vIn);
            assertEquals(0x9000, ok.sw());
            assertEquals(1, ok.data()[0], "verifyPreComputedHash must accept a valid signature");

            byte[] wrong = vIn.clone();
            wrong[65] ^= 1;
            Probe.Rsp no = probe.verify(0, wrong);
            assertEquals(0x9000, no.sw());
            assertEquals(0, no.data()[0], "verifyPreComputedHash must reject a wrong hash");
        }
        Results.row("Admission 4", "precomputed", "pass", "sign+verify on 32-byte hashes");
    }

    /** Strict minimal DER decode of {@code 30 len 02 lr r 02 ls s}. */
    private static BigInteger[] derDecode(byte[] der) {
        int i = 2;
        BigInteger[] out = new BigInteger[2];
        for (int k = 0; k < 2; k++) {
            if (der[i] != 2) {
                throw new IllegalArgumentException("not a DER ECDSA signature");
            }
            int len = der[i + 1] & 0xFF;
            out[k] = new BigInteger(1, Arrays.copyOfRange(der, i + 2, i + 2 + len));
            i += 2 + len;
        }
        return out;
    }
}
