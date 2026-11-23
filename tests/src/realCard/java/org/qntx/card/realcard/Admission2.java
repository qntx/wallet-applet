// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

/**
 * Admission 2 (protocol §3 item 2): {@code ALG_EC_PACE_GM} output is the 65-byte point {@code s·G +
 * H} on secp256k1 and Wei25519; an infinite result throws {@code CryptoException}.
 */
final class Admission2 extends Suite {
    @Test
    void products() {
        Probe probe = Suite.prepareProbe();
        SecureRandom rng = new SecureRandom();
        for (int cid = 0; cid < 2; cid++) {
            Curve c = cid == 0 ? Curve.SECP256K1 : Curve.WEI25519;
            for (int i = 0; i < 6; i++) {
                BigInteger s = c.scalar(rng);
                Curve.Point h = c.mul(c.scalar(rng), c.g);
                Probe.Rsp r = probe.ec(0x21, cid, Curve.u32(s), c.enc(h));
                org.junit.jupiter.api.Assertions.assertEquals(0x9000, r.sw(), c.name);
                assertArrayEquals(c.enc(c.add(c.mul(s, c.g), h)), r.data(), c.name + " s·G+H");
            }
        }
        Results.row("Admission 2", "products", "pass", "s·G+H on secp256k1 and wei25519");
    }

    @Test
    void infinityThrows() {
        Probe probe = Suite.prepareProbe();
        SecureRandom rng = new SecureRandom();
        for (int cid = 0; cid < 2; cid++) {
            Curve c = cid == 0 ? Curve.SECP256K1 : Curve.WEI25519;
            BigInteger s = c.scalar(rng);
            Curve.Point negSG = c.neg(c.mul(s, c.g));
            Probe.Rsp r = probe.ec(0x21, cid, Curve.u32(s), c.enc(negSG));
            assertNotEquals(0x9000, r.sw(), c.name + " infinity must throw CryptoException");
        }
        Results.row("Admission 2", "infinity", "pass", "CryptoException on infinite result");
    }
}
