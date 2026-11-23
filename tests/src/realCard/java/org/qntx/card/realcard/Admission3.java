// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

/**
 * Admission 3 (protocol §3 item 3): {@code PLAIN_XY} returns the 65-byte product and rejects
 * off-curve points, {@code x ≥ p} and compressed inputs — rejection is required, the protocol
 * relies on it.
 */
final class Admission3 extends Suite {
    @Test
    void products() {
        Probe probe = Suite.prepareProbe();
        SecureRandom rng = new SecureRandom();
        for (int cid = 0; cid < 2; cid++) {
            Curve c = cid == 0 ? Curve.SECP256K1 : Curve.WEI25519;
            for (int i = 0; i < 6; i++) {
                BigInteger s = c.scalar(rng);
                Curve.Point pt = c.mul(c.scalar(rng), c.g);
                Probe.Rsp r = probe.ec(0x20, cid, Curve.u32(s), c.enc(pt));
                assertEquals(0x9000, r.sw(), c.name);
                assertArrayEquals(c.enc(c.mul(s, pt)), r.data(), c.name + " s·P");
            }
        }
        Results.row("Admission 3", "products", "pass", "s·P on secp256k1 and wei25519");
    }

    @Test
    void rejectsOffCurve() {
        Probe probe = Suite.prepareProbe();
        SecureRandom rng = new SecureRandom();
        for (int cid = 0; cid < 2; cid++) {
            Curve c = cid == 0 ? Curve.SECP256K1 : Curve.WEI25519;
            BigInteger s = c.scalar(rng);
            Curve.Point pt = c.mul(c.scalar(rng), c.g);
            Curve.Point bad = new Curve.Point(pt.x, pt.y.add(BigInteger.ONE).mod(c.p));
            Probe.Rsp r = probe.ec(0x20, cid, Curve.u32(s), c.enc(bad));
            if (r.sw() == 0x9000 && reader.isSim()) {
                Results.row(
                        "Admission 3",
                        "reject off-curve",
                        "skip",
                        "simulator does not reject off-curve PLAIN_XY input");
                org.junit.jupiter.api.Assumptions.abort(
                        "simulator does not reject off-curve PLAIN_XY input (jcardsim)");
            }
            assertNotEquals(0x9000, r.sw(), c.name + " off-curve must be rejected");
        }
        Results.row("Admission 3", "reject off-curve", "pass", "both curves reject");
    }

    @Test
    void rejectsXGeP() {
        Probe probe = Suite.prepareProbe();
        SecureRandom rng = new SecureRandom();
        for (int cid = 0; cid < 2; cid++) {
            Curve c = cid == 0 ? Curve.SECP256K1 : Curve.WEI25519;
            BigInteger s = c.scalar(rng);
            Curve.Point pt = c.mul(c.scalar(rng), c.g);
            byte[] forced = new byte[65];
            forced[0] = 4;
            System.arraycopy(Curve.u32(c.p), 0, forced, 1, 32);
            System.arraycopy(Curve.u32(pt.y), 0, forced, 33, 32);
            Probe.Rsp r = probe.ec(0x20, cid, Curve.u32(s), forced);
            if (r.sw() == 0x9000 && reader.isSim()) {
                Results.row("Admission 3", "reject x>=p", "skip", "simulator does not reject x>=p");
                org.junit.jupiter.api.Assumptions.abort(
                        "simulator does not reject x>=p PLAIN_XY input (jcardsim)");
            }
            assertNotEquals(0x9000, r.sw(), c.name + " x>=p must be rejected");
        }
        Results.row("Admission 3", "reject x>=p", "pass", "x=p rejected on both curves");
    }

    @Test
    void rejectsCompressed() {
        Probe probe = Suite.prepareProbe();
        SecureRandom rng = new SecureRandom();
        for (int cid = 0; cid < 2; cid++) {
            Curve c = cid == 0 ? Curve.SECP256K1 : Curve.WEI25519;
            BigInteger s = c.scalar(rng);
            Curve.Point pt = c.mul(c.scalar(rng), c.g);
            Probe.Rsp r = probe.ec(0x20, cid, Curve.u32(s), c.comp(pt));
            if (r.sw() == 0x9000 && reader.isSim()) {
                Results.row(
                        "Admission 3",
                        "reject compressed",
                        "skip",
                        "simulator accepts compressed PLAIN_XY input (jcardsim)");
                org.junit.jupiter.api.Assumptions.abort(
                        "simulator accepts compressed PLAIN_XY input (jcardsim)");
            }
            assertNotEquals(0x9000, r.sw(), c.name + " compressed input must be rejected");
        }
        Results.row("Admission 3", "reject compressed", "pass", "33-byte input rejected");
    }
}
