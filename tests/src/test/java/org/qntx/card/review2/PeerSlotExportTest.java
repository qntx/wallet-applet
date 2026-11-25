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
import org.qntx.card.Internals;
import org.qntx.card.sim.Fault;

/**
 * F-01 regression, EXPORT direction (spec section 9.13): the peer-key slots initialise to the
 * nothing-up-my-sleeve point of spec section 16.1 item 1 — never the base point G — so one skipped
 * {@code Transfer.setPeer} leaves a slot holding a key whose discrete logarithm no one knows, and
 * the attacker's offer signature made with private key 1 fails the first evaluation with {@code
 * 6A80}.
 */
final class PeerSlotExportTest {
    private static final Ca2 CA = Ca2.INSTANCE;
    private static final byte[] SEED = H2.sha512(H2.ascii("review2 export seed"));
    private static final byte[] ACCESS = H2.sha256(H2.ascii("review2 code"));
    private static final byte[] ACCESS_T = H2.sha256(H2.ascii("review2 target code"));
    private static final byte[] WALLET_AID = H2.hex("F0716E74780101");
    // the peer-slot initial point of spec section 16.1 item 1 (derivation index i = 0)
    private static final byte[] PEER_INIT =
            H2.hex(
                    "04c5f15c1a0e8b16b59de48e932dba33ce55738d661a669eb1b917b910f0af9c11"
                            + "9784ef4a1aa6d202fcdaa8516e42a10d612739f528c2d92f8e2e88a125e880fe");

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
    void skippedPeerWriteIsRefused() {
        assertTrue(H2.bip32MasterValid(SEED));
        Peer2 m = Peer2.create(CA);
        Card2 card = new Card2();
        card.blank(CA);
        Session2 s = loadedSession(card, m.id());

        byte[][] atk = attackerOffer();
        Fault.armSkip("Transfer.setPeer", 1);
        Session2.Res r0;
        int setPeerCalls;
        try {
            r0 = s.cmd(0x41, 0x00, 0x00, H2.cat(m.cert, atk[0], atk[1]));
            setPeerCalls = Fault.calls("Transfer.setPeer");
        } finally {
            Fault.reset();
        }
        // the skipped write leaves PEER_INIT in the slot, under which the key-1
        // signature fails the first evaluation: 6A80, no pending export
        assertEquals(0x6A80, r0.sw, () -> "EXPORT P1=00 sw " + Integer.toHexString(r0.sw));
        assertEquals(0, r0.data.length, "no E || sig_S released");
        assertTrue(setPeerCalls >= 1, "Transfer.setPeer was never reached");
        assertArrayEquals(
                PEER_INIT,
                Internals.peerW(card.sim.applet(WALLET_AID), 0),
                "slot 0 changed despite the skipped write");
        assertArrayEquals(
                PEER_INIT,
                Internals.peerW(card.sim.applet(WALLET_AID), 1),
                "slot 1 changed despite the skipped write");
        System.out.println(
                "F-01 EXPORT P1=00 faulted: sw="
                        + Integer.toHexString(r0.sw)
                        + " setPeerCalls="
                        + setPeerCalls
                        + " slotHoldsPeerInit=true");

        Session2.Res r1 = s.cmd(0x41, 0x01, 0x00, ACCESS_T);
        assertEquals(
                0x6985,
                r1.sw,
                () -> "EXPORT P1=01 without a pending export: " + Integer.toHexString(r1.sw));
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
    void untouchedSlotHoldsPeerInitAndRefuses() {
        Peer2 m1 = Peer2.create(CA);
        Peer2 m2 = Peer2.create(CA);
        Card2 card = new Card2();
        card.blank(CA);
        Session2 s = card.open(CA);
        Session2.Res cr = s.cmd(0x21, 0x01, 0x00, H2.cat(ACCESS, SEED, m1.id(), m2.id()));
        assertEquals(0x9000, cr.sw, () -> "CREATE sw " + Integer.toHexString(cr.sw));

        // a complete genuine transfer flow to m1 fills only m1's peer slot
        Peer2.Offer offer1 = m1.offer();
        Session2.Res g0 = s.cmd(0x41, 0x00, 0x00, H2.cat(m1.cert, offer1.lk, offer1.sig));
        assertEquals(0x9000, g0.sw, () -> "genuine EXPORT P1=00 sw " + Integer.toHexString(g0.sw));
        Session2.Res g1 = s.cmd(0x41, 0x01, 0x00, ACCESS_T);
        assertEquals(0x9000, g1.sw, () -> "genuine EXPORT P1=01 sw " + Integer.toHexString(g1.sw));
        assertEquals(176, g1.data.length); // c = 3: payload 146 -> ct 160 + tag 16

        // the never-exported-to member m2 still has PEER_INIT in its slot — not G —
        // so one skip does not leave a key the attacker can sign under
        byte[] w0 = Internals.peerW(card.sim.applet(WALLET_AID), 0);
        byte[] w1 = Internals.peerW(card.sim.applet(WALLET_AID), 1);
        byte[] g = H2.uncompressed(H2.SECP.getG());
        int untouched = Arrays.equals(w0, PEER_INIT) ? 0 : Arrays.equals(w1, PEER_INIT) ? 1 : -1;
        assertTrue(untouched >= 0, "no slot still holds PEER_INIT after the genuine export");
        assertNotEquals(
                Arrays.equals(w0, g) || Arrays.equals(w1, g),
                true,
                "a peer slot holds the base point G");

        byte[][] atk = attackerOffer();
        Fault.armSkip("Transfer.setPeer", 1);
        Session2.Res r0;
        int setPeerCalls;
        try {
            r0 = s.cmd(0x41, 0x00, 0x00, H2.cat(m2.cert, atk[0], atk[1]));
            setPeerCalls = Fault.calls("Transfer.setPeer");
        } finally {
            Fault.reset();
        }
        assertEquals(0x6A80, r0.sw, () -> "attack EXPORT P1=00 sw " + Integer.toHexString(r0.sw));
        assertTrue(setPeerCalls >= 1, "Transfer.setPeer was never reached");
        assertArrayEquals(
                PEER_INIT,
                Internals.peerW(card.sim.applet(WALLET_AID), untouched),
                "m2's slot changed despite the skipped write");

        Session2.Res r1 = s.cmd(0x41, 0x01, 0x00, ACCESS_T);
        assertEquals(
                0x6985,
                r1.sw,
                () -> "EXPORT P1=01 without a pending export: " + Integer.toHexString(r1.sw));
        System.out.println(
                "F-01 3-card attack refused: p00sw="
                        + Integer.toHexString(r0.sw)
                        + " p01sw="
                        + Integer.toHexString(r1.sw)
                        + " untouchedSlot="
                        + untouched);
    }
}
