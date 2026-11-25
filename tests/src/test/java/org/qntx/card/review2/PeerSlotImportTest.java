// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.Internals;
import org.qntx.card.sim.Fault;

/**
 * F-01 regression, IMPORT direction (spec section 9.14): on a BLANK card the peer-key slot holds
 * the nothing-up-my-sleeve point of spec section 16.1 item 1 — never the base point G — so one
 * skipped {@code Transfer.setPeer} lets no attacker signature verify: the export signature made
 * with private key 1 fails the first evaluation with {@code 6A80}, no pending import is armed and
 * the card stays BLANK.
 */
final class PeerSlotImportTest {
    private static final Ca2 CA = Ca2.INSTANCE;
    private static final byte[] SEED_ATT = H2.sha512(H2.ascii("review2 import seed"));
    private static final byte[] ACCESS_ATT = H2.sha256(H2.ascii("review2 import code"));
    private static final byte[] EMPTY = new byte[0];
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

    private static final class Fixture {
        final Card2 card = new Card2();
        final Session2 session;
        final Peer2 source;
        final byte[] lkT; // link public key of the target's offer
        final BigInteger e; // attacker's ephemeral scalar
        final byte[] ep; // E = e * G, uncompressed
        final byte[] m; // the export message of spec section 9.14
        final byte[] sigS; // ECDSA over M made with private key 1

        Fixture() {
            card.blank(CA);
            session = card.open(CA);
            source = Peer2.create(CA);
            Session2.Res offer = session.cmd(0x40, 0x00, 0x00, EMPTY);
            assertEquals(0x9000, offer.sw, () -> "OFFER sw " + Integer.toHexString(offer.sw));
            assertEquals(129, offer.data.length);
            lkT = Arrays.copyOfRange(offer.data, 0, 65);
            byte[] sigT = Arrays.copyOfRange(offer.data, 65, 129);
            assertTrue(
                    H2.verify(card.identity(), H2.cat(H2.ascii("qntx-card/v1/offer"), lkT), sigT),
                    "offer signature does not verify under the card key");
            e = H2.randomScalar();
            ep = H2.uncompressed(H2.SECP.getG().multiply(e).normalize());
            m = H2.cat(H2.ascii("qntx-card/v1/export"), source.a, card.identity(), lkT, ep);
            sigS = H2.sign(BigInteger.ONE, m);
        }

        byte[] importBegin() {
            return H2.cat(source.cert, ep, sigS);
        }
    }

    @Test
    void controlRefusedWithoutFault() {
        assertTrue(H2.bip32MasterValid(SEED_ATT));
        Fixture f = new Fixture();
        Session2.Res r = f.session.cmd(0x42, 0x00, 0x00, f.importBegin());
        assertEquals(0x6A80, r.sw, () -> "IMPORT P1=00 sw " + Integer.toHexString(r.sw));
    }

    @Test
    void skippedPeerWriteIsRefused() {
        assertTrue(H2.bip32MasterValid(SEED_ATT));
        Fixture f = new Fixture();

        Fault.armSkip("Transfer.setPeer", 1);
        Session2.Res r0;
        int setPeerCalls;
        try {
            r0 = f.session.cmd(0x42, 0x00, 0x00, f.importBegin());
            setPeerCalls = Fault.calls("Transfer.setPeer");
        } finally {
            Fault.reset();
        }
        // the skipped write leaves PEER_INIT in the slot, under which the key-1
        // sig_S fails the first evaluation: 6A80, no pending import
        assertEquals(0x6A80, r0.sw, () -> "IMPORT P1=00 sw " + Integer.toHexString(r0.sw));
        assertTrue(setPeerCalls >= 1, "Transfer.setPeer was never reached");
        assertArrayEquals(
                PEER_INIT,
                Internals.peerW(f.card.sim.applet(WALLET_AID), 0),
                "slot 0 changed despite the skipped write");
        System.out.println(
                "F-01 IMPORT P1=00 faulted: sw="
                        + Integer.toHexString(r0.sw)
                        + " setPeerCalls="
                        + setPeerCalls
                        + " slotHoldsPeerInit=true");

        // no pending import was armed: P1=01 is refused whatever the ciphertext
        Session2.Res r1 = f.session.cmd(0x42, 0x01, 0x00, new byte[176]);
        assertEquals(
                0x6985,
                r1.sw,
                () -> "IMPORT P1=01 without a pending import: " + Integer.toHexString(r1.sw));

        // the card stayed BLANK and answers no VERIFY — the attacker's code included
        Session2 s2 = f.card.open(CA);
        Session2.Res status = s2.cmd(0x20, 0x00, 0x00, EMPTY);
        assertEquals(0x9000, status.sw);
        assertArrayEquals(new byte[] {0x01, 0x00}, status.data, "STATUS is not BLANK");
        Session2.Res verify = s2.cmd(0x22, 0x00, 0x00, ACCESS_ATT);
        assertEquals(
                0x6985,
                verify.sw,
                () -> "VERIFY on a BLANK card: " + Integer.toHexString(verify.sw));
        System.out.println(
                "F-01 post-import: status="
                        + H2.hex(status.data)
                        + " verifySw="
                        + Integer.toHexString(verify.sw));
    }
}
