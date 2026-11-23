// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javacard.security.MessageDigest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.tests.Vecs;

/**
 * §9.4–§9.8 wallet commands against a real card image: status words, the state matrix, the fault
 * paths architecture §14.4 W1/W10 lists, and the session lifecycle around ERASE and CHANGE.
 */
final class WalletCommandTest {

    private Card card;
    private Session session;

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    private void blank() throws Exception {
        byte[] a = Vecs.cardA(card = Vecs.factory());
        card = Vecs.blankFor(card, a);
        session = Vecs.open(card);
    }

    private void loaded() throws Exception {
        blank();
        session = Vecs.loadWallet(card);
    }

    private void verify() throws Exception {
        Response r = Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash());
        assertEquals(0x9000, r.sw(), "VERIFY with the create access hash");
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    @Test
    void statusReportsLifeAndFreeTries() throws Exception {
        blank();
        Response r = Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]);
        assertEquals(0x9000, r.sw());
        assertArrayEquals(new byte[] {0x01, 0x00}, r.data(), "BLANK, tries is 0");

        loaded();
        r = Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]);
        assertArrayEquals(new byte[] {0x02, 0x0a}, r.data(), "LOADED, 10 free tries");
    }

    @Test
    void createImportReturnsWalletInfo() throws Exception {
        loaded();
        Response r = Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash());
        assertEquals(0x9000, r.sw());
        assertArrayEquals(
                Vecs.seedMasterPublicKey(),
                java.util.Arrays.copyOf(r.data(), 33),
                "WalletInfo master public key");
    }

    @Test
    void createRejectsImportedSeedWithInvalidMaster() throws Exception {
        blank();
        Fault.arm("Derivation.master", 1, Const.CHECK_FAIL);
        byte[] data = concat(Vecs.accessHash(), Vecs.seed());
        Response r = Vecs.roundtrip(card, session, 0x21, 1, 0, data);
        assertEquals(0x6a80, r.sw());
        r = Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]);
        assertArrayEquals(new byte[] {0x01, 0x00}, r.data(), "rejected CREATE wrote nothing");
    }

    @Test
    void createGenerateRedrawsAfterOneInvalidMaster() throws Exception {
        blank();
        Fault.arm("Derivation.master", 1, Const.CHECK_FAIL);
        Fault.countCalls();
        byte[] data = concat(Vecs.accessHash(), Vecs.entropy());
        Response r = Vecs.roundtrip(card, session, 0x21, 0, 0, data);
        assertEquals(0x9000, r.sw());
        assertTrue(
                Fault.calls("Derivation.master") >= 2,
                "P1=0 redraws after a faulted master: " + Fault.calls("Derivation.master"));
    }

    @Test
    void createOnLoadedCardIsRejected() throws Exception {
        loaded();
        Response r =
                Vecs.roundtrip(card, session, 0x21, 1, 0, concat(Vecs.accessHash(), Vecs.seed()));
        assertEquals(0x6985, r.sw());
    }

    @Test
    void verifyWrongCodeCountsFailuresAndBlocksVerifiedCommands() throws Exception {
        loaded();
        Response r = Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHashWrong());
        assertEquals(0x63c9, r.sw());
        r = Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]);
        assertArrayEquals(new byte[] {0x02, 0x09}, r.data(), "one failure counted");
        r = Vecs.roundtrip(card, session, 0x30, 0, 0, Vecs.pathSecpEvm());
        assertEquals(0x6982, r.sw(), "PUBLIC_KEY needs a verified session");
    }

    @Test
    void waitGateForcesWaitsAfterFreeTries() throws Exception {
        loaded();
        for (int i = 0; i < 3; i++) {
            assertEquals(
                    0x63c0 | (9 - i),
                    Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHashWrong()).sw());
        }
        Response r = Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHashWrong());
        assertEquals(0x6986, r.sw(), "4th attempt waits: 15 WAITs outstanding");
        assertEquals(0, card.writes(), "a wait-refused VERIFY writes nothing (§9.5 step 3)");
        for (int i = 0; i < 15; i++) {
            assertEquals(0x9000, Vecs.roundtrip(card, session, 0x25, 0, 0, new byte[0]).sw());
        }
        // one WAIT command runs exactly the 400 SHA-256 iterations of §9.7
        assertEquals(400, card.digests(MessageDigest.ALG_SHA_256));
        r = Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHashWrong());
        assertEquals(0x63c6, r.sw(), "gate cleared by the waits");
    }

    @Test
    void verifyAtLimitErases() throws Exception {
        loaded();
        for (int i = 0; i < 10; i++) {
            if (i >= 3) {
                for (int w = 0; w < 15; w++) {
                    Vecs.roundtrip(card, session, 0x25, 0, 0, new byte[0]);
                }
            }
            Response r = Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHashWrong());
            assertEquals(i < 9 ? 0x63c0 | (9 - i) : 0x6983, r.sw(), "attempt " + i);
        }
        Response r = Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]);
        assertArrayEquals(new byte[] {0x01, 0x00}, r.data(), "card is BLANK again");
    }

    @Test
    void verifySucceedsAndExposesPublicKey() throws Exception {
        loaded();
        verify();
        Response r = Vecs.roundtrip(card, session, 0x30, 0, 0, Vecs.pathSecpEvm());
        assertEquals(0x9000, r.sw());
        assertArrayEquals(Vecs.pkSecpEvm(), r.data());
    }

    @Test
    void publicKeyFaultedChildIsReported() throws Exception {
        loaded();
        verify();
        Fault.arm("Derivation.child", 1, Const.CHECK_FAIL);
        Response r = Vecs.roundtrip(card, session, 0x30, 0, 0, Vecs.pathSecpEvm());
        assertEquals(0x6a80, r.sw());
    }

    @Test
    void publicKeyMulThrowIsReported() throws Exception {
        loaded();
        verify();
        Fault.armThrow("Secp256k1.mul", 1);
        Response r = Vecs.roundtrip(card, session, 0x30, 0, 0, Vecs.pathSecpEvm());
        assertEquals(0x6a80, r.sw());
    }

    @Test
    void eraseRefusesAnUnverifiedSession() throws Exception {
        loaded();
        Response r = Vecs.roundtrip(card, session, 0x24, 0, 0, new byte[0]);
        assertEquals(0x6982, r.sw(), "W10: ERASE needs a verified session");
    }

    @Test
    void eraseLeavesTheSessionOpenButBlank() throws Exception {
        loaded();
        verify();
        Response r = Vecs.roundtrip(card, session, 0x24, 0, 0, new byte[0]);
        assertEquals(0x9000, r.sw());
        assertEquals(0, r.data().length);
        r = Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]);
        assertArrayEquals(new byte[] {0x01, 0x00}, r.data(), "session stays open on a BLANK card");
        r = Vecs.roundtrip(card, session, 0x30, 0, 0, Vecs.pathSecpEvm());
        assertEquals(0x6985, r.sw());
    }

    @Test
    void changeRewrapsWithoutAlteringWalletInfo() throws Exception {
        loaded();
        verify();
        Response r = Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash());
        byte[] info = r.data().clone();

        r = Vecs.roundtrip(card, session, 0x23, 0, 0, Vecs.accessHashNew());
        assertEquals(0x9000, r.sw());
        assertEquals(0, r.data().length);

        // a fresh OPEN verifies with the new hash only
        session = Vecs.open(card);
        r = Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash());
        assertEquals(0x63c9, r.sw(), "old code fails after CHANGE");
        session = Vecs.open(card);
        r = Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHashNew());
        assertEquals(0x9000, r.sw());
        assertArrayEquals(info, r.data(), "WalletInfo unchanged by rewrap");
    }

    @Test
    void wrongAccessHashOnVerifyIsSixtyThreeCx() throws Exception {
        loaded();
        Response r = Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHashWrong());
        assertEquals(0x63c9, r.sw());
        assertEquals(0, r.data().length, "no output on a wrong code");
    }

    @Test
    void commandsRejectBadP1P2AndBadLength() throws Exception {
        // CREATE's own gates run on BLANK; the LOADED/verified gates precede the rest
        blank();
        assertEquals(
                0x6a86,
                Vecs.roundtrip(card, session, 0x21, 2, 0, new byte[0]).sw(),
                "CREATE P1 out of range");
        loaded();
        verify();
        assertEquals(
                0x6700,
                Vecs.roundtrip(card, session, 0x22, 0, 0, new byte[31]).sw(),
                "VERIFY needs 32 bytes");
        assertEquals(
                0x6a86,
                Vecs.roundtrip(card, session, 0x30, 2, 0, Vecs.pathSecpEvm()).sw(),
                "PUBLIC_KEY curve out of range");
    }

    @Test
    void blankCardRejectsLoadedOnlyCommands() throws Exception {
        blank();
        assertEquals(0x6985, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
        assertEquals(0x6985, Vecs.roundtrip(card, session, 0x24, 0, 0, new byte[0]).sw());
        assertEquals(0x6985, Vecs.roundtrip(card, session, 0x30, 0, 0, Vecs.pathSecpEvm()).sw());
        assertEquals(0x6985, Vecs.roundtrip(card, session, 0x23, 0, 0, Vecs.accessHash()).sw());
    }
}
