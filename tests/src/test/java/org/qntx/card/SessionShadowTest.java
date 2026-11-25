// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.tests.EmuMember;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The session shadow words of §16.2 item 1 (A4): every guarded check's second evaluation reads a
 * second, independently written word — {@code verifiedShadow} or {@code pendingExportShadow} — so a
 * data fault that rewrites word A of {@code verified} or {@code pending} satisfies the first
 * evaluation and is caught by the second, and a corrupt shadow word is a fault on its own.
 */
final class SessionShadowTest {
    private static final int INS_CHANGE = 0x23;
    private static final int INS_ERASE = 0x24;
    private static final int INS_PUBLIC_KEY = 0x30;
    private static final int INS_SIGN_ECDSA = 0x31;
    private static final int INS_SIGN_BIP340 = 0x32;
    private static final int INS_SIGN_ED25519 = 0x33;
    private static final int INS_EXPORT = 0x41;

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    private static byte[] words(Card card) {
        return Internals.words(card.applet(Spec.WALLET_AID));
    }

    /** The word-A data fault: {@code verified} reads {@code VERIFIED_YES}, the shadow stays 0. */
    private static void forgeVerified(Card card) {
        byte[] w = words(card);
        int o = Internals.sessionOffset("O_VERIFIED");
        w[o] = (byte) (Const.VERIFIED_YES >>> 8);
        w[o + 1] = (byte) Const.VERIFIED_YES;
    }

    /**
     * On a session that was never verified, word A forced to {@code VERIFIED_YES}: the dispatch
     * gate and each handler's first evaluation pass, and the second evaluation on the untouched
     * shadow refuses every guarded command with {@code 6F00}.
     */
    @Test
    void forgedVerifiedWordIsCaughtByEverySecondEval() throws Exception {
        // a depth-1 path: depth 0 (the master) is a data check, not a valid request
        byte[] bip340 = new byte[69];
        bip340[63] = 1; // tweak = 1: a valid scalar so the command reaches its gate
        bip340[64] = 0x01;
        Object[][] commands = {
            {"PUBLIC_KEY", INS_PUBLIC_KEY, new byte[] {0x01, 0, 0, 0, 0}},
            {
                "SIGN_ECDSA",
                INS_SIGN_ECDSA,
                new byte[] {
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0
                }
            },
            {"SIGN_BIP340", INS_SIGN_BIP340, bip340},
            {"SIGN_ED25519 begin", INS_SIGN_ED25519, new byte[] {0x01, (byte) 0x80, 0, 0, 0}},
            {"CHANGE", INS_CHANGE, new byte[32]},
            {"ERASE", INS_ERASE, new byte[0]},
        };
        for (Object[] c : commands) {
            Card card = Vecs.blankSelf();
            Session session = Vecs.loadWallet(card); // LOADED, open, NOT verified
            forgeVerified(card);
            Response r = Vecs.roundtrip(card, session, (int) c[1], 0, 0, (byte[]) c[2]);
            assertEquals(
                    0x6F00,
                    r.sw(),
                    () ->
                            c[0]
                                    + " accepted a forged verified word: "
                                    + Integer.toHexString(r.sw()));
            assertEquals(0, r.data().length, c[0] + " produced output");
            // the fault tore the session down — all fourteen words read back cleared
            assertArrayEquals(new byte[14], words(card), c[0] + ": no teardown");
            // and the wallet is unchanged: a fresh session reports LOADED
            Session again = Vecs.open(card);
            Response status = Vecs.roundtrip(card, again, 0x20, 0, 0, new byte[0]);
            assertArrayEquals(new byte[] {0x02, 0x0A}, status.data(), c[0] + " changed the wallet");
        }
    }

    /**
     * Word A of {@code pending} forced to {@code PENDING_EXPORT} on a verified session that ran no
     * {@code EXPORT P1=00}: the first pending evaluation passes, the second — on the untouched
     * {@code PENDING_EXPORT_SHADOW} word — refuses {@code EXPORT P1=01} with {@code 6F00}.
     */
    @Test
    void forgedPendingExportWordIsCaughtByTheSecondEval() throws Exception {
        Card card = Vecs.blankSelf();
        Session session = Vecs.loadWallet(card);
        assertEquals(
                0x9000,
                Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw(),
                "VERIFY");
        byte[] w = words(card);
        int o = Internals.sessionOffset("O_PENDING");
        w[o] = (byte) (Const.PENDING_EXPORT >>> 8);
        w[o + 1] = (byte) Const.PENDING_EXPORT;
        Response r = Vecs.roundtrip(card, session, INS_EXPORT, 1, 0, Vecs.accessHashNew());
        assertEquals(
                0x6F00,
                r.sw(),
                () -> "EXPORT P1=01 with a forged pending word: " + Integer.toHexString(r.sw()));
        assertArrayEquals(new byte[14], words(card), "no teardown after the shadow fault");
    }

    /**
     * A corrupt shadow word — any value outside {@code {0, SHADOW}} — is a detected fault on its
     * own: {@code 6F00} and the session torn down.
     */
    @Test
    void corruptShadowWordsFaultAndTearDown() throws Exception {
        for (String field : new String[] {"O_VERIFIED_SHADOW", "O_PENDING_SHADOW"}) {
            Card card = Vecs.blankSelf();
            Session session = Vecs.loadWallet(card);
            assertEquals(
                    0x9000,
                    Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw(),
                    "VERIFY " + field);
            byte[] w = words(card);
            int o = Internals.sessionOffset(field);
            w[o] = 0x12;
            w[o + 1] = 0x34;
            // a command whose second evaluation reads the corrupted word
            int ins = field.equals("O_VERIFIED_SHADOW") ? INS_PUBLIC_KEY : INS_EXPORT;
            byte[] data =
                    ins == INS_PUBLIC_KEY ? new byte[] {0x01, 0, 0, 0, 0} : Vecs.accessHashNew();
            int p1 = ins == INS_EXPORT ? 1 : 0;
            // EXPORT P1=01 also needs pending word A armed to reach the shadow read
            if (ins == INS_EXPORT) {
                int p = Internals.sessionOffset("O_PENDING");
                w[p] = (byte) (Const.PENDING_EXPORT >>> 8);
                w[p + 1] = (byte) Const.PENDING_EXPORT;
            }
            Response r = Vecs.roundtrip(card, session, ins, p1, 0, data);
            assertEquals(0x6F00, r.sw(), () -> field + " corrupt: " + Integer.toHexString(r.sw()));
            assertArrayEquals(new byte[14], words(card), field + ": no teardown");
        }
    }

    /** The normal flows keep working: the shadow words mirror word A on every writer. */
    @Test
    void genuineFlagsPassBothEvaluations() throws Exception {
        Card card = Vecs.blankSelf();
        Session session = Vecs.loadWallet(card);
        assertEquals(
                0x9000,
                Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw(),
                "VERIFY");
        byte[] w = words(card);
        int v = Internals.sessionOffset("O_VERIFIED");
        int vs = Internals.sessionOffset("O_VERIFIED_SHADOW");
        assertEquals(
                Const.VERIFIED_YES,
                (short) (((w[v] & 0xFF) << 8) | (w[v + 1] & 0xFF)),
                "verified word A");
        assertEquals(
                Const.VERIFIED_SHADOW,
                (short) (((w[vs] & 0xFF) << 8) | (w[vs + 1] & 0xFF)),
                "verified shadow word B");
        // the guarded output path answers normally
        Response pk =
                Vecs.roundtrip(card, session, INS_PUBLIC_KEY, 0, 0, new byte[] {0x01, 0, 0, 0, 0});
        assertEquals(0x9000, pk.sw(), "PUBLIC_KEY on a genuinely verified session");
        // and the pending words mirror on a real export — CREATE leaves its
        // session verified, so EXPORT P1=00 runs in the same session
        EmuMember m = new EmuMember();
        byte[] create = new byte[96 + 16];
        Card c2 = Vecs.blankSelf();
        Session s2 = Vecs.open(c2);
        System.arraycopy(Vecs.accessHash(), 0, create, 0, 32);
        System.arraycopy(Vecs.seed(), 0, create, 32, 64);
        System.arraycopy(m.cardId, 0, create, 96, 16);
        assertEquals(0x9000, Vecs.roundtrip(c2, s2, 0x21, 1, 0, create).sw(), "CREATE");
        assertEquals(
                0x9000,
                Vecs.roundtrip(c2, s2, INS_EXPORT, 0, 0, m.exportRequest()).sw(),
                "EXPORT P1=00");
        byte[] w2 = words(c2);
        int p = Internals.sessionOffset("O_PENDING");
        int ps = Internals.sessionOffset("O_PENDING_SHADOW");
        assertEquals(
                Const.PENDING_EXPORT,
                (short) (((w2[p] & 0xFF) << 8) | (w2[p + 1] & 0xFF)),
                "pending word A");
        assertEquals(
                Const.PENDING_EXPORT_SHADOW,
                (short) (((w2[ps] & 0xFF) << 8) | (w2[ps + 1] & 0xFF)),
                "pending shadow word B");
        Response e1 = Vecs.roundtrip(c2, s2, INS_EXPORT, 1, 0, Vecs.accessHashNew());
        assertEquals(0x9000, e1.sw(), "EXPORT P1=01");
        byte[] w3 = words(c2);
        assertEquals(0, w3[p] | w3[p + 1], "pending word A not ended");
        assertEquals(0, w3[ps] | w3[ps + 1], "pending shadow word B not ended");
    }
}
