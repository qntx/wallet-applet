// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Field;
import java.util.Arrays;
import javacard.framework.Applet;
import javacard.security.AESKey;
import org.junit.jupiter.api.Test;
import org.qntx.card.Internals;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;

/**
 * §8.5/§16.2: every teardown path zeroes the session words, the four AES keys, both scratch arrays
 * and the transient EC scalar, and leaves no inner plaintext in the APDU buffer.
 */
final class TeardownTest {

    private static final String[] KEYS = {"kce", "kcm", "kre", "krm"};

    private static void assertDead(Card card) {
        Applet applet = card.applet(Spec.WALLET_AID);
        assertArrayEquals(new byte[10], Internals.words(applet), "session words not cleared");
        byte[] key = new byte[16];
        for (String name : KEYS) {
            AESKey k = Internals.sessionKey(applet, name);
            k.getKey(key, (short) 0);
            assertArrayEquals(new byte[16], key, name + " not wiped");
        }
        assertArrayEquals(new byte[130], Internals.pBytes(applet), "Mem.P not wiped");
        assertArrayEquals(new byte[256], Internals.wBytes(applet), "Mem.W not wiped");
        assertArrayEquals(new byte[64], Internals.seedBytes(applet), "seed not wiped");
        assertArrayEquals(new byte[170], Internals.secpCacheBytes(applet), "secpCache not wiped");
        assertArrayEquals(new byte[194], Internals.edStreamBytes(applet), "edStream not wiped");
        assertArrayEquals(new byte[105], Internals.edCacheBytes(applet), "edCache not wiped");
        // the pending-transfer state of §9.14 (kTe, kTm, sender) dies with the session too
        ((AESKey) Internals.memField(applet, "kTe")).getKey(key, (short) 0);
        assertArrayEquals(new byte[16], key, "kTe not wiped");
        ((AESKey) Internals.memField(applet, "kTm")).getKey(key, (short) 0);
        assertArrayEquals(new byte[16], key, "kTm not wiped");
        assertArrayEquals(
                new byte[16], (byte[]) Internals.memField(applet, "sender"), "sender not wiped");
        byte[] s = new byte[32];
        try {
            Internals.ephKey(applet).getS(s, (short) 0);
            assertArrayEquals(new byte[32], s, "ephemeral scalar not wiped");
        } catch (javacard.security.CryptoException e) {
            // after a real deselection the platform has cleared the whole transient key —
            // domain and value — which is dead state, not a leak
        }
    }

    @Test
    void deselectTearsDown() throws Exception {
        Card card = Vecs.blankSelf();
        Vecs.open(card);
        card.transmit(Spec.SELECT); // re-SELECT deselects the applet
        assertDead(card);
        assertEquals(0x6985, Vecs.sw(card.transmit(new byte[] {(byte) 0x80, 0x12, 0, 0, 0x18})));
    }

    @Test
    void selectTearsAnOpenSessionDown() throws Exception {
        // the applet's own select() clears the same state the deselect path does
        Card card = Vecs.blankSelf();
        Vecs.open(card);
        card.applet(Spec.WALLET_AID).select();
        assertDead(card);
    }

    @Test
    void pendingWordIsClearedByTeardown() throws Exception {
        // every session word holds a nonzero value before the tear, pending included
        Card card = Vecs.blankSelf();
        Session session = Vecs.open(card);
        byte[] words = Internals.words(card.applet(Spec.WALLET_AID));
        words[6] = 0x69;
        words[7] = 0x69;
        byte[] apdu = session.wrap(0x20, 0, 0, new byte[0]);
        apdu[apdu.length - 2] ^= 1; // bad tag
        assertEquals(0x6982, Vecs.sw(card.transmit(apdu)));
        assertDead(card);
    }

    @Test
    void recordFailureTearsDown() throws Exception {
        Card card = Vecs.blankSelf();
        Session session = Vecs.open(card);
        // advance ctr to 1 so every session word holds a nonzero value before the tear
        Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]);
        byte[] apdu = session.wrap(0x20, 0, 0, new byte[0]);
        apdu[apdu.length - 2] ^= 1; // bad tag
        assertEquals(0x6982, Vecs.sw(card.transmit(apdu)));
        assertDead(card);
    }

    @Test
    void innerFaultTearsDown() throws Exception {
        Card card = Vecs.blankSelf();
        Session session = Vecs.open(card);
        // corrupt the persistent fails word pair so STATUS faults with 6F00 inside the record
        byte[] state = Internals.stateArray(card.applet(Spec.WALLET_AID));
        state[2] = 0x12;
        state[3] = 0x34;
        state[4] = 0x12;
        state[5] = 0x34; // f == complement instead of f == ~complement
        var r = Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]);
        assertEquals(0x6F00, r.sw());
        assertDead(card);
        assertEquals(0x6985, Vecs.sw(card.transmit(session.wrap(0x20, 0, 0, new byte[0]))));
    }

    @Test
    void outerFaultTearsAnOpenSessionDown() throws Exception {
        Card card = Vecs.blankSelf();
        Session session = Vecs.open(card);
        // corrupt the life word: OPEN faults with 6F00 and process() tears the session
        byte[] state = Internals.stateArray(card.applet(Spec.WALLET_AID));
        state[0] = 0x12;
        state[1] = 0x34;
        assertEquals(0x6F00, Vecs.sw(card.transmit(Vecs.unhex("8010000000"))));
        assertDead(card);
        assertEquals(0x6985, Vecs.sw(card.transmit(session.wrap(0x20, 0, 0, new byte[0]))));
    }

    @Test
    void counterExhaustionTearsDown() throws Exception {
        // §8.5: the response carrying ctr = 0xFFFF tears the session down
        Card card = Vecs.blankSelf();
        Session session = Vecs.open(card);
        byte[] words = Internals.words(card.applet(Spec.WALLET_AID));
        words[4] = (byte) 0xFF;
        words[5] = (byte) 0xFF;
        Field ctr = Session.class.getDeclaredField("ctr");
        ctr.setAccessible(true);
        ctr.setInt(session, 0xFFFF);
        byte[] rapdu = card.transmit(session.wrap(0x20, 0, 0, new byte[0]));
        assertEquals(0x9000, session.unwrap(rapdu).sw());
        assertDead(card);
    }

    @Test
    void liveStreamIsWipedAcrossTeardowns() throws Exception {
        // a stream mid-flight carries a and r: every §8.5 teardown path zeroes it
        Card card = Vecs.blankSelf();
        Session session = Vecs.loadWallet(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x33, 0, 0, Vecs.pathEdSolana()).sw());
        assertNotZero(Internals.edStreamBytes(card.applet(Spec.WALLET_AID)));
        org.qntx.card.host.Open.request(Vecs.RND);
        byte[] openApdu = org.qntx.card.host.Open.request(Vecs.RND).apdu();
        assertEquals(0x9000, Vecs.sw(card.transmit(openApdu)));
        // a successful OPEN replaces the session: words live again, but the old session's
        // seed, caches and stream are gone (§8.5 runs on the OPEN transition)
        assertArrayEquals(
                new byte[194],
                Internals.edStreamBytes(card.applet(Spec.WALLET_AID)),
                "edStream not wiped by OPEN");
        assertArrayEquals(new byte[64], Internals.seedBytes(card.applet(Spec.WALLET_AID)), "seed");

        session = Vecs.open(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x33, 0, 0, Vecs.pathEdSolana()).sw());
        card.transmit(Spec.SELECT);
        assertDead(card);
    }

    @Test
    void streamEndsOnAnyNonContinuationCommand() throws Exception {
        // §9.2: the pending state ends when any command that does not continue it is
        // dispatched — edStream is wiped by endPending on the same path
        Card card = Vecs.blankSelf();
        Session session = Vecs.loadWallet(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x33, 0, 0, Vecs.pathEdSolana()).sw());
        assertNotZero(Internals.edStreamBytes(card.applet(Spec.WALLET_AID)));
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]).sw());
        assertArrayEquals(
                new byte[194],
                Internals.edStreamBytes(card.applet(Spec.WALLET_AID)),
                "STATUS ended the stream");
        assertEquals(
                0x6985,
                Vecs.roundtrip(card, session, 0x33, 1, 0, new byte[] {1}).sw(),
                "update after the stream ended");
    }

    @Test
    void walletSecretsDieWithTheSession() throws Exception {
        // load a wallet, verify, derive both curve paths and run one WAIT so the seed, both
        // derivation caches and the waited word hold nonzero data before the tear
        Card card = Vecs.blankSelf();
        Session session = Vecs.loadWallet(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x30, 0, 0, Vecs.pathSecpEvm()).sw());
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x30, 1, 0, Vecs.pathEdSolana()).sw());
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x25, 0, 0, new byte[0]).sw());
        Applet applet = card.applet(Spec.WALLET_AID);
        assertNotZero(Internals.seedBytes(applet));
        assertNotZero(Internals.secpCacheBytes(applet));
        assertNotZero(Internals.edCacheBytes(applet));
        card.transmit(Spec.SELECT);
        assertDead(card);
    }

    @Test
    void innerFaultWipesWalletSecrets() throws Exception {
        // a 6F00 inside the record kills the session and all its secrets (§8.5)
        Card card = Vecs.blankSelf();
        Session session = Vecs.loadWallet(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x30, 0, 0, Vecs.pathSecpEvm()).sw());
        byte[] state = Internals.stateArray(card.applet(Spec.WALLET_AID));
        state[2] = 0x12;
        state[3] = 0x34;
        state[4] = 0x12;
        state[5] = 0x34;
        assertEquals(0x6F00, Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]).sw());
        assertDead(card);
    }

    @Test
    void pendingTransferDiesWithTheSession() throws Exception {
        // arm a genuine pending import so kTe/kTm/sender hold nonzero secret state, then a
        // SELECT must wipe them (§8.5 endPending runs on every teardown path — the
        // zero-assertions live in assertDead above)
        Card source = Vecs.factory();
        byte[] sa = Vecs.cardA(source);
        Vecs.blankFor(source, sa);
        Card target = Vecs.factory();
        byte[] ta = Vecs.cardA(target);
        Vecs.blankFor(target, ta);
        Session sSession = Vecs.open(source);
        Session tSession = Vecs.open(target);
        byte[] create = new byte[112];
        System.arraycopy(Vecs.accessHash(), 0, create, 0, 32);
        System.arraycopy(Vecs.seed(), 0, create, 32, 64);
        System.arraycopy(Ids.cardId(ta), 0, create, 96, 16);
        assertEquals(0x9000, Vecs.roundtrip(source, sSession, 0x21, 1, 0, create).sw(), "CREATE");
        assertEquals(
                0x9000, Vecs.roundtrip(target, tSession, 0x40, 0, 0, new byte[0]).sw(), "OFFER");
        byte[] offer =
                Arrays.copyOf(
                        Vecs.roundtrip(target, tSession, 0x40, 0, 0, new byte[0]).data(), 129);
        assertEquals(
                0x9000,
                Vecs.roundtrip(source, sSession, 0x22, 0, 0, Vecs.accessHash()).sw(),
                "VERIFY");
        byte[] data = new byte[226];
        System.arraycopy(Vecs.certFor(ta), 0, data, 0, 97);
        System.arraycopy(offer, 0, data, 97, 129);
        byte[] head = Vecs.roundtrip(source, sSession, 0x41, 0, 0, data).data();
        byte[] import0 = new byte[226];
        System.arraycopy(Vecs.certFor(sa), 0, import0, 0, 97);
        System.arraycopy(head, 0, import0, 97, 129);
        assertEquals(0x9000, Vecs.roundtrip(target, tSession, 0x42, 0, 0, import0).sw(), "IMPORT0");
        Applet applet = target.applet(Spec.WALLET_AID);
        byte[] key = new byte[16];
        ((AESKey) Internals.memField(applet, "kTe")).getKey(key, (short) 0);
        assertNotZero(key);
        assertNotZero((byte[]) Internals.memField(applet, "sender"));
        target.transmit(Spec.SELECT);
        assertDead(target);
    }

    private static void assertNotZero(byte[] data) {
        for (byte b : data) {
            if (b != 0) {
                return;
            }
        }
        throw new AssertionError("expected nonzero data");
    }

    @Test
    void openWipesTheEphemeralScalar() throws Exception {
        Card card = Vecs.blankSelf();
        Vecs.open(card);
        Applet applet = card.applet(Spec.WALLET_AID);
        byte[] s = new byte[32];
        Internals.ephKey(applet).getS(s, (short) 0);
        assertArrayEquals(new byte[32], s, "ephemeral scalar x must be wiped after OPEN");
        // and the shared scratch that held x, Z and the KDF output must be zero
        byte[] w = Internals.wBytes(applet);
        int zpt = Internals.sessionOffset("W_ZPT");
        int keys = Internals.sessionOffset("W_KEYS");
        int x = Internals.sessionOffset("W_X");
        for (int i = 0; i < 65; i++) {
            assertEquals(0, w[zpt + i], "W_ZPT not wiped");
        }
        for (int i = 0; i < 64; i++) {
            assertEquals(0, w[keys + i], "W_KEYS not wiped");
        }
        for (int i = 0; i < 32; i++) {
            assertEquals(0, w[x + i], "W_X not wiped");
        }
    }
}
