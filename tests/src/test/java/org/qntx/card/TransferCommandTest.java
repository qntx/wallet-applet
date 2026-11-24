// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Arrays;
import javacard.security.AESKey;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The §9.12–9.14 transfer commands end to end on simulator cards (architecture §9 T1): a full
 * two-card transfer and a re-seal, the idempotent OFFER, the member gate and peer-key write
 * metering of {@code IMPORT P1 = 0x00}, the pending rules of §9.2 and the post-install refusal.
 */
final class TransferCommandTest {
    private static final int INS_VERIFY = 0x22;
    private static final int INS_STATUS = 0x20;
    private static final int INS_CREATE = 0x21;
    private static final int INS_OFFER = 0x40;
    private static final int INS_EXPORT = 0x41;
    private static final int INS_IMPORT = 0x42;
    private static final int INS_ERASE = 0x24;
    private static final int INS_PUBLIC_KEY = 0x30;

    /** A card personalized under ca1, in BLANK with an open session and its identity. */
    private static final class Side {
        final Card card;
        final byte[] a;
        Session session;

        Side() throws Exception {
            card = Vecs.factory();
            a = Vecs.cardA(card);
            Vecs.blankFor(card, a);
            session = Vecs.open(card);
        }

        Response inner(int ins, int p1, byte[] data) throws Exception {
            return Vecs.roundtrip(card, session, ins, p1, 0, data);
        }

        byte[] offer() throws Exception {
            Response r = inner(INS_OFFER, 0, new byte[0]);
            if (r.sw() != 0x9000) {
                throw new IllegalStateException("OFFER " + Integer.toHexString(r.sw()));
            }
            return r.data();
        }

        /** CREATE P1 = 01 with the shared seed and {@code ids} as the other members. */
        byte[] create(byte[]... ids) throws Exception {
            byte[] data = new byte[96 + 16 * ids.length];
            System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
            System.arraycopy(Vecs.seed(), 0, data, 32, 64);
            for (int i = 0; i < ids.length; i++) {
                System.arraycopy(ids[i], 0, data, 96 + 16 * i, 16);
            }
            Response r = inner(INS_CREATE, 1, data);
            if (r.sw() != 0x9000) {
                throw new IllegalStateException("CREATE " + Integer.toHexString(r.sw()));
            }
            return r.data();
        }

        /** The verified EXPORT pair to {@code target}'s certificate and current offer. */
        void exportTo(
                Side target, byte[] offer, byte[] sourceHash, byte[] accessHashT, byte[][] out)
                throws Exception {
            session = Vecs.open(card);
            Response v = inner(INS_VERIFY, 0, sourceHash);
            if (v.sw() != 0x9000) {
                throw new IllegalStateException("VERIFY " + Integer.toHexString(v.sw()));
            }
            byte[] data = new byte[226];
            System.arraycopy(Vecs.certFor(target.a), 0, data, 0, 97);
            System.arraycopy(offer, 0, data, 97, 129);
            Response h = inner(INS_EXPORT, 0, data);
            if (h.sw() != 0x9000) {
                throw new IllegalStateException("EXPORT0 " + Integer.toHexString(h.sw()));
            }
            Response p = inner(INS_EXPORT, 1, accessHashT);
            if (p.sw() != 0x9000) {
                throw new IllegalStateException("EXPORT1 " + Integer.toHexString(p.sw()));
            }
            out[0] = h.data();
            out[1] = p.data();
        }

        Response import0(Side source, byte[] head) throws Exception {
            byte[] data = new byte[226];
            System.arraycopy(Vecs.certFor(source.a), 0, data, 0, 97);
            System.arraycopy(head, 0, data, 97, 129);
            return inner(INS_IMPORT, 0, data);
        }

        Response import1(byte[] payload) throws Exception {
            return inner(INS_IMPORT, 1, payload);
        }
    }

    @Test
    void twoCardTransferEndsInEqualWalletInfo() throws Exception {
        Side t = new Side();
        Side s = new Side();
        byte[] info = s.create(Ids.cardId(t.a));
        byte[] offer = t.offer();
        byte[][] export = new byte[2][];
        s.exportTo(t, offer, Vecs.accessHash(), Vecs.accessHashNew(), export);
        assertEquals(0x9000, t.import0(s, export[0]).sw());
        Response r = t.import1(export[1]);
        assertEquals(0x9000, r.sw());
        assertArrayEquals(info, r.data(), "IMPORT WalletInfo equals CREATE's");
    }

    @Test
    void resealKeepsWalletInfoAndMovesTheCode() throws Exception {
        Side t = new Side();
        Side s = new Side();
        s.create(Ids.cardId(t.a));
        byte[] offer = t.offer();
        byte[][] export = new byte[2][];
        s.exportTo(t, offer, Vecs.accessHash(), Vecs.accessHashNew(), export);
        assertEquals(0x9000, t.import0(s, export[0]).sw());
        byte[] info = t.import1(export[1]).data();
        // the target is LOADED now: re-seal it with yet another access hash (§11.3)
        byte[] offer2 = t.offer();
        byte[][] export2 = new byte[2][];
        s.exportTo(t, offer2, Vecs.accessHash(), Vecs.accessHash(), export2);
        assertEquals(0x9000, t.import0(s, export2[0]).sw());
        Response r = t.import1(export2[1]);
        assertEquals(0x9000, r.sw());
        assertArrayEquals(info, r.data(), "re-seal returns the same WalletInfo");
        // the payload carried accessHash() back: VERIFY with it succeeds
        assertEquals(0x9000, t.inner(INS_VERIFY, 0, Vecs.accessHash()).sw(), "re-sealed code");
    }

    @Test
    void secondOfferReturnsTheSameLkAndWritesNothing() throws Exception {
        Side t = new Side();
        byte[] o1 = t.offer();
        byte[] o2 = t.offer();
        assertArrayEquals(
                Arrays.copyOf(o1, 65), Arrays.copyOf(o2, 65), "same LK while offer = VALID");
        assertEquals(0, t.card.writes(), "second OFFER writes nothing (§9.12)");
    }

    @Test
    void import0FromNonMemberWritesNothing() throws Exception {
        Side t = new Side();
        Side s = new Side();
        Side stranger = new Side();
        s.create(Ids.cardId(t.a));
        byte[] offer = t.offer();
        byte[][] export = new byte[2][];
        s.exportTo(t, offer, Vecs.accessHash(), Vecs.accessHashNew(), export);
        assertEquals(0x9000, t.import0(s, export[0]).sw());
        assertEquals(0x9000, t.import1(export[1]).sw());
        // t is LOADED with members {s, t}: a certified third card is not a member (§9.14.3)
        t.offer();
        byte[] data = new byte[226];
        System.arraycopy(Vecs.certFor(stranger.a), 0, data, 0, 97);
        System.arraycopy(export[0], 0, data, 97, 129);
        assertEquals(0x6A80, t.inner(INS_IMPORT, 0, data).sw(), "non-member sender");
        assertEquals(0, t.card.writes(), "rejected IMPORT0 writes nothing");
    }

    @Test
    void peerKeySlotsWriteOncePerMember() throws Exception {
        Side t = new Side();
        Side m1 = new Side();
        Side m2 = new Side();
        // a three-card set: m1 creates, m2 and t import — members {m1, t, m2}. t imports
        // while BLANK, so its sender lands in peer slot 0; LOADED, m1 maps to slot 0 and
        // m2 to slot 1, each written once (§16.1 item 1)
        byte[] idT = Ids.cardId(t.a);
        byte[] idM2 = Ids.cardId(m2.a);
        m1.create(idT, idM2);
        byte[][] export = new byte[2][];
        m1.exportTo(m2, m2.offer(), Vecs.accessHash(), Vecs.accessHashNew(), export);
        assertEquals(0x9000, m2.import0(m1, export[0]).sw());
        assertEquals(0x9000, m2.import1(export[1]).sw());
        m2.exportTo(t, t.offer(), Vecs.accessHashNew(), Vecs.accessHashNew(), export);
        assertEquals(0x9000, t.import0(m2, export[0]).sw());
        assertEquals(0x9000, t.import1(export[1]).sw());
        // t is LOADED with three members; on its valid offer, m1 and m2 alternate
        byte[] offer = t.offer();
        m1.exportTo(t, offer, Vecs.accessHash(), Vecs.accessHash(), export);
        byte[] head1 = export[0];
        assertEquals(0x9000, t.import0(m1, head1).sw());
        int afterM1 = t.card.writes();
        m2.exportTo(t, offer, Vecs.accessHashNew(), Vecs.accessHash(), export);
        byte[] head2 = export[0];
        assertEquals(0x9000, t.import0(m2, head2).sw());
        int afterM2 = t.card.writes();
        assertEquals(1, afterM1, "first IMPORT0 of m1 writes one peer-key slot");
        assertEquals(1, afterM2, "first IMPORT0 of m2 writes the other slot");
        // repeats and alternation reuse the slots: no further setW (§16.1 item 1)
        assertEquals(0x9000, t.import0(m1, head1).sw());
        assertEquals(0, t.card.writes(), "repeat m1 writes nothing");
        assertEquals(0x9000, t.import0(m2, head2).sw());
        assertEquals(0, t.card.writes(), "repeat m2 writes nothing");
        assertEquals(0x9000, t.import0(m1, head1).sw());
        assertEquals(0, t.card.writes(), "alternated m1 writes nothing");
    }

    @Test
    void nonContinuationEndsThePendingImport() throws Exception {
        Side t = new Side();
        Side s = new Side();
        s.create(Ids.cardId(t.a));
        byte[][] export = new byte[2][];
        s.exportTo(t, t.offer(), Vecs.accessHash(), Vecs.accessHashNew(), export);
        assertEquals(0x9000, t.import0(s, export[0]).sw());
        var applet = t.card.applet(Spec.WALLET_AID);
        byte[] words = Internals.words(applet);
        assertEquals(
                Const.PENDING_IMPORT,
                (short) (((words[6] & 0xFF) << 8) | (words[7] & 0xFF)),
                "pending import armed");
        // endPending overwrites the pending keys with fresh random values, never a
        // constant (§16.2 item 4)
        byte[] kTe = aesKey(applet, "kTe");
        byte[] kTm = aesKey(applet, "kTm");
        assertEquals(0x9000, t.inner(INS_STATUS, 0, new byte[0]).sw());
        assertEquals(0, words[6] | words[7], "STATUS ended the pending import");
        assertFalse(Arrays.equals(kTe, aesKey(applet, "kTe")), "kTe overwritten");
        assertFalse(Arrays.equals(kTm, aesKey(applet, "kTm")), "kTm overwritten");
        assertFalse(Arrays.equals(new byte[16], aesKey(applet, "kTe")), "kTe not a constant");
        assertFalse(Arrays.equals(new byte[16], aesKey(applet, "kTm")), "kTm not a constant");
        assertArrayEquals(
                new byte[16], (byte[]) Internals.memField(applet, "sender"), "sender wiped");
    }

    @Test
    void nonContinuationEndsThePendingExport() throws Exception {
        Side t = new Side();
        Side s = new Side();
        s.create(Ids.cardId(t.a));
        byte[] offer = t.offer();
        s.session = Vecs.open(s.card);
        assertEquals(0x9000, s.inner(INS_VERIFY, 0, Vecs.accessHash()).sw());
        byte[] data = new byte[226];
        System.arraycopy(Vecs.certFor(t.a), 0, data, 0, 97);
        System.arraycopy(offer, 0, data, 97, 129);
        assertEquals(0x9000, s.inner(INS_EXPORT, 0, data).sw());
        var applet = s.card.applet(Spec.WALLET_AID);
        byte[] words = Internals.words(applet);
        assertEquals(
                Const.PENDING_EXPORT,
                (short) (((words[6] & 0xFF) << 8) | (words[7] & 0xFF)),
                "pending export armed");
        byte[] kTe = aesKey(applet, "kTe");
        byte[] kTm = aesKey(applet, "kTm");
        assertEquals(0x9000, s.inner(INS_STATUS, 0, new byte[0]).sw());
        assertEquals(0, words[6] | words[7], "STATUS ended the pending export");
        assertFalse(Arrays.equals(kTe, aesKey(applet, "kTe")), "kTe overwritten");
        assertFalse(Arrays.equals(kTm, aesKey(applet, "kTm")), "kTm overwritten");
        assertFalse(Arrays.equals(new byte[16], aesKey(applet, "kTe")), "kTe not a constant");
        assertFalse(Arrays.equals(new byte[16], aesKey(applet, "kTm")), "kTm not a constant");
        assertArrayEquals(
                new byte[16], (byte[]) Internals.memField(applet, "sender"), "sender wiped");
    }

    @Test
    void import0AfterACommittedInstallIs6985() throws Exception {
        Side t = new Side();
        Side s = new Side();
        s.create(Ids.cardId(t.a));
        byte[][] export = new byte[2][];
        s.exportTo(t, t.offer(), Vecs.accessHash(), Vecs.accessHashNew(), export);
        assertEquals(0x9000, t.import0(s, export[0]).sw());
        assertEquals(0x9000, t.import1(export[1]).sw());
        // T-INSTALL returned offer to NONE (§9.14): the same export cannot be imported again
        assertEquals(0x6985, t.import0(s, export[0]).sw());
    }

    private static byte[] aesKey(Object applet, String name) {
        byte[] out = new byte[16];
        ((AESKey) Internals.memField((javacard.framework.Applet) applet, name))
                .getKey(out, (short) 0);
        return out;
    }

    @Test
    void installClearsVerifiedAndWipesSecrets() throws Exception {
        // IMPORT P1=01 (§9.14): T-INSTALL clears the session flag, wipes the staged seed,
        // the decrypted payload in the APDU buffer and the derivation caches, overwrites
        // the link private scalar inside the commit and leaves a zeroed members tail
        Side t = new Side();
        Side s = new Side();
        s.create(Ids.cardId(t.a));
        byte[][] e = new byte[2][];
        s.exportTo(t, t.offer(), Vecs.accessHash(), Vecs.accessHashNew(), e);
        assertEquals(0x9000, t.import0(s, e[0]).sw());
        assertEquals(0x9000, t.import1(e[1]).sw());
        // t is LOADED: fill the secp256k1 node cache, then re-seal over it
        t.session = Vecs.open(t.card);
        t.inner(INS_VERIFY, 0, Vecs.accessHashNew());
        t.inner(INS_PUBLIC_KEY, 0, org.qntx.card.host.Paths.wire("m/0'/1"));
        var applet = t.card.applet(Spec.WALLET_AID);
        org.junit.jupiter.api.Assertions.assertFalse(
                Arrays.equals(
                        new byte[Internals.secpCacheBytes(applet).length],
                        Internals.secpCacheBytes(applet)),
                "secp cache never filled");
        s.exportTo(t, t.offer(), Vecs.accessHash(), Vecs.accessHash(), e);
        byte[] linkBefore = Internals.linkPrivate(applet);
        assertEquals(0x9000, t.import0(s, e[0]).sw());
        org.qntx.card.sim.Fault.countCalls();
        Response r = t.import1(e[1]);
        assertEquals(0x9000, r.sw());
        // the §9.14 payload wipe must run before the response lands — a dropped call
        // shows up as one wipe fewer (the session's own tail wipe hides the effect)
        assertEquals(
                11,
                org.qntx.card.sim.Fault.calls("Bytes.wipe"),
                "payload, seed, sender and scratch wipes of IMPORT P1=1");
        assertArrayEquals(new byte[64], Internals.seedBytes(applet), "staged seed not wiped");
        assertArrayEquals(
                new byte[Internals.secpCacheBytes(applet).length],
                Internals.secpCacheBytes(applet),
                "secp cache not wiped");
        assertArrayEquals(
                new byte[Internals.edCacheBytes(applet).length],
                Internals.edCacheBytes(applet),
                "ed cache not wiped");
        byte[] words = Internals.words(applet);
        assertEquals(
                Const.VERIFIED_NO,
                javacard.framework.Util.getShort(words, (short) 2),
                "verified must be cleared");
        org.junit.jupiter.api.Assertions.assertFalse(
                Arrays.equals(linkBefore, Internals.linkPrivate(applet)),
                "link scalar not rewritten by T-INSTALL");
        byte[] state = Internals.stateArray(applet);
        // members: c(1) ‖ ID(s) ‖ ID(t) ‖ zeros for a two-member wallet
        for (int i = State.OFF_MEMBERS + 33; i < State.OFF_MEMBERS + 49; i++) {
            assertEquals(0, state[i], "members tail byte " + i + " not zeroed");
        }
        // §9.14: the decrypted payload is wiped before the response is sent — the seed
        // must be gone from the APDU buffer the card last touched
        byte[] apdu = t.card.apduBuffer();
        for (int i = 0; i + 64 <= apdu.length; i++) {
            org.junit.jupiter.api.Assertions.assertFalse(
                    Arrays.equals(apdu, i, i + 64, Vecs.seed(), 0, 64),
                    "payload seed still in the APDU buffer at " + i);
        }
        // the wiped span past the WalletInfo response record (payload ‖ 16-byte tag)
        // is all zeros: without the wipe the decrypted payload — seed tail, accessHash
        // and member IDs — would remain
        // the wiped span past the WalletInfo response record is all zeros: without
        // the wipe the decrypted payload — seed tail, accessHash, member IDs — would
        // remain (the record appends a 21-byte trailer after the payload)
        int dataOff = javacard.framework.ISO7816.OFFSET_CDATA + 3;
        for (int i = r.data().length + 24; i < dataOff + e[1].length; i++) {
            assertEquals(0, apdu[i], "payload byte " + i + " not wiped");
        }
    }

    @Test
    void rngFixedScalarBecomesTheLinkKey() throws Exception {
        // with the RNG fixed, every nextBytes serves the same block: T-CREATE, T-ERASE
        // and T-INSTALL must all route that fresh draw into linkPrivate — a skipped
        // randomScalar leaves stale scratch there instead
        byte[] scalar = new byte[32];
        Arrays.fill(scalar, (byte) 0x11);
        org.qntx.card.sim.Rng.fix(scalar);
        try {
            Side t = new Side();
            var applet = t.card.applet(Spec.WALLET_AID);
            t.create();
            assertArrayEquals(scalar, Internals.linkPrivate(applet), "T-CREATE link scalar");
            t.inner(INS_VERIFY, 0, Vecs.accessHash());
            assertEquals(0x9000, t.inner(INS_ERASE, 0, new byte[0]).sw(), "ERASE");
            assertArrayEquals(scalar, Internals.linkPrivate(applet), "T-ERASE link scalar");
            Side s = new Side();
            s.create(Ids.cardId(t.a));
            byte[][] e = new byte[2][];
            s.exportTo(t, t.offer(), Vecs.accessHash(), Vecs.accessHashNew(), e);
            assertEquals(0x9000, t.import0(s, e[0]).sw());
            assertEquals(0x9000, t.import1(e[1]).sw());
            assertArrayEquals(scalar, Internals.linkPrivate(applet), "T-INSTALL link scalar");
        } finally {
            org.qntx.card.sim.Rng.reset();
        }
    }

    @Test
    void export0WipesTheScalar() throws Exception {
        // the single-use e lives in the transient ephKey slot: wiped on every path (§16.5)
        Side t = new Side();
        Side s = new Side();
        s.create(Ids.cardId(t.a));
        byte[][] e = new byte[2][];
        s.exportTo(t, t.offer(), Vecs.accessHash(), Vecs.accessHashNew(), e);
        byte[] sbuf = new byte[32];
        assertEquals(32, Internals.ephKey(s.card.applet(Spec.WALLET_AID)).getS(sbuf, (short) 0));
        assertArrayEquals(new byte[32], sbuf, "ephemeral scalar not wiped");
    }

    @Test
    void eraseRewritesLinkKey() throws Exception {
        Side t = new Side();
        var applet = t.card.applet(Spec.WALLET_AID);
        byte[] before = Internals.linkPrivate(applet);
        t.create();
        t.inner(INS_VERIFY, 0, Vecs.accessHash());
        assertEquals(0x9000, t.inner(INS_ERASE, 0, new byte[0]).sw(), "ERASE");
        org.junit.jupiter.api.Assertions.assertFalse(
                Arrays.equals(before, Internals.linkPrivate(applet)),
                "link scalar not rewritten by T-ERASE");
    }
}
