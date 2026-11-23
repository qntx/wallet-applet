// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import javacard.framework.Util;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.TornException;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * Architecture §14.6 T6 — the transfer transactions under power loss. T-OFFER and T-INSTALL (a
 * BLANK install and a LOADED re-seal) are single commits: a tear at any of their writes leaves the
 * card in the all-before state — the previous offer word and link key, the previous wallet (or
 * none) — and a torn peer-slot {@code setW} fails only the torn command, which a repeat completes.
 */
final class TransferTearTest {
    private static final int INS_CREATE = 0x21;
    private static final int INS_VERIFY = 0x22;
    private static final int INS_OFFER = 0x40;
    private static final int INS_EXPORT = 0x41;
    private static final int INS_IMPORT = 0x42;

    private static final class Side {
        final Card card;
        final byte[] a;
        final byte[] cert;
        Session session;

        Side() throws Exception {
            card = Vecs.factory();
            a = Vecs.cardA(card);
            cert = Vecs.certFor(a);
            Vecs.blankFor(card, a);
            session = Vecs.open(card);
        }

        Response inner(int ins, int p1, byte[] data) throws Exception {
            return Vecs.roundtrip(card, session, ins, p1, 0, data);
        }

        void powerUp() throws Exception {
            card.powerCycle();
            card.transmit(Spec.SELECT);
            session = Vecs.open(card);
        }

        byte[] create(byte[]... ids) throws Exception {
            byte[] data = new byte[96 + 16 * ids.length];
            System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
            System.arraycopy(Vecs.seed(), 0, data, 32, 64);
            for (int i = 0; i < ids.length; i++) {
                System.arraycopy(ids[i], 0, data, 96 + 16 * i, 16);
            }
            Response r = inner(INS_CREATE, 1, data);
            assertEquals(0x9000, r.sw(), "CREATE");
            return r.data();
        }

        byte[] offer() throws Exception {
            Response r = inner(INS_OFFER, 0, new byte[0]);
            assertEquals(0x9000, r.sw(), "OFFER");
            return r.data();
        }

        /**
         * The verified export pair to {@code target}'s current offer, sealed under {@code
         * accessHashT}.
         */
        byte[][] exportTo(Side target, byte[] accessHashT) throws Exception {
            assertEquals(0x9000, inner(INS_VERIFY, 0, Vecs.accessHash()).sw(), "VERIFY");
            byte[] data = new byte[226];
            System.arraycopy(target.cert, 0, data, 0, 97);
            System.arraycopy(target.offer(), 0, data, 97, 129);
            Response h = inner(INS_EXPORT, 0, data);
            assertEquals(0x9000, h.sw(), "EXPORT0");
            Response p = inner(INS_EXPORT, 1, accessHashT);
            assertEquals(0x9000, p.sw(), "EXPORT1");
            return new byte[][] {h.data(), p.data()};
        }

        byte[][] exportTo(Side target) throws Exception {
            return exportTo(target, Vecs.accessHashNew());
        }

        byte[] import0Data(Side source, byte[] head) {
            byte[] data = new byte[226];
            System.arraycopy(source.cert, 0, data, 0, 97);
            System.arraycopy(head, 0, data, 97, 129);
            return data;
        }
    }

    private static short word(Card card, short off) {
        return Util.getShort(Internals.stateArray(card.applet(Spec.WALLET_AID)), off);
    }

    private static boolean blank(Card card) {
        return word(card, State.OFF_LIFE) == Const.LIFE_BLANK;
    }

    /**
     * The complete persistent state of the wallet side of a card: the {@code state} array (life,
     * ct/tag/fp, origin, members, fails, offer), the {@code wrapKey} bytes and the link key pair.
     * Every write of T-OFFER/T-INSTALL precedes the commit, so the only reachable post-tear state
     * is the snapshot itself.
     */
    private static final class Snap {
        private final byte[] state;
        private final byte[] wrap;
        private final byte[] scalar;
        private final byte[] point;

        Snap(Card card) {
            javacard.framework.Applet applet = card.applet(Spec.WALLET_AID);
            state = Internals.stateArray(applet).clone();
            byte[] w = new byte[32];
            try {
                Internals.wrapKey(applet).getKey(w, (short) 0);
            } catch (javacard.security.CryptoException e) {
                w = null; // a BLANK card's wrapKey is not initialised
            }
            wrap = w;
            scalar = linkScalar(card);
            point = linkPoint(card);
        }

        /** Every persistent byte must be identical to the snapshot. */
        void assertIntact(Card card, String ctx) {
            javacard.framework.Applet applet = card.applet(Spec.WALLET_AID);
            assertArrayEquals(state, Internals.stateArray(applet), ctx + ": state array");
            byte[] w = new byte[32];
            try {
                Internals.wrapKey(applet).getKey(w, (short) 0);
            } catch (javacard.security.CryptoException e) {
                w = null;
            }
            assertArrayEquals(wrap, w, ctx + ": wrapKey");
            assertArrayEquals(scalar, linkScalar(card), ctx + ": link private scalar");
            assertArrayEquals(point, linkPoint(card), ctx + ": link public point");
        }
    }

    private static javacard.security.KeyPair linkPair(Card card) {
        return (javacard.security.KeyPair)
                getField(Internals.transfer(card.applet(Spec.WALLET_AID)), "linkKey");
    }

    /** The stored link private scalar, or {@code null} when the key is not initialised. */
    private static byte[] linkScalar(Card card) {
        byte[] out = new byte[32];
        try {
            ((javacard.security.ECPrivateKey) linkPair(card).getPrivate()).getS(out, (short) 0);
            return out;
        } catch (javacard.security.CryptoException e) {
            return null;
        }
    }

    /** The stored link public point, or {@code null} when the key is not initialised. */
    private static byte[] linkPoint(Card card) {
        byte[] out = new byte[65];
        try {
            ((javacard.security.ECPublicKey) linkPair(card).getPublic()).getW(out, (short) 0);
            return out;
        } catch (javacard.security.CryptoException e) {
            return null;
        }
    }

    private static Object getField(Object o, String name) {
        try {
            java.lang.reflect.Field f = o.getClass().getDeclaredField(name);
            f.setAccessible(true);
            return f.get(o);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void offerTearsAtomically() throws Exception {
        int n;
        {
            Side t = new Side();
            t.offer();
            n = t.card.writes();
        }
        for (int tear = 1; tear <= n; tear++) {
            Side t = new Side();
            Snap before = new Snap(t.card);
            t.card.tearAt(tear);
            assertThrows(TornException.class, () -> t.inner(INS_OFFER, 0, new byte[0]));
            t.powerUp();
            assertEquals(
                    Const.OFFER_NONE,
                    word(t.card, State.OFF_OFFER),
                    "tear " + tear + ": offer word must stay NONE");
            before.assertIntact(t.card, "tear " + tear);
            // the repeat OFFER installs a fresh pair normally
            byte[] offer = t.offer();
            assertTrue(t.card.writes() >= 1, "tear " + tear + ": the repeat commits T-OFFER");
            assertArrayEquals(
                    linkPoint(t.card),
                    Arrays.copyOf(offer, 65),
                    "tear " + tear + ": OFFER returns the stored link point");
            assertEquals(Const.OFFER_VALID, word(t.card, State.OFF_OFFER));
        }
    }

    @Test
    void installOnBlankTearsAtomically() throws Exception {
        Side t0 = new Side();
        Side s0 = new Side();
        s0.create(Ids.cardId(t0.a));
        byte[][] export = s0.exportTo(t0);
        int n;
        {
            assertEquals(0x9000, t0.inner(INS_IMPORT, 0, t0.import0Data(s0, export[0])).sw());
            assertEquals(0x9000, t0.inner(INS_IMPORT, 1, export[1]).sw());
            n = t0.card.writes();
        }
        for (int tear = 1; tear <= n; tear++) {
            Side t = new Side();
            Side s = new Side();
            s.create(Ids.cardId(t.a));
            byte[][] e = s.exportTo(t);
            assertEquals(0x9000, t.inner(INS_IMPORT, 0, t.import0Data(s, e[0])).sw());
            Snap before = new Snap(t.card);
            t.card.tearAt(tear);
            assertThrows(
                    TornException.class,
                    () -> t.card.transmit(t.session.wrap(INS_IMPORT, 1, 0, e[1])));
            t.powerUp();
            assertTrue(blank(t.card), "tear " + tear + ": T-INSTALL must not leave a mix");
            before.assertIntact(t.card, "tear " + tear);
            // a retried import works on the untouched card
            byte[][] e2 = s.exportTo(t);
            assertEquals(0x9000, t.inner(INS_IMPORT, 0, t.import0Data(s, e2[0])).sw());
            assertEquals(0x9000, t.inner(INS_IMPORT, 1, e2[1]).sw());
        }
    }

    @Test
    void installOnLoadedTearsAtomically() throws Exception {
        // the re-seal uses a different access hash than the first install so the torn
        // transaction's before/after states are distinguishable
        int n;
        {
            Side t = new Side();
            Side s = new Side();
            s.create(Ids.cardId(t.a));
            byte[][] e1 = s.exportTo(t, Vecs.accessHashNew());
            assertEquals(0x9000, t.inner(INS_IMPORT, 0, t.import0Data(s, e1[0])).sw());
            assertEquals(0x9000, t.inner(INS_IMPORT, 1, e1[1]).sw());
            byte[][] e2 = s.exportTo(t, Vecs.accessHash());
            assertEquals(0x9000, t.inner(INS_IMPORT, 0, t.import0Data(s, e2[0])).sw());
            assertEquals(0x9000, t.inner(INS_IMPORT, 1, e2[1]).sw());
            n = t.card.writes();
        }
        for (int tear = 1; tear <= n; tear++) {
            Side t = new Side();
            Side s = new Side();
            s.create(Ids.cardId(t.a));
            byte[][] e1 = s.exportTo(t, Vecs.accessHashNew());
            assertEquals(0x9000, t.inner(INS_IMPORT, 0, t.import0Data(s, e1[0])).sw());
            assertEquals(0x9000, t.inner(INS_IMPORT, 1, e1[1]).sw());
            byte[][] e2 = s.exportTo(t, Vecs.accessHash());
            assertEquals(0x9000, t.inner(INS_IMPORT, 0, t.import0Data(s, e2[0])).sw());
            Snap before = new Snap(t.card);
            t.card.tearAt(tear);
            assertThrows(
                    TornException.class,
                    () -> t.card.transmit(t.session.wrap(INS_IMPORT, 1, 0, e2[1])));
            t.powerUp();
            assertTrue(!blank(t.card), "tear " + tear + ": still LOADED");
            before.assertIntact(t.card, "tear " + tear);
            // the pre-re-seal wallet is intact: the old access hash verifies, the hash the
            // torn re-seal would have installed does not
            assertEquals(
                    0x9000,
                    t.inner(INS_VERIFY, 0, Vecs.accessHashNew()).sw(),
                    "tear " + tear + ": old hash");
            assertEquals(
                    0x63C9,
                    t.inner(INS_VERIFY, 0, Vecs.accessHash()).sw(),
                    "tear " + tear + ": new hash");
        }
    }

    @Test
    void tornPeerSlotWriteOnlyFailsThatCommand() throws Exception {
        Side t = new Side();
        Side s = new Side();
        s.create(Ids.cardId(t.a));
        t.offer();
        // measure the single peer-slot write of a clean IMPORT0
        byte[] head;
        {
            byte[][] e = s.exportTo(t);
            head = e[0];
            assertEquals(0x9000, t.inner(INS_IMPORT, 0, t.import0Data(s, head)).sw());
        }
        int n = t.card.writes();
        assertTrue(n <= 1, "IMPORT0 writes at most the peer slot");
        if (n == 0) {
            return; // the slot already held the point — nothing to tear
        }
        for (int tear = 1; tear <= n; tear++) {
            Side t2 = new Side();
            Side s2 = new Side();
            s2.create(Ids.cardId(t2.a));
            t2.offer();
            byte[][] e = s2.exportTo(t2);
            t2.card.tearAt(tear);
            assertThrows(
                    TornException.class,
                    () ->
                            t2.card.transmit(
                                    t2.session.wrap(INS_IMPORT, 0, 0, t2.import0Data(s2, e[0]))));
            t2.powerUp();
            // the repeat IMPORT0 completes and the payload installs
            assertEquals(
                    0x9000,
                    t2.inner(INS_IMPORT, 0, t2.import0Data(s2, e[0])).sw(),
                    "tear " + tear + ": repeat IMPORT0");
            assertEquals(0x9000, t2.inner(INS_IMPORT, 1, e[1]).sw(), "tear " + tear + ": IMPORT1");
        }
    }
}
