// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * Fail-closed fuzzing of the transfer commands in the style of {@code
 * RecordTest.fuzzRandomRecordsFailClosed}: random single-byte and random-length mutations of valid
 * OFFER/EXPORT/IMPORT data. A mutated input is never accepted ({@code EXPORT P1=0x01}'s opaque
 * access-hash argument excepted — any 32-byte value is by definition a fresh hash), never faults
 * {@code 6F00}, and never produces a persistent write beyond the single allowed peer-slot {@code
 * setW}. Case count: {@code -Dqntx.fuzz=N}, a small default under PIT.
 */
final class TransferFuzzTest {
    private static final int CASES = Integer.getInteger("qntx.fuzz", 2000);

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

        byte[] offer() throws Exception {
            Response r = inner(INS_OFFER, 0, new byte[0]);
            assertEquals(0x9000, r.sw(), "OFFER");
            return r.data();
        }
    }

    /** A mutation of {@code base}: a flipped byte, a changed length or a replaced byte. */
    private static byte[] mutate(byte[] base) {
        switch (Vecs.RND.nextInt(3)) {
            case 0 -> {
                byte[] m = base.clone();
                m[Vecs.RND.nextInt(m.length)] ^= (byte) (1 << Vecs.RND.nextInt(8));
                return m;
            }
            case 1 -> {
                // session records carry at most 236 bytes
                int len = 1 + Vecs.RND.nextInt(Math.min(base.length + 16, 235));
                byte[] m = new byte[len];
                System.arraycopy(base, 0, m, 0, Math.min(len, base.length));
                if (len > base.length) {
                    Vecs.RND.nextBytes(Arrays.copyOfRange(m, base.length, len));
                }
                if (Arrays.equals(m, base)) {
                    m[m.length - 1] ^= 1;
                }
                return m;
            }
            default -> {
                byte[] m = base.clone();
                m[Vecs.RND.nextInt(m.length)] = (byte) Vecs.RND.nextInt(256);
                if (Arrays.equals(m, base)) {
                    m[0] ^= 1;
                }
                return m;
            }
        }
    }

    private static void assertRefusal(Card card, int sw, String what) {
        assertNotEquals(0x9000, sw, what + " accepted a mutation");
        assertNotEquals(0x6F00, sw, what + " faulted");
        assertTrue(card.writes() <= 1, what + " wrote beyond the peer slot");
    }

    private static byte[] state(Card card) {
        return Internals.stateArray(card.applet(Spec.WALLET_AID));
    }

    private static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] part : parts) {
            len += part.length;
        }
        byte[] out = new byte[len];
        int off = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, off, part.length);
            off += part.length;
        }
        return out;
    }

    @Test
    void offerMutationsFailClosed() throws Exception {
        Side t = new Side();
        for (int i = 0; i < CASES; i++) {
            byte[] data = new byte[1 + Vecs.RND.nextInt(40)];
            Vecs.RND.nextBytes(data);
            Response r = t.inner(INS_OFFER, 0, data);
            assertNotEquals(0x9000, r.sw(), "OFFER with " + data.length + " data bytes");
            assertNotEquals(0x6F00, r.sw(), "OFFER faulted");
            assertEquals(0, t.card.writes(), "OFFER with data wrote");
            // the valid empty OFFER still works and arms the offer
            assertEquals(0x9000, t.inner(INS_OFFER, 0, new byte[0]).sw());
        }
    }

    @Test
    void export0MutationsFailClosed() throws Exception {
        Side s = new Side();
        Side t = new Side();
        byte[] create = new byte[96 + 16];
        System.arraycopy(Vecs.accessHash(), 0, create, 0, 32);
        System.arraycopy(Vecs.seed(), 0, create, 32, 64);
        System.arraycopy(Ids.cardId(t.a), 0, create, 96, 16);
        assertEquals(0x9000, s.inner(INS_CREATE, 1, create).sw());
        assertEquals(0x9000, s.inner(INS_VERIFY, 0, Vecs.accessHash()).sw());
        byte[] offer = t.offer();
        byte[] good = concat(t.cert, offer);
        assertEquals(0x9000, s.inner(INS_EXPORT, 0, good).sw(), "the unmutated input");
        for (int i = 0; i < CASES; i++) {
            byte[] m = mutate(good);
            Response r = s.inner(INS_EXPORT, 0, m);
            assertRefusal(s.card, r.sw(), "EXPORT0 case " + i);
        }
    }

    @Test
    void export1MutationsFailClosed() throws Exception {
        Side s = new Side();
        Side t = new Side();
        byte[] create = new byte[96 + 16];
        System.arraycopy(Vecs.accessHash(), 0, create, 0, 32);
        System.arraycopy(Vecs.seed(), 0, create, 32, 64);
        System.arraycopy(Ids.cardId(t.a), 0, create, 96, 16);
        assertEquals(0x9000, s.inner(INS_CREATE, 1, create).sw());
        assertEquals(0x9000, s.inner(INS_VERIFY, 0, Vecs.accessHash()).sw());
        byte[] good = Vecs.accessHashNew();
        for (int i = 0; i < CASES; i++) {
            // arm a fresh pending export for every case: mutations of the access hash are
            // opaque and still succeed; only the length can reject
            byte[] head = concat(t.cert, t.offer());
            assertEquals(0x9000, s.inner(INS_EXPORT, 0, head).sw());
            byte[] m = mutate(good);
            Response r = s.inner(INS_EXPORT, 1, m);
            assertNotEquals(0x6F00, r.sw(), "EXPORT1 case " + i + " faulted");
            if (m.length != 32) {
                assertNotEquals(0x9000, r.sw(), "EXPORT1 case " + i + " wrong length");
            }
            assertEquals(0, s.card.writes(), "EXPORT1 case " + i + " wrote");
        }
    }

    @Test
    void import0MutationsFailClosed() throws Exception {
        Side s = new Side();
        Side t = new Side();
        byte[] create = new byte[96 + 16];
        System.arraycopy(Vecs.accessHash(), 0, create, 0, 32);
        System.arraycopy(Vecs.seed(), 0, create, 32, 64);
        System.arraycopy(Ids.cardId(t.a), 0, create, 96, 16);
        assertEquals(0x9000, s.inner(INS_CREATE, 1, create).sw());
        assertEquals(0x9000, s.inner(INS_VERIFY, 0, Vecs.accessHash()).sw());
        byte[] head = s.inner(INS_EXPORT, 0, concat(t.cert, t.offer())).data();
        byte[] good = concat(s.cert, head);
        byte[] before = state(t.card).clone();
        for (int i = 0; i < CASES; i++) {
            byte[] m = mutate(good);
            Response r = t.inner(INS_IMPORT, 0, m);
            assertRefusal(t.card, r.sw(), "IMPORT0 case " + i);
            assertArrayEquals(before, state(t.card), "IMPORT0 case " + i + " changed state");
        }
    }

    @Test
    void import1MutationsFailClosed() throws Exception {
        Side s = new Side();
        Side t = new Side();
        byte[] create = new byte[96 + 16];
        System.arraycopy(Vecs.accessHash(), 0, create, 0, 32);
        System.arraycopy(Vecs.seed(), 0, create, 32, 64);
        System.arraycopy(Ids.cardId(t.a), 0, create, 96, 16);
        assertEquals(0x9000, s.inner(INS_CREATE, 1, create).sw());
        assertEquals(0x9000, s.inner(INS_VERIFY, 0, Vecs.accessHash()).sw());
        byte[] head = s.inner(INS_EXPORT, 0, concat(t.cert, t.offer())).data();
        byte[] payload = s.inner(INS_EXPORT, 1, Vecs.accessHashNew()).data();
        byte[] import0 = concat(s.cert, head);
        byte[] before = state(t.card).clone();
        for (int i = 0; i < CASES; i++) {
            assertEquals(0x9000, t.inner(INS_IMPORT, 0, import0).sw(), "arm " + i);
            byte[] m = mutate(payload);
            Response r = t.inner(INS_IMPORT, 1, m);
            assertRefusal(t.card, r.sw(), "IMPORT1 case " + i);
            assertArrayEquals(before, state(t.card), "IMPORT1 case " + i + " installed");
        }
    }
}
