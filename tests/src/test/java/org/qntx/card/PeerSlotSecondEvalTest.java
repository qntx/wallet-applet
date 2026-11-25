// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.util.Arrays;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Transfer;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.tests.EmuMember;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The second evaluation's recomputed inputs of §16.2 item 4 (A3): {@code Transfer.recheckPeer}
 * re-reads the peer slot before {@code sig_T}/{@code sig_S} is trusted a second time, and {@code
 * hashM}/{@code transferKeys} feed the second evaluation its own TH slot — so a key or hash the
 * first evaluation used can never be replayed into the second.
 */
final class PeerSlotSecondEvalTest {
    private static final int INS_STATUS = 0x20;
    private static final int INS_CREATE = 0x21;
    private static final int INS_VERIFY = 0x22;
    private static final int INS_OFFER = 0x40;
    private static final int INS_EXPORT = 0x41;
    private static final int INS_IMPORT = 0x42;

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    private static BigInteger randomScalar() {
        BigInteger k;
        do {
            k = new BigInteger(256, Vecs.RND);
        } while (k.signum() == 0 || k.compareTo(Crypto.N) >= 0);
        return k;
    }

    private static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) {
            len += p.length;
        }
        byte[] out = new byte[len];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    private static int pending(Card card) {
        byte[] w = Internals.words(card.applet(Spec.WALLET_AID));
        int o = Internals.sessionOffset("O_PENDING");
        return ((w[o] & 0xFF) << 8) | (w[o + 1] & 0xFF);
    }

    /** A LOADED card with member {@code m} and a verified session. */
    private static Object[] loaded(EmuMember m) throws Exception {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        Vecs.blankFor(card, a);
        Session session = Vecs.open(card);
        byte[] create = new byte[96 + 16];
        System.arraycopy(Vecs.accessHash(), 0, create, 0, 32);
        System.arraycopy(Vecs.seed(), 0, create, 32, 64);
        System.arraycopy(m.cardId, 0, create, 96, 16);
        assertEquals(
                0x9000, Vecs.roundtrip(card, session, INS_CREATE, 1, 0, create).sw(), "CREATE");
        assertEquals(
                0x9000,
                Vecs.roundtrip(card, session, INS_VERIFY, 0, 0, Vecs.accessHash()).sw(),
                "VERIFY");
        return new Object[] {card, session};
    }

    // ── T3a: a preloaded attacker-known key in the slot ─────────────────────

    /**
     * Slot 0 holds a key the attacker knows — {@code 1·G} and a random {@code k·G} — and {@code
     * setPeer} is skipped: the first {@code sig_T} evaluation verifies under the preloaded key,
     * then {@code recheckPeer} compares the slot with the certificate point and faults.
     */
    @Test
    void exportRecheckPeerRefusesPreloadedKey() throws Exception {
        for (BigInteger k : new BigInteger[] {BigInteger.ONE, randomScalar()}) {
            EmuMember m = new EmuMember();
            Object[] f = loaded(m);
            Card card = (Card) f[0];
            Session session = (Session) f[1];
            Internals.setPeerW(card.applet(Spec.WALLET_AID), 0, Crypto.publicKey(k));

            // the offer the first evaluation accepts: sig_T made under the preloaded k
            byte[] lk = Crypto.publicKey(randomScalar());
            byte[] sigT = Crypto.sign(k, Crypto.sha256(Transfer.LABEL_OFFER, lk));
            byte[] cmd = concat(m.cert, lk, sigT);
            Response r;
            try {
                Fault.armSkip("Transfer.setPeer", 1);
                r = Vecs.roundtrip(card, session, INS_EXPORT, 0, 0, cmd);
            } finally {
                Fault.reset();
            }
            assertEquals(
                    0x6F00,
                    r.sw(),
                    () -> "EXPORT P1=00 with a preloaded slot: " + Integer.toHexString(r.sw()));
            assertEquals(0, pending(card), "a pending export survived the fault");
        }
    }

    /**
     * The IMPORT direction of {@link #exportRecheckPeerRefusesPreloadedKey}: on a BLANK card the
     * preloaded slot passes the first {@code sig_S} verification, and {@code recheckPeer} refuses
     * before the pending import keys exist.
     */
    @Test
    void importRecheckPeerRefusesPreloadedKey() throws Exception {
        for (BigInteger k : new BigInteger[] {BigInteger.ONE, randomScalar()}) {
            EmuMember s = new EmuMember();
            Card card = Vecs.factory();
            byte[] a = Vecs.cardA(card);
            Vecs.blankFor(card, a);
            Session session = Vecs.open(card);
            Response offer = Vecs.roundtrip(card, session, INS_OFFER, 0, 0, new byte[0]);
            assertEquals(0x9000, offer.sw(), "OFFER");
            byte[] lk = Arrays.copyOf(offer.data(), 65);
            Internals.setPeerW(card.applet(Spec.WALLET_AID), 0, Crypto.publicKey(k));

            byte[] e = Crypto.publicKey(randomScalar());
            byte[] msg = EmuMember.transcript(s.a, a, lk, e);
            byte[] sigS = Crypto.sign(k, Crypto.sha256(msg));
            byte[] cmd = concat(s.cert, e, sigS);
            Response r;
            try {
                Fault.armSkip("Transfer.setPeer", 1);
                r = Vecs.roundtrip(card, session, INS_IMPORT, 0, 0, cmd);
            } finally {
                Fault.reset();
            }
            assertEquals(
                    0x6F00,
                    r.sw(),
                    () -> "IMPORT P1=00 with a preloaded slot: " + Integer.toHexString(r.sw()));
            assertEquals(0, pending(card), "a pending import survived the fault");
        }
    }

    // ── T3b: the second hashM feeds the second evaluation ────────────────────

    /**
     * {@code hashM} evaluated twice in {@code import0}, each into its own TH slot: skipping the
     * first leaves a bad TH for the {@code 6A80} data check; skipping the second leaves TH' stale —
     * never the first evaluation's — and the recomputed {@code sig_S} check faults.
     */
    @Test
    void importSecondHashMIsItsOwn() throws Exception {
        EmuMember s = new EmuMember();
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        Vecs.blankFor(card, a);
        Session session = Vecs.open(card);
        Response offer = Vecs.roundtrip(card, session, INS_OFFER, 0, 0, new byte[0]);
        assertEquals(0x9000, offer.sw(), "OFFER");
        byte[] lk = Arrays.copyOf(offer.data(), 65);
        byte[][] head = s.importHead(a, lk);

        int calls;
        try {
            Fault.countCalls();
            Response ok = Vecs.roundtrip(card, session, INS_IMPORT, 0, 0, head[0]);
            assertEquals(0x9000, ok.sw(), "genuine IMPORT P1=00");
            calls = Fault.calls("Transfer.hashM");
        } finally {
            Fault.reset();
        }
        assertEquals(2, calls, "hashM evaluations per IMPORT P1=00");

        for (int i = 1; i <= 2; i++) {
            Card c2 = Vecs.factory();
            byte[] a2 = Vecs.cardA(c2);
            Vecs.blankFor(c2, a2);
            Session s2 = Vecs.open(c2);
            Response o2 = Vecs.roundtrip(c2, s2, INS_OFFER, 0, 0, new byte[0]);
            assertEquals(0x9000, o2.sw(), "OFFER " + i);
            byte[][] h2 = s.importHead(a2, Arrays.copyOf(o2.data(), 65));
            Response r;
            try {
                Fault.armSkip("Transfer.hashM", i);
                r = Vecs.roundtrip(c2, s2, INS_IMPORT, 0, 0, h2[0]);
            } finally {
                Fault.reset();
            }
            int eval = i;
            assertEquals(
                    eval == 1 ? 0x6A80 : 0x6F00,
                    r.sw(),
                    () -> "hashM eval " + eval + " skipped: " + Integer.toHexString(r.sw()));
            assertEquals(0, pending(c2), "eval " + i + " left a pending import");
        }
    }

    // ── T3c: forcing recheckPeer's internals still refuses ──────────────────

    /**
     * A forced failure inside {@code recheckPeer} — the {@code decompress} of the certificate point
     * or the slot {@code Bytes.equal} — is a detected disagreement, {@code 6F00} either way; the
     * second evaluation never inherits the first's verdict.
     */
    @Test
    void recheckPeerInternalsForced() throws Exception {
        EmuMember m = new EmuMember();
        // EXPORT0: decompress inside recheckPeer is the command's second decompress call
        for (int i = 1; i <= 2; i++) {
            Object[] f = loaded(m);
            Card card = (Card) f[0];
            Session session = (Session) f[1];
            byte[] cmd = m.exportRequest();
            Response r;
            try {
                Fault.arm("Secp256k1.decompress", i, Const.CHECK_FAIL);
                r = Vecs.roundtrip(card, session, INS_EXPORT, 0, 0, cmd);
            } finally {
                Fault.reset();
            }
            // eval 1: the staged point fails the data check (6A80); eval 2: recheckPeer (6F00)
            int eval = i;
            assertEquals(
                    eval == 1 ? 0x6A80 : 0x6F00,
                    r.sw(),
                    () -> "decompress " + eval + " forced: " + Integer.toHexString(r.sw()));
            assertEquals(0, pending(card), "decompress " + i + " left a pending export");
        }

        // IMPORT0 on a BLANK card: force the last Bytes.equal — the recheckPeer slot compare
        EmuMember s = new EmuMember();
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        Vecs.blankFor(card, a);
        Session session = Vecs.open(card);
        Response offer = Vecs.roundtrip(card, session, INS_OFFER, 0, 0, new byte[0]);
        assertEquals(0x9000, offer.sw(), "OFFER");
        byte[][] head = s.importHead(a, Arrays.copyOf(offer.data(), 65));
        int equals;
        try {
            Fault.countCalls();
            Response ok = Vecs.roundtrip(card, session, INS_IMPORT, 0, 0, head[0]);
            assertEquals(0x9000, ok.sw(), "genuine IMPORT P1=00");
            equals = Fault.calls("Bytes.equal");
        } finally {
            Fault.reset();
        }
        // rebuild the pending-import-free card for the faulted run
        Card c2 = Vecs.factory();
        byte[] a2 = Vecs.cardA(c2);
        Vecs.blankFor(c2, a2);
        Session s2 = Vecs.open(c2);
        Response o2 = Vecs.roundtrip(c2, s2, INS_OFFER, 0, 0, new byte[0]);
        assertEquals(0x9000, o2.sw(), "OFFER 2");
        byte[][] h2 = s.importHead(a2, Arrays.copyOf(o2.data(), 65));
        Response r;
        try {
            Fault.arm("Bytes.equal", equals, Const.CHECK_FAIL);
            r = Vecs.roundtrip(c2, s2, INS_IMPORT, 0, 0, h2[0]);
        } finally {
            Fault.reset();
        }
        assertEquals(
                0x6F00, r.sw(), () -> "last Bytes.equal forced: " + Integer.toHexString(r.sw()));
        assertEquals(0, pending(c2), "the forced equal left a pending import");
        // and the card is still BLANK — nothing was installed
        Session s3 = Vecs.open(c2);
        Response status = Vecs.roundtrip(c2, s3, INS_STATUS, 0, 0, new byte[0]);
        assertArrayEquals(new byte[] {0x01, 0x00}, status.data(), "card not BLANK after 6F00");
    }
}
