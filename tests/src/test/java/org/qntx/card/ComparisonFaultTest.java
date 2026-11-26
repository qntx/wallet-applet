// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Transfer;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.tests.EmuMember;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The §16.2 item-4/5 comparisons killed under PIT: every {@code Bytes.equal}/{@code
 * Bytes.isZero}/{@code Secp256k1.inRange} guard the fix added is armed through {@link Fault#arm} —
 * a method-keyed woven short call, stable under PIT's probes — so the check's own comparison is
 * forced to its refusing value and the command must answer {@code 6F00}. This complements {@link
 * DerivationFaultTest}, whose numbered instruction sites only exist under the {@code sites} weave
 * of {@code gateSweep}; these tests run under the plain weave and inside PIT.
 *
 * <p>Each test first counts the armed method's calls on the unfaulted command and arms the counted
 * index, so a reorder of the comparisons fails loudly instead of arming a different check.
 */
final class ComparisonFaultTest {

    private static final int INS_CREATE = 0x21;
    private static final int INS_VERIFY = 0x22;
    private static final int INS_CHANGE = 0x23;
    private static final int INS_EXPORT = 0x41;
    private static final int INS_IMPORT = 0x42;
    private static final int INS_OFFER = 0x40;
    private static final String EQUAL = "Bytes.equal";
    private static final String ISZERO = "Bytes.isZero";
    private static final String INRANGE = "Secp256k1.inRange";

    @AfterEach
    void disarm() {
        Fault.reset();
    }

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

        void create(byte[]... ids) throws Exception {
            byte[] data = new byte[96 + 16 * ids.length];
            System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
            System.arraycopy(Vecs.seed(), 0, data, 32, 64);
            for (int i = 0; i < ids.length; i++) {
                System.arraycopy(ids[i], 0, data, 96 + 16 * i, 16);
            }
            assertEquals(0x9000, inner(INS_CREATE, 1, data).sw(), "CREATE");
        }

        void verify() throws Exception {
            assertEquals(0x9000, inner(INS_VERIFY, 0, Vecs.accessHash()).sw(), "VERIFY");
        }

        /** A 6F00 tears the card session down: a fresh OPEN and, for a LOADED card, VERIFY. */
        void reopen(boolean andVerify) throws Exception {
            session = Vecs.open(card);
            if (andVerify) {
                verify();
            }
        }
    }

    private static Side loaded(EmuMember member) throws Exception {
        Side side = new Side();
        side.create(member.cardId);
        side.verify();
        return side;
    }

    private static int calls(String method, ThrowingRunnable run) throws Exception {
        Fault.countCalls();
        run.run();
        int n = Fault.calls(method);
        Fault.reset();
        return n;
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    /** SW of an armed run: {@code 6F00} whether the card answered it or the fault tore the session. */
    private static int sw(ThrowingIntSupplier r) throws Exception {
        try {
            return r.get();
        } catch (org.qntx.card.host.SessionBrokenException torn) {
            return 0x6F00;
        }
    }

    private interface ThrowingIntSupplier {
        int get() throws Exception;
    }

    private static Response open(Card card) throws Exception {
        byte[] rapdu = card.transmit(org.qntx.card.host.Open.request(Vecs.RND).apdu());
        return new Response(
                Arrays.copyOf(rapdu, rapdu.length - 2),
                ((rapdu[rapdu.length - 2] & 0xFF) << 8) | (rapdu[rapdu.length - 1] & 0xFF));
    }

    // ── Session.open: the second scalar check and the two key comparisons ────

    @Test
    void openInRangeForcedIsCaught() throws Exception {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        Vecs.blankFor(card, a);
        int n = calls(INRANGE, () -> assertEquals(0x9000, open(card).sw()));
        Fault.arm(INRANGE, n, Const.CHECK_FAIL);
        assertEquals(0x6F00, open(card).sw(), "forced inRange CHECK_FAIL");
    }

    @Test
    void openKeyComparesForcedAreCaught() throws Exception {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        Vecs.blankFor(card, a);
        int t = calls(EQUAL, () -> assertEquals(0x9000, open(card).sw()));
        for (int n : new int[] {t - 1, t}) {
            Fault.arm(EQUAL, n, Const.CHECK_FAIL);
            assertEquals(0x6F00, open(card).sw(), "forced Bytes.equal " + n + "/" + t);
            Fault.reset();
        }
    }

    // ── CREATE: zero checks and staged copies ────────────────────────────────

    @Test
    void createZeroChecksForcedAreCaught() throws Exception {
        // the drawn T is checked non-zero inside the (possibly repeated) draw loop and the
        // finished seed once more after it: force the first and the last Bytes.isZero call
        byte[] data = new byte[64];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.entropy(), 0, data, 32, 32);
        Card card = Vecs.factory();
        Vecs.blankFor(card, Vecs.cardA(card));
        Session session = Vecs.open(card);
        int z =
                calls(
                        ISZERO,
                        () ->
                                assertEquals(
                                        0x9000,
                                        Vecs.roundtrip(card, session, INS_CREATE, 0, 0, data)
                                                .sw()));
        int faults = 0;
        for (int n = 1; n <= z; n++) {
            // a CREATE can only run on a BLANK card: fresh one per armed run
            Card c2 = Vecs.factory();
            Vecs.blankFor(c2, Vecs.cardA(c2));
            Session s2 = Vecs.open(c2);
            Fault.arm(ISZERO, n, Const.CHECK_OK);
            int sw = sw(() -> Vecs.roundtrip(c2, s2, INS_CREATE, 0, 0, data).sw());
            Fault.reset();
            if (sw == 0x6F00) {
                faults++;
            }
        }
        // the drawn T's zero check in the draw loop and the seed's after it (§9.4, §16.2 item 4)
        assertTrue(
                faults >= 2,
                "expected at least two refusing Bytes.isZero evaluations of CREATE P1=00, got "
                        + faults);
    }

    @Test
    void createSeedCopiesForcedAreCaught() throws Exception {
        byte[] data = new byte[96 + 16];
        byte[] id = new EmuMember().cardId;
        {
            Card card = Vecs.factory();
            Vecs.blankFor(card, Vecs.cardA(card));
            Session session = Vecs.open(card);
            System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
            System.arraycopy(Vecs.seed(), 0, data, 32, 64);
            System.arraycopy(id, 0, data, 96, 16);
        }
        Card card = Vecs.factory();
        Vecs.blankFor(card, Vecs.cardA(card));
        Session session = Vecs.open(card);
        int t =
                calls(
                        EQUAL,
                        () ->
                                assertEquals(
                                        0x9000,
                                        Vecs.roundtrip(card, session, INS_CREATE, 1, 0, data)
                                                .sw()));
        int faults = 0;
        for (int n = 1; n <= t; n++) {
            Card c2 = Vecs.factory();
            Vecs.blankFor(c2, Vecs.cardA(c2));
            Session s2 = Vecs.open(c2);
            Fault.arm(EQUAL, n, Const.CHECK_FAIL);
            int sw = sw(() -> Vecs.roundtrip(c2, s2, INS_CREATE, 1, 0, data).sw());
            Fault.reset();
            if (sw != 0x6F00) {
                continue;
            }
            // the staged seed is wiped before the fault is thrown (§9.4): it must not survive
            assertTrue(
                    Arrays.equals(new byte[64], Internals.seedBytes(c2.applet(Spec.WALLET_AID))),
                    "seed left staged after the refused CREATE");
            faults++;
        }
        // the staged seed and access-hash copies are compared before install (§16.2 item 4)
        assertTrue(
                faults >= 2,
                "expected at least two refusing Bytes.equal evaluations of CREATE P1=01, got "
                        + faults);
    }

    // ── CHANGE: the staged access hash ───────────────────────────────────────

    @Test
    void changeStagedCopyForcedIsCaught() throws Exception {
        EmuMember member = new EmuMember();
        Side side = loaded(member);
        int t =
                calls(
                        EQUAL,
                        () ->
                                assertEquals(
                                        0x9000,
                                        side.inner(INS_CHANGE, 0, Vecs.accessHashNew()).sw()));
        Fault.arm(EQUAL, t, Const.CHECK_FAIL);
        assertEquals(0x6F00, sw(() -> side.inner(INS_CHANGE, 0, Vecs.accessHashNew()).sw()));
    }

    // ── EXPORT/IMPORT: the second scalar checks and the key comparisons ──────

    @Test
    void exportInRangeForcedIsCaught() throws Exception {
        EmuMember target = new EmuMember();
        Side source = loaded(target);
        int n =
                calls(
                        INRANGE,
                        () ->
                                assertEquals(
                                        0x9000,
                                        source.inner(INS_EXPORT, 0, target.exportRequest()).sw()));
        Fault.arm(INRANGE, n, Const.CHECK_FAIL);
        assertEquals(0x6F00, source.inner(INS_EXPORT, 0, target.exportRequest()).sw());
    }

    @Test
    void exportLoadKeysForcedAreCaught() throws Exception {
        for (int back = 1; back <= 2; back++) {
            EmuMember target = new EmuMember();
            Side source = loaded(target);
            int t =
                    calls(
                            EQUAL,
                            () ->
                                    assertEquals(
                                            0x9000,
                                            source.inner(INS_EXPORT, 0, target.exportRequest())
                                                    .sw()));
            Fault.arm(EQUAL, t - back + 1, Const.CHECK_FAIL);
            assertEquals(
                    0x6F00,
                    sw(() -> source.inner(INS_EXPORT, 0, target.exportRequest()).sw()),
                    "forced Bytes.equal " + (t - back + 1) + "/" + t);
            Fault.reset();
        }
    }

    @Test
    void export1StagedCopiesForcedAreCaught() throws Exception {
        EmuMember target = new EmuMember();
        Side source = loaded(target);
        assertEquals(0x9000, source.inner(INS_EXPORT, 0, target.exportRequest()).sw());
        int t =
                calls(
                        EQUAL,
                        () ->
                                assertEquals(
                                        0x9000,
                                        source.inner(INS_EXPORT, 1, Vecs.accessHashNew()).sw()));
        int faults = 0;
        for (int n = 1; n <= t; n++) {
            // each armed run needs the pending export its predecessor consumed
            assertEquals(0x9000, source.inner(INS_EXPORT, 0, target.exportRequest()).sw());
            Fault.arm(EQUAL, n, Const.CHECK_FAIL);
            int sw = sw(() -> source.inner(INS_EXPORT, 1, Vecs.accessHashNew()).sw());
            Fault.reset();
            source.reopen(true);
            if (sw == 0x6F00) {
                faults++;
            }
        }
        // the staged seed and access-hash copies are compared before sealing (§16.2 item 4)
        assertTrue(
                faults >= 2,
                "expected at least two refusing Bytes.equal evaluations of EXPORT P1=01, got "
                        + faults);
    }

    @Test
    void importInRangeForcedIsCaught() throws Exception {
        EmuMember source = new EmuMember();
        Side target = new Side();
        byte[] offer = target.inner(INS_OFFER, 0, new byte[0]).data();
        byte[] lk = Arrays.copyOf(offer, 65);
        byte[][] head = source.importHead(target.a, lk);
        int n =
                calls(
                        INRANGE,
                        () -> assertEquals(0x9000, target.inner(INS_IMPORT, 0, head[0]).sw()));
        Fault.arm(INRANGE, n, Const.CHECK_FAIL);
        assertEquals(0x6F00, target.inner(INS_IMPORT, 0, head[0]).sw());
    }

    // ── Wallet.install (IMPORT P1=01): the staged payload copies ─────────────

    @Test
    void installStagedCopiesForcedAreCaught() throws Exception {
        EmuMember source = new EmuMember();
        Side target = loaded(source);
        target.reopen(false);
        byte[] offer = target.inner(INS_OFFER, 0, new byte[0]).data();
        byte[] lk = Arrays.copyOf(offer, 65);
        byte[][] head = source.importHead(target.a, lk);
        assertEquals(0x9000, target.inner(INS_IMPORT, 0, head[0]).sw(), "IMPORT0");
        byte[] z = EmuMember.ecdhX(new java.math.BigInteger(1, head[1]), lk);
        byte[] m =
                EmuMember.transcript(
                        source.a, target.a, lk, Arrays.copyOfRange(head[0], 97, 162));
        byte[] payload =
                EmuMember.payload(
                        0x02,
                        Vecs.seed(),
                        Vecs.accessHash(),
                        Ids.cardId(target.a),
                        source.cardId);
        byte[] record = EmuMember.sealRecord(z, m, payload);
        int t =
                calls(
                        EQUAL,
                        () ->
                                assertEquals(
                                        0x9000,
                                        target.inner(INS_IMPORT, 1, Transfer.import1(record))
                                                .sw(),
                                        "IMPORT1"));
        int faults = 0;
        for (int n = 1; n <= t; n++) {
            // each armed run needs a fresh offer and the pending import its predecessor used
            offer = target.inner(INS_OFFER, 0, new byte[0]).data();
            head = source.importHead(target.a, Arrays.copyOf(offer, 65));
            assertEquals(0x9000, target.inner(INS_IMPORT, 0, head[0]).sw(), "IMPORT0");
            Fault.arm(EQUAL, n, Const.CHECK_FAIL);
            int sw = sw(() -> target.inner(INS_IMPORT, 1, Transfer.import1(record)).sw());
            Fault.reset();
            target.reopen(false);
            if (sw == 0x6F00) {
                faults++;
            }
        }
        // the staged seed and access-hash copies are compared before install (§16.2 item 4)
        assertTrue(
                faults >= 2,
                "expected at least two refusing Bytes.equal evaluations of IMPORT P1=01, got "
                        + faults);
    }

    // ── Session words and range helpers: direct (Internals) checks ───────────

    private static ISOException fault(ThrowingRunnable r) {
        try {
            r.run();
        } catch (ISOException e) {
            return e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        throw new AssertionError("no ISOException");
    }

    @Test
    void corruptPendingWordIsCaught() throws Exception {
        Side side = new Side();
        byte[] words = Internals.words(side.card.applet(Spec.WALLET_AID));
        Util.setShort(words, (short) Internals.sessionOffset("O_PENDING"), (short) 0xBEEF);
        ISOException e =
                fault(
                        () ->
                                Internals.invoke(
                                        Internals.session(side.card.applet(Spec.WALLET_AID)),
                                        "pending",
                                        new Class[0]));
        assertEquals(0x6F00, e.getReason() & 0xFFFF);
    }

    @Test
    void corruptPendingShadowIsCaught() throws Exception {
        Side side = new Side();
        byte[] words = Internals.words(side.card.applet(Spec.WALLET_AID));
        Util.setShort(words, (short) Internals.sessionOffset("O_PENDING_SHADOW"), (short) 0xBEEF);
        ISOException e =
                fault(
                        () ->
                                Internals.invoke(
                                        Internals.session(side.card.applet(Spec.WALLET_AID)),
                                        "pendingExportShadow",
                                        new Class[0]));
        assertEquals(0x6F00, e.getReason() & 0xFFFF);
    }

    @Test
    void txDepthInsideTransactionIsOne() throws Exception {
        Side side = new Side();
        JCSystem.beginTransaction();
        try {
            Object d =
                    Internals.invoke(
                            Internals.session(side.card.applet(Spec.WALLET_AID)),
                            "txDepth",
                            new Class[0]);
            assertEquals(1, ((Number) d).intValue(), "transaction depth inside a transaction");
        } finally {
            JCSystem.abortTransaction();
        }
    }

    @Test
    void countRangeRefusesOutsideTwoThree() throws Exception {
        Side side = new Side();
        Object transfer = Internals.transfer(side.card.applet(Spec.WALLET_AID));
        for (short c : new short[] {0, 1, 4, 8}) {
            ISOException e =
                    fault(
                            () ->
                                    Internals.invoke(
                                            transfer, "countRange", new Class[] {short.class}, c));
            assertEquals(
                    0x6A80, e.getReason() & 0xFFFF, "countRange(" + c + ") must refuse");
        }
        for (short c : new short[] {2, 3}) {
            Object r =
                    Internals.invoke(transfer, "countRange", new Class[] {short.class}, c);
            assertEquals(c, ((Number) r).shortValue());
        }
    }
}
