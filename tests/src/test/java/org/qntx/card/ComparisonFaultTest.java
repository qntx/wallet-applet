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
import org.qntx.card.host.Certificates;
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
    private static final String AGREE = "Secp256k1.agree";

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

    /**
     * SW of an armed run: {@code 6F00} whether the card answered it or the fault tore the session.
     */
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

    /**
     * Arms every call of {@code method} in turn and records the resulting status word; the map is
     * asserted literally so a removed guard — which makes its own armed call a no-op — shifts the
     * refusing indices and fails.
     */
    private static java.util.Map<Integer, Integer> sws(
            String method, int occurrences, short value, ThrowingIntSupplier command)
            throws Exception {
        java.util.Map<Integer, Integer> map = new java.util.TreeMap<>();
        for (int n = 1; n <= occurrences; n++) {
            Fault.arm(method, n, value);
            map.put(n, sw(command));
            Fault.reset();
        }
        return map;
    }

    // ── Session.open: the second scalar check and the two key comparisons ────

    @Test
    void openInRangeForcedIsCaught() throws Exception {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        Vecs.blankFor(card, a);
        int n = calls(INRANGE, () -> assertEquals(0x9000, open(card).sw()));
        java.util.Map<Integer, Integer> map =
                sws(INRANGE, n, Const.CHECK_FAIL, () -> open(card).sw());
        assertEquals("{1=28416, 2=28416, 3=28416}", map.toString(), "open inRange");
    }

    @Test
    void openKeyComparesForcedAreCaught() throws Exception {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        Vecs.blankFor(card, a);
        int t = calls(EQUAL, () -> assertEquals(0x9000, open(card).sw()));
        java.util.Map<Integer, Integer> map =
                sws(EQUAL, t, Const.CHECK_FAIL, () -> open(card).sw());
        assertEquals("{1=28416, 2=28416}", map.toString(), "open equal");
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
        // a CREATE can only run on a BLANK card: fresh one per armed run, built unfaulted so
        // the setup's own isZero calls do not consume the armed index
        java.util.Map<Integer, Integer> map = new java.util.TreeMap<>();
        for (int n = 1; n <= z; n++) {
            Card c2 = Vecs.factory();
            Vecs.blankFor(c2, Vecs.cardA(c2));
            Session s2 = Vecs.open(c2);
            Fault.arm(ISZERO, n, Const.CHECK_OK);
            map.put(n, sw(() -> Vecs.roundtrip(c2, s2, INS_CREATE, 0, 0, data).sw()));
            Fault.reset();
        }
        // the drawn T's zero check in the draw loop and the seed's after it (§9.4, §16.2 item 4)
        assertEquals("{1=28416, 2=36864, 3=28416, 4=28416}", map.toString(), "create0 isZero");
    }

    @Test
    void createSeedHashesForcedAreCaught() throws Exception {
        // the twice-computed seed is compared inside the draw loop and the staged access
        // hash once more before install (§16.2 item 4): force each Bytes.equal call
        byte[] data = new byte[64];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.entropy(), 0, data, 32, 32);
        Card card = Vecs.factory();
        Vecs.blankFor(card, Vecs.cardA(card));
        Session session = Vecs.open(card);
        int t =
                calls(
                        EQUAL,
                        () ->
                                assertEquals(
                                        0x9000,
                                        Vecs.roundtrip(card, session, INS_CREATE, 0, 0, data)
                                                .sw()));
        java.util.Map<Integer, Integer> map = new java.util.TreeMap<>();
        for (int n = 1; n <= t; n++) {
            Card c2 = Vecs.factory();
            Vecs.blankFor(c2, Vecs.cardA(c2));
            Session s2 = Vecs.open(c2);
            Fault.arm(EQUAL, n, Const.CHECK_FAIL);
            map.put(n, sw(() -> Vecs.roundtrip(c2, s2, INS_CREATE, 0, 0, data).sw()));
            Fault.reset();
        }
        assertEquals("{1=28416, 2=28416, 3=28416, 4=28416}", map.toString(), "create0 equal");
    }

    /**
     * The draw loop's {@code Bytes.wipe(W_T)} before {@code nextBytes} is a counted call: a
     * mutation that drops it leaves the seed the draw produced identical, so the only
     * observable is the call count itself.
     */
    @Test
    void createDrawWipeIsCounted() throws Exception {
        byte[] data = new byte[64];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.entropy(), 0, data, 32, 32);
        Card card = Vecs.factory();
        Vecs.blankFor(card, Vecs.cardA(card));
        Session session = Vecs.open(card);
        int w =
                calls(
                        "Bytes.wipe",
                        () ->
                                assertEquals(
                                        0x9000,
                                        Vecs.roundtrip(card, session, INS_CREATE, 0, 0, data)
                                                .sw()));
        assertEquals(8, w, "create0 Bytes.wipe calls");
    }

    /**
     * The staged-seed wipe on the compare-fail path: the same fault is armed as in {@link
     * #createSeedCopiesForcedAreCaught} and the {@code Bytes.wipe} count is asserted — the
     * teardown wipe lands the same under the mutation, so the count is what separates them.
     */
    @Test
    void createStagedSeedWipeIsCounted() throws Exception {
        byte[] data = new byte[96 + 16];
        byte[] id = new EmuMember().cardId;
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        System.arraycopy(id, 0, data, 96, 16);
        Card card = Vecs.factory();
        Vecs.blankFor(card, Vecs.cardA(card));
        Session s2 = Vecs.open(card);
        // n = 1 is the staged-seed compare (the first Bytes.equal of CREATE P1=01)
        Fault.countCalls();
        Fault.arm(EQUAL, 1, Const.CHECK_FAIL);
        int sw = sw(() -> Vecs.roundtrip(card, s2, INS_CREATE, 1, 0, data).sw());
        assertEquals(0x6F00, sw, "forced staged-seed compare");
        assertEquals(10, Fault.calls("Bytes.wipe"), "create1 Bytes.wipe calls");
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
        java.util.Map<Integer, Integer> map = new java.util.TreeMap<>();
        for (int n = 1; n <= t; n++) {
            Card c2 = Vecs.factory();
            Vecs.blankFor(c2, Vecs.cardA(c2));
            Session s2 = Vecs.open(c2);
            Fault.arm(EQUAL, n, Const.CHECK_FAIL);
            int sw = sw(() -> Vecs.roundtrip(c2, s2, INS_CREATE, 1, 0, data).sw());
            Fault.reset();
            map.put(n, sw);
            if (sw != 0x6F00) {
                continue;
            }
            // the staged seed is wiped before the fault is thrown (§9.4): it must not survive
            assertTrue(
                    Arrays.equals(new byte[64], Internals.seedBytes(c2.applet(Spec.WALLET_AID))),
                    "seed left staged after the refused CREATE");
        }
        // the staged seed and access-hash copies are compared before install (§16.2 item 4)
        assertEquals(
                "{1=28416, 2=28416, 3=36864, 4=28416, 5=28416}", map.toString(), "create1 equal");
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
        java.util.Map<Integer, Integer> map = new java.util.TreeMap<>();
        for (int n = 1; n <= t; n++) {
            // a benignly forced nth lets the CHANGE succeed and moves the access hash: fresh card
            Side s2 = loaded(member);
            Fault.arm(EQUAL, n, Const.CHECK_FAIL);
            map.put(n, sw(() -> s2.inner(INS_CHANGE, 0, Vecs.accessHashNew()).sw()));
            Fault.reset();
        }
        assertEquals("{1=28416, 2=28416, 3=28416}", map.toString(), "change equal");
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
        java.util.Map<Integer, Integer> map = new java.util.TreeMap<>();
        for (int k = 1; k <= n; k++) {
            Fault.arm(INRANGE, k, Const.CHECK_FAIL);
            map.put(k, sw(() -> source.inner(INS_EXPORT, 0, target.exportRequest()).sw()));
            Fault.reset();
            source.reopen(true);
        }
        assertEquals(
                "{1=27264, 2=27264, 3=27264, 4=27264, 5=28416, 6=28416, 7=28416, 8=28416, 9=28416, 10=28416, 11=28416}",
                map.toString(),
                "export0 inRange");
    }

    @Test
    void exportLoadKeysForcedAreCaught() throws Exception {
        EmuMember target = new EmuMember();
        Side source = loaded(target);
        int t =
                calls(
                        EQUAL,
                        () ->
                                assertEquals(
                                        0x9000,
                                        source.inner(INS_EXPORT, 0, target.exportRequest()).sw()));
        java.util.Map<Integer, Integer> map = new java.util.TreeMap<>();
        for (int n = 1; n <= t; n++) {
            Fault.arm(EQUAL, n, Const.CHECK_FAIL);
            map.put(n, sw(() -> source.inner(INS_EXPORT, 0, target.exportRequest()).sw()));
            Fault.reset();
            source.reopen(true);
        }
        assertEquals(
                "{1=28416, 2=28416, 3=36864, 4=28416, 5=36864, 6=36864, 7=27264, 8=27264, 9=36864, 10=28416, 11=36864, 12=36864, 13=27264, 14=28416, 15=28416, 16=28416, 17=28416}",
                map.toString(),
                "export0 equal");
    }

    /**
     * An export request naming the source's own identity is refused by the {@code A != A} check of
     * §9.13 step 2; forcing that compare lets the request through so {@code memberSlot} still has
     * to reject the self-export — without the {@code self == found} check the offer signature then
     * fails with 6A80 instead. The session's tag compare takes the first two {@code Bytes.equal}
     * calls of every command, so the certificate compare is the third.
     */
    @Test
    void memberSlotSelfExportIsFault() throws Exception {
        EmuMember target = new EmuMember();
        Side source = loaded(target);
        byte[] selfCert = Certificates.issue(Vecs.caPrivate(), source.a);
        byte[] offer = target.newOffer();
        byte[] request = new byte[selfCert.length + offer.length];
        System.arraycopy(selfCert, 0, request, 0, selfCert.length);
        System.arraycopy(offer, 0, request, selfCert.length, offer.length);
        Fault.arm(EQUAL, 3, Const.CHECK_FAIL);
        try {
            assertEquals(
                    Const.SW_FAULT,
                    sw(() -> source.inner(INS_EXPORT, 0, request).sw()),
                    "self export");
        } finally {
            Fault.reset();
            source.reopen(true);
        }
    }

    /** Forcing {@code memberSlot}'s candidate check at self's index makes {@code self == found}. */
    @Test
    void memberSlotSelfIsFault() throws Exception {
        EmuMember target = new EmuMember();
        Side source = loaded(target);
        int t =
                calls(
                        EQUAL,
                        () ->
                                assertEquals(
                                        0x9000,
                                        source.inner(INS_EXPORT, 0, target.exportRequest()).sw()));
        java.util.Map<Integer, Integer> map = new java.util.TreeMap<>();
        for (int n = 1; n <= t; n++) {
            Fault.arm(EQUAL, n, Const.CHECK_OK);
            map.put(n, sw(() -> source.inner(INS_EXPORT, 0, target.exportRequest()).sw()));
            Fault.reset();
            source.reopen(true);
        }
        // CHECK_OK at self's P_CAND call yields self == found → 6F00; memberSlot runs twice
        assertEquals(
                "{1=36864, 2=36864, 3=27264, 4=36864, 5=36864, 6=28416, 7=36864, 8=36864, 9=36864, 10=36864, 11=36864, 12=28416, 13=36864, 14=36864, 15=36864, 16=36864, 17=36864}",
                map.toString(),
                "export0 memberSlot");
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
        java.util.Map<Integer, Integer> map = new java.util.TreeMap<>();
        for (int n = 1; n <= t; n++) {
            // each armed run needs the pending export its predecessor consumed
            assertEquals(0x9000, source.inner(INS_EXPORT, 0, target.exportRequest()).sw());
            Fault.arm(EQUAL, n, Const.CHECK_FAIL);
            int sw = sw(() -> source.inner(INS_EXPORT, 1, Vecs.accessHashNew()).sw());
            Fault.reset();
            map.put(n, sw);
            source.reopen(true);
        }
        // the staged seed and access-hash copies are compared before sealing (§16.2 item 4)
        assertEquals("{1=28416, 2=28416, 3=28416, 4=28416}", map.toString(), "export1 equal");
    }

    @Test
    void importInRangeForcedIsCaught() throws Exception {
        EmuMember source = new EmuMember();
        Side target = new Side();
        byte[] offer = target.inner(INS_OFFER, 0, new byte[0]).data();
        byte[] lk = Arrays.copyOf(offer, 65);
        byte[][] head = source.importHead(target.a, lk);
        byte[][] first = head;
        int n =
                calls(
                        INRANGE,
                        () -> assertEquals(0x9000, target.inner(INS_IMPORT, 0, first[0]).sw()));
        java.util.Map<Integer, Integer> map = new java.util.TreeMap<>();
        for (int k = 1; k <= n; k++) {
            // each armed run needs the pending import a fresh OFFER created
            offer = target.inner(INS_OFFER, 0, new byte[0]).data();
            head = source.importHead(target.a, Arrays.copyOf(offer, 65));
            byte[][] imp = head;
            Fault.arm(INRANGE, k, Const.CHECK_FAIL);
            map.put(k, sw(() -> target.inner(INS_IMPORT, 0, imp[0]).sw()));
            Fault.reset();
            target.reopen(false);
        }
        assertEquals(
                "{1=27264, 2=27264, 3=28416, 4=28416, 5=27264, 6=27264, 7=28416, 8=28416}",
                map.toString(),
                "import0 inRange");
    }

    /** The double {@code secp.agree} products of IMPORT P1=00 (§16.2 item 4) refuse when forced. */
    @Test
    void importAgreeChecksForcedAreCaught() throws Exception {
        EmuMember source = new EmuMember();
        Side target = new Side();
        byte[] offer = target.inner(INS_OFFER, 0, new byte[0]).data();
        byte[] lk = Arrays.copyOf(offer, 65);
        byte[][] head = source.importHead(target.a, lk);
        byte[][] first = head;
        int n =
                calls(
                        AGREE,
                        () -> assertEquals(0x9000, target.inner(INS_IMPORT, 0, first[0]).sw()));
        java.util.Map<Integer, Integer> map = new java.util.TreeMap<>();
        for (int k = 1; k <= n; k++) {
            offer = target.inner(INS_OFFER, 0, new byte[0]).data();
            head = source.importHead(target.a, Arrays.copyOf(offer, 65));
            byte[][] imp = head;
            Fault.arm(AGREE, k, Const.CHECK_FAIL);
            map.put(k, sw(() -> target.inner(INS_IMPORT, 0, imp[0]).sw()));
            Fault.reset();
            target.reopen(false);
        }
        assertEquals("{1=28416, 2=28416}", map.toString(), "import0 agree");
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
                EmuMember.transcript(source.a, target.a, lk, Arrays.copyOfRange(head[0], 97, 162));
        byte[] payload =
                EmuMember.payload(
                        0x02, Vecs.seed(), Vecs.accessHash(), Ids.cardId(target.a), source.cardId);
        byte[] record = EmuMember.sealRecord(z, m, payload);
        byte[] first = record;
        int t =
                calls(
                        EQUAL,
                        () ->
                                assertEquals(
                                        0x9000,
                                        target.inner(INS_IMPORT, 1, Transfer.import1(first)).sw(),
                                        "IMPORT1"));
        java.util.Map<Integer, Integer> map = new java.util.TreeMap<>();
        for (int n = 1; n <= t; n++) {
            // each armed run needs a fresh offer, the pending import its predecessor used and
            // a record sealed under THIS offer's transcript — a stale record dies at the MAC
            // and never reaches the staged compares
            offer = target.inner(INS_OFFER, 0, new byte[0]).data();
            lk = Arrays.copyOf(offer, 65);
            head = source.importHead(target.a, lk);
            assertEquals(0x9000, target.inner(INS_IMPORT, 0, head[0]).sw(), "IMPORT0");
            z = EmuMember.ecdhX(new java.math.BigInteger(1, head[1]), lk);
            m = EmuMember.transcript(source.a, target.a, lk, Arrays.copyOfRange(head[0], 97, 162));
            record = EmuMember.sealRecord(z, m, payload);
            byte[] rec = record;
            Fault.arm(EQUAL, n, Const.CHECK_FAIL);
            int sw = sw(() -> target.inner(INS_IMPORT, 1, Transfer.import1(rec)).sw());
            Fault.reset();
            map.put(n, sw);
            target.reopen(false);
        }
        // the staged seed and access-hash copies are compared before install (§16.2 item 4)
        assertEquals(
                "{1=28416, 2=28416, 3=27264, 4=28416, 5=36864, 6=27264, 7=36864, 8=36864, 9=27264, 10=27264, 11=27264, 12=28416, 13=28416, 14=28416, 15=28416, 16=28416, 17=28416}",
                map.toString(),
                "import1 equal");
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
            assertEquals(0x6A80, e.getReason() & 0xFFFF, "countRange(" + c + ") must refuse");
        }
        for (short c : new short[] {2, 3}) {
            Object r = Internals.invoke(transfer, "countRange", new Class[] {short.class}, c);
            assertEquals(c, ((Number) r).shortValue());
        }
    }
}
