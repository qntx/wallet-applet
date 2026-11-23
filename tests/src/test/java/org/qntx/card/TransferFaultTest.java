// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.SessionBrokenException;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * Fault mutants of the transfer guards (architecture §9 T3, §16.2 item 4; h2 brief item 11): {@link
 * Fault#arm}/{@link Fault#armSkip} force every single evaluation of the certificate and membership
 * results in EXPORT0, of the certificate and membership guarding the peer-slot write in IMPORT0, of
 * the stored MAC, the life guard and the three LOADED equality checks in IMPORT1, of the verified
 * guard in EXPORT1 and of the life guard and commit read-back of OFFER. Each forced evaluation must
 * end in {@code 6F00}/{@code 6A80} — never a T-INSTALL, never a payload, never a committed T-OFFER.
 */
final class TransferFaultTest {
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

        void verify() throws Exception {
            assertEquals(0x9000, inner(INS_VERIFY, 0, Vecs.accessHash()).sw(), "VERIFY");
        }

        /** A 6F00 of an armed command tears the card session: OPEN again (and re-verify). */
        void reopen() throws Exception {
            session = Vecs.open(card);
        }
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

    /** A source LOADED with the shared wallet (members: source + target), verified. */
    private static Side loaded(Side target) throws Exception {
        Side source = new Side();
        source.create(Ids.cardId(target.a));
        source.verify();
        return source;
    }

    /** A genuine export head+payload of {@code source} to {@code target}. */
    private static byte[][] export(Side source, Side target) throws Exception {
        byte[] data = concat(target.cert, target.offer());
        Response h = source.inner(INS_EXPORT, 0, data);
        assertEquals(0x9000, h.sw(), "EXPORT0");
        Response p = source.inner(INS_EXPORT, 1, Vecs.accessHashNew());
        assertEquals(0x9000, p.sw(), "EXPORT1");
        return new byte[][] {h.data(), p.data()};
    }

    private static int measure(Side side, int ins, int p1, byte[] data, String method)
            throws Exception {
        try {
            Fault.countCalls();
            side.inner(ins, p1, data);
            return Fault.calls(method);
        } finally {
            Fault.reset();
        }
    }

    private static int pending(Side side) {
        byte[] w = Internals.words(side.card.applet(Spec.WALLET_AID));
        return ((w[6] & 0xFF) << 8) | (w[7] & 0xFF);
    }

    private static void assertKilled(int sw, String what) {
        assertTrue(
                sw == 0x6F00 || sw == 0x6A80,
                what + " must be 6F00/6A80, was " + Integer.toHexString(sw));
    }

    // ── EXPORT0 ─────────────────────────────────────────────────────────────

    @Test
    void export0CertificateForced() throws Exception {
        Side target = new Side();
        Side source = loaded(target);
        byte[] data = concat(target.cert, target.offer());
        assertEquals(1, measure(source, INS_EXPORT, 0, data, "Identity.verifyCert"));
        try {
            Fault.arm("Identity.verifyCert", 1, Const.CHECK_FAIL);
            assertKilled(source.inner(INS_EXPORT, 0, data).sw(), "cert forced FAIL");
            assertEquals(0, pending(source), "no pending export");
        } finally {
            Fault.reset();
        }
    }

    @Test
    void export0MembershipForced() throws Exception {
        Side target = new Side();
        Side source = loaded(target);
        byte[] data = concat(target.cert, target.offer());
        int calls = measure(source, INS_EXPORT, 0, data, "Transfer.memberSlot");
        // the slot lookup once + its double recompute before the pending export
        assertEquals(3, calls, "memberSlot evaluations");
        for (int i = 1; i <= calls; i++) {
            try {
                // force the wrong peer slot (the only other slot of a two-member wallet)
                Fault.arm("Transfer.memberSlot", i, (short) 1);
                Response r = source.inner(INS_EXPORT, 0, data);
                assertKilled(r.sw(), "memberSlot eval " + i);
                assertEquals(0, pending(source), "eval " + i + " left a pending export");
            } finally {
                Fault.reset();
            }
            // the 6F00 tore the session
            source.reopen();
            source.verify();
        }
    }

    // ── IMPORT0 ─────────────────────────────────────────────────────────────

    /** A LOADED target that holds the shared wallet, with a live offer. */
    private static Side loadedTarget(Side source) throws Exception {
        Side target = new Side();
        source.create(Ids.cardId(target.a));
        byte[][] e = export(source, target);
        assertEquals(0x9000, target.inner(INS_IMPORT, 0, concat(source.cert, e[0])).sw());
        assertEquals(0x9000, target.inner(INS_IMPORT, 1, e[1]).sw());
        target.offer();
        return target;
    }

    @Test
    void import0CertificateForced() throws Exception {
        Side source = new Side();
        Side target = loadedTarget(source);
        byte[] data = concat(source.cert, export(source, target)[0]);
        assertEquals(1, measure(target, INS_IMPORT, 0, data, "Identity.verifyCert"));
        try {
            Fault.arm("Identity.verifyCert", 1, Const.CHECK_FAIL);
            assertKilled(target.inner(INS_IMPORT, 0, data).sw(), "cert forced FAIL");
            assertEquals(0, pending(target), "no pending import");
        } finally {
            Fault.reset();
        }
    }

    @Test
    void import0MembershipForced() throws Exception {
        Side source = new Side();
        Side target = loadedTarget(source);
        byte[] data = concat(source.cert, export(source, target)[0]);
        int calls = measure(target, INS_IMPORT, 0, data, "Transfer.memberSlot");
        assertEquals(3, calls, "slot lookup + double recompute before the write");
        for (int i = 1; i <= calls; i++) {
            try {
                Fault.arm("Transfer.memberSlot", i, (short) 1);
                Response r = target.inner(INS_IMPORT, 0, data);
                assertKilled(r.sw(), "memberSlot eval " + i);
                assertEquals(0, pending(target), "eval " + i + " left a pending import");
            } finally {
                Fault.reset();
            }
            target.reopen();
        }
    }

    // ── IMPORT1 ─────────────────────────────────────────────────────────────

    /** Arms a pending import of a genuine export on {@code target} (LOADED, offered). */
    private static byte[][] armImport(Side target, Side source) throws Exception {
        byte[][] e = export(source, target);
        assertEquals(
                0x9000, target.inner(INS_IMPORT, 0, concat(source.cert, e[0])).sw(), "IMPORT0");
        return e;
    }

    @Test
    void import1MacForced() throws Exception {
        Side source = new Side();
        Side target = loadedTarget(source);
        byte[][] e = armImport(target, source);
        // evals 1 and 2 are the §8.3 request-tag check; the stored-MAC eval is 3
        try {
            Fault.arm("Bytes.equal", 3, Const.CHECK_FAIL);
            assertKilled(target.inner(INS_IMPORT, 1, e[1]).sw(), "mac forced FAIL");
            assertEquals(0, pending(target));
        } finally {
            Fault.reset();
        }
        // the card recovers: a genuine import after the fault installs
        target.reopen();
        e = armImport(target, source);
        assertEquals(0x9000, target.inner(INS_IMPORT, 1, e[1]).sw());
    }

    @Test
    void import1LifeForced() throws Exception {
        Side source = new Side();
        Side target = loadedTarget(source);
        byte[][] e = armImport(target, source);
        int calls = measure(target, INS_IMPORT, 1, e[1], "State.life");
        // the dispatch gate's read plus import1's own read and install's double read-back;
        // eval 1 is the gate's (BLANK is an allowed life for IMPORT — arming it is benign)
        assertTrue(calls >= 4, "life evaluations " + calls);
        for (int i = 2; i <= calls; i++) {
            target.reopen();
            e = armImport(target, source);
            try {
                // BLANK would skip every re-seal check — install's read-back must catch it
                Fault.arm("State.life", i, Const.LIFE_BLANK);
                int sw = target.inner(INS_IMPORT, 1, e[1]).sw();
                assertNotEquals(0x9000, sw, "life eval " + i + " must not install");
                assertTrue(
                        sw == 0x6F00 || sw == 0x6A80 || sw == 0x6985,
                        "life eval " + i + ": " + Integer.toHexString(sw));
            } finally {
                Fault.reset();
            }
        }
    }

    @Test
    void import1EqualityChecksForced() throws Exception {
        Side source = new Side();
        Side target = loadedTarget(source);
        byte[][] e = armImport(target, source);
        int equalCalls = measure(target, INS_IMPORT, 1, e[1], "State.equal");
        e = armImport(target, source);
        int originCalls = measure(target, INS_IMPORT, 1, e[1], "State.origin");
        // reseal's single evals (members, fp) + the guard block's doubles (members, fp)
        assertEquals(6, equalCalls, "State.equal evaluations");
        // reseal's origin + the guard block's double + the post-install WalletInfo
        // read-back (Wallet.install), which legitimately returns 9000 — not a check
        assertEquals(4, originCalls, "State.origin evaluations");
        for (int i = 1; i <= equalCalls; i++) {
            target.reopen();
            e = armImport(target, source);
            try {
                Fault.arm("State.equal", i, Const.CHECK_FAIL);
                assertKilled(target.inner(INS_IMPORT, 1, e[1]).sw(), "equal eval " + i);
            } finally {
                Fault.reset();
            }
        }
        for (int i = 1; i <= 3; i++) {
            target.reopen();
            e = armImport(target, source);
            try {
                // the wallet is imported (CREATE P1=1): force GENERATED to mismatch
                Fault.arm("State.origin", i, Const.ORIGIN_GENERATED);
                assertKilled(target.inner(INS_IMPORT, 1, e[1]).sw(), "origin eval " + i);
            } finally {
                Fault.reset();
            }
        }
    }

    /**
     * The three foreign payloads of {@code rejectedPayloads}' reseal rows (valid MAC, wrong
     * wallet): forcing each failing check's evaluation to pass must hand the refusal to the doubled
     * guard block — {@code 6F00}, never an install.
     */
    @Test
    void import1ForeignPayloadChecksForced() throws Exception {
        java.util.Map<String, Object> t = TransferVecs.find("transfers", "imported-reseal-target");
        TransferVecs.Side source = new TransferVecs.Side("source");
        TransferVecs.Side target = new TransferVecs.Side("target");
        TransferVecs.createWallet(source, TransferVecs.wallet("imported"));
        // put the imported wallet on the target first, then a fresh offer + pending import
        // of the reseal head
        TransferVecs.offerWith(target, TransferVecs.find("transfers", "imported-to-target"));
        assertEquals(
                0x9000,
                target.inner(
                                TransferVecs.INS_IMPORT,
                                0,
                                TransferVecs.concat(
                                        source.cert(),
                                        Vecs.hex(
                                                TransferVecs.find(
                                                        "transfers", "imported-to-target"),
                                                "E"),
                                        Vecs.hex(
                                                TransferVecs.find(
                                                        "transfers", "imported-to-target"),
                                                "exportSignature")))
                        .sw());
        assertEquals(
                0x9000,
                target.inner(
                                TransferVecs.INS_IMPORT,
                                1,
                                TransferVecs.concat(
                                        Vecs.hex(
                                                TransferVecs.find(
                                                        "transfers", "imported-to-target"),
                                                "ct"),
                                        Vecs.hex(
                                                TransferVecs.find(
                                                        "transfers", "imported-to-target"),
                                                "tag")))
                        .sw());
        TransferVecs.offerWith(target, t);
        // foreign payloads (valid MAC, wrong wallet): the failing single evaluation to
        // force — equal eval 1 is reseal's members check, eval 2 its fp check
        Object[][] cases = {
            {"reseal-other-members", "State.equal", 1, Const.CHECK_OK},
            {"reseal-other-members-three", "State.equal", 1, Const.CHECK_OK},
            {"reseal-other-seed", "State.equal", 2, Const.CHECK_OK},
            {"reseal-other-origin", "State.origin", 1, Const.ORIGIN_GENERATED},
        };
        for (Object[] c : cases) {
            String name = (String) c[0];
            String method = (String) c[1];
            int nth = (Integer) c[2];
            short forced = (Short) c[3];
            java.util.Map<String, Object> row = TransferVecs.find("rejectedPayloads", name);
            // a 6F00 of the previous case tore the session: open a fresh one each round
            target.session = Vecs.open(target.card);
            // the refusal without the fault is 6A80 — sanity
            assertEquals(
                    0x9000,
                    TransferVecs.import0(
                                    target,
                                    source,
                                    t,
                                    Vecs.hex(t, "E"),
                                    Vecs.hex(t, "exportSignature"))
                            .sw());
            Response plain =
                    target.inner(
                            TransferVecs.INS_IMPORT,
                            1,
                            TransferVecs.concat(Vecs.hex(row, "ct"), Vecs.hex(row, "tag")));
            assertEquals(0x6A80, plain.sw(), name + " refused without fault");
            // now force the failing single evaluation to OK: the doubled guard must fire
            assertEquals(
                    0x9000,
                    TransferVecs.import0(
                                    target,
                                    source,
                                    t,
                                    Vecs.hex(t, "E"),
                                    Vecs.hex(t, "exportSignature"))
                            .sw());
            try {
                Fault.arm(method, nth, forced);
                Response armed =
                        target.inner(
                                TransferVecs.INS_IMPORT,
                                1,
                                TransferVecs.concat(Vecs.hex(row, "ct"), Vecs.hex(row, "tag")));
                assertTrue(
                        armed.sw() == 0x6F00 || armed.sw() == 0x6A80,
                        name
                                + " with "
                                + method
                                + " eval "
                                + nth
                                + " forced: "
                                + Integer.toHexString(armed.sw()));
            } finally {
                Fault.reset();
            }
        }
    }

    // ── EXPORT1 ─────────────────────────────────────────────────────────────

    @Test
    void export1VerifiedForced() throws Exception {
        Side target = new Side();
        Side source = loaded(target);
        byte[] data = concat(target.cert, target.offer());
        assertEquals(0x9000, source.inner(INS_EXPORT, 0, data).sw());
        int calls = measure(source, INS_EXPORT, 1, Vecs.accessHashNew(), "Session.verified");
        // the guarded double evaluation before the payload is output
        assertTrue(calls >= 2, "verified evaluations " + calls);
        for (int i = 1; i <= calls; i++) {
            source.reopen();
            source.verify();
            assertEquals(0x9000, source.inner(INS_EXPORT, 0, data).sw(), "re-arm " + i);
            try {
                Fault.arm("Session.verified", i, Const.VERIFIED_NO);
                int sw = source.inner(INS_EXPORT, 1, Vecs.accessHashNew()).sw();
                assertNotEquals(0x9000, sw, "verified eval " + i + " must not output");
                assertTrue(
                        sw == 0x6F00 || sw == 0x6982,
                        "verified eval " + i + ": " + Integer.toHexString(sw));
            } finally {
                Fault.reset();
            }
        }
    }

    // ── OFFER ────────────────────────────────────────────────────────────────

    @Test
    void offerLifeForced() throws Exception {
        int calls = measure(new Side(), INS_OFFER, 0, new byte[0], "State.life");
        // the APDU gate's read plus the guarded double read before T-OFFER
        assertTrue(calls >= 3, "life evaluations " + calls);
        for (int i = 1; i <= calls; i++) {
            // the guard only runs while offer != VALID: a fresh card per eval
            Side t = new Side();
            int sw;
            try {
                Fault.arm("State.life", i, Const.LIFE_FACTORY);
                try {
                    sw = t.inner(INS_OFFER, 0, new byte[0]).sw();
                } catch (SessionBrokenException outer) {
                    // the gate read is outside the record: an outer refusal counts
                    sw = -1;
                }
            } finally {
                Fault.reset();
            }
            assertNotEquals(0x9000, sw, "life eval " + i + " must not offer");
            t.reopen();
            // the card recovers: the next OFFER succeeds
            assertEquals(0x9000, t.inner(INS_OFFER, 0, new byte[0]).sw());
        }
    }

    @Test
    void offerSkippedCommitIsCaught() throws Exception {
        Side t = new Side();
        try {
            Fault.armSkip("JCSystem.commitTransaction", 1);
            Response r = t.inner(INS_OFFER, 0, new byte[0]);
            assertEquals(0x6F00, r.sw(), "the txDepth read-back must catch a skipped commit");
        } finally {
            Fault.reset();
        }
        // no LK was output and no offer was committed: the next OFFER does T-OFFER again
        byte[] state = Internals.stateArray(t.card.applet(Spec.WALLET_AID));
        assertEquals(
                Const.OFFER_NONE,
                javacard.framework.Util.getShort(state, State.OFF_OFFER),
                "offer must stay NONE");
        t.reopen();
        assertEquals(0x9000, t.inner(INS_OFFER, 0, new byte[0]).sw());
        assertTrue(t.card.writes() >= 1, "the repeat commits T-OFFER");
    }

    // ---- read-back and guard evaluations the plain suite cannot reach ----

    @Test
    void offerReadBackForced() throws Exception {
        int depthCalls = measure(new Side(), INS_OFFER, 0, new byte[0], "Session.txDepth");
        int offerCalls = measure(new Side(), INS_OFFER, 0, new byte[0], "State.offer");
        // the committed read-back (R7): txDepth twice, offer word twice after the entry check
        assertEquals(2, depthCalls, "txDepth evaluations");
        assertEquals(3, offerCalls, "offer evaluations");
        for (int i = 1; i <= depthCalls; i++) {
            Side t = new Side();
            try {
                Fault.arm("Session.txDepth", i, (short) 1);
                assertKilled(t.inner(INS_OFFER, 0, new byte[0]).sw(), "txDepth eval " + i);
            } finally {
                Fault.reset();
            }
        }
        for (int i = 2; i <= offerCalls; i++) {
            Side t = new Side();
            try {
                Fault.arm("State.offer", i, Const.OFFER_NONE);
                assertKilled(t.inner(INS_OFFER, 0, new byte[0]).sw(), "offer eval " + i);
            } finally {
                Fault.reset();
            }
        }
    }

    @Test
    void offerWordCorruptIsFault() throws Exception {
        // the armed store lands on tOffer's offer-word setShort: committed, so the next
        // offer() must hit the coded-member check (6F00), never re-run T-OFFER
        Side t = new Side();
        try {
            Fault.armStore(1, (short) 0x1111);
            t.inner(INS_OFFER, 0, new byte[0]);
        } finally {
            Fault.reset();
        }
        byte[] state = Internals.stateArray(t.card.applet(Spec.WALLET_AID));
        assertEquals(
                0x1111,
                javacard.framework.Util.getShort(state, State.OFF_OFFER),
                "the armed store hit the offer word");
        t.reopen();
        assertEquals(
                0x6F00,
                t.inner(INS_OFFER, 0, new byte[0]).sw(),
                "a corrupted offer word must fault");
    }

    @Test
    void import1OfferWordForced() throws Exception {
        Side source = new Side();
        Side target = loadedTarget(source);
        byte[][] e = armImport(target, source);
        try {
            Fault.arm("State.offer", 1, Const.OFFER_NONE);
            assertEquals(
                    0x6985, target.inner(INS_IMPORT, 1, e[1]).sw(), "offer gate of IMPORT P1=01");
        } finally {
            Fault.reset();
        }
    }

    @Test
    void import1DuplicateCheckForced() throws Exception {
        // evals 1-3 of Bytes.equal are the record tag and the stored MAC; eval 4 is the
        // first pairwise member comparison of a two-member payload — forcing it to OK is
        // a duplicate, which must be 6A80, never an install
        Side target = new Side();
        Side source = loaded(target);
        byte[][] e = export(source, target);
        assertEquals(0x9000, target.inner(INS_IMPORT, 0, concat(source.cert, e[0])).sw());
        try {
            Fault.arm("Bytes.equal", 4, Const.CHECK_OK);
            assertKilled(target.inner(INS_IMPORT, 1, e[1]).sw(), "forced duplicate");
            assertEquals(0, pending(target), "pending import left");
        } finally {
            Fault.reset();
        }
    }

    @Test
    void import1MasterCheckForced() throws Exception {
        Side target = new Side();
        Side source = loaded(target);
        byte[][] e = export(source, target);
        assertEquals(0x9000, target.inner(INS_IMPORT, 0, concat(source.cert, e[0])).sw());
        try {
            Fault.arm("Derivation.master", 1, Const.CHECK_FAIL);
            assertKilled(target.inner(INS_IMPORT, 1, e[1]).sw(), "master forced FAIL");
            assertEquals(0, pending(target), "pending import left");
        } finally {
            Fault.reset();
        }
    }

    @Test
    void import1MacHeldForced() throws Exception {
        // the stored MAC result twice through held(): each armable evaluation
        Side target = new Side();
        Side source = loaded(target);
        byte[][] e = armImport(target, source);
        int calls = measure(target, INS_IMPORT, 1, e[1], "Transfer.held");
        assertEquals(2, calls, "held evaluations of the stored MAC result");
        for (int i = 1; i <= calls; i++) {
            target.reopen();
            e = armImport(target, source);
            try {
                Fault.arm("Transfer.held", i, Const.CHECK_FAIL);
                assertKilled(target.inner(INS_IMPORT, 1, e[1]).sw(), "held eval " + i);
                assertEquals(0, pending(target), "eval " + i + " left a pending import");
            } finally {
                Fault.reset();
            }
        }
    }

    @Test
    void export0HeldForced() throws Exception {
        Side target = new Side();
        Side source = loaded(target);
        byte[] data = concat(target.cert, target.offer());
        int calls = measure(source, INS_EXPORT, 0, data, "Transfer.held");
        assertEquals(2, calls, "held evaluations of the stored certificate result");
        for (int i = 1; i <= calls; i++) {
            try {
                Fault.arm("Transfer.held", i, Const.CHECK_FAIL);
                assertKilled(source.inner(INS_EXPORT, 0, data).sw(), "held eval " + i);
                assertEquals(0, pending(source), "eval " + i + " left a pending export");
            } finally {
                Fault.reset();
            }
            source.reopen();
            source.verify();
        }
    }

    @Test
    void import0HeldForced() throws Exception {
        Side source = new Side();
        Side target = loadedTarget(source);
        byte[] data = concat(source.cert, export(source, target)[0]);
        int calls = measure(target, INS_IMPORT, 0, data, "Transfer.held");
        assertEquals(2, calls, "held evaluations of the stored certificate result");
        for (int i = 1; i <= calls; i++) {
            try {
                Fault.arm("Transfer.held", i, Const.CHECK_FAIL);
                assertKilled(target.inner(INS_IMPORT, 0, data).sw(), "held eval " + i);
                assertEquals(0, pending(target), "eval " + i + " left a pending import");
            } finally {
                Fault.reset();
            }
            target.reopen();
        }
    }

    @Test
    void import0AgreeForced() throws Exception {
        Side source = new Side();
        Side target = loadedTarget(source);
        byte[] data = concat(source.cert, export(source, target)[0]);
        try {
            Fault.arm("Secp256k1.agree", 1, Const.CHECK_FAIL);
            assertKilled(target.inner(INS_IMPORT, 0, data).sw(), "agree forced FAIL");
            assertEquals(0, pending(target), "pending import left");
        } finally {
            Fault.reset();
        }
    }

    @Test
    void export0BadPrefixForced() throws Exception {
        // LK_T[0] != 0x04 is a data check at its own position: a skipped check must not
        // let an unsigned-prefix point through, so the signature and agreement checks are
        // armed to pass and the prefix check alone decides
        Side target = new Side();
        Side source = loaded(target);
        byte[] offer = target.offer();
        offer[0] = 0x02;
        byte[] data = concat(target.cert, offer);
        try {
            Fault.arm("Secp256k1.verifyHash", 2, Const.CHECK_OK);
            Fault.arm("Secp256k1.agree", 1, Const.CHECK_OK);
            assertEquals(
                    0x6A80, source.inner(INS_EXPORT, 0, data).sw(), "LK prefix check must fire");
        } finally {
            Fault.reset();
        }
    }

    @Test
    void memberSlotCountForced() throws Exception {
        // the member count is read once from persistent state inside memberSlot: a
        // skipped read must be the coded-count fault (6F00), not the not-a-member 6A80
        Side target = new Side();
        Side source = loaded(target);
        byte[] data = concat(target.cert, target.offer());
        Internals.pBytes(source.card.applet(Spec.WALLET_AID))[16] = 0;
        try {
            Fault.armSkip("State.read", 1);
            assertEquals(
                    0x6F00, source.inner(INS_EXPORT, 0, data).sw(), "skipped member-count read");
        } finally {
            Fault.reset();
        }
        source.reopen();
        source.verify();
        Internals.pBytes(source.card.applet(Spec.WALLET_AID))[16] = 4;
        try {
            Fault.armSkip("State.read", 1);
            assertEquals(
                    0x6F00,
                    source.inner(INS_EXPORT, 0, data).sw(),
                    "a count past three is a fault, not a member lookup");
        } finally {
            Fault.reset();
        }
    }

    @Test
    void memberSlotSelfForced() throws Exception {
        // evals 1-2 of Bytes.equal are the record tag, 3 is the A != A self-check; per
        // member i the self compare is 4+2i and the candidate compare 5+2i — a self left
        // unfound or a self landing on the candidate position is a coded fault, 6F00
        Side target = new Side();
        Side source = loaded(target);
        byte[] data = concat(target.cert, target.offer());
        try {
            Fault.arm("Bytes.equal", 4, Const.CHECK_FAIL);
            Fault.arm("Bytes.equal", 6, Const.CHECK_FAIL);
            assertEquals(0x6F00, source.inner(INS_EXPORT, 0, data).sw(), "self missing");
        } finally {
            Fault.reset();
        }
        source.reopen();
        source.verify();
        try {
            // the self compare forced at the candidate's position in all three memberSlot
            // calls (evals 6, 12, 16): self == found must fault, never return a slot
            Fault.arm("Bytes.equal", 6, Const.CHECK_OK);
            Fault.arm("Bytes.equal", 12, Const.CHECK_OK);
            Fault.arm("Bytes.equal", 16, Const.CHECK_OK);
            assertEquals(0x6F00, source.inner(INS_EXPORT, 0, data).sw(), "self is found");
        } finally {
            Fault.reset();
        }
    }

    @Test
    void export1CountForced() throws Exception {
        // a skipped member read leaves the staged count zeroed: the c >= 2 fault check
        // of the pending export must fire, not the payload path
        Side target = new Side();
        Side source = loaded(target);
        byte[] data = concat(target.cert, target.offer());
        assertEquals(0x9000, source.inner(INS_EXPORT, 0, data).sw());
        Internals.hBytes(source.card.applet(Spec.WALLET_AID))[97] = 0;
        try {
            Fault.armSkip("State.read", 1);
            assertEquals(
                    0x6F00,
                    source.inner(INS_EXPORT, 1, Vecs.accessHashNew()).sw(),
                    "skipped member read");
        } finally {
            Fault.reset();
        }
        source.reopen();
        source.verify();
        assertEquals(0x9000, source.inner(INS_EXPORT, 0, data).sw());
        Internals.hBytes(source.card.applet(Spec.WALLET_AID))[97] = 4;
        try {
            Fault.armSkip("State.read", 1);
            assertEquals(
                    0x6F00,
                    source.inner(INS_EXPORT, 1, Vecs.accessHashNew()).sw(),
                    "a count past three is a fault");
        } finally {
            Fault.reset();
        }
    }

    @Test
    void export0ToOneMemberWalletIsJustNotMember() throws Exception {
        // a one-member wallet reaches the c < 1 || c > 3 boundary at c = 1: the loop finds
        // only the self ID, so the refusal is the ordinary not-a-member 6A80, not 6F00
        Side target = new Side();
        Side source = new Side();
        source.create();
        source.verify();
        byte[] data = concat(target.cert, target.offer());
        assertEquals(
                0x6A80,
                source.inner(INS_EXPORT, 0, data).sw(),
                "c = 1 walks the member loop, no fault");
    }

    @Test
    void dirtySha256IsResetByExportHash() throws Exception {
        // dirt before EXPORT P1=0: hashM must reset or the transcript hash — and with it
        // sig_S — is wrong; the host decoder is the oracle
        Side target = new Side();
        Side source = loaded(target);
        byte[] offer = target.offer();
        Internals.sha256(source.card.applet(Spec.WALLET_AID))
                .update(new byte[] {9, 9, 9, 9}, (short) 0, (short) 4);
        byte[] head = source.inner(INS_EXPORT, 0, concat(target.cert, offer)).data();
        byte[] lkT = java.util.Arrays.copyOf(offer, 65);
        org.qntx.card.host.Transfer.decodeExportHead(head, source.cert, target.cert, lkT);
    }

    @Test
    void dirtySha256IsResetByCardId() throws Exception {
        // dirt before EXPORT P1=0: cardId feeds the member lookup, so a missing reset
        // would turn a member target into 6A80
        Side target = new Side();
        Side source = loaded(target);
        Internals.sha256(source.card.applet(Spec.WALLET_AID))
                .update(new byte[] {9, 9, 9, 9}, (short) 0, (short) 4);
        byte[] data = concat(target.cert, target.offer());
        assertEquals(0x9000, source.inner(INS_EXPORT, 0, data).sw(), "cardId must reset");
    }

    @Test
    void dirtySha256IsResetByOfferHash() throws Exception {
        // junk left mid-digest must not leak into TH: without reset() the offer
        // signature no longer verifies (the pattern of dirtySha256IsResetByIdentityId)
        Side t = new Side();
        Internals.sha256(t.card.applet(Spec.WALLET_AID))
                .update(new byte[] {9, 9, 9, 9}, (short) 0, (short) 4);
        byte[] offer = t.inner(INS_OFFER, 0, new byte[0]).data();
        org.qntx.card.host.Transfer.decodeOffer(offer, t.cert);
    }

    @Test
    void dirtySha256IsResetByCertVerify() throws Exception {
        // dirt before IMPORT P1=0: verifyCert must reset the shared digest or the
        // certificate fails on the wrong transcript hash
        Side target = new Side();
        Side source = loaded(target);
        byte[][] e = export(source, target);
        Internals.sha256(target.card.applet(Spec.WALLET_AID))
                .update(new byte[] {9, 9, 9, 9}, (short) 0, (short) 4);
        assertEquals(
                0x9000,
                target.inner(INS_IMPORT, 0, concat(source.cert, e[0])).sw(),
                "cert verify must reset the digest");
    }
}
