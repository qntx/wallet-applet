// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import javacard.framework.Applet;
import javacard.framework.Util;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * §16.2/§9.5 fault mutants (architecture §14.4 W6): each mutant is armed on the real command path
 * and must produce no uncounted comparison ({@code Wallet.match} call count), no T-OK (the
 * persistent {@code fails} stays where it was) and no output (non-9000 inner status).
 */
final class FaultMutantTest {

    private Card card;
    private Session session;

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    private Applet applet() {
        return card.applet(Spec.WALLET_AID);
    }

    private void loaded() throws Exception {
        card = Vecs.blankSelf();
        session = Vecs.loadWallet(card);
    }

    private void verified() throws Exception {
        loaded();
        assertEquals(0x9000, verify(Vecs.accessHash()).sw());
    }

    private void setFails(short f) {
        byte[] s = Internals.stateArray(applet());
        Util.setShort(s, State.OFF_FAILS, f);
        Util.setShort(s, (short) (State.OFF_FAILS + 2), (short) ~f);
    }

    private void setWaited(short w) {
        Util.setShort(Internals.words(applet()), (short) 8, w);
    }

    private short fails() {
        return Util.getShort(Internals.stateArray(applet()), State.OFF_FAILS);
    }

    private boolean blank() {
        return Util.getShort(Internals.stateArray(applet()), State.OFF_LIFE) == Const.LIFE_BLANK;
    }

    private Response verify(byte[] code) throws Exception {
        return Vecs.roundtrip(card, session, 0x22, 0, 0, code);
    }

    private Response inner(int ins, int p1, byte[] data) throws Exception {
        return Vecs.roundtrip(card, session, ins, p1, 0, data);
    }

    private void newSession() throws Exception {
        session = Vecs.open(card);
    }

    @Test
    void deletedTFailCallIsCaught() throws Exception {
        loaded();
        Fault.countCalls();
        Fault.armSkip("Wallet.tFail", 1);
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertEquals(0, Fault.calls("Wallet.match"));
        assertTrue(blank());
    }

    @Test
    void deletedTFailCommitIsCaught() throws Exception {
        loaded();
        Fault.countCalls();
        Fault.armSkip("JCSystem.commitTransaction", 1);
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertEquals(0, Fault.calls("Wallet.match"));
        assertTrue(blank());
    }

    @Test
    void overwrittenFailsReadIsCaught() throws Exception {
        // f_a overwritten after its complement check: the gate's f1 != f_b + 1 catches it
        for (short f : new short[] {1, 2}) {
            loaded();
            setFails(f);
            Fault.countCalls();
            Fault.arm("State.readFails", 1, (short) (f - 1));
            assertEquals(0x6F00, verify(Vecs.accessHash()).sw(), "f=" + f);
            assertEquals(0, Fault.calls("Wallet.match"));
            assertTrue(blank());
        }
        // at f = 3 arming f_a to 0 dodges the wait gate the same way the mutant would
        loaded();
        setFails((short) 3);
        Fault.countCalls();
        Fault.arm("State.readFails", 1, (short) 0);
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertEquals(0, Fault.calls("Wallet.match"));
        assertTrue(blank());
    }

    @Test
    void overwrittenTFailValueIsCaught() throws Exception {
        // consistent pair: T-FAIL stores v, ~v — the gate sees f1 = v != f + 1
        loaded();
        Fault.armStore(1, (short) 0x4242);
        Fault.armStore(2, (short) ~0x4242);
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertTrue(blank());

        // inconsistent pair: only the value write is replaced — the complement check fails
        loaded();
        Fault.armStore(1, (short) 0x4242);
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertTrue(blank());
    }

    @Test
    void skippedLimitCheckStillErases() throws Exception {
        // belowLimit call 1 forced OK: the f_b evaluation still sees f = L and erases
        loaded();
        setFails(Const.FAIL_LIMIT);
        Fault.countCalls();
        Fault.arm("Wallet.belowLimit", 1, Const.CHECK_OK);
        assertEquals(0x6983, verify(Vecs.accessHash()).sw());
        assertEquals(0, Fault.calls("Wallet.match"));
        assertTrue(blank());

        loaded();
        setFails(Const.FAIL_LIMIT);
        Fault.countCalls();
        Fault.arm("Wallet.belowLimit", 2, Const.CHECK_OK);
        assertEquals(0x6983, verify(Vecs.accessHash()).sw());
        assertEquals(0, Fault.calls("Wallet.match"));
        assertTrue(blank());
    }

    @Test
    void forcedMatchBranchCountsTheFailure() throws Exception {
        // match call 1 forced: call 2 recomputes and fails — exact 63Cx, counted, not verified
        loaded();
        Fault.arm("Wallet.match", 1, Const.CHECK_OK);
        assertEquals(0x63c9, verify(Vecs.accessHashWrong()).sw());
        assertEquals(1, fails());
        newSession();
        assertEquals(0x6982, inner(0x30, 0, Vecs.pathSecpEvm()).sw());

        // match call 1 real fails first: the forced call 2 is never reached
        loaded();
        Fault.arm("Wallet.match", 2, Const.CHECK_OK);
        assertEquals(0x63c9, verify(Vecs.accessHashWrong()).sw());
        assertEquals(1, fails());
    }

    @Test
    void forcedMatchPairHitsTheFingerprintGate() throws Exception {
        // both matches forced (one arm per key): match call 1 via its own arm, match call 2
        // via its CMAC compare — equal calls 1-2 are the session tag dual check, so the
        // second match's compare is equal call 4; the decrypted garbage seed then fails
        // the fingerprint check
        loaded();
        Fault.countCalls();
        Fault.arm("Wallet.match", 1, Const.CHECK_OK);
        Fault.arm("Bytes.equal", 4, Const.CHECK_OK);
        assertEquals(0x6F00, verify(Vecs.accessHashWrong()).sw());
        assertEquals(1, fails(), "the failure was committed before the comparison");

        // even one forced fingerprint evaluation leaves the second one to catch it
        loaded();
        Fault.arm("Wallet.match", 1, Const.CHECK_OK);
        Fault.arm("Bytes.equal", 4, Const.CHECK_OK);
        Fault.arm("Wallet.fingerprint", 1, Const.CHECK_OK);
        assertEquals(0x6F00, verify(Vecs.accessHashWrong()).sw());
        assertEquals(1, fails());
    }

    @Test
    void skippedWaitGateStillCountsEveryComparison() throws Exception {
        loaded();
        setFails((short) 3);
        int comparisons = 0;
        // f = 3 … 9: every VERIFY sees waited = 15 faulted in; the count still reaches L
        for (int i = 3; i < Const.FAIL_LIMIT; i++) {
            Fault.reset();
            Fault.countCalls();
            Fault.arm("Session.waited", 1, (short) Const.WAIT_UNITS);
            int sw = verify(Vecs.accessHashWrong()).sw();
            comparisons += Fault.calls("Wallet.match");
            assertEquals(i < Const.FAIL_LIMIT - 1 ? 0x63c0 | (9 - i) : 0x6983, sw, "f=" + i);
        }
        assertEquals(Const.FAIL_LIMIT - 3, comparisons, "each failure reached the comparison once");
        assertTrue(blank());
    }

    @Test
    void skippedEraseVerifiedGateIsCaught() throws Exception {
        loaded();
        Fault.arm("Session.verified", 1, Const.VERIFIED_YES);
        assertEquals(0x6F00, inner(0x24, 0, new byte[0]).sw());
        assertEquals(0, card.writes(), "no persistent write on the faulted gate");
        assertTrue(!blank());
    }

    @Test
    void skippedChangeVerifiedGateIsCaught() throws Exception {
        loaded();
        Fault.arm("Session.verified", 1, Const.VERIFIED_YES);
        assertEquals(0x6F00, inner(0x23, 0, Vecs.accessHashNew()).sw());
        assertEquals(0, card.writes());
        assertTrue(!blank());
    }

    @Test
    void skippedPublicKeyVerifiedGateIsCaught() throws Exception {
        loaded();
        Fault.arm("Session.verified", 1, Const.VERIFIED_YES);
        assertEquals(0x6F00, inner(0x30, 0, Vecs.pathSecpEvm()).sw());
        assertTrue(!blank());
    }

    @Test
    void forcedCreateLifeEvaluationsAreCaught() throws Exception {
        // dispatch reads life once; the in-handler double check catches a flipped second read
        byte[] data = new byte[96];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        card = Vecs.blankSelf();
        session = Vecs.open(card);
        Fault.arm("State.life", 2, Const.LIFE_LOADED);
        assertEquals(0x6F00, inner(0x21, 1, data).sw());
        assertEquals(0, card.writes());
    }

    @Test
    void forcedEraseLifeEvaluationsAreCaught() throws Exception {
        verified();
        Fault.arm("State.life", 2, Const.LIFE_BLANK);
        assertEquals(0x6F00, inner(0x24, 0, new byte[0]).sw());
        assertTrue(!blank());

        verified();
        Fault.arm("State.life", 3, Const.LIFE_BLANK);
        assertEquals(0x6F00, inner(0x24, 0, new byte[0]).sw());
        assertTrue(!blank());
    }

    @Test
    void inconsistentFailsReadsAreCaught() throws Exception {
        // a forced complement mismatch reads back -1: either independent read faults into
        // T-ERASE before any comparison
        loaded();
        Fault.arm("State.readFails", 1, (short) -1);
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertTrue(blank());

        loaded();
        Fault.arm("State.readFails", 2, (short) -1);
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertTrue(blank());
    }

    @Test
    void negativeFailsCountErases() throws Exception {
        // a faulted negative count must not pass the below-limit range test
        loaded();
        Fault.arm("State.readFails", 1, (short) -5);
        assertEquals(0x6983, verify(Vecs.accessHash()).sw());
        assertTrue(blank());
    }

    @Test
    void corruptedFailsReadIsCaught() throws Exception {
        // one flipped byte of the coded pair is read back as -1 → T-ERASE, no comparison
        loaded();
        byte[] p = Internals.stateArray(applet());
        p[State.OFF_FAILS] = (byte) (p[State.OFF_FAILS] ^ 0x55);
        Fault.countCalls();
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertEquals(0, Fault.calls("Wallet.match"));
        assertTrue(blank());
    }

    @Test
    void skippedFirstGateCheckIsCaught() throws Exception {
        // the first gate evaluation really fails (skipped commit → open transaction): a
        // deleted first check would let the command continue into the comparison
        loaded();
        Fault.countCalls();
        Fault.armSkip("JCSystem.commitTransaction", 1);
        Fault.arm("Wallet.gate", 2, Const.CHECK_OK);
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertEquals(0, Fault.calls("Wallet.match"));
        assertTrue(blank());
    }

    @Test
    void forcedSecondGateFailureIsCaught() throws Exception {
        loaded();
        Fault.arm("Wallet.gate", 2, Const.CHECK_FAIL);
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertTrue(blank());
    }

    @Test
    void gateRejectsOutOfRangeFails() throws Exception {
        // f = 1000 with a consistent complement, armed past the f_a/f_b range checks and
        // the wait gate: the gate's own range test still sees f1 - 1 beyond the limit
        loaded();
        setFails((short) 1000);
        setWaited((short) Const.WAIT_UNITS);
        Fault.arm("Wallet.belowLimit", 1, Const.CHECK_OK);
        Fault.arm("Wallet.belowLimit", 2, Const.CHECK_OK);
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertTrue(blank());
    }

    @Test
    void forcedFingerprintFailuresWipe() throws Exception {
        // either independent fingerprint evaluation forced to fail → seed wiped + 6F00
        loaded();
        Fault.countCalls();
        Fault.arm("Wallet.fingerprint", 1, Const.CHECK_FAIL);
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertEquals(
                14,
                Fault.calls("Bytes.wipe"),
                "the fingerprint-fault path wiped seed, caches and scratch");
        assertArrayEquals(new byte[64], Internals.seedBytes(applet()));

        loaded();
        Fault.countCalls();
        Fault.arm("Wallet.fingerprint", 2, Const.CHECK_FAIL);
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertEquals(
                14,
                Fault.calls("Bytes.wipe"),
                "the second fingerprint-fault path wiped seed, caches and scratch");
        assertArrayEquals(new byte[64], Internals.seedBytes(applet()));
    }

    @Test
    void forcedChangeVerifiedEvaluationsAreCaught() throws Exception {
        // dispatch reads verified once; the in-handler double check catches flipped reads
        verified();
        Fault.arm("Session.verified", 2, Const.VERIFIED_NO);
        assertEquals(0x6F00, inner(0x23, 0, Vecs.accessHashNew()).sw());
        assertEquals(0, card.writes());
        assertTrue(!blank());

        verified();
        Fault.arm("Session.verified", 3, Const.VERIFIED_NO);
        assertEquals(0x6F00, inner(0x23, 0, Vecs.accessHashNew()).sw());
        assertTrue(!blank());
    }

    @Test
    void forcedEraseVerifiedEvaluationsAreCaught() throws Exception {
        verified();
        Fault.arm("Session.verified", 2, Const.VERIFIED_NO);
        assertEquals(0x6F00, inner(0x24, 0, new byte[0]).sw());
        assertTrue(!blank());

        verified();
        Fault.arm("Session.verified", 3, Const.VERIFIED_NO);
        assertEquals(0x6F00, inner(0x24, 0, new byte[0]).sw());
        assertTrue(!blank());
    }

    @Test
    void forcedPublicKeyVerifiedEvaluationsAreCaught() throws Exception {
        verified();
        Fault.arm("Session.verified", 2, Const.VERIFIED_NO);
        assertEquals(0x6F00, inner(0x30, 0, Vecs.pathSecpEvm()).sw());
        assertTrue(!blank());

        verified();
        Fault.arm("Session.verified", 3, Const.VERIFIED_NO);
        assertEquals(0x6F00, inner(0x30, 0, Vecs.pathSecpEvm()).sw());
        assertTrue(!blank());
    }

    @Test
    void forcedCreateLifeCheckTwoIsCaught() throws Exception {
        byte[] data = new byte[96];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        card = Vecs.blankSelf();
        session = Vecs.open(card);
        Fault.arm("State.life", 3, Const.LIFE_LOADED);
        assertEquals(0x6F00, inner(0x21, 1, data).sw());
        assertEquals(0, card.writes());
    }

    @Test
    void forcedStatusLifeIsCaught() throws Exception {
        // a faulted second life read must fault, never report a tries byte
        loaded();
        Fault.arm("State.life", 2, Const.LIFE_FACTORY);
        assertEquals(0x6F00, inner(0x20, 0, new byte[0]).sw());
    }

    @Test
    void corruptedOriginIsCaught() throws Exception {
        loaded();
        Internals.stateArray(applet())[State.OFF_ORIGIN] = (byte) 0x77;
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertTrue(!blank());
    }

    @Test
    void corruptedMemberCountIsCaught() throws Exception {
        loaded();
        Internals.stateArray(applet())[State.OFF_MEMBERS] = 4;
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertTrue(!blank());

        loaded();
        Internals.stateArray(applet())[State.OFF_MEMBERS] = 0;
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertTrue(!blank());
    }

    @Test
    void createResetsFailsAndOffer() throws Exception {
        // T-CREATE must re-establish fails = 0 and offer = NONE even on a corrupted BLANK
        card = Vecs.blankSelf();
        session = Vecs.open(card);
        byte[] p = Internals.stateArray(applet());
        Util.setShort(p, State.OFF_FAILS, (short) 5);
        Util.setShort(p, (short) (State.OFF_FAILS + 2), (short) ~5);
        Util.setShort(p, State.OFF_OFFER, (short) 0x1111);
        byte[] data = new byte[96];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        assertEquals(0x9000, inner(0x21, 1, data).sw());
        assertEquals(0, Util.getShort(p, State.OFF_FAILS));
        assertEquals(Const.OFFER_NONE, Util.getShort(p, State.OFF_OFFER));
    }

    @Test
    void eraseClearsEveryPersistentField() throws Exception {
        // populate the node cache so the post-erase wipes are observable
        verified();
        assertEquals(0x9000, inner(0x30, 0, Vecs.pathSecpEvm()).sw());
        assertEquals(0x9000, inner(0x24, 0, new byte[0]).sw());
        byte[] p = Internals.stateArray(applet());
        assertEquals(0, Util.getShort(p, State.OFF_ORIGIN));
        assertArrayEquals(
                new byte[49], Arrays.copyOfRange(p, State.OFF_MEMBERS, State.OFF_MEMBERS + 49));
        assertEquals(Const.OFFER_NONE, Util.getShort(p, State.OFF_OFFER));
        assertArrayEquals(new byte[64], Internals.seedBytes(applet()));
        assertArrayEquals(new byte[170], Internals.secpCacheBytes(applet()));
        // the verified word itself is cleared — a skipped clearVerified is observable
        assertEquals(Const.VERIFIED_NO, Util.getShort(Internals.words(applet()), (short) 2));
    }

    @Test
    void failedVerifyClearsVerifiedAndWipesSeed() throws Exception {
        verified();
        assertEquals(0x63c9, verify(Vecs.accessHashWrong()).sw());
        assertEquals(0x6982, inner(0x30, 0, Vecs.pathSecpEvm()).sw());
        assertArrayEquals(new byte[64], Internals.seedBytes(applet()));
    }

    @Test
    void faultedMasterIsCaught() throws Exception {
        // master is armed through both callers: walletInfo (VERIFY) and PUBLIC_KEY
        loaded();
        Fault.arm("Derivation.master", 1, Const.CHECK_FAIL);
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertTrue(!blank());

        verified();
        Fault.arm("Derivation.master", 1, Const.CHECK_FAIL);
        assertEquals(0x6F00, inner(0x30, 0, Vecs.pathSecpEvm()).sw());
        assertTrue(!blank());
    }

    @Test
    void successfulVerifyLeavesWipedScalar() throws Exception {
        loaded();
        Fault.countCalls();
        Response r = verify(Vecs.accessHash());
        assertEquals(0x9000, r.sw());
        // WalletInfo: masterPublicKey(33) ‖ origin(1) ‖ c(1) ‖ ids(16·c), c = 1 here
        assertEquals(51, r.data().length);
        byte[] s = new byte[32];
        Internals.ephKey(applet()).getS(s, (short) 0);
        assertArrayEquals(new byte[32], s);
        assertEquals(8, Fault.calls("Bytes.wipe"), "every success-path wipe ran");
    }

    @Test
    void masterRejectsPokedMaterial() throws Exception {
        // hmac skipped on calls 1 and 2: the output buffer keeps the poked content — a zero
        // scalar or one ≥ n must fail the master checks
        loaded();
        Derivation d = Internals.derivation(applet());
        byte[] n = Internals.nBytes(applet());
        Class<?>[] sig = {byte[].class, short.class, short.class, byte[].class, short.class};
        Fault.armSkip("Derivation.hmac", 1);
        Fault.armSkip("Derivation.hmac", 2);
        Arrays.fill(n, (byte) 0);
        assertEquals(
                Const.CHECK_FAIL,
                (Short)
                        Internals.invoke(
                                d,
                                "master",
                                sig,
                                Vecs.seed(),
                                (short) 0,
                                (short) 64,
                                n,
                                (short) 0));
        Arrays.fill(n, (byte) 0xFF);
        assertEquals(
                Const.CHECK_FAIL,
                (Short)
                        Internals.invoke(
                                d,
                                "master",
                                sig,
                                Vecs.seed(),
                                (short) 0,
                                (short) 64,
                                n,
                                (short) 0));
    }

    @Test
    void faultedChildWipesKeyMaterial() throws Exception {
        // a throwing scalar multiplication fails the child step: the node key material is
        // wiped before the 6A80
        verified();
        Fault.countCalls();
        Fault.armThrow("Secp256k1.mul", 1);
        assertEquals(0x6A80, inner(0x30, 0, Vecs.pathSecpEvm()).sw());
        assertEquals(1, Fault.calls("Secp256k1.wipeScalar"), "the catch wiped the scalar");
        assertEquals(6, Fault.calls("Bytes.wipe"), "node and scratch wipes ran");
        assertArrayEquals(new byte[64], Arrays.copyOf(Internals.nBytes(applet()), 64));
    }

    @Test
    void publicKeyWipesWorkingBuffers() throws Exception {
        verified();
        Fault.countCalls();
        assertEquals(0x9000, inner(0x30, 0, Vecs.pathSecpEvm()).sw());
        assertEquals(3, Fault.calls("Secp256k1.wipeScalar"), "every mul scalar wiped");
        assertEquals(6, Fault.calls("Bytes.wipe"), "P and scratch wipes ran");
        assertArrayEquals(new byte[130], Internals.pBytes(applet()));

        verified();
        Fault.countCalls();
        assertEquals(0x9000, inner(0x30, 1, Vecs.pathEdSolana()).sw());
        assertEquals(8, Fault.calls("Bytes.wipe"), "H, P and scratch wipes ran");
        assertArrayEquals(new byte[96], Arrays.copyOf(Internals.hBytes(applet()), 96));
        assertArrayEquals(new byte[130], Internals.pBytes(applet()));
    }

    @Test
    void waitUnitWipesScratchAndCounts() throws Exception {
        loaded();
        Fault.countCalls();
        assertEquals(0x9000, inner(0x25, 0, new byte[0]).sw());
        assertEquals(7, Fault.calls("Bytes.wipe"), "waitUnit and scratch wipes ran");
        assertArrayEquals(new byte[32], Arrays.copyOf(Internals.wBytes(applet()), 32));
        assertEquals(1, Util.getShort(Internals.words(applet()), (short) 8));
        // the counter saturates at WAIT_UNITS
        setWaited((short) Const.WAIT_UNITS);
        assertEquals(0x9000, inner(0x25, 0, new byte[0]).sw());
        assertEquals(Const.WAIT_UNITS, Util.getShort(Internals.words(applet()), (short) 8));
    }

    @Test
    void installWipesInitialKeyMaterial() {
        // initState's wrapKey.setKey leaves the random key bytes in W[0..16): the command's
        // wipeScratch zeroes them before the response. W is read right after the drive —
        // later commands would overwrite W and mask any residue.
        Card c = new Card();
        c.install(Spec.WALLET_AID, WalletApplet.class);
        c.transmit(Spec.SELECT);
        Vecs.driveInit(c);
        Applet applet = c.applet(Spec.WALLET_AID);
        assertArrayEquals(new byte[16], Arrays.copyOf(Internals.wBytes(applet), 16));
        byte[] k = new byte[16];
        assertEquals(16, Internals.wrapKey(applet).getKey(k, (short) 0));
        assertTrue(!Arrays.equals(new byte[16], k), "the initialisation wrap key was set");
    }

    @Test
    void publicKeyRejectsEmptyPath() throws Exception {
        loaded();
        assertEquals(0x6700, inner(0x30, 0, new byte[0]).sw());
    }

    @Test
    void publicKeyRejectsMismatchedLength() throws Exception {
        // depth 4 needs 17 data bytes: shorter and longer are both 6700 before any derivation
        verified();
        assertEquals(0x6700, inner(0x30, 0, Vecs.unhex("048000002c8000003c80000000")).sw());
        assertEquals(
                0x6700,
                inner(0x30, 0, Vecs.unhex("048000002c8000003c800000008000000000000000")).sw());
    }

    @Test
    void publicKeyDepthBoundsAreInclusive() throws Exception {
        verified();
        assertEquals(0x9000, inner(0x30, 0, Vecs.unhex("018000002c")).sw());
        assertEquals(0x9000, inner(0x30, 0, Vecs.unhex("0a" + "8000002c".repeat(10))).sw());
        assertEquals(0x6A80, inner(0x30, 0, Vecs.unhex("00")).sw());
        assertEquals(0x6A80, inner(0x30, 0, Vecs.unhex("0b" + "8000002c".repeat(11))).sw());
    }

    @Test
    void createRejectsBadLengths() throws Exception {
        // p1 = 0: base 64, at most two other members → valid lengths are {64, 80, 96};
        // p1 = 1: base 96 → {96, 112, 128}
        card = Vecs.blankSelf();
        session = Vecs.open(card);
        assertEquals(0x6700, inner(0x21, 0, new byte[63]).sw());
        assertEquals(0x6700, inner(0x21, 0, new byte[65]).sw());
        assertEquals(0x6700, inner(0x21, 0, new byte[72]).sw());
        assertEquals(0x6700, inner(0x21, 0, new byte[112]).sw());
        assertEquals(0x6700, inner(0x21, 1, new byte[95]).sw());
        assertEquals(0x6700, inner(0x21, 1, new byte[97]).sw());
        assertEquals(0x6700, inner(0x21, 1, new byte[113]).sw());
        assertEquals(0x6700, inner(0x21, 1, new byte[144]).sw());
    }

    @Test
    void openTransactionIsAbortedAfterDispatch() throws Exception {
        // a skipped T-OK commit leaves the transaction open: the §16.1-item-2 backstop must
        // abort it and downgrade the response to 6F00 instead of returning the wallet info
        loaded();
        Fault.armSkip("JCSystem.commitTransaction", 2);
        assertEquals(0x6F00, verify(Vecs.accessHash()).sw());
        assertTrue(!blank(), "the T-FAIL commit stands: life stays LOADED");
        newSession();
        assertEquals(0x9000, verify(Vecs.accessHash()).sw());
    }

    @Test
    void createWithMembersEchoesEveryId() throws Exception {
        Card c = Vecs.factory();
        byte[] a = Vecs.cardA(c);
        Vecs.blankFor(c, a);
        card = c;
        session = Vecs.open(c);
        byte[] self = Vecs.symbol("id.self", c, a);
        byte[] o1 = Vecs.symbol("id.other1", c, a);
        byte[] o2 = Vecs.symbol("id.other2", c, a);
        byte[] data = new byte[128];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        System.arraycopy(o1, 0, data, 96, 16);
        System.arraycopy(o2, 0, data, 112, 16);
        assertEquals(0x9000, inner(0x21, 1, data).sw());
        Response r = verify(Vecs.accessHash());
        assertEquals(0x9000, r.sw());
        // walletInfo: pubkey(33) ‖ origin(1) ‖ c(1) ‖ ID(A) ‖ o1 ‖ o2
        assertEquals(83, r.data().length);
        byte[] ids = new byte[48];
        System.arraycopy(self, 0, ids, 0, 16);
        System.arraycopy(o1, 0, ids, 16, 16);
        System.arraycopy(o2, 0, ids, 32, 16);
        assertArrayEquals(ids, Arrays.copyOfRange(r.data(), 35, 83));
        // the persistent record is c ‖ ID(A) ‖ o1 ‖ o2 — no pad for c = 3
        byte[] rec = new byte[49];
        rec[0] = 3;
        System.arraycopy(ids, 0, rec, 1, 48);
        assertArrayEquals(
                rec,
                Arrays.copyOfRange(
                        Internals.stateArray(applet()), State.OFF_MEMBERS, State.OFF_MEMBERS + 49));
    }

    @Test
    void createSingleMemberPadsTheRecord() throws Exception {
        // the record is fixed-width: a one-other wallet pads the third slot with zeros
        Card c = Vecs.factory();
        byte[] a = Vecs.cardA(c);
        Vecs.blankFor(c, a);
        card = c;
        session = Vecs.open(c);
        byte[] self = Vecs.symbol("id.self", c, a);
        byte[] o1 = Vecs.symbol("id.other1", c, a);
        byte[] data = new byte[112];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        System.arraycopy(o1, 0, data, 96, 16);
        assertEquals(0x9000, inner(0x21, 1, data).sw());
        byte[] rec = new byte[49];
        rec[0] = 2;
        System.arraycopy(self, 0, rec, 1, 16);
        System.arraycopy(o1, 0, rec, 17, 16);
        assertArrayEquals(
                rec,
                Arrays.copyOfRange(
                        Internals.stateArray(applet()), State.OFF_MEMBERS, State.OFF_MEMBERS + 49));
    }

    @Test
    void eraseResetsTheOfferWord() throws Exception {
        // T-ERASE writes offer ← NONE (§4.3): a poked stale offer must not survive
        verified();
        byte[] s = Internals.stateArray(applet());
        Util.setShort(s, State.OFF_OFFER, (short) 0x1234);
        assertEquals(0x9000, inner(0x24, 0, new byte[0]).sw());
        assertEquals(Const.OFFER_NONE, Util.getShort(s, State.OFF_OFFER));
    }

    @Test
    void stepSecpHonoursFaultedChecks() throws Exception {
        // the range/zero checks guard the child step: a faulted read takes the rejection path
        verified();
        Fault.arm("ModArith.below", 2, Const.CHECK_FAIL);
        assertEquals(0x6A80, inner(0x30, 0, Vecs.pathSecpEvm()).sw());

        verified();
        Fault.arm("ModArith.isZero", 2, Const.CHECK_OK);
        assertEquals(0x6A80, inner(0x30, 0, Vecs.pathSecpEvm()).sw());
    }

    @Test
    void masterChecksHonoursFaultedReads() throws Exception {
        // master's own key-validity checks (the first below/isZero of a cold secp derivation)
        verified();
        Fault.arm("ModArith.below", 1, Const.CHECK_FAIL);
        assertEquals(0x6F00, inner(0x30, 0, Vecs.pathSecpEvm()).sw());

        verified();
        Fault.arm("ModArith.isZero", 1, Const.CHECK_OK);
        assertEquals(0x6F00, inner(0x30, 0, Vecs.pathSecpEvm()).sw());
    }

    @Test
    void depthTwoWarmLeafCostsOneMul() throws Exception {
        // depth ∈ [2, 10] hits the node cache: a second depth-2 call is one HMAC + one mul
        verified();
        byte[] path = Vecs.unhex("028000002c8000003c");
        assertEquals(0x9000, inner(0x30, 0, path).sw());
        Fault.countCalls();
        assertEquals(0x9000, inner(0x30, 0, path).sw());
        assertEquals(2, card.digests(javacard.security.MessageDigest.ALG_SHA_512));
        assertEquals(1, Fault.calls("Secp256k1.mul"));
    }

    @Test
    void coldDerivationStoresOnlyTheParentPath() throws Exception {
        // the cache store copies exactly (depth−1)·4 path bytes — never the leaf index
        verified();
        byte[] cache = Internals.secpCacheBytes(applet());
        Arrays.fill(cache, 17, 25, (byte) 0xAA);
        assertEquals(0x9000, inner(0x30, 0, Vecs.pathSecpEvm()).sw());
        // pathSecpEvm = 05 ‖ 44' ‖ 60' ‖ 0' ‖ 0 ‖ 0: the parent is its first 16 bytes
        assertArrayEquals(
                Vecs.unhex("8000002c8000003c8000000000000000"), Arrays.copyOfRange(cache, 1, 17));
        assertArrayEquals(
                new byte[] {-86, -86, -86, -86, -86, -86, -86, -86},
                Arrays.copyOfRange(cache, 17, 25));
    }

    @Test
    void createRejectsSelfAndDuplicateMembers() throws Exception {
        Card c = Vecs.factory();
        byte[] a = Vecs.cardA(c);
        Vecs.blankFor(c, a);
        card = c;
        session = Vecs.open(c);
        byte[] self = Vecs.symbol("id.self", c, a);
        byte[] o1 = Vecs.symbol("id.other1", c, a);
        byte[] data = new byte[128];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        System.arraycopy(self, 0, data, 96, 16);
        System.arraycopy(o1, 0, data, 112, 16);
        assertEquals(0x6A80, inner(0x21, 1, data).sw());
        System.arraycopy(o1, 0, data, 96, 16);
        assertEquals(0x6A80, inner(0x21, 1, data).sw());
    }

    @Test
    void createClearsBothCaches() throws Exception {
        // a fresh wallet must not inherit derivation nodes cached for a previous seed
        card = Vecs.blankSelf();
        session = Vecs.open(card);
        Arrays.fill(Internals.secpCacheBytes(applet()), (byte) 0x77);
        Arrays.fill(Internals.edCacheBytes(applet()), (byte) 0x77);
        byte[] data = new byte[96];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        assertEquals(0x9000, inner(0x21, 1, data).sw());
        assertArrayEquals(new byte[170], Internals.secpCacheBytes(applet()));
        assertArrayEquals(new byte[105], Internals.edCacheBytes(applet()));
    }

    @Test
    void createInvalidSeedWipesKeyMaterial() throws Exception {
        // an imported seed whose master is invalid is wiped before the 6A80
        card = Vecs.blankSelf();
        session = Vecs.open(card);
        byte[] data = new byte[96];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        Fault.arm("Derivation.master", 1, Const.CHECK_FAIL);
        assertEquals(0x6A80, inner(0x21, 1, data).sw());
        assertArrayEquals(new byte[64], Internals.seedBytes(applet()));
    }

    @Test
    void masterFailureRetriesTheDraw() throws Exception {
        // CREATE p1 = 0 redraws T until the seed yields a valid master
        card = Vecs.blankSelf();
        session = Vecs.open(card);
        byte[] data = new byte[64];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.entropy(), 0, data, 32, 32);
        Fault.countCalls();
        Fault.arm("Derivation.master", 1, Const.CHECK_FAIL);
        assertEquals(0x9000, inner(0x21, 0, data).sw());
        // call 1 faulted, call 2 is the retry, call 3 derives the response's master public key
        assertEquals(3, Fault.calls("Derivation.master"), "the failed draw was retried");
    }

    @Test
    void seedGenerationFeedsEveryByte() throws Exception {
        // the seed hash consumes the label, the drawn T and the host entropy
        card = Vecs.blankSelf();
        session = Vecs.open(card);
        byte[] data = new byte[64];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.entropy(), 0, data, 32, 32);
        assertEquals(0x9000, inner(0x21, 0, data).sw());
        assertEquals(5, card.digests(javacard.security.MessageDigest.ALG_SHA_512));
        assertEquals(849, card.digestBytes(javacard.security.MessageDigest.ALG_SHA_512));
    }

    @Test
    void childHonoursEdHardening() throws Exception {
        // an ed25519 child step is always hardened: no parent point is ever computed
        loaded();
        Derivation d = Internals.derivation(applet());
        byte[] n = Internals.nBytes(applet());
        Arrays.fill(n, (byte) 0x11);
        byte[] idx = {0, 0, 0, 5};
        byte[] hard = {(byte) 0x80, 0, 0, 5};
        byte[] pub = new byte[33];
        Class<?>[] sig = {byte[].class, short.class, byte.class, byte[].class, short.class};
        Fault.countCalls();
        Internals.invoke(d, "child", sig, idx, (short) 0, Derivation.CURVE_ED, pub, (short) 0);
        assertEquals(0, Fault.calls("Secp256k1.mul"), "ed25519 never derives a parent point");
        Fault.reset();
        Fault.countCalls();
        Internals.invoke(d, "child", sig, hard, (short) 0, Derivation.CURVE_SECP, pub, (short) -1);
        assertEquals(0, Fault.calls("Secp256k1.mul"), "a hardened index needs no parent point");
        Fault.reset();
        Fault.countCalls();
        Internals.invoke(d, "child", sig, idx, (short) 0, Derivation.CURVE_SECP, pub, (short) -1);
        assertEquals(1, Fault.calls("Secp256k1.mul"), "pOff < 0 computes k_par·G");
    }

    @Test
    void childReusesOnlyTheCurrentParentsSlot() throws Exception {
        loaded();
        Derivation d = Internals.derivation(applet());
        byte[] n = Internals.nBytes(applet());
        Arrays.fill(n, (byte) 0x11);
        byte[] idx = {0, 0, 0, 5};
        byte[] pub = new byte[65];
        Class<?>[] sig = {byte[].class, short.class, byte.class, byte[].class, short.class};
        // the slot is the 65-byte uncompressed point itself: 0x04 is the point prefix and
        // doubles as the presence marker; every other marker recomputes and refills
        pub[0] = 0x04;
        pub[64] = 0x02;
        Fault.countCalls();
        Internals.invoke(d, "child", sig, idx, (short) 0, Derivation.CURVE_SECP, pub, (short) 0);
        assertEquals(0, Fault.calls("Secp256k1.mul"), "marker 04 reuses the slot");
        Fault.reset();
        Fault.countCalls();
        pub[0] = 0x02;
        Internals.invoke(d, "child", sig, idx, (short) 0, Derivation.CURVE_SECP, pub, (short) 0);
        assertEquals(1, Fault.calls("Secp256k1.mul"), "marker 02 computes the point");
        assertEquals(0x04, pub[0], "the slot was refilled uncompressed");
        Fault.reset();
        Fault.countCalls();
        pub[0] = 0;
        Internals.invoke(d, "child", sig, idx, (short) 0, Derivation.CURVE_SECP, pub, (short) 0);
        assertEquals(1, Fault.calls("Secp256k1.mul"), "marker 0 computes the point");
        assertEquals(0x04, pub[0], "the slot was filled");
    }

    @Test
    void dirtySha256IsResetByIdentityId() throws Exception {
        // a command that died between update and doFinal leaves pending bytes: ID(A) must
        // hash A only, or a faulted earlier hash poisons every later member record
        Card c = Vecs.factory();
        byte[] a = Vecs.cardA(c);
        Vecs.blankFor(c, a);
        card = c;
        session = Vecs.open(c);
        Internals.sha256(applet()).update(new byte[] {9, 9, 9, 9}, (short) 0, (short) 4);
        byte[] data = new byte[96];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        Response r = inner(0x21, 1, data);
        assertEquals(0x9000, r.sw());
        // walletInfo = pubkey(33) ‖ origin(1) ‖ c(1) ‖ ID(A)
        assertArrayEquals(Vecs.symbol("id.self", c, a), Arrays.copyOfRange(r.data(), 35, 51));
        assertEquals(
                2,
                card.resets(javacard.security.MessageDigest.ALG_SHA_256),
                "identity id + fingerprint");
        assertEquals(
                2,
                card.resets(javacard.security.MessageDigest.ALG_SHA_512),
                "master check + response key HMACs");
    }

    @Test
    void dirtySha256IsResetByFingerprint() throws Exception {
        // the fingerprint hash feeds the wrap KEK: pending bytes must not flip VERIFY to 6F00;
        // the dirt lands after OPEN (which resets for its own session hash) so fpHash is the
        // first sha256 use of the VERIFY command
        loaded();
        Internals.sha256(applet()).update(new byte[] {9, 9, 9, 9}, (short) 0, (short) 4);
        Response r = verify(Vecs.accessHash());
        assertEquals(0x9000, r.sw());
        assertEquals(
                2,
                card.resets(javacard.security.MessageDigest.ALG_SHA_256),
                "unwrap + fingerprint");
    }

    @Test
    void dirtySha512IsResetBySeedDraw() throws Exception {
        // a dirty engine must not burn a seed redraw: the draw resets before update
        Card c = Vecs.factory();
        byte[] a = Vecs.cardA(c);
        Vecs.blankFor(c, a);
        card = c;
        session = Vecs.open(c);
        Internals.sha512(applet()).update(new byte[] {9, 9, 9, 9}, (short) 0, (short) 4);
        byte[] data = new byte[64];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.entropy(), 0, data, 32, 32);
        Response r = inner(0x21, 0, data);
        assertEquals(0x9000, r.sw());
        assertEquals(
                5,
                card.digests(javacard.security.MessageDigest.ALG_SHA_512),
                "one seed doFinal + two master HMACs");
        assertEquals(
                3,
                card.resets(javacard.security.MessageDigest.ALG_SHA_512),
                "seed draw + two HMACs");
    }

    @Test
    void dirtySha512IsResetByEdHash() throws Exception {
        // the ed25519 h = SHA-512(sk) must not absorb pending bytes from a dead command
        verified();
        Internals.sha512(applet()).update(new byte[] {9, 9, 9, 9}, (short) 0, (short) 4);
        Response r = inner(0x30, 1, Vecs.pathEdSolana());
        assertEquals(0x9000, r.sw());
        assertArrayEquals(Vecs.pkEdSolana(), r.data());
        assertEquals(
                6,
                card.resets(javacard.security.MessageDigest.ALG_SHA_512),
                "master + four child HMACs + the leaf hash");
    }
}
