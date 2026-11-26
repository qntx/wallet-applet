// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Ecdsa;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.sim.Rng;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The hand-written fault mutants of architecture §14.5 G4: every faulted signing computation must
 * be caught by the §16.2 double checks — inner {@code 6F00}, empty data and the session torn down
 * (the next record gets outer {@code 6985}). The one documented escape (a result fault paired with
 * a matching computation fault on the self-verify itself) is kept here as a limitation test.
 */
final class SignFaultTest {

    private Card card;
    private Session session;

    @AfterEach
    void disarm() {
        Fault.reset();
        Rng.reset();
    }

    private void verified() throws Exception {
        card = Vecs.blankSelf();
        session = Vecs.loadWallet(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
    }

    /** Open + CREATE but no VERIFY — the session the second-level gates must reject. */
    private void unverified() throws Exception {
        card = Vecs.blankSelf();
        session = Vecs.loadWallet(card);
    }

    private javacard.framework.Applet applet() {
        return card.applet(Spec.WALLET_AID);
    }

    private Response inner(int ins, int p1, byte[] data) throws Exception {
        return Vecs.roundtrip(card, session, ins, p1, 0, data);
    }

    /** The fault outcome: inner 6F00, empty data, then the next record gets outer 6985. */
    private void assertNoOutput(Response r) throws Exception {
        assertEquals(0x6F00, r.sw());
        assertEquals(0, r.data().length);
        assertEquals(
                0x6985,
                Vecs.sw(card.transmit(session.wrap(0x20, 0, 0, new byte[0]))),
                "session torn down");
    }

    private static byte[] ecdsaData(byte[] path) {
        byte[] data = new byte[32 + path.length];
        System.arraycopy(Vecs.digest(), 0, data, 0, 32);
        System.arraycopy(path, 0, data, 32, path.length);
        return data;
    }

    private static byte[] bip340Data(byte[] message, byte[] tweak, byte[] path) {
        byte[] data = new byte[64 + path.length];
        System.arraycopy(message, 0, data, 0, 32);
        System.arraycopy(tweak, 0, data, 32, 32);
        System.arraycopy(path, 0, data, 64, path.length);
        return data;
    }

    @Test
    void ecdsaLeafWithoutTheAddMod() throws Exception {
        // the leaf's k = IL + k_par is the last ModArith.addMod of the command (the leaf of
        // evm is non-hardened): skipping it signs with k_par, which the self-verify rejects
        verified();
        Fault.countCalls();
        assertEquals(0x9000, inner(0x31, 0, ecdsaData(Vecs.pathSecpEvm())).sw());
        int addMods = Fault.calls("ModArith.addMod");
        Fault.reset();
        // a fresh card: the count run warmed secpCache, which would shorten the warm
        // derivation and shift the leaf's addMod index
        verified();
        Fault.armSkip("ModArith.addMod", addMods);
        assertNoOutput(inner(0x31, 0, ecdsaData(Vecs.pathSecpEvm())));
    }

    @Test
    void ecdsaFlipCaughtOnBothLeafKinds() throws Exception {
        // a hardened leaf: every index hardened — Q = k·G via PLAIN_XY
        byte[] hardened = Vecs.unhex("058000002c8000003c800000008000000080000000");
        for (byte[] path : new byte[][] {Vecs.pathSecpEvm(), hardened}) {
            verified();
            Fault.armEcdsaFlip(1);
            assertNoOutput(inner(0x31, 0, ecdsaData(path)));
        }
    }

    @Test
    void ecdsaFlipEscapesWhenTheVerifyResultIsCorrupted() throws Exception {
        // Documented §16.2 item 5 limit kept as a test: the self-verify evaluates one computed
        // result twice, so a result fault needs a matching computation fault — forcing
        // verifyHash to CHECK_OK lets the flipped signature out. A real card fault model that
        // corrupts both computation and its check defeats this defence by construction.
        verified();
        Fault.arm("Secp256k1.verifyHash", 1, Const.CHECK_OK);
        Fault.arm("Secp256k1.verifyHash", 2, Const.CHECK_OK);
        Fault.armEcdsaFlip(1);
        Response r = inner(0x31, 0, ecdsaData(Vecs.pathSecpEvm()));
        assertEquals(0x9000, r.sw(), "the bad signature escaped — limitation documented");
        byte[] pub =
                org.qntx.card.host.Crypto.decompress(
                        org.qntx.card.host.Bip32.derive(Vecs.seed(), "m/44'/60'/0'/0/0")
                                .publicKey());
        assertFalse(
                Ecdsa.verify(pub, Vecs.digest(), r.data()),
                "the escaped signature is invalid under the leaf key");
    }

    @Test
    void bip340NegationsSharesAndMaskedAdds() throws Exception {
        Map<String, Object> doc = Vecs.load("bip340.json");
        // negateIf call order inside sign: d0, y(P), d, y(Q), k, c = n − e
        int[] saw6F00 = new int[7];
        for (int ci = 0; ci < 4; ci++) {
            Map<String, Object> c = Vecs.list(doc, "cases").get(ci);
            byte[] aux = Vecs.hex(c, "aux");
            byte[] expected = Vecs.hex(c, "signature");
            byte[] data =
                    bip340Data(Vecs.hex(c, "message"), Vecs.hex(c, "tweak"), Vecs.hex(c, "wire"));
            for (int i = 1; i <= 6; i++) {
                verified();
                Rng.fix(aux);
                Fault.armSkip("ModArith.negateIf", i);
                Response r = inner(0x32, 0, data);
                if (r.sw() == 0x9000) {
                    // a no-op negation (bit 0) leaves the signature exact
                    assertArrayEquals(expected, r.data(), c.get("name") + " skip " + i);
                } else {
                    assertNoOutput(r);
                    saw6F00[i]++;
                }
            }
            // the masked recombination and the share split break s whenever dropped
            verified();
            Fault.countCalls();
            Rng.fix(aux);
            assertEquals(0x9000, inner(0x32, 0, data).sw());
            int adds = Fault.calls("ModArith.addMod");
            int shares = Fault.calls("ModArith.share");
            Fault.reset();
            for (int i = adds - 1; i <= adds; i++) {
                verified();
                Rng.fix(aux);
                Fault.armSkip("ModArith.addMod", i);
                assertNoOutput(inner(0x32, 0, data));
            }
            for (int i = 1; i <= shares; i++) {
                verified();
                Rng.fix(aux);
                Fault.armSkip("ModArith.share", i);
                assertNoOutput(inner(0x32, 0, data));
            }
        }
        // the d0, d and k negations must actually have been armed in a taken state
        assertTrue(saw6F00[1] > 0, "d0 negation never faulted");
        assertTrue(saw6F00[3] > 0, "d negation never faulted");
        assertTrue(saw6F00[6] > 0, "c negation never faulted");
        if (saw6F00[5] == 0) {
            // every vector aux left R even; draw auxes until the k negation fires
            Map<String, Object> c = Vecs.list(doc, "cases").get(0);
            byte[] data =
                    bip340Data(Vecs.hex(c, "message"), Vecs.hex(c, "tweak"), Vecs.hex(c, "wire"));
            for (int t = 0; t < 32 && saw6F00[5] == 0; t++) {
                byte[] aux = new byte[32];
                Vecs.RND.nextBytes(aux);
                verified();
                Rng.fix(aux);
                Fault.armSkip("ModArith.negateIf", 5);
                Response r = inner(0x32, 0, data);
                if (r.sw() != 0x9000) {
                    saw6F00[5]++;
                    assertNoOutput(r);
                } else {
                    assertTrue(
                            org.qntx.card.host.Bip340.verify(
                                    Vecs.hex(c, "outputKey"), Vecs.message(), r.data()));
                }
            }
        }
        assertTrue(saw6F00[5] > 0, "k negation never faulted");
    }

    @Test
    void ed25519FinishMaskedAndCorruptStream() throws Exception {
        byte[] stream = new byte[8];
        Vecs.RND.nextBytes(stream);
        // mulMasked's two addMod are the last of finish; share is the only share call
        for (String m : new String[] {"ModArith.addMod", "ModArith.share"}) {
            verified();
            assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
            assertEquals(0x9000, inner(0x33, 1, stream).sw());
            Fault.countCalls();
            assertEquals(0x9000, inner(0x33, 2, new byte[] {9}).sw());
            int count = Fault.calls(m);
            Fault.reset();
            int first = m.endsWith("addMod") ? count - 1 : 1;
            for (int i = first; i <= count; i++) {
                verified();
                assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
                assertEquals(0x9000, inner(0x33, 1, stream).sw());
                Fault.armSkip(m, i);
                assertNoOutput(inner(0x33, 2, new byte[] {9}));
            }
        }
        // a fault that rewrites stored state after A was computed is caught: corrupt one
        // byte of a, r and R in edStream between begin and finish
        for (int off : new int[] {0, 32, 70}) {
            verified();
            assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
            Internals.edStreamBytes(applet())[off] ^= 1;
            assertNoOutput(inner(0x33, 2, stream));
        }
    }

    @Test
    void secondLevelVerifiedGatesHold() throws Exception {
        for (int ins : new int[] {0x31, 0x32, 0x33}) {
            byte[] data =
                    ins == 0x31
                            ? ecdsaData(Vecs.pathSecpEvm())
                            : ins == 0x32
                                    ? bip340Data(
                                            Vecs.message(), Vecs.tweakBip86(), Vecs.pathSecpEvm())
                                    : Vecs.pathEdSolana();
            // fool the dispatch gate alone: the handler's own first eval still reads NO
            // and refuses before the shadow word is even read (§16.2 item 4)
            unverified();
            int before = edCounter();
            Fault.countCalls();
            Fault.arm("Session.verified", 1, Const.VERIFIED_YES);
            Response r = inner(ins, 0, data);
            int writes = card.writes();
            assertNoOutput(r);
            assertEquals(
                    ins == 0x31 ? 1 : 0,
                    writes,
                    "only the ECDSA setW may persist, INS " + Integer.toHexString(ins));
            assertEquals(before, edCounter(), "edCounter unchanged");
            assertEquals(
                    0,
                    Fault.calls("Session.verifiedShadow"),
                    "the first handler evaluation refused alone, before the shadow read, INS "
                            + Integer.toHexString(ins));
            // force each single one of the two second-level evaluations
            unverified();
            Fault.arm("Session.verified", 1, Const.VERIFIED_YES);
            Fault.arm("Session.verified", 2, Const.VERIFIED_YES);
            assertNoOutput(inner(ins, 0, data));
            unverified();
            Fault.arm("Session.verified", 1, Const.VERIFIED_YES);
            Fault.arm("Session.verified", 3, Const.VERIFIED_YES);
            assertNoOutput(inner(ins, 0, data));
        }
    }

    @Test
    void tEdctrCommitAndCallSkips() throws Exception {
        // a skipped commit leaves the transaction open: the depth gate fires before output
        verified();
        int before = edCounter();
        Fault.armSkip("JCSystem.commitTransaction", 1);
        assertNoOutput(inner(0x33, 0, Vecs.pathEdSolana()));
        assertEquals(before, edCounter(), "edCounter unchanged");
        // a skipped T-EDCTR leaves the counter unwritten: the read-back gate fires
        verified();
        before = edCounter();
        Fault.armSkip("Ed25519.tEdctr", 1);
        assertNoOutput(inner(0x33, 0, Vecs.pathEdSolana()));
        assertEquals(before, edCounter(), "edCounter unchanged");
    }

    private int edCounter() {
        byte[] s = Internals.stateArray(applet());
        return ((s[State.OFF_EDCOUNTER] & 0xFF) << 24)
                | ((s[State.OFF_EDCOUNTER + 1] & 0xFF) << 16)
                | ((s[State.OFF_EDCOUNTER + 2] & 0xFF) << 8)
                | (s[State.OFF_EDCOUNTER + 3] & 0xFF);
    }

    @Test
    void eachSelfVerifyEvalStandsAlone() throws Exception {
        // §16.2 item 5 evaluates one computed result twice: faulting either evaluation on
        // its own must still keep the signature in — otherwise a single gate is dead code
        byte[] bip = bip340Data(Vecs.message(), Vecs.tweakBip86(), Vecs.pathSecpEvm());
        // v1 and v2 are the last two verifyHash calls of the command — earlier ones
        // belong to the non-hardened leaf's public-derivation check
        verified();
        Fault.countCalls();
        assertEquals(0x9000, inner(0x31, 0, ecdsaData(Vecs.pathSecpEvm())).sw());
        int verifies = Fault.calls("Secp256k1.verifyHash");
        Fault.reset();
        for (int nth : new int[] {verifies - 1, verifies}) {
            verified();
            Fault.arm("Secp256k1.verifyHash", nth, Const.CHECK_FAIL);
            assertNoOutput(inner(0x31, 0, ecdsaData(Vecs.pathSecpEvm())));
            verified();
            Fault.arm("Bip340.verifyPoint", nth - verifies + 2, Const.CHECK_FAIL);
            assertNoOutput(inner(0x32, 0, bip));
        }
        // the k = 0 fault gate is the last isZero call of sign — earlier ones are the
        // derive path and tweak checks
        verified();
        Fault.countCalls();
        assertEquals(0x9000, inner(0x32, 0, bip).sw());
        int isZeros = Fault.calls("ModArith.isZero");
        Fault.reset();
        verified();
        Fault.arm("ModArith.isZero", isZeros, Const.CHECK_OK);
        assertNoOutput(inner(0x32, 0, bip));
        // the mod-n reduces are fault-injectable through their coded return
        for (int nth : new int[] {1, 2}) {
            verified();
            Fault.arm("ModArith.reduce", nth, Const.CHECK_FAIL);
            assertNoOutput(inner(0x32, 0, bip));
        }
        // and the edKey scalar reduce is the first of an Ed25519 begin
        verified();
        Fault.arm("ModArith.reduce", 1, Const.CHECK_FAIL);
        assertNoOutput(inner(0x33, 0, Vecs.pathEdSolana()));
        // finish's two stream compares are the last Bytes.equal calls of the APDU —
        // the record tag check spends the first two
        verified();
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        Fault.countCalls();
        assertEquals(0x9000, inner(0x33, 2, new byte[] {9}).sw());
        int equals = Fault.calls("Bytes.equal");
        Fault.reset();
        for (int nth : new int[] {equals - 1, equals}) {
            verified();
            assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
            Fault.arm("Bytes.equal", nth, Const.CHECK_FAIL);
            assertNoOutput(inner(0x33, 2, new byte[] {9}));
        }
        // finish's two checks are Session.verified call 2 (the dispatch gate is 1) and
        // the first verifiedShadow read — different words, each faulted alone
        verified();
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        Fault.arm("Session.verified", 2, Const.VERIFIED_NO);
        assertNoOutput(inner(0x33, 2, new byte[] {9}));
        verified();
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        Fault.arm("Session.verifiedShadow", 1, Const.VERIFIED_NO);
        assertNoOutput(inner(0x33, 2, new byte[] {9}));
    }

    @Test
    void txDepthAndStreamDigestGates() throws Exception {
        // §16.1 item 3: an open transaction after T-EDCTR is a fault even when the
        // read-back would still match — the gate is armed through the woven wrapper
        verified();
        Fault.arm("Session.txDepth", 1, (short) 1);
        assertNoOutput(inner(0x33, 0, Vecs.pathEdSolana()));
        // endPending's digest reset is the only cleanup of an abandoned stream; count
        // the woven call so removing it is caught, then prove the cleanup is needed
        verified();
        byte[] chunk = new byte[64];
        Vecs.RND.nextBytes(chunk);
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        assertEquals(0x9000, inner(0x33, 1, chunk).sw());
        Fault.countCalls();
        assertEquals(0x9000, inner(0x20, 0, new byte[0]).sw());
        assertEquals(1, Fault.calls("Mem.resetSha512"), "STATUS ended the stream");
        Fault.reset();
        // a begin after the abandoned stream must still work — the stream hash state
        // was reset, not carried into the new nonce or challenge
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        Fault.countCalls();
        Response r = inner(0x33, 2, new byte[] {9});
        assertEquals(0x9000, r.sw());
        assertEquals(9, Fault.calls("Bytes.wipe"), "3 finish + 2 endPending + 4 scratch");
    }

    @Test
    void signWipeCounts() throws Exception {
        // a dropped scalar wipe is unobservable in the output; the woven call count is not
        byte[] hardened = Vecs.unhex("058000002c8000003c800000008000000080000000");
        verified();
        Fault.countCalls();
        assertEquals(0x9000, inner(0x31, 0, ecdsaData(hardened)).sw());
        assertEquals(1, Fault.calls("Secp256k1.wipeScalar"), "hardened leaf scalar wipe");
        verified();
        Fault.countCalls();
        assertEquals(
                0x9000,
                inner(0x32, 0, bip340Data(Vecs.message(), Vecs.tweakBip86(), Vecs.pathSecpEvm()))
                        .sw());
        assertEquals(5, Fault.calls("Secp256k1.wipeScalar"), "every scalar slot wiped");
    }

    @Test
    void counterByteEdgesAndCarry() throws Exception {
        // every byte's FF test is load-bearing: a non-FF byte anywhere must pass the gate
        for (long v : new long[] {0x00FFFFFFL, 0xFF00FFFFL, 0xFFFF00FFL, 0xFFFFFF00L}) {
            verified();
            byte[] s = Internals.stateArray(applet());
            s[State.OFF_EDCOUNTER] = (byte) (v >>> 24);
            s[State.OFF_EDCOUNTER + 1] = (byte) (v >>> 16);
            s[State.OFF_EDCOUNTER + 2] = (byte) (v >>> 8);
            s[State.OFF_EDCOUNTER + 3] = (byte) v;
            assertEquals(
                    0x9000,
                    inner(0x33, 0, Vecs.pathEdSolana()).sw(),
                    "begin at counter " + Long.toHexString(v));
        }
        // a low-byte carry: N + 1 must propagate past byte 4, not stop at the increment
        verified();
        byte[] s = Internals.stateArray(applet());
        s[State.OFF_EDCOUNTER + 3] = (byte) 0xFF;
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        assertEquals(0x100, edCounter(), "carry propagated into byte 3");
    }

    @Test
    void pendingWordFaultAndMembers() throws Exception {
        // a corrupt pending word is a detected fault; a different member just isn't the
        // stream — both directions exercise the four membership checks of pending()
        verified();
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        byte[] w = Internals.words(applet());
        w[6] = 0x77;
        w[7] = 0x77;
        assertNoOutput(inner(0x33, 2, new byte[0]));
        for (int member : new int[] {Const.PENDING_EXPORT, Const.PENDING_IMPORT}) {
            verified();
            assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
            w = Internals.words(applet());
            w[6] = (byte) (member >> 8);
            w[7] = (byte) member;
            assertEquals(0x6985, inner(0x33, 2, new byte[] {9}).sw());
        }
    }
}
