// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Ecdsa;
import org.qntx.card.host.Ed25519;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Wei25519Map;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.sim.Rng;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * SIGN_ECDSA, SIGN_BIP340 and the SIGN_ED25519 stream as commands (architecture §14.4 G1): the
 * pending-state lifecycle, edCounter accounting, persistent-write and transaction checks, and the
 * fault paths the §16.2 double checks exist for.
 */
final class SignCommandTest {

    private Card card;
    private Session session;

    @AfterEach
    void disarm() {
        Fault.reset();
        Rng.reset();
    }

    private javacard.framework.Applet applet() {
        return card.applet(Spec.WALLET_AID);
    }

    private void verified() throws Exception {
        card = Vecs.blankSelf();
        session = Vecs.loadWallet(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
    }

    private static byte[] ecdsaData(byte[] path) {
        byte[] data = new byte[32 + path.length];
        System.arraycopy(Vecs.digest(), 0, data, 0, 32);
        System.arraycopy(path, 0, data, 32, path.length);
        return data;
    }

    private Response inner(int ins, int p1, byte[] data) throws Exception {
        return Vecs.roundtrip(card, session, ins, p1, 0, data);
    }

    private int edCounter() {
        byte[] s = Internals.stateArray(applet());
        return ((s[State.OFF_EDCOUNTER] & 0xFF) << 24)
                | ((s[State.OFF_EDCOUNTER + 1] & 0xFF) << 16)
                | ((s[State.OFF_EDCOUNTER + 2] & 0xFF) << 8)
                | (s[State.OFF_EDCOUNTER + 3] & 0xFF);
    }

    private void pokeEdCounter(long v) {
        byte[] s = Internals.stateArray(applet());
        for (int i = 0; i < 4; i++) {
            s[State.OFF_EDCOUNTER + 3 - i] = (byte) (v >>> (i * 8));
        }
    }

    @Test
    void counterExhaustionIsCheckedBeforeTheData() throws Exception {
        // §9.2: edCounter == 0xFFFFFFFF answers 6985 before the path checks — even a
        // depth-0 path that would otherwise be 6A80, and no write is attempted
        verified();
        pokeEdCounter(0xFFFF_FFFFL);
        assertEquals(0x6985, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        assertEquals(0x6985, inner(0x33, 0, new byte[] {0}).sw(), "data checks come second");
        assertEquals(0, card.writes());
        assertEquals(-1, edCounter(), "the counter itself is untouched");
    }

    @Test
    void counterGrowsByExactlyOnePerSuccessfulBegin() throws Exception {
        verified();
        assertEquals(0, edCounter());
        // failed begins cost nothing: unhardened path (6A80), bad depth (6A80)
        assertEquals(0x6A80, inner(0x33, 0, Vecs.unhex("040000002c800001f58000000080000000")).sw());
        assertEquals(0x6A80, inner(0x33, 0, new byte[] {0}).sw());
        assertEquals(0, edCounter(), "6A80 begins do not tick the counter");
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        assertEquals(1, edCounter());
        assertEquals(0x9000, inner(0x33, 2, new byte[] {1, 2, 3}).sw());
        assertEquals(1, edCounter(), "finish does not tick the counter");
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        assertEquals(2, edCounter());
    }

    @Test
    void updateAndFinishCommitNothing() throws Exception {
        verified();
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        assertEquals(1, card.commits().size(), "begin commits T-EDCTR once");
        assertEquals(0x9000, inner(0x33, 1, new byte[] {9, 9}).sw());
        assertEquals(0x9000, inner(0x33, 2, new byte[] {9}).sw());
        assertEquals(0, card.writes(), "update and finish write nothing persistent");
    }

    @Test
    void bip340WritesNothingPersistent() throws Exception {
        verified();
        byte[] data = new byte[64 + Vecs.pathSecpEvm().length];
        System.arraycopy(Vecs.message(), 0, data, 0, 32);
        System.arraycopy(Vecs.tweakBip86(), 0, data, 32, 32);
        System.arraycopy(Vecs.pathSecpEvm(), 0, data, 64, Vecs.pathSecpEvm().length);
        assertEquals(0x9000, inner(0x32, 0, data).sw());
        assertEquals(0, card.writes(), "BIP-340 holds no persistent state");
        assertEquals(0, card.commits().size());
    }

    @Test
    void ecdsaWritesExactlyOneVerifyKeyWithoutATransaction() throws Exception {
        verified();
        assertEquals(0x9000, inner(0x31, 0, ecdsaData(Vecs.pathSecpEvm())).sw());
        // the rotating verify key's setW is the command's only persistent write (§5.4)
        assertEquals(1, card.writes(), "one setW on a rotating verify key");
        assertEquals(0, card.commits().size(), "no transaction around it");
    }

    @Test
    void everyNonContinuationEndsTheStream() throws Exception {
        // §9.2: only P1 = 1 and P1 = 2 continue the stream; everything else ends it —
        // STATUS, a failed or successful VERIFY, PUBLIC_KEY, the other sign commands,
        // WAIT, an unknown INS and a P1/P2 error all leave update at 6985
        int[][] ends = {
            {0x20, 0}, // STATUS
            {0x22, 0}, // VERIFY (wrong hash)
            {0x23, 0}, // CHANGE (session stays verified under the new hash)
            {0x30, 0}, // PUBLIC_KEY
            {0x31, 0}, // SIGN_ECDSA
            {0x32, 0}, // SIGN_BIP340
            {0x25, 0}, // WAIT
            {0x7f, 0}, // unknown INS -> 6D00
            {0x33, 3}, // bad P1 -> 6A86
        };
        for (int[] e : ends) {
            verified();
            assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
            byte[] data =
                    e[0] == 0x22
                            ? Vecs.accessHashWrong()
                            : e[0] == 0x23
                                    ? Vecs.accessHashNew()
                                    : e[0] == 0x30
                                            ? Vecs.pathSecpEvm()
                                            : e[0] == 0x31
                                                    ? ecdsaData(Vecs.pathSecpEvm())
                                                    : e[0] == 0x32
                                                            ? new byte
                                                                    [64 + Vecs.pathSecpEvm().length]
                                                            : new byte[0];
            if (e[0] == 0x32) {
                System.arraycopy(Vecs.message(), 0, data, 0, 32);
                System.arraycopy(Vecs.tweakBip86(), 0, data, 32, 32);
                System.arraycopy(Vecs.pathSecpEvm(), 0, data, 64, Vecs.pathSecpEvm().length);
            }
            inner(e[0], e[1], data);
            // isolate the row: the pending word and edStream must be gone before any
            // further command runs — VERIFY below would end a leftover stream itself
            byte[] words = Internals.words(applet());
            assertEquals(
                    0, words[6] | words[7], "pending word after INS " + Integer.toHexString(e[0]));
            assertArrayEquals(new byte[194], Internals.edStreamBytes(applet()), "edStream wiped");
            // re-verify so the update reaches the stream check whatever the row left;
            // CHANGE stored the new access hash (§9.6) and the session stays verified
            byte[] reverify = e[0] == 0x23 ? Vecs.accessHashNew() : Vecs.accessHash();
            assertEquals(0x9000, inner(0x22, 0, reverify).sw(), "re-verify");
            assertEquals(
                    0x6985,
                    inner(0x33, 1, new byte[] {1}).sw(),
                    "INS " + Integer.toHexString(e[0]) + " ended the stream");
        }
    }

    @Test
    void aFailedUpdateEndsTheStream() throws Exception {
        verified();
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        assertEquals(0x6700, inner(0x33, 1, new byte[0]).sw(), "empty chunk is 6700");
        assertEquals(0x6985, inner(0x33, 1, new byte[] {1}).sw(), "the stream is gone");
    }

    @Test
    void beginAgainReplacesTheStream() throws Exception {
        // begin does not continue a stream: the old one ends silently and the new R rules
        verified();
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        assertEquals(0x9000, inner(0x33, 1, new byte[] {0x55}).sw());
        Response second = inner(0x33, 0, Vecs.pathEdSolana());
        assertEquals(0x9000, second.sw());
        // the update continues only the new stream: finish signs just the new message
        byte[] encodedA = Wei25519Map.encode(Vecs.pkEdSolana());
        byte[] stream = Ed25519.stream(Wei25519Map.encode(second.data()), encodedA, new byte[] {7});
        Response fin2 = inner(0x33, 1, Arrays.copyOfRange(stream, 0, stream.length - 1));
        assertEquals(0x9000, fin2.sw());
        Response fin3 = inner(0x33, 2, new byte[] {stream[stream.length - 1]});
        assertEquals(0x9000, fin3.sw());
        byte[] sig = Ed25519.signature(Wei25519Map.encode(second.data()), fin3.data());
        assertTrue(Ed25519.verify(encodedA, new byte[] {7}, sig), "only the new stream signed");
    }

    @Test
    void finishEndsTheStream() throws Exception {
        verified();
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        assertEquals(0x9000, inner(0x33, 2, new byte[] {9}).sw());
        assertEquals(0x6985, inner(0x33, 2, new byte[] {9}).sw(), "a second finish is 6985");
        assertArrayEquals(new byte[194], Internals.edStreamBytes(applet()));
    }

    @Test
    void recordFailureEndsTheStream() throws Exception {
        verified();
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        byte[] apdu = session.wrap(0x20, 0, 0, new byte[0]);
        apdu[apdu.length - 2] ^= 1;
        assertEquals(0x6982, Vecs.sw(card.transmit(apdu)));
        assertArrayEquals(new byte[194], Internals.edStreamBytes(applet()));
    }

    @Test
    void theStreamSurvivesManyUpdates() throws Exception {
        verified();
        Response begin = inner(0x33, 0, Vecs.pathEdSolana());
        assertEquals(0x9000, begin.sw());
        byte[] message = new byte[1000];
        Vecs.RND.nextBytes(message);
        byte[] stream =
                Ed25519.stream(
                        Wei25519Map.encode(begin.data()),
                        Wei25519Map.encode(Vecs.pkEdSolana()),
                        message);
        for (int i = 0; i < 4; i++) {
            byte[] chunk = new byte[236];
            System.arraycopy(stream, i * 236, chunk, 0, 236);
            assertEquals(0x9000, inner(0x33, 1, chunk).sw(), "update " + i);
        }
        byte[] tail = new byte[stream.length - 944];
        System.arraycopy(stream, 944, tail, 0, tail.length);
        Response fin = inner(0x33, 2, tail);
        assertEquals(0x9000, fin.sw());
        byte[] sig = Ed25519.signature(Wei25519Map.encode(begin.data()), fin.data());
        assertTrue(
                Ed25519.verify(Wei25519Map.encode(Vecs.pkEdSolana()), message, sig),
                "the 1000-byte signature verifies");
    }

    @Test
    void dirtySha512BeforeBeginDoesNotChangeTheResult() throws Exception {
        // a crashed command may leave pending bytes in the shared engine: begin resets
        // it before the nonce hash (and the stream context starts empty)
        verified();
        Internals.sha512(applet()).update(new byte[] {1, 2, 3}, (short) 0, (short) 3);
        Response begin = inner(0x33, 0, Vecs.pathEdSolana());
        assertEquals(0x9000, begin.sw());
        byte[] stream =
                Ed25519.stream(
                        Wei25519Map.encode(begin.data()),
                        Wei25519Map.encode(Vecs.pkEdSolana()),
                        new byte[0]);
        Response fin = inner(0x33, 2, stream);
        assertEquals(0x9000, fin.sw());
        byte[] sig = Ed25519.signature(Wei25519Map.encode(begin.data()), fin.data());
        assertTrue(
                Ed25519.verify(Wei25519Map.encode(Vecs.pkEdSolana()), new byte[0], sig),
                "empty-message signature verifies");
    }

    @Test
    void ecdsaSignatureVerifiesAndIsSelfChecked() throws Exception {
        verified();
        Response r = inner(0x31, 0, ecdsaData(Vecs.pathSecpEvm()));
        assertEquals(0x9000, r.sw());
        assertEquals(64, r.data().length);
        byte[] pk = Crypto.decompress(Vecs.hex(Vecs.secpTemplate("evm"), "publicKey"));
        assertTrue(Ecdsa.verify(pk, Vecs.digest(), r.data()));
        // §16.2 item 6: a corrupted engine output must fault before anything leaves
        Fault.armEcdsaFlip(1);
        assertEquals(0x6F00, inner(0x31, 0, ecdsaData(Vecs.pathSecpEvm())).sw());
    }

    @Test
    void flippedVerifyReadsAreCaught() throws Exception {
        // the double evaluation of the verified flag — word then shadow word — before
        // the output (§16.2 item 4): faulting either read is 6F00 and no signature leaves
        verified();
        Fault.arm("Session.verified", 2, Const.VERIFIED_NO);
        assertEquals(0x6F00, inner(0x31, 0, ecdsaData(Vecs.pathSecpEvm())).sw());

        verified();
        Fault.arm("Session.verifiedShadow", 1, Const.VERIFIED_NO);
        assertEquals(0x6F00, inner(0x31, 0, ecdsaData(Vecs.pathSecpEvm())).sw());
    }

    @Test
    void bip340FaultedSelfVerifyIs6F00() throws Exception {
        verified();
        byte[] data = new byte[64 + Vecs.pathSecpEvm().length];
        System.arraycopy(Vecs.message(), 0, data, 0, 32);
        System.arraycopy(Vecs.tweakBip86(), 0, data, 32, 32);
        System.arraycopy(Vecs.pathSecpEvm(), 0, data, 64, Vecs.pathSecpEvm().length);
        assertEquals(0x9000, inner(0x32, 0, data).sw());
        // x(V) == x(R) is a Bytes.equal the self-check evaluates twice; the record's
        // tag check is calls 1-2 and the cold derive's cache-path compare is call 3,
        // so the first self-check read is 4
        Fault.arm("Bytes.equal", 4, Const.CHECK_FAIL);
        assertEquals(0x6F00, inner(0x32, 0, data).sw());
    }

    @Test
    void ed25519FaultedSelfVerifyIs6F00() throws Exception {
        verified();
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        // the finish self-check compares V with R; a faulted read is a detected fault
        verified();
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        assertEquals(0x9000, inner(0x33, 1, new byte[] {1}).sw());
        Fault.arm("Bytes.equal", 3, Const.CHECK_FAIL);
        assertEquals(0x6F00, inner(0x33, 2, new byte[] {9}).sw());
    }

    @Test
    void streamChunkLengthBounds() throws Exception {
        // §9.11: update and finish carry 1..236 bytes — the bounds are checkLength's,
        // so the wrong lengths never reach the stream
        verified();
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        assertEquals(0x6700, inner(0x33, 1, new byte[0]).sw(), "empty update");
        // the failed row ended the stream; begin again for the finish bounds
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        assertEquals(0x6700, inner(0x33, 2, new byte[0]).sw(), "empty finish");
        // §9.2 pending states: the failed finish ended the stream as well
        assertEquals(0x6985, inner(0x33, 1, new byte[] {1}).sw(), "the failed finish ended it");
        assertEquals(0x6700, inner(0x33, 2, new byte[0]).sw(), "empty finish without a stream");
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
        assertEquals(0x9000, inner(0x33, 2, new byte[236]).sw(), "a 236-byte tail signs");
    }
}
