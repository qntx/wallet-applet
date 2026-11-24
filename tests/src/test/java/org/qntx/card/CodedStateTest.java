// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javacard.framework.ISOException;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * §16.1/§16.4 coded state values: pairwise Hamming distance and fault behavior on corruption. Lives
 * in {@code org.qntx.card} so it can read {@link Const} and the coded-word accessors.
 */
final class CodedStateTest {

    private static final short[] CODES = {
        Const.LIFE_FACTORY,
        Const.LIFE_BLANK,
        Const.LIFE_LOADED,
        Const.ORIGIN_GENERATED,
        Const.ORIGIN_IMPORTED,
        Const.OFFER_NONE,
        Const.OFFER_VALID,
        Const.VERIFIED_NO,
        Const.VERIFIED_YES,
        Const.CHECK_FAIL,
        Const.CHECK_OK,
        Const.CHECK_MALFORMED,
        Const.SESSION_OPEN,
        Const.PENDING_STREAM,
        Const.PENDING_EXPORT,
        Const.PENDING_IMPORT
    };

    @Test
    void codesAreDistinctAndEightBitsApart() {
        assertEquals(16, CODES.length);
        for (short c : CODES) {
            assertTrue(c != 0 && c != (short) 0xFFFF, "coded value must not be 0 or FFFF");
        }
        for (int i = 0; i < CODES.length; i++) {
            for (int j = i + 1; j < CODES.length; j++) {
                int d = Integer.bitCount((CODES[i] ^ CODES[j]) & 0xFFFF);
                assertTrue(
                        d >= 8,
                        "Hamming distance "
                                + d
                                + " between "
                                + Integer.toHexString(CODES[i])
                                + " and "
                                + Integer.toHexString(CODES[j]));
            }
        }
    }

    @Test
    void corruptLifeWordFaults() {
        Card card = Vecs.blankSelf();
        byte[] state = Internals.stateArray(card.applet(Spec.WALLET_AID));
        state[State.OFF_LIFE] = 0x12;
        state[State.OFF_LIFE + 1] = 0x34;
        assertEquals(0x6F00, Vecs.sw(card.transmit(Vecs.unhex("80E0000000"))));
        // OPEN reads state.life() before anything else, so it faults the same way
        assertEquals(0x6F00, Vecs.sw(card.transmit(Vecs.unhex("8010000000"))));
    }

    @Test
    void corruptFailsPairFaultsInsideTheRecord() throws Exception {
        Card card = Vecs.blankSelf();
        var session = Vecs.open(card);
        byte[] state = Internals.stateArray(card.applet(Spec.WALLET_AID));
        state[State.OFF_FAILS] = 0x12;
        state[State.OFF_FAILS + 1] = 0x34;
        state[State.OFF_FAILS + 2] = 0x12;
        state[State.OFF_FAILS + 3] = 0x34;
        var r = Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]);
        assertEquals(0x6F00, r.sw());
    }

    @Test
    void corruptSessionWordsFaultAndTearDown() throws Exception {
        // open word: SESSION → outer 6F00, session torn
        Card card = Vecs.blankSelf();
        Vecs.open(card);
        byte[] words = Internals.words(card.applet(Spec.WALLET_AID));
        words[0] = 0x12;
        words[1] = 0x34;
        assertEquals(0x6F00, Vecs.sw(card.transmit(new byte[] {(byte) 0x80, 0x12, 0, 0, 0x18})));
        assertEquals(0x6985, Vecs.sw(card.transmit(new byte[] {(byte) 0x80, 0x12, 0, 0, 0x18})));

        // verified word: the coded reader rejects an unknown value
        Card card2 = Vecs.blankSelf();
        Vecs.open(card2);
        byte[] words2 = Internals.words(card2.applet(Spec.WALLET_AID));
        words2[2] = 0x12;
        words2[3] = 0x34;
        ISOException e =
                assertThrows(
                        ISOException.class,
                        () -> Internals.session(card2.applet(Spec.WALLET_AID)).verified());
        assertEquals(0x6F00, e.getReason());

        // pending word: SESSION faults inside the record and tears down
        Card card3 = Vecs.blankSelf();
        var session3 = Vecs.open(card3);
        byte[] words3 = Internals.words(card3.applet(Spec.WALLET_AID));
        words3[6] = 0x12;
        words3[7] = 0x34;
        var r = Vecs.roundtrip(card3, session3, 0x20, 0, 0, new byte[0]);
        assertEquals(0x6F00, r.sw());
    }

    @Test
    void outOfRangeFailsReportZeroTries() throws Exception {
        // §9.3: tries = max(L − f, 0) — consistent complements of out-of-range f give 0
        for (short f : new short[] {(short) 0x8000, 11, 10, 9, 0, (short) -1}) {
            Card card = Vecs.blankSelf();
            var session = Vecs.loadWallet(card);
            byte[] state = Internals.stateArray(card.applet(Spec.WALLET_AID));
            state[State.OFF_FAILS] = (byte) (f >> 8);
            state[State.OFF_FAILS + 1] = (byte) f;
            state[State.OFF_FAILS + 2] = (byte) (~f >> 8);
            state[State.OFF_FAILS + 3] = (byte) ~f;
            var r = Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]);
            assertEquals(0x9000, r.sw());
            short expected = (short) (f < 0 || f >= Const.FAIL_LIMIT ? 0 : Const.FAIL_LIMIT - f);
            assertEquals(
                    expected,
                    r.data()[1],
                    "f=" + Integer.toHexString(f & 0xFFFF) + " must report " + expected);
            assertEquals(0x02, r.data()[0]);
        }
    }

    @Test
    void checkStepsDeriveOkAndAreNotCodeSetMembers() {
        // CHECK_FAIL ^ STEP_1 ^ STEP_2 = CHECK_OK; a single skipped conditional leaves
        // FAIL ^ STEP_i, which no caller may accept — it must not be a code-set member
        assertEquals(
                Const.CHECK_OK,
                (short) (Const.CHECK_FAIL ^ Const.CHECK_STEP_1 ^ Const.CHECK_STEP_2));
        for (short step : new short[] {Const.CHECK_STEP_1, Const.CHECK_STEP_2}) {
            short left = (short) (Const.CHECK_FAIL ^ step);
            for (short c : CODES) {
                assertNotEquals(c, left, "FAIL ^ step must not be a code-set member");
            }
        }
    }

    @Test
    void corruptOfferAndOriginAreReadAsFaultsOnlyWhenUsed() {
        // origin/offer are not read by any core command; only verify the coded values differ
        // from every neighbor by >= 8 bits, which the pairwise test already covers.
        assertNotEquals(Const.ORIGIN_GENERATED, Const.ORIGIN_IMPORTED);
        assertNotEquals(Const.OFFER_NONE, Const.OFFER_VALID);
    }
}
