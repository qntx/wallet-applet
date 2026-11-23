// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * §9.2 inner-dispatch gates and §8.5 pending words that no core-stage command can reach through the
 * table alone: the dispatch tables and session words are driven directly so the gate logic itself
 * is exercised rather than only its reachable rows.
 */
final class GateTest {

    @Test
    void lifeGateRejectsADisallowedRow() throws Exception {
        // deny STATUS in every life state: STATUS must then answer 6985 inside the record
        Card card = Vecs.blankSelf();
        var session = Vecs.open(card);
        byte saved = Const.INNER_LIFE[0];
        try {
            Const.INNER_LIFE[0] = 0;
            assertEquals(0x6985, Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]).sw());
        } finally {
            Const.INNER_LIFE[0] = saved;
        }
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]).sw());
    }

    @Test
    void verifiedGateRejectsAnUnverifiedSession() throws Exception {
        // mark STATUS as verification-gated: the unverified session must get 6982
        Card card = Vecs.blankSelf();
        var session = Vecs.open(card);
        byte saved = Const.INNER_VERIFIED[0];
        try {
            Const.INNER_VERIFIED[0] = 1;
            assertEquals(0x6982, Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]).sw());
        } finally {
            Const.INNER_VERIFIED[0] = saved;
        }
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]).sw());
    }

    @Test
    void pendingWordsAreClearedByANonContinuation() throws Exception {
        Card card = Vecs.blankSelf();
        var session = Vecs.open(card);
        byte[] words = Internals.words(card.applet(Spec.WALLET_AID));
        short[] codes = {Const.PENDING_STREAM, Const.PENDING_EXPORT, Const.PENDING_IMPORT};
        for (short code : codes) {
            words[6] = (byte) (code >>> 8);
            words[7] = (byte) code;
            // STATUS continues none of the pending states: the word must be cleared
            assertEquals(0x9000, Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]).sw());
            assertEquals(0, words[6] | words[7], "pending word not cleared");
        }
    }

    @Test
    void continuationInsKeepsThePendingWord() throws Exception {
        // each pending state is continued only by its own continuation command (§9.2):
        // the word must survive beginDispatch, and endDispatch clears it when the
        // continuation itself fails (the INS is unknown in core -> inner 6D00)
        Card card = Vecs.blankSelf();
        var session = Vecs.open(card);
        byte[] words = Internals.words(card.applet(Spec.WALLET_AID));
        short[][] cont = {
            {Const.PENDING_STREAM, 0x33, 1},
            {Const.PENDING_STREAM, 0x33, 2},
            {Const.PENDING_EXPORT, 0x41, 1},
            {Const.PENDING_IMPORT, 0x42, 1},
        };
        for (short[] c : cont) {
            words[6] = (byte) (c[0] >>> 8);
            words[7] = (byte) c[0];
            var r = Vecs.roundtrip(card, session, c[1], c[2], 0, new byte[0]);
            // the stream and export continuations fail BLANK's life-state check (6985);
            // IMPORT allows BLANK, so an empty body reaches the length check (6700)
            assertEquals(
                    c[0] == Const.PENDING_IMPORT ? 0x6700 : 0x6985,
                    r.sw(),
                    "pending " + Integer.toHexString(c[0]));
            assertEquals(0, words[6] | words[7], "pending word not cleared after failed command");
        }
    }

    @Test
    void verifiedYesWordSatisfiesTheGate() throws Exception {
        // drive the coded verified word to VERIFIED_YES and gate STATUS: the gate must open
        Card card = Vecs.blankSelf();
        var session = Vecs.open(card);
        byte[] words = Internals.words(card.applet(Spec.WALLET_AID));
        words[2] = (byte) (Const.VERIFIED_YES >>> 8);
        words[3] = (byte) Const.VERIFIED_YES;
        byte saved = Const.INNER_VERIFIED[0];
        try {
            Const.INNER_VERIFIED[0] = 1;
            assertEquals(0x9000, Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]).sw());
        } finally {
            Const.INNER_VERIFIED[0] = saved;
        }
    }

    @Test
    void unknownInnerInsRowIs6D00() throws Exception {
        // an empty inner table makes every inner INS unknown: STATUS -> 6D00
        Card card = Vecs.blankSelf();
        var session = Vecs.open(card);
        byte saved = Const.INNER_INS[0];
        try {
            Const.INNER_INS[0] = 0x7F;
            assertEquals(0x6D00, Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]).sw());
        } finally {
            Const.INNER_INS[0] = saved;
        }
    }

    @Test
    void loadedLifeUsesTheLoadedBit() throws Exception {
        // drive the life word to LOADED: OPEN and STATUS keep working, and the LOADED
        // table bit must be the one the inner gate consults (§9.2)
        Card card = Vecs.blankSelf();
        javacard.framework.Applet applet = card.applet(Spec.WALLET_AID);
        byte[] state = Internals.stateArray(applet);
        state[0] = (byte) (Const.LIFE_LOADED >>> 8);
        state[1] = (byte) Const.LIFE_LOADED;
        var session = Vecs.open(card);
        var r = Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]);
        assertEquals(0x9000, r.sw());
        assertEquals(0x02, r.data()[0] & 0xFF);
        // a row restricted to BLANK denies STATUS on the LOADED card
        byte saved = Const.INNER_LIFE[0];
        try {
            Const.INNER_LIFE[0] = (byte) Const.LIFE_BIT_BLANK;
            assertEquals(0x6985, Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]).sw());
        } finally {
            Const.INNER_LIFE[0] = saved;
        }
    }

    @Test
    void aLifeValueWithoutABitDeniesTheRow() throws Exception {
        // a coded life that is neither BLANK nor LOADED maps to bit 0: the gate
        // denies the row without faulting (§9.2)
        Card card = Vecs.blankSelf();
        var session = Vecs.open(card);
        byte[] state = Internals.stateArray(card.applet(Spec.WALLET_AID));
        state[State.OFF_LIFE] = (byte) (Const.LIFE_FACTORY >>> 8);
        state[State.OFF_LIFE + 1] = (byte) Const.LIFE_FACTORY;
        assertEquals(0x6985, Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]).sw());
    }

    @Test
    void statusWithDataIs6700() throws Exception {
        // §9.2 checking order: a known INS whose data length does not fit the command
        Card card = Vecs.blankSelf();
        var session = Vecs.open(card);
        assertEquals(0x6700, Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[] {1}).sw());
    }

    @Test
    void innerP1AndP2AreCheckedSeparately() throws Exception {
        Card card = Vecs.blankSelf();
        var session = Vecs.open(card);
        assertEquals(0x6A86, Vecs.roundtrip(card, session, 0x20, 1, 0, new byte[0]).sw());
        assertEquals(0x6A86, Vecs.roundtrip(card, session, 0x20, 0, 1, new byte[0]).sw());
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]).sw());
    }
}
