// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.AESKey;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * Direct calls into the package-private {@link Session}: the §9.2 pending-state machine and the
 * coded word decoding cannot be observed through APDUs in core stage (no continuation command
 * exists yet), so the words are set and the methods are invoked directly.
 */
final class SessionDirectTest {

    private static Session open(Card card) throws Exception {
        Vecs.open(card);
        return Internals.session(card.applet(Spec.WALLET_AID));
    }

    private static byte[] words(Card card) {
        return Internals.words(card.applet(Spec.WALLET_AID));
    }

    private static void setPending(byte[] words, short code) {
        words[6] = (byte) (code >>> 8);
        words[7] = (byte) code;
    }

    private static short pendingOf(byte[] words) {
        return (short) (((words[6] & 0xFF) << 8) | (words[7] & 0xFF));
    }

    @Test
    void beginDispatchReturnsTheContinuationCode() throws Exception {
        Card card = Vecs.blankSelf();
        Session s = open(card);
        byte[] w = words(card);
        setPending(w, (short) 0);
        assertEquals(0, s.beginDispatch((byte) 0x20, (byte) 0));

        // §9.2: each pending state is continued only by its own continuation command
        short[][] table = {
            {Const.PENDING_STREAM, Const.INS_SIGN_ED25519, 1, Const.PENDING_STREAM},
            {Const.PENDING_STREAM, Const.INS_SIGN_ED25519, 2, Const.PENDING_STREAM},
            {Const.PENDING_STREAM, Const.INS_SIGN_ED25519, 0, 0},
            {Const.PENDING_STREAM, Const.INS_STATUS, 0, 0},
            {Const.PENDING_STREAM, Const.INS_EXPORT, 1, 0},
            {Const.PENDING_EXPORT, Const.INS_EXPORT, 1, Const.PENDING_EXPORT},
            {Const.PENDING_EXPORT, Const.INS_EXPORT, 0, 0},
            {Const.PENDING_EXPORT, Const.INS_SIGN_ED25519, 1, 0},
            {Const.PENDING_IMPORT, Const.INS_IMPORT, 1, Const.PENDING_IMPORT},
            {Const.PENDING_IMPORT, Const.INS_IMPORT, 0, 0},
            {Const.PENDING_IMPORT, Const.INS_STATUS, 0, 0},
            {Const.PENDING_IMPORT, Const.INS_STATUS, 1, 0},
            {Const.PENDING_EXPORT, Const.INS_STATUS, 1, 0},
            {Const.PENDING_STREAM, Const.INS_STATUS, 1, 0},
        };
        for (short[] row : table) {
            setPending(w, row[0]);
            short cont = s.beginDispatch((byte) row[1], (byte) row[2]);
            assertEquals(row[3], cont, "pending " + Integer.toHexString(row[0]));
            // a non-continuation command ends the pending state it does not continue
            assertEquals(row[3], pendingOf(w), "word for " + Integer.toHexString(row[0]));
        }
    }

    @Test
    void beginDispatchFaultsOnACorruptWord() throws Exception {
        Card card = Vecs.blankSelf();
        Session s = open(card);
        byte[] w = words(card);
        setPending(w, (short) 0x1234);
        ISOException e =
                assertThrows(ISOException.class, () -> s.beginDispatch((byte) 0x20, (byte) 0));
        assertEquals(Const.SW_FAULT, e.getReason());
    }

    @Test
    void endDispatchClearsEverythingButSignP1Success() throws Exception {
        Card card = Vecs.blankSelf();
        Session s = open(card);
        byte[] w = words(card);
        // §9.2: a continuation ends its pending state unless it is a successful SIGN P1=1
        short[][] table = {
            {Const.PENDING_STREAM, Const.INS_SIGN_ED25519, 1, (short) 0x9000, Const.PENDING_STREAM},
            {Const.PENDING_STREAM, Const.INS_SIGN_ED25519, 1, (short) 0x6D00, 0},
            {Const.PENDING_STREAM, Const.INS_SIGN_ED25519, 2, (short) 0x9000, 0},
            {Const.PENDING_STREAM, Const.INS_STATUS, 1, (short) 0x9000, 0},
            {Const.PENDING_EXPORT, Const.INS_EXPORT, 1, (short) 0x9000, 0},
            // the keep-rule is purely SIGN+P1=1+9000; which pending state it continues
            // was already resolved by beginDispatch
            {Const.PENDING_EXPORT, Const.INS_SIGN_ED25519, 1, (short) 0x9000, Const.PENDING_EXPORT},
            {Const.PENDING_IMPORT, Const.INS_IMPORT, 1, (short) 0x9000, 0},
        };
        for (short[] row : table) {
            setPending(w, row[0]);
            s.endDispatch(row[0], (byte) row[1], (byte) row[2], row[3]);
            assertEquals(row[4], pendingOf(w), "pending " + Integer.toHexString(row[0]));
        }
        // a zero pending argument leaves the word alone
        setPending(w, Const.PENDING_IMPORT);
        s.endDispatch((short) 0, Const.INS_SIGN_ED25519, (byte) 1, (short) 0x9000);
        assertEquals(Const.PENDING_IMPORT, pendingOf(w));
        setPending(w, Const.PENDING_STREAM);
        s.endDispatch((short) 0, Const.INS_STATUS, (byte) 0, (short) 0x9000);
        assertEquals(Const.PENDING_STREAM, pendingOf(w));
    }

    @Test
    void verifiedDecodesTheCodedWord() throws Exception {
        Card card = Vecs.blankSelf();
        Session s = open(card);
        byte[] w = words(card);
        w[2] = (byte) (Const.VERIFIED_YES >>> 8);
        w[3] = (byte) Const.VERIFIED_YES;
        assertEquals(Const.VERIFIED_YES, s.verified());
        w[2] = (byte) (Const.VERIFIED_NO >>> 8);
        w[3] = (byte) Const.VERIFIED_NO;
        assertEquals(Const.VERIFIED_NO, s.verified());
        w[2] = 0;
        w[3] = 0;
        assertEquals(Const.VERIFIED_NO, s.verified());
        w[2] = 0x12;
        w[3] = 0x34;
        ISOException e = assertThrows(ISOException.class, s::verified);
        assertEquals(Const.SW_FAULT, e.getReason());
    }

    @Test
    void teardownClearsEveryWordAndKey() throws Exception {
        Card card = Vecs.blankSelf();
        Session s = open(card);
        Applet applet = card.applet(Spec.WALLET_AID);
        byte[] w = words(card);
        // every word nonzero before the tear: pending is the only one not set by OPEN
        setPending(w, Const.PENDING_STREAM);
        w[2] = (byte) (Const.VERIFIED_YES >>> 8);
        w[3] = (byte) Const.VERIFIED_YES;
        w[4] = 0;
        w[5] = 7;
        s.teardown();
        assertArrayEquals(new byte[14], w);
        byte[] key = new byte[16];
        for (String name : new String[] {"kce", "kcm", "kre", "krm"}) {
            AESKey k = Internals.sessionKey(applet, name);
            k.getKey(key, (short) 0);
            assertArrayEquals(new byte[16], key, name + " not zeroed");
        }
    }

    @Test
    void aCommandRoundTripWipesScratch() throws Exception {
        // §16.3 item 3: session() wipes Mem.W before the response is wrapped, so no
        // record plaintext or key material survives the command
        Card card = Vecs.blankSelf();
        var session = Vecs.open(card);
        Applet applet = card.applet(Spec.WALLET_AID);
        byte[] w = Internals.wBytes(applet);
        w[0] = 0x5A; // dirty the scratch so the wipe is observable
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]).sw());
        assertArrayEquals(new byte[w.length], w);
    }

    @Test
    void afterResponseAdvancesTheCounterOrTearsDown() throws Exception {
        Card card = Vecs.blankSelf();
        Session s = open(card);
        byte[] w = words(card);
        s.afterResponse(ISO7816.SW_NO_ERROR);
        assertEquals(1, w[5] & 0xFF);
        assertEquals(0, w[4]);
        // ctr = 0xFFFF on the wire tears the session down (§8.5)
        w[4] = (byte) 0xFF;
        w[5] = (byte) 0xFF;
        s.afterResponse(ISO7816.SW_NO_ERROR);
        assertArrayEquals(new byte[14], w);
    }
}
