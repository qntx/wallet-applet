// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review;

import static org.qntx.card.review.ReviewHost.*;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.Arrays;
import org.qntx.card.NdefApplet;
import org.qntx.card.WalletApplet;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.TornException;

/**
 * Card lifecycle for the review: install, SELECT, initialisation (U/F setups), PERSONALIZE under
 * the review CA (B), CREATE (L1/L2/L3), VERIFY-with-waits (v) and raw persistent-state injection
 * for the setup-only cells (H9, H10, E11, F31).
 *
 * <p>State injection: the simulator exposes the installed {@link WalletApplet} instance; its
 * private field {@code state} (class {@code State}) holds one persistent {@code byte[]} also called
 * {@code state}. Review-known offsets from the lead's handoff: {@code life} at 0 (u16 coded),
 * {@code fails} at 2..6 (f u16 then its complement), {@code edCounter} at 10..14 (u32 BE). The
 * bytes are written directly between commands — this is setup injection, standing in for a torn or
 * corrupted NVM image, not a card operation.
 */
final class ReviewCard {

    /** The review CA: a fixed BouncyCastle secp256k1 key pair chosen by the reviewer. */
    static final class Ca {
        final BigInteger priv;
        final byte[] pub65;

        Ca(BigInteger priv) {
            this.priv = priv;
            this.pub65 = uncomp(g().multiply(priv));
        }

        byte[] sign(byte[] msg) {
            return ecdsaSign(priv, msg);
        }

        byte[] issue(byte[] a33) {
            return concat(a33, sign(concat(LABEL_CERT, a33)));
        }
    }

    /** Review CA, fixed for reproducibility (any scalar in [1, n−1] would do). */
    static final Ca CA =
            new Ca(
                    new BigInteger(
                            "5ED0C0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DEC0DE", 16));

    /** The review NDEF message: an NDEF URI record (9 B, within the 1–100 B bound of §15). */
    static final byte[] NDEF_MSG = unhex("D101055504716E7478");

    final Card card = new Card();
    byte[] cardA;
    byte[] cert;

    /** U setup: wallet + NDEF applets installed, nothing but SELECT sent yet. */
    static ReviewCard uninitialised() {
        ReviewCard c = new ReviewCard();
        c.card.install(AID_WALLET, WalletApplet.class);
        c.card.install(AID_NDEF, NdefApplet.class, NDEF_MSG);
        return c;
    }

    /** F setup: U driven to the end of initialisation (§4.3, §14.1). Returns A. */
    byte[] factory() {
        transmit(SELECT_WALLET);
        byte[] resp;
        int calls = 0;
        do {
            resp = transmit(unhex("80E0000000"));
            calls++;
            if (calls > 20) {
                throw new IllegalStateException("initialisation not done after 20 GET_IDENTITY");
            }
        } while (sw(resp) == 0x6283);
        if (sw(resp) != 0x9000) {
            throw new IllegalStateException(
                    "GET_IDENTITY " + String.format("%04X", sw(resp)) + " during init");
        }
        cardA = respData(resp);
        return cardA;
    }

    /** B setup: F personalised with the review CA (§14.2). */
    ReviewCard blank() {
        return blank(CA);
    }

    ReviewCard blank(Ca ca) {
        factory();
        cert = ca.issue(cardA);
        byte[] data = concat(cert, ca.pub65);
        byte[] resp =
                transmit(
                        concat(
                                unhex("80E20000"),
                                new byte[] {(byte) data.length},
                                data,
                                new byte[] {0x00}));
        if (sw(resp) != 0x9000) {
            throw new IllegalStateException("PERSONALIZE " + String.format("%04X", sw(resp)));
        }
        return this;
    }

    /** A session opened on this card against the review CA. */
    ReviewSession open() {
        ReviewSession s = new ReviewSession(card::transmit, CA.pub65);
        byte[] r = s.open();
        if (r == null) {
            throw new IllegalStateException("OPEN failed: " + s.openFailure);
        }
        cert = s.cert;
        return s;
    }

    /** CREATE P1=0x01 (import) inside a fresh session (§9.4). */
    ReviewSession create(byte[] seed, byte[] accessHash, byte[]... others) {
        ReviewSession s = open();
        byte[] data = concat(accessHash, seed, concat(others));
        ReviewSession.Inner r = s.cmd((byte) 0x21, (byte) 0x01, (byte) 0, data);
        if (r.sw != 0x9000) {
            throw new IllegalStateException("CREATE " + String.format("%04X", r.sw));
        }
        return s;
    }

    /** L1: LOADED, c = 1 (no other members). Session returned stays verified (§9.4). */
    ReviewSession loaded(byte[] seed, byte[] accessHash) {
        return create(seed, accessHash);
    }

    /**
     * Drives f wrong VERIFYs inside one session (setup for the `Lx f=k` cells): for f ≥ F = 3 each
     * attempt needs W = 15 WAITs first (§7.3, §9.15).
     */
    static void failTo(ReviewSession s, byte[] wrongHash, int f) {
        for (int i = 0; i < f; i++) {
            if (i >= 3) {
                waitW(s);
            }
            ReviewSession.Inner r = s.cmd((byte) 0x22, (byte) 0, (byte) 0, wrongHash);
            if ((r.sw & 0xFFF0) != 0x63C0) {
                throw new IllegalStateException(
                        "wrong VERIFY at f=" + i + " gave " + String.format("%04X", r.sw));
            }
        }
    }

    static ReviewSession.Inner inner(
            ReviewSession s, byte ins, byte p1, byte p2, byte[] data, int expectSw) {
        ReviewSession.Inner r = s.cmd(ins, p1, p2, data);
        if (r.sw != expectSw) {
            throw new IllegalStateException(
                    String.format("INS %02X expected %04X got %04X", ins, expectSw, r.sw));
        }
        return r;
    }

    /** Waits W units (§9.15) inside the session. */
    static void waitW(ReviewSession s) {
        for (int i = 0; i < 15; i++) {
            inner(s, (byte) 0x25, (byte) 0, (byte) 0, new byte[0], 0x9000);
        }
    }

    byte[] transmit(byte[] apdu) {
        return card.transmit(apdu);
    }

    byte[] transmitSw(byte[] apdu, int expectSw) {
        byte[] r = card.transmit(apdu);
        if (sw(r) != expectSw) {
            throw new IllegalStateException(
                    String.format("expected %04X got %04X", expectSw, sw(r)));
        }
        return r;
    }

    /** Wraps an unchecked transmit so callers can ignore TornException where expected. */
    byte[] tryTransmit(byte[] apdu) {
        try {
            return card.transmit(apdu);
        } catch (TornException t) {
            return null;
        }
    }

    // setup-only persistent-state injection

    /**
     * The persistent state byte[] inside the WalletApplet's {@code state} object (offsets in the
     * class javadoc). Writes here are direct byte stores between commands — they emulate a
     * corrupted or torn NVM image, they are not card operations.
     */
    byte[] stateArray() {
        try {
            Object applet = card.applet(AID_WALLET);
            Field outer = WalletApplet.class.getDeclaredField("state");
            outer.setAccessible(true);
            Object stateObj = outer.get(applet);
            Field inner = stateObj.getClass().getDeclaredField("state");
            inner.setAccessible(true);
            return (byte[]) inner.get(stateObj);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("state injection failed", e);
        }
    }

    /** Injects fails = f with the correct complement at offsets 2..6. */
    void injectFails(int f) {
        byte[] st = stateArray();
        st[2] = (byte) (f >>> 8);
        st[3] = (byte) f;
        int comp = (~f) & 0xFFFF;
        st[4] = (byte) (comp >>> 8);
        st[5] = (byte) comp;
    }

    /** Injects a raw fails pair (for the corrupted-complement cell H10). */
    void injectFailsPair(int f, int complement) {
        byte[] st = stateArray();
        st[2] = (byte) (f >>> 8);
        st[3] = (byte) f;
        st[4] = (byte) (complement >>> 8);
        st[5] = (byte) complement;
    }

    /** Injects edCounter (u32 BE at 10..14). */
    void injectEdCounter(long v) {
        byte[] st = stateArray();
        byte[] e = u32(v);
        System.arraycopy(e, 0, st, 10, 4);
    }

    long readEdCounter() {
        byte[] st = stateArray();
        long v = 0;
        for (int i = 10; i < 14; i++) {
            v = (v << 8) | (st[i] & 0xFF);
        }
        return v;
    }

    static boolean eq(byte[] a, byte[] b) {
        return Arrays.equals(a, b);
    }
}
