// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review3;

import java.util.Arrays;
import org.qntx.card.NdefApplet;
import org.qntx.card.WalletApplet;
import org.qntx.card.sim.Card;

/**
 * A simulator card prepared per the production procedure of §14.3: the wallet and NDEF applets
 * installed under the §2 instance AIDs, the bounded factory initialisation driven by repeated
 * GET_IDENTITY (§4.3, §14.1) and PERSONALIZE under a {@link Ca3} (§14.2). Ends BLANK; the
 * compressed identity {@code A} and certificate are read back for the host.
 */
final class Card3 {

    /** §2: the wallet applet instance AID. */
    static final byte[] WALLET_AID = H3.unhex("F0716E74780101");

    /** §2: the NDEF applet instance AID. */
    static final byte[] NDEF_AID = H3.unhex("D2760000850101");

    // §6: SELECT of the wallet applet.
    private static final byte[] SELECT = H3.cat(H3.unhex("00A4040007"), WALLET_AID, new byte[] {0});

    // §14.1: GET_IDENTITY.
    private static final byte[] GET_IDENTITY = H3.unhex("80E0000000");

    // §14.3 step 4: the personalisation tool bounds the initialisation repetitions at 16.
    private static final int INIT_BOUND = 16;

    // §15: the NDEF message is the applet-specific install data, 1–100 bytes; the applet
    // does not parse it. A short Text record ("qntx", language "en").
    private static final byte[] NDEF_MSG = H3.unhex("D101065402656E716E7478");

    private final Card card;
    private final byte[] a;
    private final byte[] cert;

    /**
     * Installs both applets, selects the wallet, runs factory initialisation and personalises under
     * {@code ca}. The card ends in {@code BLANK} with no open session.
     */
    Card3(Ca3 ca) {
        card = new Card();
        card.install(WALLET_AID, WalletApplet.class);
        card.install(NDEF_AID, NdefApplet.class, NDEF_MSG);
        select();
        a = initialise();
        byte[] resp = transmit(H3.cat(H3.unhex("80E20000A2"), ca.personalizeData(a)));
        require(swOf(resp) == 0x9000, "PERSONALIZE failed: " + H3.hex(resp));
        cert = ca.cert(a);
    }

    /** §6: selects the wallet applet; returns {@code 9000} expected. */
    final void select() {
        byte[] resp = card.transmit(SELECT);
        require(resp.length == 2 && swOf(resp) == 0x9000, "SELECT failed: " + H3.hex(resp));
    }

    /** §4.3/§14.1: repeated GET_IDENTITY until a step returns other than {@code 6283}. */
    private byte[] initialise() {
        for (int i = 0; i < INIT_BOUND; i++) {
            byte[] resp = card.transmit(GET_IDENTITY);
            int sw = swOf(resp);
            if (sw == 0x6283) {
                continue;
            }
            require(sw == 0x9000 && resp.length == 35, "GET_IDENTITY failed: " + H3.hex(resp));
            return Arrays.copyOf(resp, 33);
        }
        throw new IllegalStateException(
                "initialisation did not finish in " + INIT_BOUND + " steps");
    }

    /** One raw APDU exchange; the response is {@code data ‖ SW}. */
    byte[] transmit(byte[] apdu) {
        return card.transmit(apdu);
    }

    /** The underlying simulator card (fault instrumentation runs on its commands). */
    Card sim() {
        return card;
    }

    /** The compressed identity key {@code A} returned by GET_IDENTITY (§14.1). */
    byte[] a() {
        return a;
    }

    /** {@code ID(A)}, this card's card ID (§1). */
    byte[] id() {
        return H3.cardId(a);
    }

    /** The certificate installed by PERSONALIZE (§5.2). */
    byte[] cert() {
        return cert;
    }

    /** The last two bytes of a raw response as an unsigned status word. */
    static int swOf(byte[] resp) {
        return ((resp[resp.length - 2] & 0xFF) << 8) | (resp[resp.length - 1] & 0xFF);
    }

    /** The data half of a raw response (everything before {@code SW}). */
    static byte[] dataOf(byte[] resp) {
        return Arrays.copyOf(resp, resp.length - 2);
    }

    private static void require(boolean ok, String what) {
        if (!ok) {
            throw new IllegalStateException(what);
        }
    }
}
