// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review2;

import org.qntx.card.NdefApplet;
import org.qntx.card.WalletApplet;
import org.qntx.card.sim.Card;

/**
 * A simulator card prepared per spec section 14.3: wallet and NDEF applets installed, SELECT,
 * GET_IDENTITY-driven initialisation (bounded at 16 steps), PERSONALIZE under the review2 CA, then
 * OPEN sessions through {@link Session2}.
 */
final class Card2 {
    private static final byte[] WALLET_AID = H2.hex("F0716E74780101");
    private static final byte[] NDEF_AID = H2.hex("D2760000850101");
    private static final byte[] NDEF_MSG = H2.hex("D101055504716E7478");
    private static final byte[] SELECT =
            H2.cat(new byte[] {0x00, (byte) 0xA4, 0x04, 0x00, 0x07}, WALLET_AID, new byte[] {0x00});
    private static final byte[] GET_IDENTITY = H2.hex("80E0000000");

    final Card sim = new Card();
    private byte[] identity; // compressed A, learned at initialisation

    Card2() {
        sim.install(WALLET_AID, WalletApplet.class);
        sim.install(NDEF_AID, NdefApplet.class, NDEF_MSG);
    }

    /** SELECT of spec section 6; also the step before GET_IDENTITY (spec section 14.3). */
    void select() {
        byte[] resp = sim.transmit(SELECT);
        if (Session2.swOf(resp) != 0x9000) {
            throw new IllegalStateException("SELECT failed: " + H2.hex(resp));
        }
    }

    /**
     * Initialisation of spec section 4.3: repeat GET_IDENTITY until it stops returning 6283,
     * bounded at 16; returns the compressed identity key A.
     */
    byte[] initialise() {
        for (int step = 0; step < 16; step++) {
            byte[] resp = sim.transmit(GET_IDENTITY);
            int sw = Session2.swOf(resp);
            if (sw == 0x6283) {
                continue;
            }
            if (sw != 0x9000) {
                throw new IllegalStateException("GET_IDENTITY failed: " + H2.hex(resp));
            }
            byte[] a = Session2.dataOf(resp);
            if (a.length != 33) {
                throw new IllegalStateException("GET_IDENTITY length: " + a.length);
            }
            identity = a;
            return a;
        }
        throw new IllegalStateException("initialisation did not complete in 16 steps");
    }

    /** PERSONALIZE of spec section 14.2 under the review2 CA. */
    void personalise(Ca2 ca) {
        byte[] cert = ca.issue(identity);
        byte[] apdu =
                H2.cat(
                        new byte[] {(byte) 0x80, (byte) 0xE2, 0x00, 0x00, (byte) 0xA2},
                        cert,
                        ca.publicKey());
        byte[] resp = sim.transmit(apdu);
        if (Session2.swOf(resp) != 0x9000) {
            throw new IllegalStateException("PERSONALIZE failed: " + H2.hex(resp));
        }
    }

    /** SELECT + initialisation + PERSONALIZE: a BLANK card under the review2 CA. */
    void blank(Ca2 ca) {
        select();
        initialise();
        personalise(ca);
    }

    byte[] identity() {
        return identity.clone();
    }

    /** OPEN of spec section 8.1 after re-selecting the wallet applet. */
    Session2 open(Ca2 ca) {
        select();
        return Session2.open(sim, ca);
    }
}
