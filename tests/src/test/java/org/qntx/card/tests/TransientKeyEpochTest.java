// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javacard.framework.Applet;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import org.junit.jupiter.api.Test;
import org.qntx.card.Internals;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;

/**
 * Simulator patch 13 (architecture.md §8): a {@code CLEAR_ON_DESELECT} EC key's domain parameters
 * die with the selection epoch — deselect and card reset both clear them — and {@code setS} on the
 * domainless key throws {@code CryptoException.ILLEGAL_VALUE}, the behavior the
 * probe-transient-reselect card run measured. {@code WalletApplet.select()} re-loads both domains,
 * so the wallet-level check replays the whole signing surface across deselection and a power cycle.
 */
final class TransientKeyEpochTest {

    private static final byte[] S = new byte[32];

    @Test
    void deselectClearsTransientEcDomains() {
        Card card = Vecs.factory();
        Applet applet = card.applet(Spec.WALLET_AID);
        ECPrivateKey eph = Internals.ephKey(applet);
        ECPrivateKey scalar = Internals.scalarKey(applet);
        eph.setS(S, (short) 0, (short) 32); // select() loaded the domains
        scalar.setS(S, (short) 0, (short) 32);
        card.deselectApplet();
        assertIllegalValue(eph);
        assertIllegalValue(scalar);
        card.transmit(Spec.SELECT); // select() loads them again
        eph.setS(S, (short) 0, (short) 32);
        scalar.setS(S, (short) 0, (short) 32);
        card.powerCycle();
        assertIllegalValue(eph);
        assertIllegalValue(scalar);
        card.transmit(Spec.SELECT);
        eph.setS(S, (short) 0, (short) 32);
        scalar.setS(S, (short) 0, (short) 32);
    }

    @Test
    void signingSurvivesReselectionAndPowerCycle() throws Exception {
        Card card = Vecs.factory();
        Vecs.blankFor(card, Vecs.cardA(card));
        Vecs.loadWallet(card);
        card.transmit(Spec.SELECT); // a deselect↔select cycle before the session
        signSuite(card);
        card.powerCycle();
        card.transmit(Spec.SELECT);
        signSuite(card);
    }

    /** OPEN, VERIFY, both PUBLIC_KEY curves and all three signers over a fresh session. */
    private static void signSuite(Card card) throws Exception {
        Session session = Vecs.open(card);
        assertOk(Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()), "VERIFY");
        assertOk(Vecs.roundtrip(card, session, 0x30, 0, 0, Vecs.pathSecpEvm()), "PUBLIC_KEY secp");
        assertOk(Vecs.roundtrip(card, session, 0x30, 1, 0, Vecs.pathEdSolana()), "PUBLIC_KEY ed");
        assertOk(
                Vecs.roundtrip(
                        card, session, 0x31, 0, 0, concat(Vecs.digest(), Vecs.pathSecpEvm())),
                "SIGN_ECDSA");
        assertOk(
                Vecs.roundtrip(
                        card,
                        session,
                        0x32,
                        0,
                        0,
                        concat(Vecs.message(), Vecs.tweakBip86(), Vecs.pathSecpEvm())),
                "SIGN_BIP340");
        assertOk(Vecs.roundtrip(card, session, 0x33, 0, 0, Vecs.pathEdSolana()), "SIGN_ED begin");
        assertOk(Vecs.roundtrip(card, session, 0x33, 1, 0, new byte[200]), "SIGN_ED update");
        assertOk(Vecs.roundtrip(card, session, 0x33, 2, 0, new byte[17]), "SIGN_ED finish");
    }

    private static void assertIllegalValue(ECPrivateKey key) {
        CryptoException e =
                assertThrows(CryptoException.class, () -> key.setS(S, (short) 0, (short) 32));
        assertEquals(CryptoException.ILLEGAL_VALUE, e.getReason());
    }

    private static void assertOk(Response r, String what) {
        assertEquals(0x9000, r.sw(), what);
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
}
