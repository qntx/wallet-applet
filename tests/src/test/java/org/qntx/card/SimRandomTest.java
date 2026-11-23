// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Arrays;
import javacard.framework.Applet;
import javacard.security.RandomData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Response;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Rng;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The simulator patch that seeds every card's {@code SecureRandom} with fresh OS entropy: two
 * {@link Card}s draw different identity keys and different link keys — real cards differ, and the
 * transfer tests below need distinct peers. {@link Rng#fix} still takes over applet {@code
 * RandomData} engines.
 */
final class SimRandomTest {

    @AfterEach
    void disarm() {
        Rng.reset();
    }

    @Test
    void cardsDrawDifferentIdentityKeys() {
        Card c1 = Vecs.factory();
        Card c2 = Vecs.factory();
        assertFalse(
                Arrays.equals(Vecs.cardA(c1), Vecs.cardA(c2)),
                "two sim cards generated the same identity key");
    }

    @Test
    void cardsDrawDifferentLinkKeys() throws Exception {
        assertFalse(
                Arrays.equals(offerLk(), offerLk()), "two sim cards generated the same link key");
    }

    /** OFFER's {@code LK} on a fresh BLANK card — the link pair generated at install. */
    private static byte[] offerLk() throws Exception {
        Card card = Vecs.blankSelf();
        org.qntx.card.host.Session session = Vecs.open(card);
        Response r = Vecs.roundtrip(card, session, 0x40, 0, 0, new byte[0]);
        assertEquals(0x9000, r.sw(), "OFFER");
        return Arrays.copyOf(r.data(), 65);
    }

    @Test
    void rngFixStillFixesRandomDataOutputs() {
        Card card = Vecs.factory();
        Applet applet = card.applet(Spec.WALLET_AID);
        RandomData engine = (RandomData) Internals.memField(applet, "random");
        byte[] block = new byte[32];
        for (int i = 0; i < block.length; i++) {
            block[i] = (byte) (0xC0 + i);
        }
        Rng.fix(block);
        byte[] out = new byte[8];
        engine.generateData(out, (short) 0, (short) out.length);
        assertArrayEquals(Arrays.copyOf(block, 8), out, "Rng.fix serves the block from index 0");
    }
}
