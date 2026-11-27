// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Open;
import org.qntx.card.sim.Card;

/** §14.1 GET_IDENTITY and §5.1 identity-key properties, verified host-side. */
final class IdentityTest {

    @Test
    void returnsAnOnCurveCompressedKey() {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        assertEquals(33, a.length);
        assertTrue(a[0] == 0x02 || a[0] == 0x03);
        byte[] point = Crypto.decompress(a); // throws if not on the curve
        assertEquals(65, point.length);
        assertEquals(0x04, point[0]);
        // parity of y matches the prefix, independently of the applet's encoder
        boolean yOdd = point[64] % 2 != 0;
        assertEquals(yOdd, a[0] == 0x03);
    }

    @Test
    void stableAcrossPowerCycle() {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        card.powerCycle();
        card.transmit(Spec.SELECT);
        assertArrayEquals(a, Vecs.cardA(card));
    }

    @Test
    void p1AndP2AreCheckedSeparately() {
        Card card = Vecs.factory();
        assertEquals(0x6A86, Vecs.sw(card.transmit(Vecs.unhex("80e0010000"))));
        assertEquals(0x6A86, Vecs.sw(card.transmit(Vecs.unhex("80e0000100"))));
    }

    @Test
    void identityIsNotTheGeneratorOrAZeroKey() {
        byte[] a = Vecs.cardA(Vecs.factory());
        assertFalse(
                Arrays.equals(Crypto.compress(Crypto.publicKey(BigInteger.ONE)), a),
                "A must not be G");
        byte[] g = new byte[33];
        assertFalse(Arrays.equals(g, a));
    }

    @Test
    void certificateBindsTheSameA() throws Exception {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        byte[] cert = Vecs.certFor(a);
        byte[] rapdu = card.transmit(Vecs.personalizeApdu(cert));
        assertEquals(0x9000, Vecs.sw(rapdu));
        Open.Request req = Open.request(Vecs.RND);
        byte[] open = card.transmit(req.apdu());
        assertEquals(0x9000, Vecs.sw(open));
        // the returned cert[0..33) must be exactly the A we personalized and queried
        assertArrayEquals(cert, Arrays.copyOfRange(open, 129, 226));
        org.qntx.card.host.Session session =
                Open.response(req.secret(), req.apdu(), open, List.of(Vecs.caPublic()));
        assertArrayEquals(a, session.identity());
    }

    @Test
    void openCardEphIsOnCurve() throws Exception {
        // A successful OPEN already means the card signed TH and self-verified the
        // signature under A (§16.2 item 6); the ephemeral point must also be on curve.
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        assertEquals(0x9000, Vecs.sw(card.transmit(Vecs.personalizeApdu(Vecs.certFor(a)))));
        Open.Request req = Open.request(Vecs.RND);
        byte[] open = card.transmit(req.apdu());
        assertEquals(0x9000, Vecs.sw(open));
        assertEquals(0x04, open[0]);
        byte[] decompressed = Crypto.decompress(Crypto.compress(Arrays.copyOf(open, 65)));
        assertArrayEquals(Arrays.copyOf(open, 65), decompressed);
        // the certified A in the response is the card's own A
        assertArrayEquals(a, Arrays.copyOfRange(open, 129, 162));
    }
}
