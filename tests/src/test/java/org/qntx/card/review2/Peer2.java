// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review2;

import java.math.BigInteger;

/**
 * A host-emulated genuine member card: a random secp256k1 identity key d, its compressed public key
 * A, and a certificate issued by the review2 CA. Produces OFFER-style link key offers signed by d
 * (spec sections 9.12, 11.2).
 */
final class Peer2 {
    /** A genuine offer: the link secret l, the public LK, and sig_T = Sign(d, offer || LK). */
    static final class Offer {
        final BigInteger secret;
        final byte[] lk;
        final byte[] sig;

        Offer(BigInteger secret, byte[] lk, byte[] sig) {
            this.secret = secret;
            this.lk = lk;
            this.sig = sig;
        }
    }

    final BigInteger d;
    final byte[] a; // compressed identity public key A (33)
    final byte[] cert; // A || r || s (97)

    private Peer2(BigInteger d, byte[] a, byte[] cert) {
        this.d = d;
        this.a = a;
        this.cert = cert;
    }

    static Peer2 create(Ca2 ca) {
        BigInteger d = H2.randomScalar();
        byte[] a = H2.compress(H2.SECP.getG().multiply(d).normalize());
        return new Peer2(d, a, ca.issue(a));
    }

    byte[] id() {
        return H2.cardId(a);
    }

    /** A genuine OFFER answer: fresh link key LK and Sign(d, "qntx-card/v1/offer" || LK). */
    Offer offer() {
        BigInteger l = H2.randomScalar();
        byte[] lk = H2.uncompressed(H2.SECP.getG().multiply(l).normalize());
        byte[] sig = H2.sign(d, H2.cat(H2.ascii("qntx-card/v1/offer"), lk));
        return new Offer(l, lk, sig);
    }
}
