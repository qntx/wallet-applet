// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review3;

/**
 * A review3 batch CA (§5.2, §14.2): an own secp256k1 key pair that issues certificates {@code
 * cert(97) = A(33) ‖ r(32) ‖ s(32)} with {@code (r, s) = Sign(ca, "qntx-card/v1/cert" ‖ A)} and
 * supplies the {@code cert ‖ caKey} PERSONALIZE data. Test CA only — production hosts must not
 * trust test anchors (§5.2).
 */
final class Ca3 {

    /** §5.2: the certificate's signature label. */
    private static final byte[] LABEL_CERT = H3.label("qntx-card/v1/cert");

    private final java.math.BigInteger priv;
    private final byte[] pub; // uncompressed, 65 bytes

    /** A fresh random CA key pair. */
    Ca3() {
        this(H3.u256(H3.randomScalar()));
    }

    /** A CA from an existing 32-byte private scalar. */
    Ca3(byte[] priv32) {
        priv = H3.bigInt(priv32);
        if (priv.signum() <= 0 || priv.compareTo(H3.N) >= 0) {
            throw new IllegalArgumentException("CA private key outside [1, n − 1]");
        }
        pub = H3.pubPoint(priv);
    }

    /** {@code caKey}: the uncompressed CA public key (65 bytes, §14.2). */
    byte[] publicKey() {
        return pub;
    }

    /** The private scalar, for signers emulating the CA's HSM (§14.3 step 5). */
    java.math.BigInteger privateKey() {
        return priv;
    }

    /**
     * §5.2: the 97-byte certificate of the compressed identity key {@code a} — {@code A ‖ Sign(ca,
     * "qntx-card/v1/cert" ‖ A)}.
     */
    byte[] cert(byte[] a) {
        if (a.length != 33) {
            throw new IllegalArgumentException("A must be 33 bytes (compressed)");
        }
        return H3.cat(a, sign(a));
    }

    /** The signature half of {@link #cert}: {@code Sign(ca, label ‖ A)} as {@code r ‖ s}. */
    byte[] sign(byte[] a) {
        return H3.ecdsaSign(priv, H3.sha256(H3.cat(LABEL_CERT, a)));
    }

    /**
     * §5.2: {@code Verify(anchor, "qntx-card/v1/cert" ‖ A, r ‖ s)} — this CA as the single trusted
     * anchor.
     */
    boolean verifyCert(byte[] cert) {
        if (cert.length != 97) {
            return false;
        }
        byte[] a = java.util.Arrays.copyOfRange(cert, 0, 33);
        byte[] sig = java.util.Arrays.copyOfRange(cert, 33, 97);
        return H3.ecdsaVerify(pub, H3.sha256(H3.cat(LABEL_CERT, a)), sig);
    }

    /**
     * §14.2: the PERSONALIZE data {@code cert(97) ‖ caKey(65)} for the card with identity {@code
     * a}.
     */
    byte[] personalizeData(byte[] a) {
        return H3.cat(cert(a), pub);
    }
}
