// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review2;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * The review2 test CA of spec section 5.2: a fixed secp256k1 private key that issues cert = A || r
 * || s over SHA-256("qntx-card/v1/cert" || A).
 */
final class Ca2 {
    static final Ca2 INSTANCE = new Ca2();

    private final BigInteger priv;
    private final byte[] pubUncompressed;

    private Ca2() {
        byte[] raw = new byte[32];
        Arrays.fill(raw, (byte) 0x2E);
        priv = H2.intbe(raw);
        pubUncompressed = H2.uncompressed(H2.SECP.getG().multiply(priv).normalize());
    }

    /** The 65-byte uncompressed CA public key installed by PERSONALIZE (spec section 14.2). */
    byte[] publicKey() {
        return pubUncompressed.clone();
    }

    /** cert(97) = A(33) || r(32) || s(32) over SHA-256("qntx-card/v1/cert" || A). */
    byte[] issue(byte[] compressedA) {
        byte[] sig = H2.sign(priv, H2.cat(H2.ascii("qntx-card/v1/cert"), compressedA));
        return H2.cat(compressedA, sig);
    }
}
