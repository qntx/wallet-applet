// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review3;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * An emulated genuine card for the transfer commands of §9.12–§9.14 and §11: an identity key pair
 * with a certificate under the review3 CA, plus a link key pair. As transfer target it produces the
 * offer {@code LK ‖ sig_T} and derives the import keys from the received export head; as sender it
 * produces the export head {@code cert_S ‖ E ‖ sig_S} and the same keys. Both roles are the
 * card-side computations of the spec, run by the host — nothing here is the applet under test.
 */
final class Peer3 {

    // §9.12–§9.13 labels.
    private static final byte[] LABEL_OFFER = H3.label("qntx-card/v1/offer");
    private static final byte[] LABEL_EXPORT = H3.label("qntx-card/v1/export");
    private static final byte[] LABEL_KDF_TRANSFER = H3.label("qntx-card/v1/kdf-transfer");

    private final BigInteger idPriv;
    private final byte[] a; // compressed identity, 33 bytes
    private final byte[] cert; // 97 bytes under the Ca3
    private final BigInteger linkPriv;
    private final byte[] lk; // uncompressed link public key, 65 bytes

    /** A fresh genuine card: random identity and link keys, certified by {@code ca}. */
    Peer3(Ca3 ca) {
        idPriv = H3.randomScalar();
        a = H3.compress(H3.point(H3.pubPoint(idPriv)));
        cert = ca.cert(a);
        linkPriv = H3.randomScalar();
        lk = H3.pubPoint(linkPriv);
    }

    /** The compressed identity {@code A} (33 bytes). */
    byte[] a() {
        return a;
    }

    /** {@code ID(A)} (§1). */
    byte[] id() {
        return H3.cardId(a);
    }

    /** The certificate under the review3 CA (§5.2). */
    byte[] cert() {
        return cert;
    }

    /** The stored link public key {@code LK} (65 bytes, uncompressed). */
    byte[] lk() {
        return lk;
    }

    /**
     * §9.12, target side: {@code LK(65) ‖ Sign(idKey, "qntx-card/v1/offer" ‖ LK)(64)} — what a
     * genuine target's OFFER returns.
     */
    byte[] offer() {
        byte[] sig = H3.ecdsaSign(idPriv, H3.sha256(H3.cat(LABEL_OFFER, lk)));
        return H3.cat(lk, sig);
    }

    /**
     * The pending import keys of the target role (§9.14 {@code P1 = 0x00}): with the sender's
     * compressed identity {@code aS} and export point {@code e}, {@code Z = x-coordinate of l·E}
     * and {@code K_te ‖ K_tm = KDF(Z, "qntx-card/v1/kdf-transfer", TH, 32)} where {@code TH =
     * SHA-256("qntx-card/v1/export" ‖ A_S ‖ A_T ‖ LK_T ‖ E)}.
     */
    byte[][] importKeys(byte[] aS, byte[] e) {
        byte[] m = H3.cat(LABEL_EXPORT, aS, a, lk, e);
        byte[] th = H3.sha256(m);
        byte[] z = H3.ecdhX(linkPriv, e);
        byte[] keys = H3.kdf(z, LABEL_KDF_TRANSFER, th, 32);
        return new byte[][] {Arrays.copyOfRange(keys, 0, 16), Arrays.copyOfRange(keys, 16, 32)};
    }

    /** What {@link #exportHead} returns: the 226-byte head and the derived transfer keys. */
    static final class ExportHead {
        /** {@code cert_S(97) ‖ E(65) ‖ sig_S(64)}, the IMPORT {@code P1 = 0x00} data. */
        final byte[] head;

        /** {@code K_te(16)}, the payload encryption key (§9.13). */
        final byte[] kTe;

        /** {@code K_tm(16)}, the payload MAC key (§9.13). */
        final byte[] kTm;

        ExportHead(byte[] head, byte[] kTe, byte[] kTm) {
            this.head = head;
            this.kTe = kTe;
            this.kTm = kTm;
        }
    }

    /**
     * §9.13 {@code P1 = 0x00}, sender side: for the target with compressed identity {@code aT} and
     * offer key {@code lkT}, draws {@code e}, computes {@code E = e·G}, {@code Z = x(e·LK_T)},
     * {@code TH = SHA-256(M)} with {@code M = "qntx-card/v1/export" ‖ A_S ‖ A_T ‖ LK_T ‖ E}, {@code
     * sig_S = Sign(idKey, M)} and {@code K_te ‖ K_tm = KDF(Z, label, TH, 32)}.
     */
    ExportHead exportHead(byte[] aT, byte[] lkT) {
        BigInteger e = H3.randomScalar();
        byte[] ephem = H3.pubPoint(e);
        byte[] z = H3.ecdhX(e, lkT);
        byte[] m = H3.cat(LABEL_EXPORT, a, aT, lkT, ephem);
        byte[] th = H3.sha256(m);
        byte[] sig = H3.ecdsaSign(idPriv, th);
        byte[] keys = H3.kdf(z, LABEL_KDF_TRANSFER, th, 32);
        return new ExportHead(
                H3.cat(cert, ephem, sig),
                Arrays.copyOfRange(keys, 0, 16),
                Arrays.copyOfRange(keys, 16, 32));
    }

    /**
     * §9.13 {@code P1 = 0x01}: {@code ct = CBC(K_te, 0¹⁶, M2(payload))} and {@code tag = CMAC(K_tm,
     * ct)}; returns {@code ct ‖ tag}. Used to build both genuine and forged payload records.
     */
    static byte[] seal(byte[] kTe, byte[] kTm, byte[] payload) {
        byte[] ct = H3.cbcEnc(kTe, H3.zeros(16), H3.m2(payload));
        return H3.cat(ct, H3.cmac(kTm, ct));
    }

    /**
     * The target-side opening of a {@code ct ‖ tag} record (§9.14 {@code P1 = 0x01} checks 1–2):
     * verifies {@code CMAC(K_tm, ct) = tag} in constant time, decrypts and strips M2. Returns the
     * payload, or {@code null} on a tag or padding failure (the card's {@code 6A80}).
     */
    static byte[] unseal(byte[] kTe, byte[] kTm, byte[] ctTag) {
        if (ctTag.length < 32 || ((ctTag.length - 16) & 0xF) != 0) {
            return null;
        }
        byte[] ct = Arrays.copyOf(ctTag, ctTag.length - 16);
        byte[] tag = Arrays.copyOfRange(ctTag, ctTag.length - 16, ctTag.length);
        if (!H3.equal(H3.cmac(kTm, ct), tag)) {
            return null;
        }
        return H3.unM2(H3.cbcDec(kTe, H3.zeros(16), ct));
    }
}
