// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review;

import static org.qntx.card.review.ReviewHost.*;

import java.math.BigInteger;
import org.qntx.card.review.ReviewCard.Ca;

/**
 * A host-controlled member card (the fake member M/N of the matrix): own secp256k1 identity key
 * pair, a certificate issued by the review CA, a link key pair, and the §11 protocol parts the host
 * plays for it — OFFER bytes (LK ‖ sig_T), EXPORT-source bytes (cert_S ‖ E ‖ sig_S plus the §9.13
 * payload encryption), and EXPORT-target decryption of a card's pending-export record.
 */
final class FakeMember {

    final BigInteger id; // identity private key m
    final byte[] a; // compressed identity public key A_M (33)
    final byte[] cert; // cert_M (97) under the review CA
    final byte[] cardId; // ID(A_M) (16)
    final BigInteger link; // link private key l_M
    final byte[] lk; // link public key LK_M, uncompressed (65)

    FakeMember(Ca ca) {
        this.id = randomScalar();
        this.a = compr(g().multiply(id));
        this.cert = ca.issue(a);
        this.cardId = cardId(a);
        this.link = randomScalar();
        this.lk = uncomp(g().multiply(link));
    }

    /** sig_T of the offer: Sign(m, "qntx-card/v1/offer" ‖ LK) (§9.13 check 5). */
    byte[] offerSig() {
        return ecdsaSign(id, concat(LABEL_OFFER, lk));
    }

    /** The OFFER response a real card of this member would produce: LK ‖ sig_T. */
    byte[] offer() {
        return concat(lk, offerSig());
    }

    /** cert_T ‖ LK_T ‖ sig_T for the card's EXPORT P1=0x00 (§9.13). */
    byte[] exportRequest() {
        return concat(cert, lk, offerSig());
    }

    /**
     * As an EXPORT source: E = e·G with a fresh host-drawn scalar and sig_S over
     * "qntx-card/v1/export" ‖ A_S ‖ A_T ‖ LK_T ‖ E (§9.13). Returns {cert_S(97) ‖ E(65) ‖
     * sig_S(64), e(32)} — the scalar is needed for K_te ‖ K_tm.
     */
    byte[][] exportOffer(byte[] targetA33, byte[] targetLk) {
        BigInteger e = randomScalar();
        byte[] ep = uncomp(g().multiply(e));
        byte[] m = concat(LABEL_EXPORT, a, targetA33, targetLk, ep);
        byte[] sigS = ecdsaSign(id, m);
        return new byte[][] {concat(cert, ep, sigS), i2b(e, 32)};
    }

    /** Z = x-coordinate of l·E for the target side of §9.13/§9.14. */
    byte[] z(byte[] e65) {
        return ecdhX(link, e65);
    }

    /** K_te ‖ K_tm for the transfer transcript M (§9.13): KDF(Z, label, SHA-256(M), 32). */
    static byte[][] transferKeys(byte[] z, byte[] m) {
        byte[] k = kdf(z, LABEL_KDF_TRANSFER, sha256(m), 32);
        return new byte[][] {slice(k, 0, 16), slice(k, 16, 16)};
    }

    /**
     * As the EXPORT source (G5/G6/G10): the pending-import record ct ‖ tag of §9.13/§9.14 for a
     * target holding link key l_T and with offer transcript M. payload as given.
     */
    static byte[][] sealRecord(byte[] z, byte[] m, byte[] payload) {
        byte[][] keys = transferKeys(z, m);
        byte[] ct = cbc(keys[0], new byte[16], m2(payload));
        byte[] tag = cmac(keys[1], ct);
        return new byte[][] {concat(ct, tag), keys[0], keys[1]};
    }

    /**
     * As the EXPORT target: verify the card's record ct ‖ tag and recover the §9.13 payload; null
     * when the CMAC or unM2 fails.
     */
    static byte[] unsealRecord(byte[] z, byte[] m, byte[] record) {
        byte[][] keys = transferKeys(z, m);
        byte[] ct = slice(record, 0, record.length - 16);
        byte[] tag = slice(record, record.length - 16, 16);
        if (!java.util.Arrays.equals(cmac(keys[1], ct), tag)) {
            return null;
        }
        return unM2(cbcInv(keys[0], new byte[16], ct));
    }
}
