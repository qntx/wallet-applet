// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review3;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * The §8 secure session, host side: OPEN (§8.1) including the certificate check against the trusted
 * anchor and the verification of the card's session signature under its {@code A}, then the
 * command/response record layer (§8.3–§8.4) with the shared 16-bit counter. Every failure abandons
 * the session by throwing — the spec gives no option to continue (§8.1, §8.4).
 */
final class Session3 {

    // §8.1: the transcript label and the session-KDF label.
    private static final byte[] LABEL_SESSION = H3.label("qntx-card/v1/session");
    private static final byte[] LABEL_KDF_SESSION = H3.label("qntx-card/v1/kdf-session");

    // §9.2 inner INS codes used by the review3 tests.
    static final int INS_STATUS = 0x20;
    static final int INS_CREATE = 0x21;
    static final int INS_VERIFY = 0x22;
    static final int INS_PUBLIC_KEY = 0x30;
    static final int INS_OFFER = 0x40;
    static final int INS_EXPORT = 0x41;
    static final int INS_IMPORT = 0x42;

    /** The inner result of a record exchange: response data and the inner status word. */
    static final class Resp {
        final byte[] data;
        final int sw;

        Resp(byte[] data, int sw) {
            this.data = data;
            this.sw = sw;
        }
    }

    private final Card3 card;
    private final byte[] cert;
    private final byte[] a;
    private final byte[] kce;
    private final byte[] kcm;
    private final byte[] kre;
    private final byte[] krm;
    private int ctr;

    /**
     * Runs §8.1: a fresh host ephemeral, the OPEN exchange, the certificate and session-signature
     * checks and the session-key derivation. {@code anchor} is the single trusted CA (§5.2).
     */
    Session3(Card3 card, Ca3 anchor) {
        this.card = card;
        BigInteger x = H3.randomScalar();
        byte[] hostEph = H3.pubPoint(x);
        byte[] resp = card.transmit(H3.cat(H3.unhex("8010000041"), hostEph, new byte[] {0}));
        if (Card3.swOf(resp) != 0x9000 || resp.length != 228) {
            throw new IllegalStateException("OPEN failed: " + H3.hex(resp));
        }
        byte[] body = Card3.dataOf(resp);
        byte[] cardEph = Arrays.copyOfRange(body, 0, 65);
        byte[] sig = Arrays.copyOfRange(body, 65, 129);
        cert = Arrays.copyOfRange(body, 129, 226);
        if (!anchor.verifyCert(cert)) {
            throw new IllegalStateException("certificate rejected by the trusted anchor");
        }
        a = Arrays.copyOfRange(cert, 0, 33);
        if (!Arrays.equals(a, card.a())) {
            throw new IllegalStateException("certificate A differs from GET_IDENTITY's");
        }
        byte[] transcript = H3.cat(LABEL_SESSION, hostEph, cardEph, a);
        byte[] th = H3.sha256(transcript);
        if (!H3.ecdsaVerify(H3.decompress(a), th, sig)) {
            throw new IllegalStateException("session signature does not verify");
        }
        byte[] z = H3.ecdhX(x, cardEph);
        byte[] keys = H3.kdf(z, LABEL_KDF_SESSION, th, 64);
        kce = Arrays.copyOfRange(keys, 0, 16);
        kcm = Arrays.copyOfRange(keys, 16, 32);
        kre = Arrays.copyOfRange(keys, 32, 48);
        krm = Arrays.copyOfRange(keys, 48, 64);
        ctr = 0;
    }

    /** The card's certificate from the OPEN response (§8.1). */
    byte[] cert() {
        return cert;
    }

    /** {@code A} taken from the verified certificate (§8.1). */
    byte[] cardA() {
        return a;
    }

    /** {@code ID(A)} of the card this session talks to (§1). */
    byte[] cardId() {
        return H3.cardId(a);
    }

    /**
     * One inner command (§8.3–§8.4): wraps {@code INS ‖ P1 ‖ P2 ‖ data} into a command record,
     * verifies and unwraps the response record and returns the inner data and status. An outer
     * status other than {@code 9000} means the session is torn down (§8.3 steps 2–5); a bad
     * response tag or padding abandons the session on the host side too (§8.4).
     */
    Resp command(int ins, int p1, int p2, byte[] data) {
        byte[] plain = H3.cat(new byte[] {(byte) ins, (byte) p1, (byte) p2}, data);
        byte[] iv = H3.aesBlock(kce, H3.cat(new byte[] {1}, H3.zeros(13), H3.u16(ctr)));
        byte[] ct = H3.cbcEnc(kce, iv, H3.m2(plain));
        byte[] tag = Arrays.copyOf(H3.cmac(kcm, H3.cat(H3.u16(ctr), ct)), 8);
        byte[] apdu =
                H3.cat(
                        new byte[] {(byte) 0x80, (byte) 0x12, 0, 0, (byte) (ct.length + 8)},
                        ct,
                        tag,
                        new byte[] {0});
        byte[] resp = card.transmit(apdu);
        int outer = Card3.swOf(resp);
        if (outer != 0x9000) {
            throw new IllegalStateException(
                    "SESSION outer status " + Integer.toHexString(outer) + ": session torn down");
        }
        byte[] body = Card3.dataOf(resp);
        byte[] rct = Arrays.copyOf(body, body.length - 8);
        byte[] rtag = Arrays.copyOfRange(body, body.length - 8, body.length);
        byte[] expected = Arrays.copyOf(H3.cmac(krm, H3.cat(H3.u16(ctr), rct)), 8);
        if (!H3.equal(expected, rtag)) {
            throw new IllegalStateException("response tag mismatch: session abandoned");
        }
        byte[] riv = H3.aesBlock(kre, H3.cat(new byte[] {2}, H3.zeros(13), H3.u16(ctr)));
        byte[] rplain = H3.unM2(H3.cbcDec(kre, riv, rct));
        if (rplain == null || rplain.length < 2) {
            throw new IllegalStateException("response padding invalid: session abandoned");
        }
        int sw = ((rplain[rplain.length - 2] & 0xFF) << 8) | (rplain[rplain.length - 1] & 0xFF);
        byte[] innerData = Arrays.copyOf(rplain, rplain.length - 2);
        // §8.4: both sides advance ctr after the response; the card tears the session down
        // after a ctr = 0xFFFF response and after an inner 6F00, which the next command
        // surfaces as an outer status (§8.5).
        ctr++;
        return new Resp(innerData, sw);
    }

    Resp command(int ins, int p1, int p2) {
        return command(ins, p1, p2, new byte[0]);
    }

    /** STATUS (§9.3): {@code life(1) ‖ tries(1)}. */
    Resp status() {
        return command(INS_STATUS, 0, 0);
    }

    /**
     * CREATE {@code P1 = 0x01} (§9.4): {@code accessHash(32) ‖ seed(64) ‖ others}; returns
     * WalletInfo. The session becomes verified.
     */
    Resp createImport(byte[] accessHash, byte[] seed, byte[] others) {
        return command(INS_CREATE, 0x01, 0, H3.cat(accessHash, seed, others));
    }

    /** VERIFY (§9.5): the 32-byte candidate access hash; returns WalletInfo on {@code 9000}. */
    Resp verify(byte[] accessHash) {
        return command(INS_VERIFY, 0, 0, accessHash);
    }

    /** OFFER (§9.12): returns {@code LK(65) ‖ sig_T(64)} (129 bytes). */
    Resp offer() {
        return command(INS_OFFER, 0, 0);
    }

    /**
     * EXPORT {@code P1 = 0x00} (§9.13): {@code cert_T ‖ LK_T ‖ sig_T}; returns {@code E ‖ sig_S}.
     */
    Resp export0(byte[] certT, byte[] lkT, byte[] sigT) {
        return command(INS_EXPORT, 0, 0, H3.cat(certT, lkT, sigT));
    }

    /** EXPORT {@code P1 = 0x01} (§9.13): the target access hash; returns {@code ct ‖ tag}. */
    Resp export1(byte[] accessHashT) {
        return command(INS_EXPORT, 0x01, 0, accessHashT);
    }

    /** IMPORT {@code P1 = 0x00} (§9.14): the 226-byte head {@code cert_S ‖ E ‖ sig_S}. */
    Resp import0(byte[] head) {
        return command(INS_IMPORT, 0, 0, head);
    }

    /** IMPORT {@code P1 = 0x01} (§9.14): {@code ct ‖ tag}; returns WalletInfo. */
    Resp import1(byte[] ct, byte[] tag) {
        return command(INS_IMPORT, 0x01, 0, H3.cat(ct, tag));
    }

    /** PUBLIC_KEY (§9.8): secp256k1 {@code P1 = 0x00} → {@code publicKey(33) ‖ chainCode(32)}. */
    Resp publicKey(int p1, long... path) {
        return command(INS_PUBLIC_KEY, p1, 0, H3.pathBytes(path));
    }
}
