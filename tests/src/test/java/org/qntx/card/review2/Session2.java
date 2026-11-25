// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review2;

import java.math.BigInteger;
import java.util.Arrays;
import org.qntx.card.sim.Card;

/**
 * The review2 host session of spec section 8: OPEN (section 8.1), the command record of section 8.3
 * and the response record check of section 8.4. Implemented only from the spec.
 */
final class Session2 {
    /** Inner command outcome: the inner status word and data (empty on an outer failure). */
    static final class Res {
        final int sw;
        final byte[] data;

        Res(int sw, byte[] data) {
            this.sw = sw;
            this.data = data;
        }
    }

    private final Card card;
    private final byte[] cardA; // compressed identity key of the card (33)
    private final byte[] cardCert; // cert as sent in OPEN (97)
    private final byte[] kce;
    private final byte[] kcm;
    private final byte[] kre;
    private final byte[] krm;
    private int ctr;
    private boolean closed;

    private Session2(Card card, byte[] cardA, byte[] cardCert, byte[] keys) {
        this.card = card;
        this.cardA = cardA;
        this.cardCert = cardCert;
        kce = Arrays.copyOfRange(keys, 0, 16);
        kcm = Arrays.copyOfRange(keys, 16, 32);
        kre = Arrays.copyOfRange(keys, 32, 48);
        krm = Arrays.copyOfRange(keys, 48, 64);
    }

    byte[] identity() {
        return cardA.clone();
    }

    byte[] cert() {
        return cardCert.clone();
    }

    boolean closed() {
        return closed;
    }

    /** OPEN of spec section 8.1; verifies the certificate and the session signature. */
    static Session2 open(Card card, Ca2 ca) {
        BigInteger hostSecret = H2.randomScalar();
        byte[] hostEph = H2.uncompressed(H2.SECP.getG().multiply(hostSecret).normalize());
        byte[] apdu =
                H2.cat(
                        new byte[] {(byte) 0x80, 0x10, 0x00, 0x00, 0x41},
                        hostEph,
                        new byte[] {0x00});
        byte[] resp = card.transmit(apdu);
        int sw = swOf(resp);
        if (sw != 0x9000 || resp.length != 228) {
            throw new IllegalStateException("OPEN failed: " + H2.hex(resp));
        }
        byte[] cardEph = Arrays.copyOfRange(resp, 0, 65);
        byte[] sig = Arrays.copyOfRange(resp, 65, 129);
        byte[] cert = Arrays.copyOfRange(resp, 129, 226);
        byte[] cardA = Arrays.copyOfRange(cert, 0, 33);

        // spec section 8.1: verify cert against the anchor before any record is sent.
        if (!H2.verify(
                ca.publicKey(),
                H2.cat(H2.ascii("qntx-card/v1/cert"), cardA),
                Arrays.copyOfRange(cert, 33, 97))) {
            throw new IllegalStateException("OPEN: certificate does not verify under the CA");
        }
        byte[] th = H2.sha256(H2.cat(H2.ascii("qntx-card/v1/session"), hostEph, cardEph, cardA));
        if (!H2.verifyHash(cardA, th, sig)) {
            throw new IllegalStateException("OPEN: session signature does not verify");
        }
        byte[] z =
                H2.big32(
                        H2.point(cardEph)
                                .multiply(hostSecret)
                                .normalize()
                                .getAffineXCoord()
                                .toBigInteger());
        byte[] keys = H2.kdf(z, "qntx-card/v1/kdf-session", th, 64);
        return new Session2(card, cardA, cert, keys);
    }

    /** One inner command in a section 8.3 record; checks the section 8.4 response. */
    Res cmd(int ins, int p1, int p2, byte[] data) {
        if (closed) {
            throw new IllegalStateException("session is closed");
        }
        byte[] plain = H2.cat(new byte[] {(byte) ins, (byte) p1, (byte) p2}, data);
        byte[] iv = H2.aesBlock(kce, H2.cat(new byte[] {0x01}, new byte[13], H2.u16(ctr)));
        byte[] ct = H2.cbc(true, kce, iv, H2.m2(plain));
        byte[] tag = Arrays.copyOf(H2.cmac(kcm, H2.cat(H2.u16(ctr), ct)), 8);
        byte[] apdu =
                H2.cat(
                        new byte[] {(byte) 0x80, 0x12, 0x00, 0x00, (byte) (ct.length + 8)},
                        ct,
                        tag,
                        new byte[] {0x00});
        byte[] resp = card.transmit(apdu);
        int sw = swOf(resp);
        if (sw != 0x9000) {
            // section 8.3: steps 2-5 fail in clear and tear the session down.
            closed = true;
            return new Res(sw, new byte[0]);
        }
        byte[] body = Arrays.copyOfRange(resp, 0, resp.length - 2);
        byte[] rct = Arrays.copyOfRange(body, 0, body.length - 8);
        byte[] rtag = Arrays.copyOfRange(body, body.length - 8, body.length);
        byte[] expectTag = Arrays.copyOf(H2.cmac(krm, H2.cat(H2.u16(ctr), rct)), 8);
        if (!constantTimeEqual(expectTag, rtag)) {
            closed = true;
            throw new IllegalStateException("response record tag mismatch");
        }
        byte[] riv = H2.aesBlock(kre, H2.cat(new byte[] {0x02}, new byte[13], H2.u16(ctr)));
        byte[] innerPlain = H2.unM2(H2.cbc(false, kre, riv, rct));
        if (innerPlain == null || innerPlain.length < 2) {
            closed = true;
            throw new IllegalStateException("response record unM2 failed");
        }
        int innerSw =
                ((innerPlain[innerPlain.length - 2] & 0xFF) << 8)
                        | (innerPlain[innerPlain.length - 1] & 0xFF);
        byte[] innerData = Arrays.copyOf(innerPlain, innerPlain.length - 2);
        ctr++;
        if (innerSw == 0x6F00 || ctr == 0x10000) {
            // section 8.5: inner 6F00 and counter exhaustion tear the session down.
            closed = true;
        }
        return new Res(innerSw, innerData);
    }

    /** A raw APDU to the card outside the record layer (e.g. SELECT, GET_IDENTITY). */
    byte[] outer(byte[] apdu) {
        return card.transmit(apdu);
    }

    static int swOf(byte[] resp) {
        if (resp.length < 2) {
            return -1;
        }
        return ((resp[resp.length - 2] & 0xFF) << 8) | (resp[resp.length - 1] & 0xFF);
    }

    static byte[] dataOf(byte[] resp) {
        return Arrays.copyOf(resp, Math.max(0, resp.length - 2));
    }

    private static boolean constantTimeEqual(byte[] a, byte[] b) {
        int diff = a.length ^ b.length;
        for (int i = 0; i < Math.min(a.length, b.length); i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
}
