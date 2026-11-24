// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review;

import static org.qntx.card.review.ReviewHost.*;

import java.util.Arrays;
import java.util.function.UnaryOperator;

/**
 * Independent §8 session client. OPEN verifies the card certificate under the review CA and the
 * session signature over TH exactly as §8.1 requires; every response record is checked per §8.4
 * (outer 9000, tag, unM2, ctr) — a failed check is a finding, not something to adapt to.
 */
final class ReviewSession {

    /** Result of one inner command: inner status word and inner response data. */
    static final class Inner {
        final int sw;
        final byte[] data;

        Inner(int sw, byte[] data) {
            this.sw = sw;
            this.data = data;
        }
    }

    /** Result of a raw §8.3 exchange: outer SW, raw response data, inner if a record came back. */
    static final class Raw {
        final int outer;
        final byte[] data;
        Inner inner;

        Raw(int outer, byte[] data) {
            this.outer = outer;
            this.data = data;
        }
    }

    final UnaryOperator<byte[]> tx;
    final byte[] caPub;
    final java.math.BigInteger hostD;
    byte[] kce, kcm, kre, krm;
    int ctr;
    boolean open;
    byte[] cert;
    byte[] cardA;
    byte[] lastResponseRecord;
    String openFailure;
    int responsesChecked;

    /** Global §8.4 tally for the D14 cell: every response record checked across all sessions. */
    static int responsesCheckedTotal;

    /** One line per response record that failed a §8.4 host check (outer 9000 but bad tag/M2). */
    static final java.util.List<String> checkViolations = new java.util.ArrayList<>();

    ReviewSession(UnaryOperator<byte[]> transmit, byte[] caPub) {
        this.tx = transmit;
        this.caPub = caPub;
        this.hostD = randomScalar();
    }

    /**
     * §8.1 OPEN with a fresh hostEph. Returns the raw 226-byte response when the exchange
     * succeeded, or null after recording the failure in {@link #openFailure}. The host checks of
     * §8.1 run in order: cert under the review CA, cardEph on the curve, signature over TH.
     */
    byte[] open() {
        byte[] hostEph = uncomp(g().multiply(hostD));
        byte[] apdu =
                concat(
                        unhex("80100000"),
                        new byte[] {(byte) hostEph.length},
                        hostEph,
                        new byte[] {0x00});
        byte[] resp = tx.apply(apdu);
        if (sw(resp) != 0x9000) {
            openFailure = "OPEN outer SW " + String.format("%04X", sw(resp));
            return null;
        }
        byte[] data = respData(resp);
        if (data.length != 226) {
            openFailure = "OPEN response " + data.length + " B, expected 226";
            return null;
        }
        byte[] cardEph = slice(data, 0, 65);
        byte[] sig = slice(data, 65, 64);
        byte[] cert = slice(data, 129, 97);
        if (!certVerify(caPub, cert)) {
            openFailure = "OPEN cert does not verify under the review CA";
            return null;
        }
        byte[] a = slice(cert, 0, 33);
        if (!validPoint(cardEph)) {
            openFailure = "OPEN cardEph not a valid point";
            return null;
        }
        byte[] m = concat(LABEL_SESSION, hostEph, cardEph, a);
        if (!ecdsaVerify(a, m, sig)) {
            openFailure = "OPEN session signature invalid";
            return null;
        }
        byte[] z = ecdhX(hostD, cardEph);
        byte[] th = sha256(m);
        byte[] keys = kdf(z, LABEL_KDF_SESSION, th, 64);
        kce = slice(keys, 0, 16);
        kcm = slice(keys, 16, 16);
        kre = slice(keys, 32, 16);
        krm = slice(keys, 48, 16);
        ctr = 0;
        open = true;
        this.cert = cert;
        this.cardA = a;
        return data;
    }

    /** Builds the §8.3 command record for an inner command. */
    byte[] record(byte ins, byte p1, byte p2, byte[] data) {
        byte[] plain = concat(new byte[] {ins, p1, p2}, data);
        byte[] iv = aesBlock(kce, concat(new byte[] {0x01}, new byte[13], u16(ctr)));
        byte[] ct = cbc(kce, iv, m2(plain));
        byte[] tag = slice(cmac(kcm, u16(ctr), ct), 0, 8);
        return concat(ct, tag);
    }

    /** Wraps a record in its APDU (§8.3). */
    byte[] recordApdu(byte p1, byte p2, byte[] record) {
        return concat(
                new byte[] {(byte) 0x80, 0x12, p1, p2, (byte) record.length},
                record,
                new byte[] {0x00});
    }

    /**
     * Sends one inner command as a record, checks the response record per §8.4, increments ctr.
     * {@code check} is null on an outer failure (6985/6982/…) so callers see the raw outer SW.
     */
    Raw send(byte ins, byte p1, byte p2, byte[] data) {
        return raw(recordApdu((byte) 0, (byte) 0, record(ins, p1, p2, data)));
    }

    /**
     * Sends raw record bytes (the negative-path helper for the D cells). The response is still
     * checked per §8.4 when the outer SW is 9000.
     */
    Raw raw(byte[] apdu) {
        byte[] resp = tx.apply(apdu);
        int outer = sw(resp);
        Raw r = new Raw(outer, respData(resp));
        if (outer != 0x9000) {
            if (outer == 0x6985 || outer == 0x6982) {
                open = false;
            }
            return r;
        }
        byte[] d = r.data;
        lastResponseRecord = Arrays.copyOf(d, d.length);
        if (d.length < 24 || (d.length - 8) % 16 != 0) {
            checkViolations.add("outer 9000 but response " + d.length + " B, not ct‖tag8");
            responsesCheckedTotal++;
            r.inner = new Inner(-1, d);
            return r;
        }
        byte[] ct = slice(d, 0, d.length - 8);
        byte[] tag = slice(d, d.length - 8, 8);
        byte[] expect = slice(cmac(krm, u16(ctr), ct), 0, 8);
        responsesChecked++;
        responsesCheckedTotal++;
        if (!Arrays.equals(expect, tag)) {
            checkViolations.add("outer 9000 but bad K_rm tag at ctr " + ctr);
            r.inner = new Inner(-2, d);
            return r;
        }
        byte[] iv = aesBlock(kre, concat(new byte[] {0x02}, new byte[13], u16(ctr)));
        byte[] plain = unM2(cbcInv(kre, iv, ct));
        if (plain == null || plain.length < 2) {
            checkViolations.add("outer 9000 but response does not unM2 at ctr " + ctr);
            r.inner = new Inner(-3, d);
            return r;
        }
        int innerSw = ((plain[plain.length - 2] & 0xFF) << 8) | (plain[plain.length - 1] & 0xFF);
        r.inner = new Inner(innerSw, slice(plain, 0, plain.length - 2));
        ctr = (ctr + 1) & 0xFFFF;
        if (ctr == 0) {
            open = false;
        }
        if (innerSw == 0x6F00) {
            open = false;
        }
        return r;
    }

    /** Convenience: inner command, asserts the record layer worked, returns the inner result. */
    Inner cmd(byte ins, byte p1, byte p2, byte[] data) {
        Raw r = send(ins, p1, p2, data);
        if (r.inner == null) {
            return new Inner(-r.outer, data);
        }
        return r.inner;
    }
}
