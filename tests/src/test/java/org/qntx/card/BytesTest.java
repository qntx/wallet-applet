// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.qntx.card.tests.Vecs;

/**
 * {@link Bytes#unpad} against the previous whole-record scan as the oracle: correctly padded
 * plaintexts of every length and every malformed tail — the record layer only ever calls it on a
 * MAC-verified ciphertext, so scanning just the last block must give identical answers.
 */
final class BytesTest {

    /** The pre-optimisation implementation, kept verbatim as the oracle. */
    private static short unpadScanAll(byte[] buf, short off, short len) {
        if (len <= 0 || (short) (len & 0x0F) != 0) {
            return -1;
        }
        short marker = -1;
        for (short i = 0; i < len; i++) {
            if (buf[(short) (off + i)] != 0) {
                marker = i;
            }
        }
        if (marker < 0
                || buf[(short) (off + marker)] != (byte) 0x80
                || (short) (len - marker) > 16) {
            return -1;
        }
        return marker;
    }

    private static void agree(byte[] buf, short off, short len, String what) {
        assertEquals(unpadScanAll(buf, off, len), Bytes.unpad(buf, off, len), what);
    }

    @Test
    void unpadAgreesWithTheFullScanOnPaddedPlaintexts() {
        byte[] buf = new byte[272 + 8];
        for (int len = 0; len <= 255; len++) {
            for (int trial = 0; trial < 4; trial++) {
                Vecs.RND.nextBytes(buf);
                short padded = Bytes.pad(buf, (short) 8, (short) len);
                agree(buf, (short) 8, padded, "padded len=" + len);
            }
        }
    }

    @Test
    void unpadAgreesWithTheFullScanOnMalformedTails() {
        byte[] buf = new byte[272 + 8];
        // no marker at all (all zeros), any size
        for (int len = 16; len <= 256; len += 16) {
            byte[] zeros = new byte[len + 8];
            agree(zeros, (short) 8, (short) len, "all zeros len=" + len);
        }
        // marker 0x80 too far back: more than 15 zeros follow it
        for (int len = 32; len <= 256; len += 16) {
            for (int m = 0; m < len - 16; m += 7) {
                Vecs.RND.nextBytes(buf);
                buf[8 + m] = (byte) 0x80;
                for (int i = m + 1; i < len; i++) {
                    buf[8 + i] = 0;
                }
                agree(buf, (short) 8, (short) len, "early marker len=" + len + " m=" + m);
            }
        }
        // last non-zero byte inside the last block but not 0x80
        for (int len = 16; len <= 256; len += 32) {
            for (int m = len - 16; m < len; m += 5) {
                Vecs.RND.nextBytes(buf);
                buf[8 + m] = (byte) (0x80 | (1 + Vecs.RND.nextInt(0x7F)));
                for (int i = m + 1; i < len; i++) {
                    buf[8 + i] = 0;
                }
                agree(buf, (short) 8, (short) len, "wrong byte len=" + len + " m=" + m);
            }
        }
        // random garbage, empty and non-multiple-of-16 lengths
        for (int trial = 0; trial < 64; trial++) {
            int len = 16 * (1 + Vecs.RND.nextInt(16));
            Vecs.RND.nextBytes(buf);
            agree(buf, (short) 8, (short) len, "garbage " + trial);
        }
        agree(buf, (short) 8, (short) 0, "empty");
        agree(buf, (short) 8, (short) -3, "negative");
        for (int len = 1; len < 16; len++) {
            agree(buf, (short) 8, (short) len, "not a block len=" + len);
        }
    }
}
