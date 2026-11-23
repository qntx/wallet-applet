// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import java.util.HexFormat;

/** APDU wire helpers of the real-card suite. */
final class Apdu {
    static final byte[] WALLET_AID = hex("F0716E74780101");
    static final byte[] NDEF_AID = hex("D2760000850101");
    static final byte[] EMPTY = new byte[0];

    private Apdu() {}

    /** {@code 00 A4 04 00 ‖ lc ‖ aid ‖ 00}: SELECT an applet instance by name. */
    static byte[] select(byte[] aid) {
        byte[] apdu = new byte[5 + aid.length + 1];
        apdu[1] = (byte) 0xA4;
        apdu[2] = 0x04;
        apdu[4] = (byte) aid.length;
        System.arraycopy(aid, 0, apdu, 5, aid.length);
        return apdu;
    }

    /** A case-3 short command {@code cla ins p1 p2 lc data}, or case-1 when data is empty. */
    static byte[] cmd(int cla, int ins, int p1, int p2, byte[] data) {
        byte[] apdu = new byte[data.length == 0 ? 4 : 5 + data.length];
        apdu[0] = (byte) cla;
        apdu[1] = (byte) ins;
        apdu[2] = (byte) p1;
        apdu[3] = (byte) p2;
        if (data.length != 0) {
            apdu[4] = (byte) data.length;
            System.arraycopy(data, 0, apdu, 5, data.length);
        }
        return apdu;
    }

    static int sw(byte[] response) {
        if (response.length < 2) {
            return -1;
        }
        return ((response[response.length - 2] & 0xFF) << 8)
                | (response[response.length - 1] & 0xFF);
    }

    static byte[] data(byte[] response) {
        if (response.length < 2) {
            return EMPTY;
        }
        byte[] out = new byte[response.length - 2];
        System.arraycopy(response, 0, out, 0, out.length);
        return out;
    }

    static int u16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    static long u32(byte[] b, int off) {
        return ((b[off] & 0xFFL) << 24)
                | ((b[off + 1] & 0xFFL) << 16)
                | ((b[off + 2] & 0xFFL) << 8)
                | (b[off + 3] & 0xFFL);
    }

    static byte[] hex(String s) {
        return HexFormat.of().parseHex(s.replace(" ", ""));
    }

    static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }
}
