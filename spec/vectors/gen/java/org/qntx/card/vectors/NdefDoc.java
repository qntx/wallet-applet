// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * {@code ndef.json}: the §15 capability container and NDEF file for the sample messages of the
 * brief's table (lengths 1, 16, 100), the READ BINARY rows of the 16-byte message and the rejected
 * install lengths. Independent oracle: NFC Forum T4T 2.0 §5, built by hand here.
 */
final class NdefDoc {
    /** The "qntx card" NDEF Text record, 16 bytes. */
    private static final String MSG16 = "d1010c5402656e716e74782063617264";

    private NdefDoc() {}

    static Object document() {
        List<Object> messages =
                List.of(
                        message(new byte[] {0x55}),
                        message(Vec.unhex(MSG16)),
                        message(Vec.seq(1, 100)));
        return Vec.object(
                "messages", messages, "reads", reads(), "rejectedInstall", List.of(0, 101));
    }

    private static Map<String, Object> message(byte[] msg) {
        return Vec.object(
                "msg", Vec.hex(msg), "cc", Vec.hex(cc(msg.length)), "ndefFile", Vec.hex(ndef(msg)));
    }

    /**
     * READ BINARY rows of the 16-byte message (§15): every listed offset against every listed Le,
     * {@code data} = min(Ne, size − off), {@code off > size} → 6b00.
     */
    private static List<Object> reads() {
        byte[] msg = Vec.unhex(MSG16);
        byte[][] files = {cc(msg.length), ndef(msg)};
        String[] names = {"cc", "ndef"};
        int[] les = {1, 15, 0};
        List<Object> rows = new ArrayList<>();
        for (int f = 0; f < files.length; f++) {
            int size = files[f].length;
            int[] offs = {0, 1, size - 1, size, size + 1, 0x8000, 0xFFFF};
            for (int off : offs) {
                for (int le : les) {
                    int ne = le == 0 ? 256 : le;
                    String sw = off > size ? "6b00" : "9000";
                    int len = off > size ? 0 : Math.min(ne, size - off);
                    byte[] data = new byte[len];
                    if (len > 0) {
                        System.arraycopy(files[f], off, data, 0, len);
                    }
                    rows.add(
                            Vec.object(
                                    "file", names[f],
                                    "off", off,
                                    "le", le,
                                    "data", Vec.hex(data),
                                    "sw", sw));
                }
            }
        }
        return rows;
    }

    /** §15: {@code 000F ‖ 20 ‖ 00FF ‖ 00FF ‖ 04 06 ‖ E104 ‖ u16(2+|msg|) ‖ 00 ‖ FF}. */
    private static byte[] cc(int msgLen) {
        byte[] cc = {
            0x00,
            0x0F,
            0x20,
            0x00,
            (byte) 0xFF,
            0x00,
            (byte) 0xFF,
            0x04,
            0x06,
            (byte) 0xE1,
            0x04,
            (byte) ((msgLen + 2) >> 8),
            (byte) (msgLen + 2),
            0x00,
            (byte) 0xFF
        };
        return cc;
    }

    /** §15: {@code u16(|msg|) ‖ msg}. */
    private static byte[] ndef(byte[] msg) {
        byte[] file = new byte[msg.length + 2];
        file[0] = (byte) (msg.length >> 8);
        file[1] = (byte) msg.length;
        System.arraycopy(msg, 0, file, 2, msg.length);
        return file;
    }
}
