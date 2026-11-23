// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tools;

import java.util.HexFormat;

/** Raw-APDU constants and status helpers shared by the personalise and shell commands. */
final class Apdu {

    /** SELECT the wallet instance AID (FCI-free form, like a phone's NFC stack). */
    static final byte[] SELECT_WALLET = {
        0x00, (byte) 0xA4, 0x04, 0x00, 0x07, (byte) 0xF0, 0x71, 0x6E, 0x74, 0x78, 0x01, 0x01, 0x00
    };

    /** SELECT the issuer security domain by its AID. */
    static final byte[] SELECT_ISD = {
        0x00,
        (byte) 0xA4,
        0x04,
        0x00,
        0x08,
        (byte) 0xA0,
        0x00,
        0x00,
        0x01,
        0x51,
        0x00,
        0x00,
        0x00,
        0x00
    };

    private Apdu() {}

    static int sw(byte[] response) {
        if (response == null || response.length < 2) {
            return -1;
        }
        return (response[response.length - 2] & 0xFF) << 8 | response[response.length - 1] & 0xFF;
    }

    static String status(byte[] response) {
        int sw = sw(response);
        return sw < 0 ? "no response" : String.format("%04X", sw);
    }

    static String hex(byte[] data) {
        return HexFormat.of().formatHex(data);
    }

    /** Strict hex parse; {@code null} instead of an exception for malformed input. */
    static byte[] parseHex(String hex) {
        try {
            return HexFormat.of().parseHex(hex);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
