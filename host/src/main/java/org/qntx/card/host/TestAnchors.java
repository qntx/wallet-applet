// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import java.util.Arrays;
import java.util.HexFormat;

/**
 * The public keys of the test CAs {@code ca1} and {@code ca2} of {@code spec/vectors/cert.json}.
 * They anchor only simulator and development cards: protocol.md §5.2 — production hosts MUST NOT
 * trust test anchors. The data is public, so equality is not constant time.
 */
public final class TestAnchors {
    /** cert.json {@code cas[0].public} ("ca1"), uncompressed SEC 1. */
    public static final byte[] CA1 =
            HexFormat.of()
                    .parseHex(
                            "04326ee50a70d17883e337bad61f8075e1510904110ca189423cb4fa3c7ae24d69"
                                    + "bb49ba03e8e46321cadeee736ddc1fd1bcb0bc3dad5fdd598dd1a87c31b63f22");

    /** cert.json {@code cas[1].public} ("ca2"), uncompressed SEC 1. */
    public static final byte[] CA2 =
            HexFormat.of()
                    .parseHex(
                            "04efe9c27de8130ee8404b3fd2a9e4899be37cf84f12aa470b5132c964ec74116c"
                                    + "826729ec50252e8934c35972385bfdb6e8ef418dfb498483c564ebaf0f2ae9dc");

    private TestAnchors() {}

    /** {@code anchor} is one of the test CA public keys. */
    public static boolean isTest(byte[] anchor) {
        return Arrays.equals(anchor, CA1) || Arrays.equals(anchor, CA2);
    }
}
