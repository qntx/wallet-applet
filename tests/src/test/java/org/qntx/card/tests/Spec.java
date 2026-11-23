// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import java.util.HexFormat;

/** Identifiers and status words as written in spec/protocol.md, independent of the applet. */
public final class Spec {
    /** §2: load file (package) AID. */
    public static final byte[] PACKAGE_AID = hex("F0716E747800");

    /** §2: wallet applet class AID and instance AID. */
    public static final byte[] WALLET_AID = hex("F0716E74780101");

    /** §2: NDEF applet class AID (the instance AID is the Type 4 Tag application AID). */
    public static final byte[] NDEF_APPLET_AID = hex("F0716E74780201");

    /** §2: NDEF applet instance AID. */
    public static final byte[] NDEF_AID = hex("D2760000850101");

    /** §6: SELECT of the wallet applet. */
    public static final byte[] SELECT = hex("00A4040007F0716E7478010100");

    /** §15: SELECT of the NDEF applet. */
    public static final byte[] SELECT_NDEF = hex("00A4040007D276000085010100");

    public static final byte[] SW_OK = hex("9000");
    public static final byte[] SW_CLA = hex("6E00");
    public static final byte[] SW_INS = hex("6D00");

    private Spec() {}

    public static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }
}
