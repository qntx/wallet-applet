// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * The NDEF applet (protocol.md §15): a read-only NFC Forum Type 4 Tag, mapping version 2.0, whose
 * capability container and NDEF file are written once at install. It holds no keys and no user data
 * and writes persistent memory only in the constructor.
 */
public final class NdefApplet extends Applet {
    /** §15: the capability container's file ID. */
    private static final short FID_CC = (short) 0xE103;

    /** §15: the NDEF file's file ID. */
    private static final short FID_NDEF = (short) 0xE104;

    /** §15: the message must be 1..100 bytes for the install to succeed. */
    private static final short MSG_MAX = 100;

    /** READ BINARY; ISO7816 has no constant for it. */
    private static final byte INS_READ_BINARY = (byte) 0xB0;

    /** UPDATE BINARY; ISO7816 has no constant for it. */
    private static final byte INS_UPDATE_BINARY = (byte) 0xD6;

    /** §15: offset outside the selected file; ISO7816 has no constant for 6B00. */
    private static final short SW_OFFSET_OUTSIDE_EF = (short) 0x6B00;

    private final byte[] cc;
    private final byte[] ndef;

    /**
     * The selected FID, 0 when none (architecture.md §5.1). CLEAR_ON_DESELECT is per context and
     * both applets of this package share one, so {@code process} resets it on every SELECT by AID
     * rather than relying on the platform.
     */
    private final short[] selected;

    private NdefApplet(byte[] bArray, short bOffset) {
        // GlobalPlatform install data [Li AID][Lc control][La applet data]; §15 makes the
        // applet data the NDEF message
        short aidLen = (short) (bArray[bOffset] & 0xFF);
        short ctrlLen = (short) (bArray[(short) (bOffset + aidLen + 1)] & 0xFF);
        short msgOff = (short) (bOffset + aidLen + ctrlLen + 3);
        short msgLen = (short) (bArray[(short) (bOffset + aidLen + ctrlLen + 2)] & 0xFF);
        if (msgLen < 1 || msgLen > MSG_MAX) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // §15: 000F ‖ 20 ‖ 00FF ‖ 00FF ‖ 04 06 ‖ E104 ‖ u16(2+|msg|) ‖ 00 ‖ FF
        cc = new byte[15];
        cc[1] = 0x0F;
        cc[2] = 0x20;
        cc[4] = (byte) 0xFF;
        cc[6] = (byte) 0xFF;
        cc[7] = 0x04;
        cc[8] = 0x06;
        Util.setShort(cc, (short) 9, FID_NDEF);
        Util.setShort(cc, (short) 11, (short) (msgLen + 2));
        cc[14] = (byte) 0xFF;
        // §15: u16(|msg|) ‖ msg
        ndef = new byte[(short) (msgLen + 2)];
        Util.setShort(ndef, (short) 0, msgLen);
        Util.arrayCopy(bArray, msgOff, ndef, (short) 2, msgLen);
        selected = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    /** GlobalPlatform install entry; the instance AID is taken from the install data. */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new NdefApplet(bArray, bOffset);
    }

    /** The §15 checks, in order. Every response is a status word or file bytes. */
    public void process(APDU apdu) {
        if (selectingApplet()) {
            selected[0] = 0;
            return;
        }
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_CLA] != 0) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        switch (buf[ISO7816.OFFSET_INS]) {
            case ISO7816.INS_SELECT:
                selectFile(apdu, buf);
                return;
            case INS_READ_BINARY:
                readBinary(apdu, buf);
                return;
            case INS_UPDATE_BINARY:
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                return;
        }
    }

    /**
     * SELECT file (§15): only {@code P1 P2 = 00 0C} and only the two-byte data {@code E103} or
     * {@code E104} select; every other file ID or data length is {@code 6A82} and leaves the
     * current selection untouched.
     */
    private void selectFile(APDU apdu, byte[] buf) {
        if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0x0C) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        apdu.setIncomingAndReceive();
        short fid = Util.getShort(buf, ISO7816.OFFSET_CDATA);
        if (apdu.getIncomingLength() != 2 || (fid != FID_CC && fid != FID_NDEF)) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        selected[0] = fid;
    }

    /**
     * READ BINARY (§15): {@code off = P1‖P2} is unsigned, so a negative short read is an offset
     * past any file. Returns {@code min(Ne, size − off)} bytes; {@code off = size} returns none.
     */
    private void readBinary(APDU apdu, byte[] buf) {
        byte[] file;
        if (selected[0] == FID_CC) {
            file = cc;
        } else if (selected[0] == FID_NDEF) {
            file = ndef;
        } else {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }
        short off = Util.getShort(buf, ISO7816.OFFSET_P1);
        short avail = (short) (file.length - off);
        if (off < 0 || avail < 0) {
            ISOException.throwIt(SW_OFFSET_OUTSIDE_EF);
        }
        short ne = apdu.setOutgoing();
        if (ne < avail) {
            avail = ne;
        }
        apdu.setOutgoingLength(avail);
        if (avail != 0) {
            apdu.sendBytesLong(file, off, avail);
        }
    }
}
