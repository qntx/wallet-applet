// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.admission;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * Second applet of the admission package, ported from {@code
 * applet-audit/audit-impl/evidence/probe/Probe2.java}: selecting it tests CLEAR_ON_DESELECT within
 * one package context.
 */
public class Probe2 extends Applet {
    protected Probe2() {}

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Probe2().register();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
}
