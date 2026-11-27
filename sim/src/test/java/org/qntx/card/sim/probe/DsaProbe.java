// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim.probe;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.Util;

/**
 * Probe for the architecture §6 data/store/arithmetic sites of the agent's {@code dsa=} weave:
 * every command packs exactly one of the guarded instruction shapes into its own method so a test
 * can arm a {@code #d}/{@code #s}/{@code #a} site and observe the faulted value in the response.
 */
public final class DsaProbe extends Applet {

    private static final byte INS_BRANCH = 0x10;
    private static final byte INS_LOAD = 0x11;
    private static final byte INS_STORE = 0x12;
    private static final byte INS_ARITH = 0x13;
    private static final byte INS_INVOKE = 0x14;
    private static final byte INS_LOOP = 0x15;

    private short field;
    private final short[] arr;
    private final byte[] bytes;

    private DsaProbe() {
        field = 2;
        arr = new short[] {1, 7};
        bytes = new byte[] {3, 9};
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new DsaProbe().register();
    }

    /** {@code #b1}: the {@code x == 7} test. */
    private short branch(short x) {
        if (x == 7) {
            x = 99;
        }
        return x;
    }

    /** {@code #d1} = {@code saload arr[0]}, {@code #d2} = {@code getfield field}, … */
    private short load() {
        return (short) (arr[0] + field + bytes[0] + 5);
    }

    /** {@code #s1} = {@code istore} of 42, {@code #s2} = {@code iinc}, {@code #s3} = sastore. */
    private short store(short p) {
        int x = p; // int so x++ compiles to a real iinc
        x = 42;
        x++;
        arr[1] = (short) x;
        return (short) (arr[0] + arr[1]);
    }

    /** {@code #a1}: the {@code iadd}. */
    private short arith(short x, short y) {
        return (short) (x + y);
    }

    short call(short x) {
        return (short) (x + 1);
    }

    /** {@code #i1}: the invoke of {@link #call} — an {@code "iS"} site. */
    private short invoke(short x) {
        return call(x);
    }

    /** Loop of {@code n} iterations: several sites per round for the watchdog test. */
    private short loop(short n) {
        short sum = 0;
        for (short i = 0; i < n; i++) {
            sum += i;
        }
        return sum;
    }

    private void reply(APDU apdu, short v) {
        byte[] buffer = apdu.getBuffer();
        Util.setShort(buffer, (short) 0, v);
        apdu.setOutgoingAndSend((short) 0, (short) 2);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        short p1 = (short) (buffer[ISO7816.OFFSET_P1] & 0xFF);
        short p2 = (short) (buffer[ISO7816.OFFSET_P2] & 0xFF);
        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_BRANCH -> reply(apdu, branch(p1));
            case INS_LOAD -> reply(apdu, load());
            case INS_STORE -> reply(apdu, store(p1));
            case INS_ARITH -> reply(apdu, arith(p1, p2));
            case INS_INVOKE -> reply(apdu, invoke(p1));
            case INS_LOOP -> reply(apdu, loop(p1));
            default -> reply(apdu, (short) -1);
        }
    }
}
