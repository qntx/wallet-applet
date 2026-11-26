// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javacard.framework.ISO7816;
import javacard.framework.Util;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.probe.DsaProbe;

/**
 * The {@code #d}/{@code #s}/{@code #a} sites the agent weaves under {@code dsa=} and the {@link
 * Fault#SITE_TAKE}/{@link Fault#SITE_FALL}/{@link Fault#SITE_FORCED} modes of the branch and invoke
 * sites (architecture §6): each test faults one site of {@link DsaProbe} and asserts the faulted
 * value, branch or store actually reaches the response. The watchdog's {@link Fault.Hang} is proven
 * on a loop armed below its site-hit count.
 */
final class DsaSitesTest {

    private static final byte[] AID = {0x01, 0x02, 0x03, 0x04, 0x07};
    private static final byte INS_BRANCH = 0x10;
    private static final byte INS_LOAD = 0x11;
    private static final byte INS_STORE = 0x12;
    private static final byte INS_ARITH = 0x13;
    private static final byte INS_INVOKE = 0x14;
    private static final byte INS_LOOP = 0x15;

    private Card card;

    @BeforeEach
    void setUp() {
        card = new Card();
        card.install(AID, DsaProbe.class);
        byte[] sel = new byte[5 + AID.length];
        sel[ISO7816.OFFSET_INS] = (byte) 0xA4;
        sel[ISO7816.OFFSET_P1] = 0x04;
        sel[ISO7816.OFFSET_LC] = (byte) AID.length;
        System.arraycopy(AID, 0, sel, ISO7816.OFFSET_CDATA, AID.length);
        card.transmit(sel);
    }

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    private static byte[] cmd(byte ins, byte p1, byte p2) {
        byte[] apdu = new byte[5];
        apdu[ISO7816.OFFSET_INS] = ins;
        apdu[ISO7816.OFFSET_P1] = p1;
        apdu[ISO7816.OFFSET_P2] = p2;
        return apdu;
    }

    private short ask(byte ins, byte p1, byte p2) {
        return Util.getShort(card.transmit(cmd(ins, p1, p2)), (short) 0);
    }

    @Test
    void branchTakeAndFallForceBothOutcomes() {
        assertEquals(99, ask(INS_BRANCH, (byte) 7, (byte) 0));
        assertEquals(3, ask(INS_BRANCH, (byte) 3, (byte) 0));
        // `x == 7` compiles to `if_icmpne <after the body>`: TAKE jumps away from
        // the body, FALL runs it
        Fault.armSite("DsaProbe.branch#b1", 0, Fault.SITE_TAKE);
        assertEquals(7, ask(INS_BRANCH, (byte) 7, (byte) 0), "TAKE jumps to the target");
        Fault.reset();
        Fault.armSite("DsaProbe.branch#b1", 0, Fault.SITE_FALL);
        assertEquals(99, ask(INS_BRANCH, (byte) 3, (byte) 0), "FALL runs the body");
    }

    @Test
    void dataSitesReplaceTheLoadedValue() {
        assertEquals(1 + 2 + 3 + 5, ask(INS_LOAD, (byte) 0, (byte) 0));
        // #d1 = iconst_0 (arr index), #d2 = saload arr[0], #d3 = getfield field,
        // #d4 = iconst_0 (bytes index), #d5 = baload bytes[0], #d6 = iconst_5
        Fault.armSite("DsaProbe.load#d2", 0, Fault.SITE_ZERO);
        assertEquals(0 + 2 + 3 + 5, ask(INS_LOAD, (byte) 0, (byte) 0), "ZERO replaces arr[0]");
        Fault.reset();
        Fault.armSite("DsaProbe.load#d5", 0, Fault.SITE_ONES);
        assertEquals(1 + 2 - 1 + 5, ask(INS_LOAD, (byte) 0, (byte) 0), "ONES replaces bytes[0]");
        Fault.reset();
        Fault.armSite("DsaProbe.load#d6", 0, Fault.SITE_FLIP);
        // iconst_5 faulted to 5 ^ 1 = 4
        assertEquals(1 + 2 + 3 + 4, ask(INS_LOAD, (byte) 0, (byte) 0), "FLIP flips the constant");
    }

    @Test
    void storeSitesSkipTheWrite() {
        // clean: x = 42; x++ → 43; arr[1] = 43; reply arr[0] + arr[1] = 1 + 43
        assertEquals(44, ask(INS_STORE, (byte) 0, (byte) 0));
        // #s1 = istore x=p, #s2 = istore of 42, #s3 = iinc, #s4 = sastore arr[1]
        Fault.armSite("DsaProbe.store#s2", 0, Fault.SITE_SKIP);
        // skipped istore leaves x = 0 → x++ → 1 → arr[1] = 1 → reply 2
        assertEquals(2, ask(INS_STORE, (byte) 5, (byte) 0), "skipped istore keeps the argument");
        Fault.reset();
        Fault.armSite("DsaProbe.store#s3", 0, Fault.SITE_SKIP);
        assertEquals(43, ask(INS_STORE, (byte) 0, (byte) 0), "skipped iinc leaves 42");
        Fault.reset();
        Fault.armSite("DsaProbe.store#s4", 0, Fault.SITE_SKIP);
        // arr[1] persists across commands: the skipped store leaves the previous run's 42
        assertEquals(43, ask(INS_STORE, (byte) 0, (byte) 0), "skipped sastore keeps the old 42");
    }

    @Test
    void arithSiteKeepsTheLeftOperand() {
        assertEquals(11, ask(INS_ARITH, (byte) 5, (byte) 6));
        Fault.armSite("DsaProbe.arith#a1", 0, Fault.SITE_SKIP);
        assertEquals(5, ask(INS_ARITH, (byte) 5, (byte) 6), "iadd replaced by its left operand");
    }

    @Test
    void invokeForcedPushesTheArmedValue() {
        assertEquals(4, ask(INS_INVOKE, (byte) 3, (byte) 0));
        Fault.armSite("DsaProbe.invoke#i1", 0, Fault.SITE_FORCED, (short) 77);
        assertEquals(77, ask(INS_INVOKE, (byte) 3, (byte) 0), "FORCED pushes the armed value");
        Fault.reset();
        Fault.armSite("DsaProbe.invoke#i1", 0, Fault.SITE_SKIP);
        assertEquals(0, ask(INS_INVOKE, (byte) 3, (byte) 0), "SKIP still pushes zero");
    }

    @Test
    void watchdogThrowsHangPastTheBudget() {
        assertEquals(6, ask(INS_LOOP, (byte) 4, (byte) 0));
        Fault.armSkip("nothing.armed", 1); // activates the counters
        Fault.watchdog(10);
        assertThrows(Fault.Hang.class, () -> ask(INS_LOOP, (byte) 4, (byte) 0));
        Fault.reset();
        assertEquals(6, ask(INS_LOOP, (byte) 4, (byte) 0), "reset clears the budget");
    }
}
