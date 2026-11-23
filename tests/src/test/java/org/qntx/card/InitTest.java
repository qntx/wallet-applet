// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import javacard.framework.Util;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.sim.TornException;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The §4.3 bounded initialisation: the uninitialised card answers only {@code GET_IDENTITY}, each
 * call runs exactly one idempotent step, and a torn step is repeated whole. Lives in {@code
 * org.qntx.card} for {@link Const}, {@link State#OFF_INIT} and the fault hooks.
 */
final class InitTest {

    private static final byte[] GET_IDENTITY = Vecs.unhex("80E0000000");

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    /** §9.1 order on an uninitialised card: CLA first, then the init gate before the INS table. */
    @Test
    void uninitialisedAnswers6283ToEveryCommandButGetIdentity() {
        Card card = Vecs.installed();
        assertArrayEquals(Spec.SW_OK, card.transmit(Spec.SELECT));
        for (int ins :
                new int[] {
                    0xE2, 0x10, 0x12, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x30, 0x31, 0x32, 0x33,
                    0x40, 0x41, 0x42, 0x00, 0x7F, 0xFF
                }) {
            byte[] apdu = Vecs.unhex(String.format("80%02X000000", ins));
            assertEquals(0x6283, Vecs.sw(card.transmit(apdu)), String.format("INS %02X", ins));
        }
        // wrong CLA still answers 6E00 (CLA is checked before the gate); SELECT unaffected
        assertEquals(0x6E00, Vecs.sw(card.transmit(Vecs.unhex("00E2000000"))));
        assertArrayEquals(Spec.SW_OK, card.transmit(Spec.SELECT));
        // none of the rejections advanced initialisation: GET_IDENTITY is still a step
        assertEquals(0x6283, Vecs.sw(card.transmit(GET_IDENTITY)));
    }

    /** GET_IDENTITY performs one step per call: N−1 × 6283, then 9000 carrying a stable A. */
    @Test
    void getIdentityDrivesExactlyNStepsThenYieldsA() throws Exception {
        Card card = Vecs.installed();
        for (int i = 1; i < Const.INIT_STEPS; i++) {
            assertEquals(0x6283, Vecs.sw(card.transmit(GET_IDENTITY)), "step " + i);
        }
        byte[] rapdu = card.transmit(GET_IDENTITY);
        assertEquals(0x9000, Vecs.sw(rapdu));
        assertEquals(35, rapdu.length);
        byte[] a = Vecs.cardA(card);
        assertArrayEquals(Arrays.copyOf(rapdu, 33), a, "GET_IDENTITY A is stable after init");
        // the card behaves exactly as an old-tree install afterwards
        Vecs.blankFor(card, a);
        Vecs.loadWallet(card);
    }

    /**
     * Every persistent write N of every step: tear at N, power up, resume the GET_IDENTITY loop —
     * the card completes initialisation and the whole §14 pipeline still works (the A returned by
     * OPEN verifies the session, PERSONALIZE and CREATE succeed).
     */
    @Test
    void tornInitStepsResumeAndComplete() throws Exception {
        Card probe = Vecs.installed();
        int[] stepWrites = new int[Const.INIT_STEPS];
        for (int i = 0; i < Const.INIT_STEPS; i++) {
            probe.transmit(GET_IDENTITY);
            stepWrites[i] = probe.writes();
            assertTrue(stepWrites[i] >= 1, "step " + i + " wrote nothing");
        }
        for (int step = 0; step < Const.INIT_STEPS; step++) {
            for (int n = 1; n <= stepWrites[step]; n++) {
                Card card = Vecs.installed();
                for (int i = 0; i < step; i++) {
                    card.transmit(GET_IDENTITY);
                }
                card.tearAt(n);
                int at = n;
                assertThrows(
                        TornException.class,
                        () -> card.transmit(GET_IDENTITY),
                        "step " + step + " write " + at);
                card.powerCycle();
                assertArrayEquals(Spec.SW_OK, card.transmit(Spec.SELECT));
                Vecs.driveInit(card);
                Vecs.blankFor(card, Vecs.cardA(card));
                Vecs.loadWallet(card);
            }
        }
    }

    /** §16.2 item 1: the gate reads init twice; disagreement and non-member values are 6F00. */
    @Test
    void initGateFaultsAreDetected() {
        // a non-member init poked straight into the state array → 6F00 on any command
        Card card = Vecs.installed();
        Util.setShort(
                Internals.stateArray(card.applet(Spec.WALLET_AID)), State.OFF_INIT, (short) 0x1234);
        assertEquals(0x6F00, Vecs.sw(card.transmit(GET_IDENTITY)));

        // negative init (high bit set) is a non-member too
        card = Vecs.installed();
        Util.setShort(
                Internals.stateArray(card.applet(Spec.WALLET_AID)), State.OFF_INIT, (short) -1);
        assertEquals(0x6F00, Vecs.sw(card.transmit(GET_IDENTITY)));

        // INIT_STEPS itself — one past the last step index — is a non-member boundary value
        card = Vecs.installed();
        Util.setShort(
                Internals.stateArray(card.applet(Spec.WALLET_AID)),
                State.OFF_INIT,
                Const.INIT_STEPS);
        assertEquals(0x6F00, Vecs.sw(card.transmit(GET_IDENTITY)));

        // first evaluation faulted to a non-member → 6F00
        card = Vecs.factory();
        Fault.arm("State.init", 1, (short) 0x7777);
        assertEquals(0x6F00, Vecs.sw(card.transmit(GET_IDENTITY)));
        Fault.reset();

        // second evaluation faulted away from INIT_DONE on a done card → 6F00
        card = Vecs.factory();
        Fault.arm("State.init", 2, (short) 0x1111);
        assertEquals(0x6F00, Vecs.sw(card.transmit(GET_IDENTITY)));
        Fault.reset();

        // done card, first evaluation faulted to a step index: the second read is really
        // INIT_DONE, so the GET_IDENTITY path's re-check fires 6F00 instead of running a step
        card = Vecs.factory();
        Fault.arm("State.init", 1, (short) 0);
        assertEquals(0x6F00, Vecs.sw(card.transmit(GET_IDENTITY)));
        Fault.reset();
    }

    /** A faulted init advance is a torn step: the same step runs again and completes. */
    @Test
    void skippedOrFaultedInitStoreIsRepeated() {
        // the store of `init ← i+1` is skipped: the step ran but the index did not move —
        // the next GET_IDENTITY repeats the whole step and finishes it
        Card card = Vecs.installed();
        Fault.armSkip("State.setInit", 1);
        assertEquals(0x6283, Vecs.sw(card.transmit(GET_IDENTITY)));
        Fault.reset();
        Vecs.driveInit(card);
        assertEquals(0x9000, Vecs.sw(card.transmit(GET_IDENTITY)));

        // the advance store writes a non-member value instead: the next command detects it
        card = Vecs.installed();
        Fault.armStore(1, (short) 0x1234);
        assertEquals(0x6283, Vecs.sw(card.transmit(GET_IDENTITY)));
        Fault.reset();
        assertEquals(0x6F00, Vecs.sw(card.transmit(GET_IDENTITY)));
    }
}
