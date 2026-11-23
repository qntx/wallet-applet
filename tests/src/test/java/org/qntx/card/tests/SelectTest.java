// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Card;

/** Outer dispatch of protocol.md §6 and §9.1 (architecture.md §14.2 S4). */
final class SelectTest {
    private Card card;

    @BeforeEach
    void install() {
        card = Vecs.factory();
    }

    @Test
    void selectAnswers9000WithoutDataAndWritesNothing() {
        assertArrayEquals(Spec.SW_OK, card.transmit(Spec.SELECT));
        assertEquals(0, card.writes());
        assertArrayEquals(Spec.SW_OK, card.transmit(Spec.SELECT));
        assertEquals(0, card.writes());
    }

    @Test
    void everyClassOtherThan80Answers6E00() {
        card.transmit(Spec.SELECT);
        for (int cla = 0; cla < 256; cla++) {
            if (cla == 0x80) {
                continue;
            }
            byte[] apdu = {(byte) cla, (byte) 0xE0, 0, 0, 0};
            assertArrayEquals(Spec.SW_CLA, card.transmit(apdu), "CLA " + cla);
            assertArrayEquals(
                    Spec.SW_CLA,
                    card.transmit(new byte[] {(byte) cla, 0x12, 0, 0, 1, 0}),
                    "CLA " + cla);
        }
    }

    @Test
    void classCheckPrecedesTheInstructionCheck() {
        card.transmit(Spec.SELECT);
        assertArrayEquals(Spec.SW_CLA, card.transmit(Spec.hex("00E0000000")));
        assertArrayEquals(Spec.SW_CLA, card.transmit(Spec.hex("8100000000")));
    }

    @Test
    void everyInstructionOutsideTheOuterTableIsUnknown() {
        card.transmit(Spec.SELECT);
        for (int ins = 0; ins < 256; ins++) {
            // §9.1: implemented outer commands have their own checks, not 6D00
            if (ins == 0xE0 || ins == 0xE2 || ins == 0x10 || ins == 0x12) {
                continue;
            }
            assertArrayEquals(
                    Spec.SW_INS,
                    card.transmit(new byte[] {(byte) 0x80, (byte) ins, 0, 0, 0}),
                    "INS " + ins);
            assertArrayEquals(
                    Spec.SW_INS,
                    card.transmit(new byte[] {(byte) 0x80, (byte) ins, 1, 2, 2, 3, 4, 0}),
                    "INS " + ins);
            assertEquals(0, card.writes());
        }
    }
}
