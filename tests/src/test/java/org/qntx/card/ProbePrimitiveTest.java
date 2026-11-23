// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.qntx.card.probe.AdmissionProbe;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Vecs;

/**
 * The probe's INS {@code 0x60} primitive profile (architecture §10): {@code P2 = 0} must run only
 * the dispatch for every known primitive, unknown primitives must stay {@code 6A86}, and the
 * primitives the simulator implements must actually complete a loop.
 */
final class ProbePrimitiveTest {

    private static byte[] prim(int p1, int r, byte[] data) {
        byte[] a = new byte[5 + (data == null ? 0 : data.length)];
        a[0] = (byte) 0x80;
        a[1] = 0x60;
        a[2] = (byte) p1;
        a[3] = (byte) r;
        if (data != null) {
            a[4] = (byte) data.length;
            System.arraycopy(data, 0, a, 5, data.length);
        }
        return a;
    }

    private static int sw(byte[] rapdu) {
        return ((rapdu[rapdu.length - 2] & 0xFF) << 8) | (rapdu[rapdu.length - 1] & 0xFF);
    }

    private static Card probeCard() {
        Card card = new Card();
        card.install(Vecs.unhex("F0716E7478FF01"), AdmissionProbe.class);
        card.transmit(Vecs.unhex("00A4040007F0716E7478FF0100"));
        return card;
    }

    @Test
    void zeroRepsRunsOnlyTheDispatchForEveryPrimitive() {
        Card card = probeCard();
        for (int p1 = 1; p1 <= 0x16; p1++) {
            assertEquals(
                    0x9000,
                    sw(card.transmit(prim(p1, 0, null))),
                    String.format("primitive %02X r=0", p1));
        }
        assertEquals(0x6A86, sw(card.transmit(prim(0x17, 0, null))), "unknown primitive");
        assertEquals(0x6A86, sw(card.transmit(prim(0x00, 0, null))), "primitive 0");
    }

    @Test
    void enginePrimitivesLoopOnTheSimulator() {
        Card card = probeCard();
        byte[] key = new byte[16];
        byte[] keyIv = new byte[32];
        for (int p1 : new int[] {0x07, 0x08, 0x09, 0x14, 0x15, 0x16}) {
            assertEquals(
                    0x9000,
                    sw(card.transmit(prim(p1, 4, null))),
                    String.format("primitive %02X r=4", p1));
        }
        for (int p1 : new int[] {0x02, 0x03, 0x04, 0x05, 0x06}) {
            assertEquals(
                    0x9000,
                    sw(card.transmit(prim(p1, 4, key))),
                    String.format("primitive %02X r=4", p1));
        }
        assertEquals(0x9000, sw(card.transmit(prim(0x01, 4, keyIv))), "AES-CBC init with IV");
    }
}
