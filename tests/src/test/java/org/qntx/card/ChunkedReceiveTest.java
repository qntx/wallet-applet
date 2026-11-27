// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.tests.EmuMember;
import org.qntx.card.tests.Vecs;

/**
 * {@link Card#receiveChunk} makes {@code receiveBytes} deliver at most {@code n} bytes per call,
 * the simulator's stand-in for a segmented transport — the multi-block loop of {@code receiveAll}
 * runs under either weave. The armed-fault case is {@link ReceiveBoundTest}.
 */
final class ChunkedReceiveTest {

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    /**
     * A delivery that never produces bytes: {@code receiveAll}'s zero-return check ends the command
     * with {@code 6F00} instead of spinning — the PIT-visible twin of {@link ReceiveBoundTest}
     * (which arms the instruction site under {@code gateSweep}).
     */
    @Test
    void stalledReceiveIsBounded() throws Exception {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        Vecs.blankFor(card, a);
        card.receiveStall(true);
        try {
            byte[] rapdu = card.transmit(org.qntx.card.host.Open.request(Vecs.RND).apdu());
            int sw = ((rapdu[rapdu.length - 2] & 0xFF) << 8) | (rapdu[rapdu.length - 1] & 0xFF);
            assertEquals(0x6F00, sw, "a stalled receive must fault, not spin");
        } finally {
            card.receiveStall(false);
        }
    }

    /** Chunked delivery of a 65-byte OPEN body and a CREATE body still lands each command. */
    @Test
    void chunkedReceiveAssembles() throws Exception {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        Vecs.blankFor(card, a);
        card.receiveChunk(8);
        try {
            Session session = Vecs.open(card);
            byte[] data = new byte[96 + 16];
            System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
            System.arraycopy(Vecs.seed(), 0, data, 32, 64);
            System.arraycopy(new EmuMember().cardId, 0, data, 96, 16);
            assertEquals(
                    0x9000,
                    Vecs.roundtrip(card, session, 0x21, 1, 0, data).sw(),
                    "CREATE over a chunked receive");
        } finally {
            card.receiveChunk(0);
        }
    }
}
