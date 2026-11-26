// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Agent;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.tests.Vecs;

/**
 * G-07 / §16.3: {@code receiveAll} assembles multi-block deliveries and is bounded — a {@code
 * receiveBytes} that never delivers exits with {@code 6F00} after at most {@code lc} calls instead
 * of spinning until teardown. The forced-zero fault needs the {@code sites} weave ({@code
 * gateSweep}) and self-skips without it; the positive case is {@link ChunkedReceiveTest}.
 */
final class ReceiveBoundTest {

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    /**
     * {@code receiveBytes} forced to return 0 on every call (site {@code i4} skip, {@code nth = 0})
     * after {@code setIncomingAndReceive} delivered only a chunk: the loop exits after
     * {@code MAX_RECEIVE_CALLS = 255} calls with {@code 6F00} (the faulted lc is not
     * trusted: short APDUs cap at 255). Before the bound the same fault spun forever.
     */
    @Test
    void receiveZeroReturnIsBounded() throws Exception {
        assumeTrue(Agent.siteWeaving(), "instruction-site weaving is not enabled");
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        Vecs.blankFor(card, a);
        card.receiveChunk(8);
        try {
            Fault.armSite("WalletApplet.receiveAll#i4", 0, Fault.SITE_SKIP);
            org.qntx.card.host.Open.Request req = org.qntx.card.host.Open.request(Vecs.RND);
            byte[] rapdu = card.transmit(req.apdu());
            assertEquals(
                    0x6F00,
                    ((rapdu[rapdu.length - 2] & 0xFF) << 8) | (rapdu[rapdu.length - 1] & 0xFF));
        } finally {
            card.receiveChunk(0);
        }
    }
}
