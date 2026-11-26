// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.tests.Vecs;

/**
 * VERIFY step 6's third {@code fails} read (§9.5, §16.2 item 4): a skipped T-FAIL plus a forced
 * {@code State.readFails} used to satisfy both {@code gate(fb)} evaluations — the {@code match}
 * comparison then ran on a counter that was never committed (an uncounted attempt). The gate now
 * evaluates {@code fb} and the third read {@code fc}: one forced read cannot satisfy both, and
 * {@code match} is never reached.
 */
final class VerifyFailsReadTest {
    private static final int INS_STATUS = 0x20;
    private static final int INS_VERIFY = 0x22;

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    @Test
    void skippedTFailPlusForcedReadIsRefused() throws Exception {
        Card card = Vecs.blankSelf();
        Session session = Vecs.open(card);
        // CREATE (P1 = 1) loads the wallet; a wrong code then commits T-FAIL: f = 1
        Response created =
                Vecs.roundtrip(card, session, 0x21, 1, 0, concat(Vecs.accessHash(), Vecs.seed()));
        assertEquals(0x9000, created.sw(), "CREATE");
        Response wrong = Vecs.roundtrip(card, session, INS_VERIFY, 0, 0, Vecs.accessHashWrong());
        assertEquals(0x63C9, wrong.sw(), "first wrong VERIFY");
        // fault 1: T-FAIL is skipped, so the stored counter stays f = 1; fault 2: the
        // second of the three fails reads returns f - 1 = 0, so the fb gate sees the
        // expected f = fb + 1 while the fc gate does not
        Fault.armSkip("Wallet.tFail", 1);
        Fault.arm("State.readFails", 2, (short) 0);
        int sw;
        int matchCalls;
        int tOkCalls;
        try {
            sw = Vecs.roundtrip(card, session, INS_VERIFY, 0, 0, Vecs.accessHashWrong()).sw();
            matchCalls = Fault.calls("Wallet.match");
            tOkCalls = Fault.calls("Wallet.tOk");
        } finally {
            Fault.reset();
        }
        assertEquals(0x6F00, sw, "VERIFY must refuse");
        assertEquals(0, matchCalls, "match ran an uncounted comparison");
        assertEquals(0, tOkCalls, "T-OK ran");
        // a step-6 fault erases the wallet (§9.5): a fresh session reads BLANK
        Session after = Vecs.open(card);
        Response status = Vecs.roundtrip(card, after, INS_STATUS, 0, 0, new byte[0]);
        assertEquals(0x9000, status.sw(), "STATUS");
        assertEquals(0x01, status.data()[0] & 0xFF, "life is not BLANK after the gate fault");
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
