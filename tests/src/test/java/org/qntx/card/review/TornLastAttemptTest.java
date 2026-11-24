// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.qntx.card.review.ReviewHost.*;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.TornException;

/**
 * Review finding R-04, pinned as documented behaviour (§9.5, threat-model T-D4): at f = 9 with the
 * W waits done, VERIFY with the RIGHT code commits T-FAIL(f = 10) before comparing; a power cut
 * during the following T-OK commit leaves f = 10 — the wallet is lost at the next VERIFY even
 * though the presented code was correct. T-FAIL must precede the comparison (P3), so this is a
 * documented residual risk, not a defect: hosts keep the card in the field for a VERIFY answered
 * with tries = 1. The tear index is measured on a dry run (the write count of the VERIFY command),
 * not hard-coded.
 */
final class TornLastAttemptTest {

    private static final byte[] S0 =
            unhex(
                    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
                            + "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
    private static final byte[] H0 = sha256("torn-last-attempt H0".getBytes());

    /** L1 at f = 9 with the waits done; returns {card, session}. */
    private static Object[] rig() {
        ReviewCard c = ReviewCard.uninitialised();
        c.blank();
        c.create(S0, H0);
        c.injectFails(9);
        ReviewSession s = c.open();
        ReviewCard.waitW(s);
        return new Object[] {c, s};
    }

    @Test
    void tornCorrectLastAttemptLosesTheWallet() {
        // dry run on a twin: measure the command's write count; the T-OK write is the last
        Object[] dry = rig();
        ReviewCard dc = (ReviewCard) dry[0];
        ReviewSession ds = (ReviewSession) dry[1];
        byte[] apdu =
                ds.recordApdu((byte) 0, (byte) 0, ds.record((byte) 0x22, (byte) 0, (byte) 0, H0));
        ds.raw(apdu);
        int n = dc.card.writes();
        List<Integer> commits = dc.card.commits();
        assertTrue(
                n >= 2 && commits.size() >= 2,
                "expected T-FAIL + T-OK writes, got writes=" + n + " commits=" + commits);

        // torn run: cut at the first write after T-FAIL's commit — the T-OK write
        Object[] run = rig();
        ReviewCard c = (ReviewCard) run[0];
        ReviewSession s = (ReviewSession) run[1];
        c.card.tearAt(n);
        assertThrows(
                TornException.class,
                () ->
                        s.raw(
                                s.recordApdu(
                                        (byte) 0,
                                        (byte) 0,
                                        s.record((byte) 0x22, (byte) 0, (byte) 0, H0))));
        c.card.powerCycle();
        c.transmit(SELECT_WALLET);

        // new session: STATUS 02 00 (LOADED, 0 tries), VERIFY(right) → 6983, STATUS 01 00
        ReviewSession s2 = c.open();
        ReviewSession.Inner st = s2.cmd((byte) 0x20, (byte) 0, (byte) 0, new byte[0]);
        assertEquals(0x9000, st.sw);
        assertEquals(0x02, st.data[0] & 0xFF, "life must still be LOADED");
        assertEquals(0x00, st.data[1] & 0xFF, "f = 10 → 0 tries left");
        ReviewSession s3 = c.open();
        ReviewSession.Inner v = s3.cmd((byte) 0x22, (byte) 0, (byte) 0, H0);
        assertEquals(0x6983, v.sw, "VERIFY after f = 10 must refuse without comparing");
        ReviewSession s4 = c.open();
        ReviewSession.Inner st2 = s4.cmd((byte) 0x20, (byte) 0, (byte) 0, new byte[0]);
        assertEquals(0x9000, st2.sw);
        assertEquals(0x01, st2.data[0] & 0xFF, "the card is BLANK — wallet lost");
    }
}
