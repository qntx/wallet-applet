// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review;

import static org.junit.jupiter.api.Assertions.*;
import static org.qntx.card.review.ReviewHost.*;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.qntx.card.review.ReviewSession.Inner;
import org.qntx.card.sim.Fault;

/**
 * Regression for review finding R-02: EXPORT P1=0x01 releases the seed payload guarded by the
 * pending-export check of §9.13. On the reviewed code a single fault that made the coded read
 * report {@code PENDING_EXPORT} released {@code ct ‖ tag} under the never-written pending keys — 16
 * zero bytes — and the host recovered the seed with {@code K_te = K_tm = 0¹⁶}. The fix re-reads
 * {@code Session.pending} immediately before the payload is encrypted (§16.2 item 4) and ends a
 * pending state by overwriting {@code K_te}/{@code K_tm} with fresh random values, so a payload
 * produced past a bypassed check is under keys nobody holds.
 *
 * <p>The attack test counts the {@code Session.pending} evaluations of a genuine EXPORT P1=0x01,
 * then arms every single position to {@code PENDING_EXPORT} on a card with no pending export — each
 * must be refused. The two-fault case (both evaluations armed) may output a record, but its CMAC
 * must not verify under the zero key and its plaintext under the zero key must not be the seed: the
 * pending keys are random.
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
    void forcedPendingRefusedAtEveryEvaluation() {
        ReviewCard c = ReviewCard.uninitialised();
        c.blank();
        FakeMember m = new FakeMember(ReviewCard.CA);
        ReviewSession s = c.create(S0, H0, m.cardId);
        try {
            // the full call count needs a genuine pending export: the check at the top
            // (6985) on the pending word plus the recomputation before the payload is
            // encrypted on the shadow word — two different methods now
            assertEquals(
                    0x9000,
                    s.cmd((byte) 0x41, (byte) 0x00, (byte) 0, m.exportRequest()).sw,
                    "EXPORT P1=0x00");
            Fault.countCalls();
            Inner ok = s.cmd((byte) 0x41, (byte) 0x01, (byte) 0, HT);
            assertEquals(0x9000, ok.sw, "dry-run genuine EXPORT P1=0x01");
            int calls = Fault.calls("Session.pending");
            assertEquals(1, calls, "the gate read; the recomputation is on the shadow word");
            Fault.reset();

            // the pending word's gate eval and the shadow word's recomputation, each
            // faulted alone — the other read still refuses
            String[] methods = {"Session.pending", "Session.pendingExportShadow"};
            for (int i = 0; i < methods.length; i++) {
                Fault.arm(methods[i], 1, PENDING_EXPORT);
                Inner e1 = s.cmd((byte) 0x41, (byte) 0x01, (byte) 0, HT);
                Fault.reset();
                assertTrue(
                        e1.sw == 0x6985 || e1.sw == 0x6F00,
                        "pending eval "
                                + (i + 1)
                                + " forced PENDING_EXPORT must be refused, was "
                                + String.format("%04X", e1.sw));
                if (e1.sw == 0x6F00) {
                    s = c.open();
                    assertEquals(
                            0x9000, s.cmd((byte) 0x22, (byte) 0, (byte) 0, H0).sw, "re-verify");
                    // the refusal left no pending export
                    assertEquals(
                            0x6985,
                            s.cmd((byte) 0x41, (byte) 0x01, (byte) 0, HT).sw,
                            "eval " + (i + 1) + " left a pending export");
                }
            }
        } finally {
            Fault.reset();
        }
    }

    @Test
    void twoFaultPendingBypassSealsUnderUnknownKeys() {
        ReviewCard c = ReviewCard.uninitialised();
        c.blank();
        FakeMember m = new FakeMember(ReviewCard.CA);
        ReviewSession s = c.create(S0, H0, m.cardId);
        try {
            // a two-fault campaign may bypass both pending evaluations — but the pending
            // keys were overwritten with fresh random values at the end of the last
            // pending state, so what comes out is ct ‖ tag under keys nobody holds
            Fault.arm("Session.pending", 1, PENDING_EXPORT);
            Fault.arm("Session.pendingExportShadow", 1, PENDING_EXPORT);
            Inner e1 = s.cmd((byte) 0x41, (byte) 0x01, (byte) 0, HT);
            Fault.reset();
            assertEquals(0x9000, e1.sw, "both evaluations faulted releases a record");
            assertEquals(160, e1.data.length, "ct ‖ tag for c = 2");

            // under the reviewed code these keys were zero; now they are random, so the
            // zero-key CMAC must not verify and the zero-key plaintext must not be the seed
            byte[] zero = new byte[16];
            byte[] ct = slice(e1.data, 0, e1.data.length - 16);
            byte[] tag = slice(e1.data, e1.data.length - 16, 16);
            assertFalse(
                    Arrays.equals(cmac(zero, ct), tag),
                    "CMAC under K_tm = 0 must not verify: K_tm is random");
            byte[] payload = unM2(cbcInv(zero, new byte[16], ct));
            assertTrue(
                    payload == null || !Arrays.equals(S0, slice(payload, 1, 64)),
                    "decrypting under K_te = 0 must not yield the seed");
        } finally {
            Fault.reset();
        }
    }
}
