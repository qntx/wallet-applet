// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review;

import static org.junit.jupiter.api.Assertions.*;
import static org.qntx.card.review.ReviewHost.*;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import org.qntx.card.review.ReviewSession.Inner;
import org.qntx.card.sim.Fault;

/**
 * Regression for review finding R-05: IMPORT P1=0x00 verifies the sender's export signature {@code
 * sig_S}. On the reviewed code a single fault making that one verification report {@code CHECK_OK}
 * let an attacker run a whole import with no source card at all — a genuine member certificate
 * (public), an attacker-chosen {@code E} whose scalar it knows, 64 garbage bytes as {@code sig_S}
 * and a payload it sealed itself — installing an attacker-known seed with {@code origin =
 * generated}. The fix recomputes the {@code sig_S} verification immediately before the pending
 * import keys are derived (§16.2 item 4).
 *
 * <p>The attack test counts the woven {@code Secp256k1.verifyHash} calls on a genuine head (the
 * member signs a real {@code sig_S}), then arms every single position to {@code CHECK_OK} on the
 * garbage-signature head. Each must be refused, no pending import may be left and the card must
 * stay {@code BLANK}.
 */
final class SpofImportSourceTest {

    private static final byte[] ATK_SEED = unhex("A5".repeat(64));
    private static final byte[] ATK_HASH = sha256("review attacker access hash".getBytes());
    private static final byte[] GARBAGE_SIG = sha512("not a signature".getBytes());
    private static final short CHECK_OK = (short) 0x6666;

    private static final class Rig {
        ReviewCard c;
        ReviewSession s;
        FakeMember m;
        BigInteger e; // the attacker's scalar behind E — it knows it
        byte[] epk; // E = e·G, uncompressed
        byte[] lkT; // the target's offered link public key
    }

    /** BLANK target that has answered OFFER; the attacker plays the source itself. */
    private static Rig rig() {
        Rig r = new Rig();
        r.c = ReviewCard.uninitialised();
        r.c.blank();
        r.m = new FakeMember(ReviewCard.CA); // genuine member cert: CA-signed, public
        r.s = r.c.open();
        Inner of = r.s.cmd((byte) 0x40, (byte) 0, (byte) 0, new byte[0]);
        assertEquals(0x9000, of.sw, "OFFER");
        r.lkT = slice(of.data, 0, 65);
        r.e = randomScalar();
        r.epk = uncomp(g().multiply(r.e));
        return r;
    }

    /** cert_S ‖ E ‖ 64 garbage bytes — a head only the sig_S check can reject. */
    private static byte[] import0Command(Rig r) {
        return concat(r.m.cert, r.epk, GARBAGE_SIG);
    }

    /** STATUS (0x20): life byte 0x01 = BLANK, in a session opened if the refusal tore the old. */
    private static void assertBlank(Rig r) {
        if (!r.s.open) {
            r.s = r.c.open();
        }
        Inner st = r.s.cmd((byte) 0x20, (byte) 0, (byte) 0, new byte[0]);
        assertEquals(0x9000, st.sw, "STATUS");
        assertEquals(0x01, st.data[0] & 0xFF, "the card must stay BLANK");
    }

    @Test
    void controlWithoutFault() {
        Rig r = rig();
        try {
            Inner i0 = r.s.cmd((byte) 0x42, (byte) 0x00, (byte) 0, import0Command(r));
            assertEquals(0x6A80, i0.sw, "control: garbage sig_S must be refused 6A80");
        } finally {
            Fault.reset();
        }
    }

    @Test
    void garbageSourceRefusedAtEveryEvaluation() {
        // the full call count needs a genuine head: the member signs a real sig_S over
        // M = "…/export" ‖ A_S ‖ A_T ‖ LK_T ‖ E — cert_S and its recomputation before
        // the peer-slot write, sig_S and its recomputation before the keys = 4
        Rig dry = rig();
        byte[][] head = dry.m.exportOffer(dry.s.cardA, dry.lkT);
        try {
            Fault.countCalls();
            Inner ok = dry.s.cmd((byte) 0x42, (byte) 0x00, (byte) 0, head[0]);
            assertEquals(0x9000, ok.sw, "dry-run genuine import head");
            int calls = Fault.calls("Secp256k1.verifyHash");
            assertEquals(4, calls, "cert_S and sig_S, each with its recomputation");
        } finally {
            Fault.reset();
        }

        for (int i = 1; i <= 4; i++) {
            Rig r = rig();
            try {
                Fault.arm("Secp256k1.verifyHash", i, CHECK_OK);
                Inner i0 = r.s.cmd((byte) 0x42, (byte) 0x00, (byte) 0, import0Command(r));
                Fault.reset();
                assertTrue(
                        i0.sw == 0x6A80 || i0.sw == 0x6F00,
                        "verifyHash eval "
                                + i
                                + " forced OK must be refused, was "
                                + String.format("%04X", i0.sw));
                if (i0.sw == 0x6F00) {
                    r.s = r.c.open();
                }
                // no pending import may be left: the attacker's own sealed record is
                // refused 6985 — Z = x(e·LK_T) with the attacker-known scalar e
                byte[] z = ecdhX(r.e, r.lkT);
                byte[] exportM = concat(LABEL_EXPORT, r.m.a, r.s.cardA, r.lkT, r.epk);
                byte[] payload =
                        concat(
                                new byte[] {0x01},
                                ATK_SEED,
                                ATK_HASH,
                                new byte[] {0x02},
                                cardId(r.s.cardA),
                                r.m.cardId);
                byte[] record = FakeMember.sealRecord(z, exportM, payload)[0];
                Inner i1 = r.s.cmd((byte) 0x42, (byte) 0x01, (byte) 0, record);
                assertEquals(0x6985, i1.sw, "eval " + i + " left a pending import");
                assertBlank(r);
            } finally {
                Fault.reset();
            }
        }
    }
}
