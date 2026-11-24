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
 * Regression for review finding R-01: EXPORT P1=0x00 authenticates the target's offer with the
 * {@code sig_T} check of §9.13 step 5 ({@code Verify(A_T, "qntx-card/v1/offer" ‖ LK_T, sig_T)}). On
 * the reviewed code a single fault on that one evaluation let an attacker substitute its own link
 * key {@code LK_T} beside the certificate of a genuine member and EXPORT P1=0x01 then released the
 * seed encrypted under keys the attacker derived from its own link private key. The fix evaluates
 * the check twice by independent recomputation (§16.2 item 4): the offer signature is verified
 * again after {@code hashM}, before {@code sig_S}, the pending export keys and {@code E} are
 * produced.
 *
 * <p>The attack test counts the woven {@code Secp256k1.verifyHash} calls of a genuine request on
 * the fixed code, then arms every single position to {@code CHECK_OK} on the forged request. Each
 * must be refused — {@code 6A80} at the data-check position, {@code 6F00} at a recomputation — and
 * no pending export may be left: the follow-up EXPORT P1=0x01 must answer {@code 6985}.
 */
final class SpofExportOfferSignatureTest {

    private static final byte[] S0 =
            unhex(
                    "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
                            + "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");
    private static final byte[] H0 = sha256("review access hash H0".getBytes());
    private static final byte[] HT = sha256("review access hash HT".getBytes());
    private static final byte[] GARBAGE_SIG = sha512("not a signature".getBytes());
    private static final short CHECK_OK = (short) 0x6666;

    private static final class Rig {
        ReviewCard c;
        ReviewSession s;
        FakeMember m;
    }

    /** Card X in L2: members = (ID(A_X), ID(A_M)), session verified with H0. */
    private static Rig rig() {
        Rig r = new Rig();
        r.c = ReviewCard.uninitialised();
        r.c.blank();
        r.m = new FakeMember(ReviewCard.CA);
        r.s = r.c.create(S0, H0, r.m.cardId); // session left verified by CREATE (§9.4)
        return r;
    }

    private static byte[] export0Command(ReviewCard c, FakeMember m, byte[] lkT, byte[] sigT) {
        return concat(m.cert, lkT, sigT);
    }

    /** A 6F00 tore the card session: OPEN and VERIFY again so the export gate is reachable. */
    private static void reopenVerified(Rig r) {
        r.s = r.c.open();
        assertEquals(0x9000, r.s.cmd((byte) 0x22, (byte) 0, (byte) 0, H0).sw, "re-verify");
    }

    @Test
    void controlWithoutFault() {
        Rig r = rig();
        try {
            BigInteger attLink = randomScalar();
            byte[] attLK = uncomp(g().multiply(attLink));
            Inner res =
                    r.s.cmd(
                            (byte) 0x41,
                            (byte) 0x00,
                            (byte) 0,
                            export0Command(r.c, r.m, attLK, GARBAGE_SIG));
            assertEquals(0x6A80, res.sw, "control: forged offer must be refused 6A80");
        } finally {
            Fault.reset();
        }
    }

    @Test
    void forgedOfferRefusedAtEveryEvaluation() {
        Rig r = rig();
        try {
            // the full call count needs a genuine request: cert, sig_T, the two
            // recomputations and the sig_S self-verification = 5 verifyHash calls
            Fault.countCalls();
            Inner ok = r.s.cmd((byte) 0x41, (byte) 0x00, (byte) 0, r.m.exportRequest());
            assertEquals(0x9000, ok.sw, "dry-run genuine offer");
            int calls = Fault.calls("Secp256k1.verifyHash");
            assertEquals(5, calls, "cert, sig_T, both recomputations, sig_S self-verify");
            Fault.reset();

            // consume the pending export so the armed runs start clean
            Inner done = r.s.cmd((byte) 0x41, (byte) 0x01, (byte) 0, HT);
            assertEquals(0x9000, done.sw);

            BigInteger attLink = randomScalar();
            byte[] attLK = uncomp(g().multiply(attLink));
            for (int i = 1; i <= calls; i++) {
                Fault.arm("Secp256k1.verifyHash", i, CHECK_OK);
                Inner e0 =
                        r.s.cmd(
                                (byte) 0x41,
                                (byte) 0x00,
                                (byte) 0,
                                export0Command(r.c, r.m, attLK, GARBAGE_SIG));
                Fault.reset();
                assertTrue(
                        e0.sw == 0x6A80 || e0.sw == 0x6F00,
                        "verifyHash eval "
                                + i
                                + " forced OK must be refused, was "
                                + String.format("%04X", e0.sw));
                if (e0.sw == 0x6F00) {
                    reopenVerified(r);
                }
                Inner e1 = r.s.cmd((byte) 0x41, (byte) 0x01, (byte) 0, HT);
                assertEquals(0x6985, e1.sw, "eval " + i + " left a pending export");
            }
        } finally {
            Fault.reset();
        }
    }
}
