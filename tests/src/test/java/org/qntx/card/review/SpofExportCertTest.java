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
 * Regression for review finding R-03: EXPORT P1=0x00 verifies the target certificate ({@code
 * Identity.verifyCert}). On the reviewed code the second "evaluation" re-tested the stored result,
 * so one fault inside the single verification passed a certificate signed by a foreign CA and the
 * card exported the wallet under {@code Z = e·LK_R} to a rogue member. The fix recomputes the
 * certificate check after {@code hashM}, before {@code sig_S}, the pending export keys and {@code
 * E} are produced (§16.2 item 4).
 *
 * <p>The attacker is a rogue card R whose ID was written into {@code members} at CREATE — a
 * host-generated identity key pair, a certificate signed by a foreign CA, a genuine offer signature
 * under its own identity key and its own link key. The attack test counts the woven {@code
 * Secp256k1.verifyHash} calls on a request with a batch-CA certificate for the same rogue identity
 * (a genuine request, so the count is the full one), then arms every single position to {@code
 * CHECK_OK} on the foreign-certificate request. Each must be refused and no pending export may be
 * left.
 */
final class SpofExportCertTest {

    private static final byte[] S0 =
            unhex(
                    "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
                            + "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");
    private static final byte[] H0 = sha256("review access hash H0".getBytes());
    private static final byte[] HT = sha256("review access hash HT".getBytes());
    private static final short CHECK_OK = (short) 0x6666;

    private static final class Rig {
        ReviewCard c;
        ReviewSession s;
        BigInteger rogueId;
        byte[] rogueA;
        byte[] rogueCert;
        BigInteger rogueLink;
        byte[] rogueLk;
        byte[] rogueSigT;
    }

    /**
     * Card X in L2: members = (ID(A_X), ID(A_R)). R is host-made: own identity key, a certificate
     * over A_R signed by a foreign CA (not the batch CA), own link key, and a genuine sig_T over
     * "…/offer" ‖ LK_R under its identity key.
     */
    private static Rig rig() {
        Rig r = new Rig();
        r.rogueId = randomScalar();
        r.rogueA = compr(g().multiply(r.rogueId));
        r.rogueCert = cert(i2b(randomScalar(), 32), r.rogueA); // foreign CA
        r.rogueLink = randomScalar();
        r.rogueLk = uncomp(g().multiply(r.rogueLink));
        r.rogueSigT = ecdsaSign(r.rogueId, concat(LABEL_OFFER, r.rogueLk));
        r.c = ReviewCard.uninitialised();
        r.c.blank();
        r.s = r.c.create(S0, H0, cardId(r.rogueA)); // session left verified by CREATE (§9.4)
        return r;
    }

    /** The forged request: foreign-CA certificate, genuine sig_T under the rogue key. */
    private static byte[] export0Command(Rig r) {
        return concat(r.rogueCert, r.rogueLk, r.rogueSigT);
    }

    /** The same rogue offer with a batch-CA certificate: a genuine request for the dry run. */
    private static byte[] genuineCommand(Rig r) {
        return concat(ReviewCard.CA.issue(r.rogueA), r.rogueLk, r.rogueSigT);
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
            Inner res = r.s.cmd((byte) 0x41, (byte) 0x00, (byte) 0, export0Command(r));
            assertEquals(0x6A80, res.sw, "control: foreign-CA cert must be refused 6A80");
        } finally {
            Fault.reset();
        }
    }

    @Test
    void foreignCertRefusedAtEveryEvaluation() {
        Rig r = rig();
        try {
            // the full call count needs a request that reaches the last check: a batch-CA
            // certificate for the same rogue identity — cert, sig_T, the two
            // recomputations and the sig_S self-verification = 5 verifyHash calls
            Fault.countCalls();
            Inner ok = r.s.cmd((byte) 0x41, (byte) 0x00, (byte) 0, genuineCommand(r));
            assertEquals(0x9000, ok.sw, "dry-run batch-CA cert");
            int calls = Fault.calls("Secp256k1.verifyHash");
            assertEquals(5, calls, "cert, sig_T, both recomputations, sig_S self-verify");
            Fault.reset();

            Inner done = r.s.cmd((byte) 0x41, (byte) 0x01, (byte) 0, HT);
            assertEquals(0x9000, done.sw, "consume the dry-run pending export");

            for (int i = 1; i <= calls; i++) {
                Fault.arm("Secp256k1.verifyHash", i, CHECK_OK);
                Inner e0 = r.s.cmd((byte) 0x41, (byte) 0x00, (byte) 0, export0Command(r));
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
