// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Open;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The wire-observable part of the simulator core suite on card A (architecture.md §10): SELECT,
 * GET_IDENTITY, PERSONALIZE, OPEN and the §8 record layer. Simulator-only hooks — write counters,
 * tearing, transient inspection — have no real-card analogue and are covered by the memprobe suite
 * instead.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
final class CoreRealCardTest {
    private static byte[] unhex(String s) {
        return HexFormat.of().parseHex(s);
    }

    @Test
    @Order(1)
    void atrAndRegistryAreCardA() throws Exception {
        Fixture.require();
        RealCard card = Fixture.connect();
        assertEquals(RealCard.EXPECTED_ATR, card.atr(), "ATR of card A");
        // baseline captured by the first gp -l inside ensureFactory
        Fixture.ensureFactory();
    }

    @Test
    @Order(2)
    void selectAnswers9000AndNeedsNoData() throws Exception {
        Fixture.require();
        RealCard card = Fixture.card();
        assertArrayEquals(Spec.SW_OK, card.transmit(Spec.SELECT));
        assertArrayEquals(Spec.SW_OK, card.transmit(Spec.SELECT));
    }

    @Test
    @Order(3)
    void classCheckPrecedesInstructionCheck() throws Exception {
        Fixture.require();
        RealCard card = Fixture.card();
        // every class other than 0x80 answers 6E00, even for a known INS; CLAs encoding a
        // logical channel (0x8x with channel bits, e.g. 0x81) never reach the applet — card
        // A's JCRE answers them 6881 itself — so the probe uses channel-0 classes only
        for (int cla : new int[] {0x00, 0x01, 0x40, 0xC0}) {
            assertEquals(
                    0x6E00,
                    RealCard.sw(card.transmit(new byte[] {(byte) cla, 0x12, 0, 0, 1, 0})),
                    "CLA " + cla);
        }
        assertEquals(0x6E00, RealCard.sw(card.transmit(unhex("00E0000000"))));
    }

    @Test
    @Order(4)
    void unknownOuterInsAnswers6D00() throws Exception {
        Fixture.require();
        RealCard card = Fixture.card();
        for (int ins : new int[] {0x00, 0x11, 0x13, 0x7F, 0xA4, 0xE1, 0xE3, 0xFF}) {
            assertEquals(
                    0x6D00,
                    RealCard.sw(card.transmit(new byte[] {(byte) 0x80, (byte) ins, 0, 0, 0})),
                    "INS " + ins);
        }
    }

    @Test
    @Order(5)
    void identityIsAStableOnCurveCompressedKey() throws Exception {
        Fixture.require();
        RealCard card = Fixture.card();
        byte[] a = Fixture.cardA();
        assertEquals(33, a.length);
        assertTrue(a[0] == 0x02 || a[0] == 0x03, "compressed prefix");
        byte[] point = Crypto.decompress(a);
        assertEquals(0x04, point[0]);
        assertTrue(
                !Arrays.equals(Arrays.copyOf(Crypto.compress(Crypto.G.getEncoded(false)), 33), a),
                "A is not the generator");
        // stable across a field power cycle (architecture §10, real-card only)
        card.reset();
        card.ok(Spec.SELECT);
        byte[] a2 = card.ok(unhex("80E0000000"));
        assertArrayEquals(a, a2, "identity stable across power cycle");
        // P1/P2 checked separately
        assertEquals(0x6A86, RealCard.sw(card.transmit(unhex("80e0010000"))));
        assertEquals(0x6A86, RealCard.sw(card.transmit(unhex("80e0000100"))));
    }

    @Test
    @Order(6)
    void personalizeTransitionsToBlank() throws Exception {
        Fixture.require();
        Fixture.ensureStrictFactory();
        RealCard card = Fixture.card();
        // the §14.2 order (life, P1/P2, length) is only observable on a command the life gate
        // lets through: once BLANK, personalize hits the gate (6985) before any P1 check
        byte[] p1 = Fixture.personalizeApdu();
        p1[2] = 1;
        assertEquals(0x6A86, RealCard.sw(card.transmit(p1)));
        assertEquals(0x6A86, RealCard.sw(card.transmit(unhex("80e2000100"))));
        assertEquals(0x6700, RealCard.sw(card.transmit(unhex("80e2000000"))));
        card.ok(Fixture.personalizeApdu());
        // PERSONALIZE is refused once BLANK (§7); GET_IDENTITY is refused outside FACTORY
        assertEquals(0x6985, RealCard.sw(card.transmit(Fixture.personalizeApdu())));
        assertEquals(0x6985, RealCard.sw(card.transmit(unhex("80E0000000"))));
        Fixture.ensureFactoryField(Fixture.Life.BLANK);
    }

    @Test
    @Order(7)
    void rejectedCertificatesKeepTheCardFactory() throws Exception {
        Fixture.require();
        Fixture.ensureStrictFactory();
        RealCard card = Fixture.card();
        byte[] a = Fixture.cardA();
        byte[] good = Vecs.certFor(a);
        // a cert under ca2 and a cert for a different A must be refused with 6A80 (§7)
        assertEquals(
                0x6A80,
                RealCard.sw(
                        card.transmit(
                                Vecs.personalizeApdu(
                                        org.qntx.card.host.Certificates.issue(
                                                Vecs.ca2Private(), a)))),
                "cert under ca2");
        assertEquals(
                0x6A80,
                RealCard.sw(card.transmit(Vecs.personalizeApdu(Vecs.certOtherA()))),
                "cert for a different A");
        // a malformed CA key is refused with 6A80 and leaves the card FACTORY
        byte[] bad = Fixture.personalizeApdu();
        bad[102 + 64] ^= 1; // off-curve CA public key (y not on the curve)
        assertEquals(0x6A80, RealCard.sw(card.transmit(bad)));
        assertEquals(0x9000, RealCard.sw(card.transmit(unhex("80E0000000"))), "still FACTORY");
        // then the good personalize succeeds
        card.ok(Vecs.personalizeApdu(good));
        Fixture.ensureFactoryField(Fixture.Life.BLANK);
    }

    @Test
    @Order(8)
    void openProducesAVerifiableSession() throws Exception {
        Fixture.require();
        Fixture.ensureBlank();
        RealCard card = Fixture.card();
        Session session = Fixture.open();
        assertEquals(0, session.counter());
        assertArrayEquals(Fixture.cardA(), session.identity());
        Response r = Fixture.cmd(session, 0x20, 0, 0, new byte[0]);
        assertEquals(0x9000, r.sw());
        assertArrayEquals(unhex("0100"), r.data(), "STATUS: BLANK, tries 0 (§9.3)");
        session.close();
    }

    @Test
    @Order(9)
    void openIsRefusedInFactoryAndChecksP1P2() throws Exception {
        Fixture.require();
        Fixture.ensureStrictFactory();
        RealCard card = Fixture.card();
        assertEquals(
                0x6985,
                RealCard.sw(card.transmit(Open.request(Vecs.RND).apdu())),
                "OPEN in FACTORY");
        Fixture.ensureBlank();
        byte[] open = Open.request(Vecs.RND).apdu();
        byte[] p1 = open.clone();
        p1[2] = 1;
        assertEquals(0x6A86, RealCard.sw(card.transmit(p1)));
        byte[] p2 = open.clone();
        p2[3] = 1;
        assertEquals(0x6A86, RealCard.sw(card.transmit(p2)));
    }

    @Test
    @Order(10)
    void openCryptoRejectTearsTheHalfOpenSessionDown() throws Exception {
        Fixture.require();
        Fixture.ensureBlank();
        RealCard card = Fixture.card();
        Session session = Fixture.open();
        // an off-curve hostEph: the structural check passed (65 bytes, 0x04) but the
        // crypto reject tears the session down — a following record sees 6985 (§8.1)
        byte[] bad = Open.request(Vecs.RND).apdu();
        bad[5 + 64] ^= 1;
        assertEquals(0x6A80, RealCard.sw(card.transmit(bad)));
        assertEquals(
                0x6985,
                RealCard.sw(card.transmit(session.wrap(0x20, 0, 0, new byte[0]))),
                "session torn down after crypto reject");
        session.close();
    }

    @Test
    @Order(11)
    void secondOpenReplacesTheSession() throws Exception {
        Fixture.require();
        Fixture.ensureBlank();
        RealCard card = Fixture.card();
        Fixture.open().close();
        Session second = Fixture.open();
        assertEquals(0x9000, Fixture.cmd(second, 0x20, 0, 0, new byte[0]).sw(), "second session");
        second.close();
    }

    @Test
    @Order(12)
    void invalidRecordsAnswer6982AndKillTheSession() throws Exception {
        Fixture.require();
        Fixture.ensureBlank();
        RealCard card = Fixture.card();
        // each variant: a record that fails a §8.3 check answers 6982, then the session is
        // dead and every further record answers 6985
        for (int variant = 0; variant < 4; variant++) {
            Session s = Fixture.open();
            byte[] apdu;
            switch (variant) {
                case 0 -> { // bad P1
                    apdu = s.wrap(0x20, 0, 0, new byte[0]);
                    apdu[2] = 0x01;
                }
                case 1 -> { // too short a record
                    apdu = new byte[21];
                    apdu[0] = (byte) 0x80;
                    apdu[1] = 0x12;
                    apdu[4] = 0x10;
                    Vecs.RND.nextBytes(Arrays.copyOfRange(apdu, 5, 21));
                }
                case 2 -> { // misaligned ciphertext
                    apdu = new byte[28];
                    apdu[0] = (byte) 0x80;
                    apdu[1] = 0x12;
                    apdu[4] = 0x17;
                    Vecs.RND.nextBytes(Arrays.copyOfRange(apdu, 5, 28));
                }
                default -> { // wrong tag
                    apdu = s.wrap(0x20, 0, 0, new byte[0]);
                    apdu[apdu.length - 2] ^= 1;
                }
            }
            assertEquals(0x6982, RealCard.sw(card.transmit(apdu)), "variant " + variant);
            assertEquals(0x6985, RealCard.sw(card.transmit(apdu)), "after variant " + variant);
            s.close();
        }
    }

    @Test
    @Order(13)
    void innerErrorsKeepTheSessionAlive() throws Exception {
        Fixture.require();
        Fixture.ensureBlank();
        Session s = Fixture.open();
        Response r = Fixture.cmd(s, 0x7F, 0, 0, new byte[0]);
        assertEquals(0x6D00, r.sw(), "unknown inner INS");
        r = Fixture.cmd(s, 0x20, 0, 0, new byte[0]);
        assertEquals(0x9000, r.sw(), "session still alive");
        r = Fixture.cmd(s, 0x20, 0, 1, new byte[0]);
        assertEquals(0x6A86, r.sw(), "inner P2 check");
        assertEquals(0x9000, Fixture.cmd(s, 0x20, 0, 0, new byte[0]).sw());
        s.close();
    }

    @Test
    @Order(14)
    void sessionRecordWithoutOpenSessionIs6985() throws Exception {
        Fixture.require();
        Fixture.ensureBlank();
        RealCard card = Fixture.card();
        // no session is open after SELECT: a SESSION record answers 6985 (§8.3)
        byte[] record = unhex("80120000");
        assertEquals(0x6985, RealCard.sw(card.transmit(record)));
    }

    @Test
    @Order(15)
    void selectTearsAnOpenSessionDown() throws Exception {
        Fixture.require();
        Fixture.ensureBlank();
        RealCard card = Fixture.card();
        Session s = Fixture.open();
        card.ok(Spec.SELECT); // re-SELECT deselects the applet first
        assertEquals(
                0x6985,
                RealCard.sw(card.transmit(s.wrap(0x20, 0, 0, new byte[0]))),
                "record after SELECT");
        s.close();
    }

    @Test
    @Order(16)
    void powerCycleKillsTheSession() throws Exception {
        Fixture.require();
        Fixture.ensureBlank();
        RealCard card = Fixture.card();
        Session s = Fixture.open();
        byte[] record = s.wrap(0x20, 0, 0, new byte[0]);
        card.reset();
        card.ok(Spec.SELECT);
        assertEquals(0x6985, RealCard.sw(card.transmit(record)), "record after power cycle");
        s.close();
        assertEquals(0, Fixture.open().counter());
    }
}
