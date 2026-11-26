// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import javacard.framework.Applet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Open;
import org.qntx.card.host.Response;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * §16.2 item 4 fault-injection tests (architecture §9): each guarded check is evaluated twice, so
 * arming one evaluation to lie must not change the rejection — the other evaluation still fires.
 * Lives in {@code org.qntx.card} for the coded constants of {@link Const}.
 */
final class FaultInjectionTest {

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    private static boolean factory(Card card) {
        return Vecs.sw(card.transmit(Vecs.unhex("80E0000000"))) == 0x9000;
    }

    private static void assertDead(Card card) {
        assertArrayEquals(new byte[14], Internals.words(card.applet(Spec.WALLET_AID)));
    }

    @Test
    void caKeyIsOnCurveCheckedTwice() {
        for (int nth = 1; nth <= 2; nth++) {
            Card card = Vecs.factory();
            byte[] a = Vecs.cardA(card);
            byte[] apdu = Vecs.personalizeApdu(Vecs.certFor(a));
            byte[] offCurve = Vecs.symbol("caKey.offCurve", card, a);
            System.arraycopy(offCurve, 0, apdu, 102, 65);
            // evaluation `nth` lies CHECK_OK; the other evaluation must still reject (§16.5)
            Fault.arm("Secp256k1.onCurve", nth, Const.CHECK_OK);
            assertEquals(0x6A80, Vecs.sw(card.transmit(apdu)), "check " + nth);
            assertEquals(0, card.writes(), "check " + nth + " persisted before the other check");
            assertEquals(nth == 1 ? 2 : 1, Fault.calls("Secp256k1.onCurve"));
            assertTrue(factory(card));
            Fault.reset();
        }
    }

    @Test
    void certSignatureIsVerifiedTwice() {
        for (int nth = 1; nth <= 2; nth++) {
            Card card = Vecs.factory();
            byte[] a = Vecs.cardA(card);
            byte[] bad = Vecs.certFor(a);
            bad[96] ^= 1; // corrupt s: the certificate no longer verifies (§5.2)
            Fault.arm("Identity.verify", nth, Const.CHECK_OK);
            assertEquals(0x6A80, Vecs.sw(card.transmit(Vecs.personalizeApdu(bad))), "check " + nth);
            assertEquals(nth == 1 ? 2 : 1, Fault.calls("Identity.verify"));
            assertTrue(factory(card));
            // the aborted transaction stored nothing
            byte[] state = Internals.stateArray(card.applet(Spec.WALLET_AID));
            assertArrayEquals(
                    new byte[Const.CERT_LEN],
                    Arrays.copyOfRange(state, State.OFF_CERT, State.OFF_CERT + Const.CERT_LEN));
            Fault.reset();
        }
    }

    @Test
    void lifeIsRecheckedTwiceInsideTPerso() {
        for (int nth = 2; nth <= 3; nth++) {
            Card card = Vecs.factory();
            byte[] a = Vecs.cardA(card);
            // life() call 1 is the §14.2 gate; calls 2 and 3 are the in-transaction rechecks
            Fault.arm("State.life", nth, Const.LIFE_BLANK);
            assertEquals(
                    0x6F00,
                    Vecs.sw(card.transmit(Vecs.personalizeApdu(Vecs.certFor(a)))),
                    "check " + nth);
            assertEquals(nth, Fault.calls("State.life"));
            assertTrue(factory(card));
            Fault.reset();
        }
    }

    @Test
    void recordTagIsComparedTwice() throws Exception {
        for (int nth = 1; nth <= 2; nth++) {
            Card card = Vecs.blankSelf();
            var session = Vecs.open(card);
            byte[] apdu = session.wrap(0x20, 0, 0, new byte[0]);
            apdu[apdu.length - 2] ^= 1; // bad tag
            Fault.arm("Bytes.equal", nth, Const.CHECK_OK);
            assertEquals(0x6982, Vecs.sw(card.transmit(apdu)), "check " + nth);
            assertEquals(nth == 1 ? 2 : 1, Fault.calls("Bytes.equal"));
            // §8.5: the session is torn down either way
            assertDead(card);
            assertEquals(0x6985, Vecs.sw(card.transmit(session.wrap(0x20, 0, 0, new byte[0]))));
            Fault.reset();
        }
    }

    @Test
    void aFaultySelfVerificationFaultsOpen() throws Exception {
        // §16.2 item 5: the armed CHECK_FAIL must fault the whole OPEN — 6F00, no response
        // data, and the previous session is torn down by process()
        Card card = Vecs.blankSelf();
        var session = Vecs.open(card);
        Fault.arm("Identity.verifyHash", 1, Const.CHECK_FAIL);
        byte[] rapdu = card.transmit(Open.request(Vecs.RND).apdu());
        assertArrayEquals(Vecs.unhex("6F00"), rapdu);
        assertDead(card);
        assertEquals(0x6985, Vecs.sw(card.transmit(session.wrap(0x20, 0, 0, new byte[0]))));
    }

    @Test
    void recordLengthIsCheckedBeforeTheTag() throws Exception {
        // §8.3 step 3 before step 4: a short or misaligned record must never reach the
        // tag comparison; arming equal makes its calls countable
        for (int lc : new int[] {8, 16, 25}) {
            Card card = Vecs.blankSelf();
            var session = Vecs.open(card);
            byte[] apdu = new byte[5 + lc + 1];
            apdu[0] = (byte) 0x80;
            apdu[1] = 0x12;
            apdu[4] = (byte) lc;
            Vecs.RND.nextBytes(Arrays.copyOfRange(apdu, 5, apdu.length - 1));
            Fault.arm("Bytes.equal", 1, Const.CHECK_FAIL);
            assertEquals(0x6982, Vecs.sw(card.transmit(apdu)), "Lc=" + lc);
            assertEquals(0, Fault.calls("Bytes.equal"), "Lc=" + lc);
            assertEquals(0x6985, Vecs.sw(card.transmit(session.wrap(0x20, 0, 0, new byte[0]))));
            Fault.reset();
        }
    }

    @Test
    void anEngineThrowInsideAHandlerIs6F00WithTeardown() throws Exception {
        // §16.3 item 4: an unexpected exception in a handler maps to 6F00, tears the
        // session down and wipes scratch — driven once per outer handler
        String[][] handlers = {
            {"80E0000000", "GET_IDENTITY"},
            {"80E2000000", "PERSONALIZE"},
        };
        for (String[] h : handlers) {
            Card card = Vecs.blankSelf();
            var session = Vecs.open(card);
            Applet applet = card.applet(Spec.WALLET_AID);
            // dirty scratch so the catch(Exception) wipe is observable
            Arrays.fill(Internals.pBytes(applet), (byte) 0x77);
            Arrays.fill(Internals.wBytes(applet), (byte) 0x77);
            Fault.armThrow("State.life", 1);
            assertEquals(0x6F00, Vecs.sw(card.transmit(Vecs.unhex(h[0]))), h[1]);
            assertDead(card);
            assertArrayEquals(new byte[130], Internals.pBytes(applet), h[1] + " P not wiped");
            assertArrayEquals(new byte[256], Internals.wBytes(applet), h[1] + " W not wiped");
            assertEquals(0x6985, Vecs.sw(card.transmit(session.wrap(0x20, 0, 0, new byte[0]))));
            Fault.reset();
        }
        // OPEN: life is its first check, so the same arm fires inside its handler
        Card card = Vecs.blankSelf();
        var session = Vecs.open(card);
        Applet applet = card.applet(Spec.WALLET_AID);
        Arrays.fill(Internals.pBytes(applet), (byte) 0x77);
        Arrays.fill(Internals.wBytes(applet), (byte) 0x77);
        Fault.armThrow("State.life", 1);
        assertEquals(0x6F00, Vecs.sw(card.transmit(Open.request(Vecs.RND).apdu())));
        assertDead(card);
        assertArrayEquals(new byte[130], Internals.pBytes(applet), "OPEN P not wiped");
        assertArrayEquals(new byte[256], Internals.wBytes(applet), "OPEN W not wiped");
        assertEquals(0x6985, Vecs.sw(card.transmit(session.wrap(0x20, 0, 0, new byte[0]))));
    }

    @Test
    void anEngineThrowInsideInnerIs6F00AndTeardown() throws Exception {
        // §8.5: the inner exception becomes an inner 6F00 record and the session dies
        Card card = Vecs.blankSelf();
        var session = Vecs.open(card);
        Applet applet = card.applet(Spec.WALLET_AID);
        Arrays.fill(Internals.pBytes(applet), (byte) 0x77);
        Fault.armThrow("Wallet.status", 1);
        Response r = Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]);
        assertEquals(0x6F00, r.sw());
        assertDead(card);
        assertArrayEquals(new byte[130], Internals.pBytes(applet), "P not wiped");
        assertArrayEquals(new byte[256], Internals.wBytes(applet), "W not wiped");
        assertEquals(0x6985, Vecs.sw(card.transmit(session.wrap(0x20, 0, 0, new byte[0]))));
    }

    @Test
    void openClearsALeftoverPendingWord() throws Exception {
        // teardown() inside OPEN clears every word; a pending word planted before a new
        // OPEN must not survive into the fresh session
        Card card = Vecs.blankSelf();
        Vecs.open(card);
        byte[] words = Internals.words(card.applet(Spec.WALLET_AID));
        words[6] = 0x69;
        words[7] = 0x69;
        Vecs.open(card);
        assertEquals(0, words[6] | words[7]);
    }

    @Test
    void selectTearsDownAnOpenSession() throws Exception {
        Card card = Vecs.blankSelf();
        Vecs.open(card);
        card.applet(Spec.WALLET_AID).select();
        assertDead(card);
    }
}
