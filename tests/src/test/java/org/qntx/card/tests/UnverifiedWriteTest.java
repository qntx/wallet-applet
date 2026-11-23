// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;

/**
 * §16.1 item 7 (architecture §14.4 W11): on a LOADED card in an unverified session the only
 * persistent writes allowed are T-FAIL per failed VERIFY and the single T-ERASE at the limit.
 */
final class UnverifiedWriteTest {

    private Card card;
    private Session session;

    private void loaded() throws Exception {
        card = Vecs.blankSelf();
        session = Vecs.loadWallet(card);
    }

    private int run(int ins, int p1, byte[] data) throws Exception {
        int sw = Vecs.roundtrip(card, session, ins, p1, 0, data).sw();
        return sw;
    }

    @Test
    void writesPerCommand() throws Exception {
        loaded();
        assertEquals(0x9000, run(0x20, 0, new byte[0]));
        assertEquals(0, card.writes(), "STATUS writes nothing");

        assertEquals(0x63c9, run(0x22, 0, Vecs.accessHashWrong()));
        assertEquals(List.of(1024), card.commits(), "wrong VERIFY commits T-FAIL only");
        assertEquals(2, card.writes(), "T-FAIL = the fails pair");

        assertEquals(0x9000, run(0x25, 0, new byte[0]));
        assertEquals(0, card.writes(), "WAIT writes nothing");
        assertEquals(0, card.commits().size());

        assertEquals(0x6982, run(0x23, 0, Vecs.accessHashNew()));
        assertEquals(0, card.writes(), "CHANGE rejected before any write");
        assertEquals(0x6982, run(0x24, 0, new byte[0]));
        assertEquals(0, card.writes(), "ERASE rejected before any write");
        assertEquals(0x6982, run(0x30, 0, Vecs.pathSecpEvm()), "PUBLIC_KEY rejected");
        assertEquals(0, card.writes());
        byte[] ecdsaData = new byte[32 + Vecs.pathSecpEvm().length];
        System.arraycopy(Vecs.digest(), 0, ecdsaData, 0, 32);
        System.arraycopy(Vecs.pathSecpEvm(), 0, ecdsaData, 32, Vecs.pathSecpEvm().length);
        assertEquals(0x6982, run(0x31, 0, ecdsaData), "SIGN_ECDSA rejected");
        assertEquals(0, card.writes(), "SIGN_ECDSA writes nothing unverified");
        byte[] bip340Data = new byte[64 + Vecs.pathSecpEvm().length];
        System.arraycopy(Vecs.pathSecpEvm(), 0, bip340Data, 64, Vecs.pathSecpEvm().length);
        assertEquals(0x6982, run(0x32, 0, bip340Data), "SIGN_BIP340 rejected");
        assertEquals(0, card.writes(), "SIGN_BIP340 writes nothing unverified");
        assertEquals(0x6982, run(0x33, 0, Vecs.pathEdSolana()), "SIGN_ED25519 begin rejected");
        assertEquals(0, card.writes(), "begin writes nothing unverified");
        assertEquals(0x6982, run(0x33, 1, new byte[] {1}), "update rejected");
        assertEquals(0x6982, run(0x33, 2, new byte[] {1}), "finish rejected");
        assertEquals(0, card.writes());

        byte[] create = new byte[96];
        System.arraycopy(Vecs.accessHash(), 0, create, 0, 32);
        System.arraycopy(Vecs.seed(), 0, create, 32, 64);
        assertEquals(0x6985, run(0x21, 1, create));
        assertEquals(0, card.writes(), "CREATE on LOADED writes nothing");
    }

    /**
     * §16.1 item 7 for the transfer commands on a LOADED card in an unverified session: OFFER
     * commits T-OFFER once and then writes nothing, IMPORT P1 = 0x00 writes the member's peer slot
     * once, a non-member head writes nothing, EXPORT is {@code 6982} without a write, and IMPORT P1
     * = 0x01 writes only inside T-INSTALL.
     */
    @Test
    void transferCommandsOnLoadedUnverified() throws Exception {
        // source: the wallet's creator; target: a member card loaded via import
        Card source = Vecs.factory();
        byte[] sa = Vecs.cardA(source);
        Vecs.blankFor(source, sa);
        Card target = Vecs.factory();
        byte[] ta = Vecs.cardA(target);
        Vecs.blankFor(target, ta);
        Session sSession = Vecs.open(source);
        Session tSession = Vecs.open(target);
        byte[] create = new byte[112];
        System.arraycopy(Vecs.accessHash(), 0, create, 0, 32);
        System.arraycopy(Vecs.seed(), 0, create, 32, 64);
        System.arraycopy(Ids.cardId(ta), 0, create, 96, 16);
        assertEquals(0x9000, Vecs.roundtrip(source, sSession, 0x21, 1, 0, create).sw(), "CREATE");
        assertEquals(
                0x9000,
                Vecs.roundtrip(target, tSession, 0x40, 0, 0, new byte[0]).sw(),
                "target's first OFFER (BLANK) commits T-OFFER");
        assertEquals(List.of(2048), target.commits(), "T-OFFER commit bytes");
        byte[] offer =
                java.util.Arrays.copyOf(
                        Vecs.roundtrip(target, tSession, 0x40, 0, 0, new byte[0]).data(), 129);
        assertEquals(0, target.writes(), "repeat OFFER writes nothing");
        assertEquals(
                0x9000,
                Vecs.roundtrip(source, sSession, 0x22, 0, 0, Vecs.accessHash()).sw(),
                "source VERIFY");
        byte[] data = new byte[226];
        System.arraycopy(Vecs.certFor(ta), 0, data, 0, 97);
        System.arraycopy(offer, 0, data, 97, 129);
        byte[] head = Vecs.roundtrip(source, sSession, 0x41, 0, 0, data).data();
        byte[] payload = Vecs.roundtrip(source, sSession, 0x41, 1, 0, Vecs.accessHashNew()).data();
        byte[] import0 = new byte[226];
        System.arraycopy(Vecs.certFor(sa), 0, import0, 0, 97);
        System.arraycopy(head, 0, import0, 97, 129);
        // the first import installs the wallet (BLANK target): one slot write + T-INSTALL
        assertEquals(0x9000, Vecs.roundtrip(target, tSession, 0x42, 0, 0, import0).sw(), "IMPORT0");
        assertTrue(target.writes() <= 1, "IMPORT0 writes at most the peer slot");
        assertEquals(0x9000, Vecs.roundtrip(target, tSession, 0x42, 1, 0, payload).sw(), "IMPORT1");
        assertEquals(List.of(2048), target.commits(), "T-INSTALL commit bytes");

        // now LOADED and unverified: OFFER arms a fresh offer
        assertEquals(
                0x9000,
                Vecs.roundtrip(target, tSession, 0x40, 0, 0, new byte[0]).sw(),
                "OFFER on LOADED unverified");
        assertEquals(List.of(2048), target.commits(), "T-OFFER is the only commit");
        assertEquals(0x9000, Vecs.roundtrip(target, tSession, 0x40, 0, 0, new byte[0]).sw());
        assertEquals(0, target.writes(), "repeat OFFER writes nothing");

        // a fresh export for the new offer: IMPORT0 from a member writes the slot once
        tSession = Vecs.open(target);
        offer =
                java.util.Arrays.copyOf(
                        Vecs.roundtrip(target, tSession, 0x40, 0, 0, new byte[0]).data(), 129);
        System.arraycopy(offer, 0, data, 97, 129);
        sSession = Vecs.open(source);
        assertEquals(0x9000, Vecs.roundtrip(source, sSession, 0x22, 0, 0, Vecs.accessHash()).sw());
        head = Vecs.roundtrip(source, sSession, 0x41, 0, 0, data).data();
        payload = Vecs.roundtrip(source, sSession, 0x41, 1, 0, Vecs.accessHashNew()).data();
        System.arraycopy(head, 0, import0, 97, 129);
        assertEquals(0x9000, Vecs.roundtrip(target, tSession, 0x42, 0, 0, import0).sw());
        assertTrue(target.writes() <= 1, "member IMPORT0 writes at most the peer slot");
        assertEquals(0x9000, Vecs.roundtrip(target, tSession, 0x42, 0, 0, import0).sw());
        assertEquals(0, target.writes(), "the same member's slot is not rewritten");

        // a non-member's head is refused with no write
        Card stranger = Vecs.factory();
        byte[] stra = Vecs.cardA(stranger);
        Vecs.blankFor(stranger, stra);
        byte[] badImport = new byte[226];
        System.arraycopy(Vecs.certFor(stra), 0, badImport, 0, 97);
        System.arraycopy(head, 0, badImport, 97, 129);
        assertEquals(0x6A80, Vecs.roundtrip(target, tSession, 0x42, 0, 0, badImport).sw());
        assertEquals(0, target.writes(), "non-member IMPORT0 writes nothing");

        // EXPORT is a verified-only command: 6982 and no write
        assertEquals(0x6982, Vecs.roundtrip(target, tSession, 0x41, 0, 0, data).sw());
        assertEquals(0, target.writes(), "EXPORT unverified writes nothing");

        // and the genuine payload installs inside T-INSTALL alone
        assertEquals(0x9000, Vecs.roundtrip(target, tSession, 0x42, 0, 0, import0).sw());
        assertEquals(0x9000, Vecs.roundtrip(target, tSession, 0x42, 1, 0, payload).sw());
        assertEquals(List.of(2048), target.commits(), "T-INSTALL is the only commit");
    }

    @Test
    void onlyTFailAndOneTEraseAcrossTheLimit() throws Exception {
        loaded();
        int tFail = 0;
        int tErase = 0;
        for (int i = 0; i < 10; i++) {
            if (i >= 3) {
                for (int w = 0; w < 15; w++) {
                    run(0x25, 0, new byte[0]);
                    assertEquals(0, card.writes(), "WAIT never writes");
                }
            }
            int sw = run(0x22, 0, Vecs.accessHashWrong());
            for (int c : card.commits()) {
                if (c == 1024) {
                    tFail++;
                } else if (c == 2048) {
                    tErase++;
                }
            }
            assertEquals(i < 9 ? 0x63c0 | (9 - i) : 0x6983, sw);
        }
        assertEquals(10, tFail, "exactly L T-FAIL commits");
        assertEquals(1, tErase, "exactly one T-ERASE commit");
    }
}
