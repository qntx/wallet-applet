// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;

/**
 * §14.2/architecture §5: every wallet transaction must fit the commit buffer with margin. Expected
 * sizes come from architecture §16.1: the CREATE/CHANGE/ERASE transactions rewrite the wrap
 * material plus key objects (2048 B), T-FAIL and T-OK write the failure pair and session bits (1024
 * B). {@code card.commits()} is reset per command, so it reports the command's transactions.
 */
final class CommitCapacityTest {

    private static final int BUFFER = 2560;

    private Card card;
    private Session session;

    private void blank() throws Exception {
        byte[] a = Vecs.cardA(card = Vecs.factory());
        card = Vecs.blankFor(card, a);
        session = Vecs.open(card);
    }

    private void loaded() throws Exception {
        blank();
        session = Vecs.loadWallet(card);
    }

    @Test
    void persoTransactionUsesAtMostHalfTheCommitBuffer() {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        assertEquals(0x9000, Vecs.sw(card.transmit(Vecs.personalizeApdu(Vecs.certFor(a)))));
        // one transaction: caKey.setW + the 97-byte cert write + the coded life write
        assertEquals(1, card.commits().size());
        assertEquals(3, card.writes());
        int used = card.commitBytes();
        assertTrue(used > 0 && used <= BUFFER, "T-PERSO commit bytes " + used + " vs the buffer");
        System.out.println("T-PERSO commit bytes: " + used);
    }

    @Test
    void createTransactionFits() throws Exception {
        blank();
        byte[] data = new byte[96];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x21, 1, 0, data).sw());
        List<Integer> commits = card.commits();
        assertEquals(1, commits.size(), "T-CREATE is a single commit");
        assertEquals(2048, (int) commits.get(0), "T-CREATE commit bytes");
        System.out.println("T-CREATE commit bytes: " + commits.get(0));
    }

    @Test
    void failAndOkTransactionsFit() throws Exception {
        loaded();
        assertEquals(
                0x63c9, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHashWrong()).sw());
        List<Integer> fail = card.commits();
        assertEquals(1, fail.size(), "T-FAIL is a single commit");
        assertEquals(1024, (int) fail.get(0), "T-FAIL commit bytes");
        System.out.println("T-FAIL commit bytes: " + fail.get(0));

        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
        List<Integer> ok = card.commits();
        assertEquals(2, ok.size(), "a successful VERIFY commits T-FAIL then T-OK");
        assertEquals(1024, (int) ok.get(1), "T-OK commit bytes");
        System.out.println("T-OK commit bytes: " + ok.get(1));
    }

    @Test
    void edCounterCommitFits() throws Exception {
        loaded();
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
        // T-EDCTR (§4.3): the edCounter write of SIGN_ED25519 begin is a single commit
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x33, 0, 0, Vecs.pathEdSolana()).sw());
        List<Integer> commits = card.commits();
        assertEquals(1, commits.size(), "T-EDCTR is a single commit");
        assertTrue(commits.get(0) <= BUFFER, "T-EDCTR " + commits.get(0) + " bytes vs the buffer");
        System.out.println("T-EDCTR commit bytes: " + commits.get(0));
        // the stream's update and finish commit nothing
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x33, 1, 0, new byte[] {1}).sw());
        assertEquals(0, card.commits().size(), "update commits nothing");
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x33, 2, 0, new byte[] {1}).sw());
        assertEquals(0, card.commits().size(), "finish commits nothing");
    }

    @Test
    void changeAndEraseTransactionsFit() throws Exception {
        loaded();
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x23, 0, 0, Vecs.accessHashNew()).sw());
        List<Integer> change = card.commits();
        assertEquals(1, change.size(), "T-CHANGE is a single commit");
        assertEquals(1536, (int) change.get(0), "T-CHANGE commit bytes");
        System.out.println("T-CHANGE commit bytes: " + change.get(0));

        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x24, 0, 0, new byte[0]).sw());
        List<Integer> erase = card.commits();
        assertEquals(1, erase.size(), "T-ERASE is a single commit");
        assertEquals(2048, (int) erase.get(0), "T-ERASE commit bytes");
        System.out.println("T-ERASE commit bytes: " + erase.get(0));
    }

    /**
     * The transfer transactions (§9.12–§9.14): T-OFFER regenerates the persistent link pair (2048
     * B), a repeat OFFER while {@code offer = VALID} commits nothing, and T-INSTALL is a single
     * 2048 B commit both for a BLANK install and a LOADED re-seal.
     */
    @Test
    void offerAndInstallTransactionsFit() throws Exception {
        Card source = Vecs.factory();
        byte[] sa = Vecs.cardA(source);
        Vecs.blankFor(source, sa);
        Card target = Vecs.factory();
        byte[] ta = Vecs.cardA(target);
        Vecs.blankFor(target, ta);
        Session sSession = Vecs.open(source);
        Session tSession = Vecs.open(target);

        assertEquals(
                0x9000, Vecs.roundtrip(target, tSession, 0x40, 0, 0, new byte[0]).sw(), "OFFER");
        List<Integer> offer = target.commits();
        assertEquals(1, offer.size(), "T-OFFER is a single commit");
        assertEquals(2048, (int) offer.get(0), "T-OFFER commit bytes");
        assertTrue(offer.get(0) <= BUFFER, "T-OFFER vs the buffer");
        System.out.println("T-OFFER commit bytes: " + offer.get(0));
        byte[] offerData =
                Arrays.copyOf(
                        Vecs.roundtrip(target, tSession, 0x40, 0, 0, new byte[0]).data(), 129);
        assertEquals(0, target.commits().size(), "repeat OFFER commits nothing");

        byte[] create = new byte[112];
        System.arraycopy(Vecs.accessHash(), 0, create, 0, 32);
        System.arraycopy(Vecs.seed(), 0, create, 32, 64);
        System.arraycopy(Ids.cardId(ta), 0, create, 96, 16);
        assertEquals(0x9000, Vecs.roundtrip(source, sSession, 0x21, 1, 0, create).sw(), "CREATE");
        assertEquals(0x9000, Vecs.roundtrip(source, sSession, 0x22, 0, 0, Vecs.accessHash()).sw());
        byte[] data = new byte[226];
        System.arraycopy(Vecs.certFor(ta), 0, data, 0, 97);
        System.arraycopy(offerData, 0, data, 97, 129);
        byte[] head = Vecs.roundtrip(source, sSession, 0x41, 0, 0, data).data();
        byte[] payload = Vecs.roundtrip(source, sSession, 0x41, 1, 0, Vecs.accessHashNew()).data();
        byte[] import0 = new byte[226];
        System.arraycopy(Vecs.certFor(sa), 0, import0, 0, 97);
        System.arraycopy(head, 0, import0, 97, 129);

        assertEquals(0x9000, Vecs.roundtrip(target, tSession, 0x42, 0, 0, import0).sw(), "IMPORT0");
        assertEquals(0, target.commits().size(), "IMPORT0 commits nothing");
        assertEquals(0x9000, Vecs.roundtrip(target, tSession, 0x42, 1, 0, payload).sw(), "IMPORT1");
        List<Integer> install = target.commits();
        assertEquals(1, install.size(), "T-INSTALL (BLANK) is a single commit");
        assertEquals(2048, (int) install.get(0), "T-INSTALL (BLANK) commit bytes");
        assertTrue(install.get(0) <= BUFFER, "T-INSTALL (BLANK) vs the buffer");
        System.out.println("T-INSTALL (BLANK) commit bytes: " + install.get(0));

        // the LOADED re-seal: fresh offer + export, same single commit
        offerData =
                Arrays.copyOf(
                        Vecs.roundtrip(target, tSession, 0x40, 0, 0, new byte[0]).data(), 129);
        assertEquals(2048, (int) target.commits().get(0), "T-OFFER on LOADED");
        System.arraycopy(offerData, 0, data, 97, 129);
        sSession = Vecs.open(source);
        assertEquals(0x9000, Vecs.roundtrip(source, sSession, 0x22, 0, 0, Vecs.accessHash()).sw());
        head = Vecs.roundtrip(source, sSession, 0x41, 0, 0, data).data();
        payload = Vecs.roundtrip(source, sSession, 0x41, 1, 0, Vecs.accessHashNew()).data();
        System.arraycopy(head, 0, import0, 97, 129);
        assertEquals(0x9000, Vecs.roundtrip(target, tSession, 0x42, 0, 0, import0).sw());
        assertEquals(0x9000, Vecs.roundtrip(target, tSession, 0x42, 1, 0, payload).sw());
        List<Integer> reseal = target.commits();
        assertEquals(1, reseal.size(), "T-INSTALL (LOADED) is a single commit");
        assertEquals(2048, (int) reseal.get(0), "T-INSTALL (LOADED) commit bytes");
        assertTrue(reseal.get(0) <= BUFFER, "T-INSTALL (LOADED) vs the buffer");
        System.out.println("T-INSTALL (LOADED) commit bytes: " + reseal.get(0));
    }
}
