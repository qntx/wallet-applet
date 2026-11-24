// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Transfer;
import org.qntx.card.host.WalletInfo;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.EmuMember;
import org.qntx.card.tests.Vecs;

/**
 * The EXPORT/IMPORT wire flow against one card with the peer played by a host-emulated member
 * ({@link EmuMember}): the exact flow {@code TransferRealCardTest}-style rows drive on card A,
 * verified here on the simulator so the real-card run only spends card time. The payload the card
 * releases must carry its seed and the new access hash, and the imported wallet must verify under
 * the transferred access hash and report the same BIP-32 master key.
 */
final class EmuMemberFlowTest {

    @Test
    void exportThenImportThroughEmulatedMembers() throws Exception {
        EmuMember m = new EmuMember();
        // card X: LOADED with members {X, M} — CREATE leaves the session verified (§9.4)
        Card x = Vecs.factory();
        byte[] aX = Vecs.cardA(x);
        Vecs.blankFor(x, aX);
        Session xs = Vecs.open(x);
        byte[] create = new byte[96 + 16];
        System.arraycopy(Vecs.accessHash(), 0, create, 0, 32);
        System.arraycopy(Vecs.seed(), 0, create, 32, 64);
        System.arraycopy(m.cardId, 0, create, 96, 16);
        assertEquals(0x9000, Vecs.roundtrip(x, xs, 0x21, 1, 0, create).sw(), "CREATE with member");
        // EXPORT P1=0 with the member's fresh offer, then P1=1 for the record
        Response e0 = Vecs.roundtrip(x, xs, 0x41, 0, 0, Transfer.export0(m.cert, m.newOffer()));
        assertEquals(0x9000, e0.sw(), "EXPORT P1=0");
        Transfer.ExportHead head =
                Transfer.decodeExportHead(e0.data(), Vecs.certFor(aX), m.cert, m.lk());
        Response e1 = Vecs.roundtrip(x, xs, 0x41, 1, 0, Transfer.export1(Vecs.accessHashNew()));
        assertEquals(0x9000, e1.sw(), "EXPORT P1=1");
        // the host as M: open the record — it must carry X's seed and the new access hash
        byte[] z = m.z(head.e());
        byte[] transcript = EmuMember.transcript(aX, m.a, m.lk(), head.e());
        byte[] payload = EmuMember.unsealRecord(z, transcript, e1.data());
        assertNotNull(payload, "emulated member cannot open the export record");
        assertArrayEquals(Vecs.seed(), Arrays.copyOfRange(payload, 1, 65), "exported seed");
        assertArrayEquals(
                Vecs.accessHashNew(),
                Arrays.copyOfRange(payload, 65, 97),
                "accessHash_T in the payload");

        // card Y: BLANK; the emulated member is the source S of a §11.3 set {S, Y}
        EmuMember s = new EmuMember();
        Card y = Vecs.factory();
        byte[] aY = Vecs.cardA(y);
        Vecs.blankFor(y, aY);
        Session ys = Vecs.open(y);
        Response offer = Vecs.roundtrip(y, ys, 0x40, 0, 0, new byte[0]);
        assertEquals(0x9000, offer.sw(), "OFFER");
        byte[] lk = Arrays.copyOf(offer.data(), 65);
        byte[][] headE = s.importHead(aY, lk);
        assertEquals(0x9000, Vecs.roundtrip(y, ys, 0x42, 0, 0, headE[0]).sw(), "IMPORT P1=0");
        byte[] zY = EmuMember.ecdhX(new java.math.BigInteger(1, headE[1]), lk);
        byte[] mY = EmuMember.transcript(s.a, aY, lk, Arrays.copyOfRange(headE[0], 97, 162));
        byte[] pld =
                EmuMember.payload(
                        0x02, Vecs.seed(), Vecs.accessHashNew(), s.cardId, Ids.cardId(aY));
        byte[] record = EmuMember.sealRecord(zY, mY, pld);
        Response i1 = Vecs.roundtrip(y, ys, 0x42, 1, 0, Transfer.import1(record));
        assertEquals(0x9000, i1.sw(), "IMPORT P1=1");
        WalletInfo w = WalletInfo.parse(i1.data());
        assertArrayEquals(Vecs.seedMasterPublicKey(), w.masterPublicKey(), "imported master");
        assertEquals(2, w.members().size(), "imported member count");
        // the transferred access hash verifies, then ERASE leaves the card BLANK
        Response v = Vecs.roundtrip(y, ys, 0x22, 0, 0, Vecs.accessHashNew());
        assertEquals(0x9000, v.sw(), "VERIFY with accessHash_T");
        assertEquals(0x9000, Vecs.roundtrip(y, ys, 0x24, 0, 0, new byte[0]).sw(), "ERASE");
    }
}
