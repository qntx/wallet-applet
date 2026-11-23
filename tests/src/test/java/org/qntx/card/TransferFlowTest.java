// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Bip32;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Transfer;
import org.qntx.card.host.WalletInfo;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The §11.3 transfer flows on genuine (random) cards, driven through the {@code host.Transfer}
 * helpers end to end — the OFFER and EXPORT signatures the host must check (§11.2) are checked by
 * the decoders themselves: two- and three-member wallets, a forgotten access code re-sealed onto a
 * LOADED card, and a limit-erased card re-provisioned as a member. Every member ends with the same
 * WalletInfo, and VERIFY works under the access hash each card was sealed with.
 */
final class TransferFlowTest {
    private static final int INS_CREATE = 0x21;
    private static final int INS_VERIFY = 0x22;
    private static final int INS_EXPORT = 0x41;
    private static final int INS_IMPORT = 0x42;
    private static final int INS_ERASE = 0x24;

    /** A genuine card personalized under ca1 (random identity), in BLANK with an open session. */
    private static final class Side {
        final Card card;
        final byte[] a;
        final byte[] cert;
        final byte[] id;
        Session session;

        Side() throws Exception {
            card = Vecs.factory();
            a = Vecs.cardA(card);
            cert = Vecs.certFor(a);
            id = Ids.cardId(a);
            Vecs.blankFor(card, a);
            session = Vecs.open(card);
        }

        Response inner(int ins, int p1, byte[] data) throws Exception {
            return Vecs.roundtrip(card, session, ins, p1, 0, data);
        }

        /** CREATE P1 = 01 (imported): {@code accessHash ‖ seed ‖ others}. */
        byte[] createImported(byte[] accessHash, byte[] seed, byte[]... others) throws Exception {
            byte[][] parts = new byte[1 + others.length][];
            parts[0] = seed;
            System.arraycopy(others, 0, parts, 1, others.length);
            return create(1, accessHash, concat(parts));
        }

        /** CREATE P1 = 00 (generated): {@code accessHash ‖ hostEntropy ‖ others}. */
        byte[] createGenerated(byte[] accessHash, byte[] hostEntropy, byte[]... others)
                throws Exception {
            byte[][] parts = new byte[1 + others.length][];
            parts[0] = hostEntropy;
            System.arraycopy(others, 0, parts, 1, others.length);
            return create(0, accessHash, concat(parts));
        }

        private byte[] create(int p1, byte[] accessHash, byte[] tail) throws Exception {
            byte[] data = new byte[32 + tail.length];
            System.arraycopy(accessHash, 0, data, 0, 32);
            System.arraycopy(tail, 0, data, 32, tail.length);
            Response r = inner(INS_CREATE, p1, data);
            assertEquals(0x9000, r.sw(), "CREATE");
            return r.data();
        }

        /**
         * The host-side transfer per §11.2/§11.3: {@code source} exports to this card and this card
         * imports, both through the {@link Transfer} codecs (which verify the offer and export
         * signatures themselves). Returns this card's WalletInfo bytes.
         */
        byte[] receiveFrom(Side source, byte[] sourceHash, byte[] accessHashT) throws Exception {
            // OFFER through the host codec: the response is verified under this card's cert
            Response o = inner(0x40, 0, new byte[0]);
            assertEquals(0x9000, o.sw(), "OFFER");
            Transfer.Offer offer = Transfer.decodeOffer(o.data(), cert);

            // EXPORT0/1 on the source (its session must be verified)
            source.session = Vecs.open(source.card);
            assertEquals(0x9000, source.inner(INS_VERIFY, 0, sourceHash).sw(), "source VERIFY");
            byte[] export0 = Transfer.export0(cert, concat(offer.lk(), offer.sig()));
            Response h = source.inner(INS_EXPORT, 0, export0);
            assertEquals(0x9000, h.sw(), "EXPORT0");
            Transfer.ExportHead head =
                    Transfer.decodeExportHead(h.data(), source.cert, cert, offer.lk());
            Response p = source.inner(INS_EXPORT, 1, Transfer.export1(accessHashT));
            assertEquals(0x9000, p.sw(), "EXPORT1");
            Transfer.ExportPayload payload = Transfer.decodeExportPayload(p.data());

            // IMPORT0/1 on this card
            Response i0 =
                    inner(
                            INS_IMPORT,
                            0,
                            Transfer.import0(source.cert, concat(head.e(), head.sig())));
            assertEquals(0x9000, i0.sw(), "IMPORT0");
            Response i1 =
                    inner(INS_IMPORT, 1, Transfer.import1(concat(payload.ct(), payload.tag())));
            assertEquals(0x9000, i1.sw(), "IMPORT1");
            return i1.data();
        }
    }

    private static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] part : parts) {
            len += part.length;
        }
        byte[] out = new byte[len];
        int off = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, off, part.length);
            off += part.length;
        }
        return out;
    }

    private static void verifies(Side side, byte[] accessHash) throws Exception {
        side.session = Vecs.open(side.card);
        assertEquals(0x9000, side.inner(INS_VERIFY, 0, accessHash).sw(), "VERIFY");
    }

    @Test
    void twoCardImportTransfer() throws Exception {
        Side source = new Side();
        Side target = new Side();
        byte[] info = source.createImported(Vecs.accessHash(), Vecs.seed(), target.id);
        byte[] imported = target.receiveFrom(source, Vecs.accessHash(), Vecs.accessHashNew());
        assertArrayEquals(info, imported, "both cards report the same WalletInfo");
        // §11.2: the host compares masterPublicKey with its own computation from the seed
        assertArrayEquals(
                Bip32.masterPublicKey(Vecs.seed()),
                Arrays.copyOf(imported, 33),
                "masterPublicKey from the seed");
        WalletInfo parsed = WalletInfo.parse(imported);
        assertMembers(List.of(source.id, target.id), parsed.members());
        // each card verifies under the access hash it was sealed with
        verifies(source, Vecs.accessHash());
        verifies(target, Vecs.accessHashNew());
    }

    @Test
    void threeCardGeneratedTransfer() throws Exception {
        Side source = new Side();
        Side target = new Side();
        Side third = new Side();
        byte[] hostEntropy = new byte[32];
        Vecs.RND.nextBytes(hostEntropy);
        byte[] info = source.createGenerated(Vecs.accessHash(), hostEntropy, target.id, third.id);
        byte[] t = target.receiveFrom(source, Vecs.accessHash(), Vecs.accessHashNew());
        assertArrayEquals(info, t, "target WalletInfo");
        byte[] th = third.receiveFrom(source, Vecs.accessHash(), Vecs.accessHashNew());
        assertArrayEquals(info, th, "third WalletInfo");
        WalletInfo parsed = WalletInfo.parse(info);
        assertEquals(1, parsed.origin(), "generated origin");
        assertMembers(List.of(source.id, target.id, third.id), parsed.members());
        verifies(source, Vecs.accessHash());
        verifies(target, Vecs.accessHashNew());
        verifies(third, Vecs.accessHashNew());
    }

    @Test
    void forgottenCodeResealsOnLoadedCard() throws Exception {
        Side source = new Side();
        Side target = new Side();
        source.createImported(Vecs.accessHash(), Vecs.seed(), target.id);
        // the first transfer sealed the target under accessHashNew
        target.receiveFrom(source, Vecs.accessHash(), Vecs.accessHashNew());
        // §11.3: that code is lost — a new export seals it under a third hash without knowing
        // the old one; the wallet contents stay identical
        byte[] newHash = new byte[32];
        Vecs.RND.nextBytes(newHash);
        byte[] info = target.receiveFrom(source, Vecs.accessHash(), newHash);
        verifies(target, newHash);
        // and the old sealed code is gone with the wallet's wrap material
        target.session = Vecs.open(target.card);
        int sw = target.inner(INS_VERIFY, 0, Vecs.accessHashNew()).sw();
        assertEquals(0x63C0 | 9, sw, "the forgotten code no longer matches");
        WalletInfo parsed = WalletInfo.parse(info);
        assertMembers(List.of(source.id, target.id), parsed.members());
    }

    private static void assertMembers(List<byte[]> expect, List<byte[]> actual) {
        assertEquals(expect.size(), actual.size(), "member count");
        for (int i = 0; i < expect.size(); i++) {
            assertArrayEquals(expect.get(i), actual.get(i), "member " + i);
        }
    }

    @Test
    void limitErasedCardIsReprovisioned() throws Exception {
        Side source = new Side();
        Side target = new Side();
        source.createImported(Vecs.accessHash(), Vecs.seed(), target.id);
        target.receiveFrom(source, Vecs.accessHash(), Vecs.accessHashNew());
        // exhaust the verify limit: T-ERASE at the tenth failure leaves the card BLANK
        target.session = Vecs.open(target.card);
        for (int i = 0; i < 9; i++) {
            assertEquals(
                    0x63C0 | (9 - i),
                    target.inner(INS_VERIFY, 0, Vecs.accessHash()).sw(),
                    "wrong-code VERIFY " + i);
            target.session = Vecs.open(target.card);
            for (int w = 0; w < 15 && i >= 2; w++) {
                target.inner(0x25, 0, new byte[0]);
            }
        }
        assertEquals(0x6983, target.inner(INS_VERIFY, 0, Vecs.accessHash()).sw(), "limit");
        assertEquals(0x9000, target.inner(0x20, 0, new byte[0]).sw(), "STATUS after erase");
        byte[] state = Internals.stateArray(target.card.applet(Spec.WALLET_AID));
        assertEquals(
                Const.LIFE_BLANK,
                javacard.framework.Util.getShort(state, State.OFF_LIFE),
                "BLANK after T-ERASE");
        // §11.3: a source member re-provisions the erased card under a fresh code
        byte[] newHash = new byte[32];
        Vecs.RND.nextBytes(newHash);
        byte[] info = target.receiveFrom(source, Vecs.accessHash(), newHash);
        assertArrayEquals(
                Bip32.masterPublicKey(Vecs.seed()),
                Arrays.copyOf(info, 33),
                "re-provisioned master");
        verifies(target, newHash);
    }

    @Test
    void erasedMemberCardForgetsItsMembership() throws Exception {
        // a member erased to BLANK must be re-provisioned: CREATE on it is allowed again
        Side source = new Side();
        Side target = new Side();
        source.createImported(Vecs.accessHash(), Vecs.seed(), target.id);
        target.receiveFrom(source, Vecs.accessHash(), Vecs.accessHashNew());
        verifies(target, Vecs.accessHashNew());
        assertEquals(0x9000, target.inner(INS_ERASE, 0, new byte[0]).sw(), "ERASE by the holder");
        byte[] info = target.receiveFrom(source, Vecs.accessHash(), Vecs.accessHashNew());
        assertArrayEquals(
                Bip32.masterPublicKey(Vecs.seed()), Arrays.copyOf(info, 33), "same wallet");
    }
}
