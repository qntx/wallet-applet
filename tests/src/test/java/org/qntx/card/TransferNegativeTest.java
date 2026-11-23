// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Certificates;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The §9.13/§9.14 refusals of architecture §14.6 T3 that vectors do not already cover, on genuine
 * random cards: a non-member, the own card, a different batch CA, a bad offer signature, tampered
 * E/ct/tag, and an export made for a stale offer after the target installed — or after it was
 * erased and re-offered. Every refusal is {@code 6A80} ({@code 6985} where the spec names it) with
 * at most the allowed peer-slot write and no pending state left.
 */
final class TransferNegativeTest {
    private static final int INS_CREATE = 0x21;
    private static final int INS_VERIFY = 0x22;
    private static final int INS_OFFER = 0x40;
    private static final int INS_EXPORT = 0x41;
    private static final int INS_IMPORT = 0x42;
    private static final int INS_ERASE = 0x24;

    private static final class Side {
        final Card card;
        final byte[] a;
        final byte[] cert;
        Session session;

        Side() throws Exception {
            card = Vecs.factory();
            a = Vecs.cardA(card);
            cert = Vecs.certFor(a);
            Vecs.blankFor(card, a);
            session = Vecs.open(card);
        }

        Response inner(int ins, int p1, byte[] data) throws Exception {
            return Vecs.roundtrip(card, session, ins, p1, 0, data);
        }

        byte[] offer() throws Exception {
            Response r = inner(INS_OFFER, 0, new byte[0]);
            assertEquals(0x9000, r.sw(), "OFFER");
            return r.data();
        }

        /** CREATE P1 = 01 with the shared seed and {@code ids} as the other members. */
        void create(byte[]... ids) throws Exception {
            byte[] data = new byte[96 + 16 * ids.length];
            System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
            System.arraycopy(Vecs.seed(), 0, data, 32, 64);
            for (int i = 0; i < ids.length; i++) {
                System.arraycopy(ids[i], 0, data, 96 + 16 * i, 16);
            }
            assertEquals(0x9000, inner(INS_CREATE, 1, data).sw(), "CREATE");
        }

        void verify() throws Exception {
            assertEquals(0x9000, inner(INS_VERIFY, 0, Vecs.accessHash()).sw(), "VERIFY");
        }

        /** A verified EXPORT0 of {@code data}; the caller asserts the result. */
        Response export0(byte[] data) throws Exception {
            return inner(INS_EXPORT, 0, data);
        }

        byte[] exportHead(Side target) throws Exception {
            verify();
            byte[] data = new byte[226];
            System.arraycopy(target.cert, 0, data, 0, 97);
            System.arraycopy(target.offer(), 0, data, 97, 129);
            Response r = export0(data);
            assertEquals(0x9000, r.sw(), "EXPORT0");
            return r.data();
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

    private static int pending(Card card) {
        byte[] w = Internals.words(card.applet(Spec.WALLET_AID));
        return ((w[6] & 0xFF) << 8) | (w[7] & 0xFF);
    }

    private static byte[] export0Data(byte[] cert, byte[] offer) {
        return concat(Arrays.copyOf(cert, 97), Arrays.copyOf(offer, 129));
    }

    /** A genuine export head + payload of {@code source} to {@code target}. */
    private static byte[][] export(Side source, Side target) throws Exception {
        byte[] head = source.exportHead(target);
        Response p = source.inner(INS_EXPORT, 1, Vecs.accessHashNew());
        assertEquals(0x9000, p.sw(), "EXPORT1");
        return new byte[][] {head, p.data()};
    }

    private static Response import0(Side target, Side source, byte[] head) throws Exception {
        return target.inner(INS_IMPORT, 0, concat(source.cert, head));
    }

    @Test
    void exportToNonMemberIsRefused() throws Exception {
        Side source = new Side();
        Side member = new Side();
        Side stranger = new Side();
        source.create(Ids.cardId(member.a));
        source.verify();
        Response r = source.export0(export0Data(stranger.cert, stranger.offer()));
        assertEquals(0x6A80, r.sw(), "non-member target");
        assertEquals(0, pending(source.card), "no pending export");
        assertEquals(0, source.card.writes(), "no peer write for a non-member");
    }

    @Test
    void exportToSelfIsRefused() throws Exception {
        Side source = new Side();
        Side member = new Side();
        source.create(Ids.cardId(member.a));
        source.verify();
        Response r = source.export0(export0Data(source.cert, member.offer()));
        assertEquals(0x6A80, r.sw(), "own certificate as the target");
        assertEquals(0, pending(source.card));
    }

    @Test
    void exportToOtherCaIsRefused() throws Exception {
        Side source = new Side();
        Side member = new Side();
        Side foreign = new Side();
        source.create(Ids.cardId(member.a), Ids.cardId(foreign.a));
        source.verify();
        // foreign is a *member* but its cert is re-issued under ca2 — check 1 must fail
        byte[] foreignCert = Certificates.issue(Vecs.ca2Private(), foreign.a);
        Response r = source.export0(export0Data(foreignCert, foreign.offer()));
        assertEquals(0x6A80, r.sw(), "member cert under the wrong CA");
        assertEquals(0, pending(source.card));
    }

    @Test
    void badOfferSignatureIsRefused() throws Exception {
        Side source = new Side();
        Side target = new Side();
        source.create(Ids.cardId(target.a));
        source.verify();
        byte[] offer = target.offer();
        offer[offer.length - 1] ^= 1;
        Response r = source.export0(export0Data(target.cert, offer));
        assertEquals(0x6A80, r.sw(), "tampered offer signature");
        assertEquals(0, pending(source.card));
    }

    @Test
    void tamperedExportHeadIsRefused() throws Exception {
        Side source = new Side();
        Side target = new Side();
        source.create(Ids.cardId(target.a));
        target.offer();
        byte[] head = export(source, target)[0];
        // tamper with E: the signature no longer matches TH
        byte[] badE = head.clone();
        badE[40] ^= 1;
        assertEquals(0x6A80, import0(target, source, badE).sw(), "tampered E");
        assertEquals(0, pending(target.card), "no pending import");
        // tamper with the signature only
        byte[] badSig = head.clone();
        badSig[128] ^= 1;
        assertEquals(0x6A80, import0(target, source, badSig).sw(), "tampered sig_S");
        assertEquals(0, pending(target.card));
    }

    @Test
    void tamperedPayloadIsRefused() throws Exception {
        Side source = new Side();
        Side target = new Side();
        source.create(Ids.cardId(target.a));
        target.offer();
        byte[][] export = export(source, target);
        assertEquals(0x9000, import0(target, source, export[0]).sw());
        // flipped ct byte: the tag no longer matches
        byte[] badCt = export[1].clone();
        badCt[0] ^= 1;
        assertEquals(0x6A80, target.inner(INS_IMPORT, 1, badCt).sw(), "tampered ct");
        assertEquals(0, pending(target.card), "the failed IMPORT1 ends the pending import");
        // flipped tag byte
        assertEquals(0x9000, import0(target, source, export[0]).sw());
        byte[] badTag = export[1].clone();
        badTag[badTag.length - 1] ^= 1;
        assertEquals(0x6A80, target.inner(INS_IMPORT, 1, badTag).sw(), "tampered tag");
    }

    @Test
    void exportForAnInstalledOfferIsStale() throws Exception {
        Side source = new Side();
        Side target = new Side();
        source.create(Ids.cardId(target.a));
        byte[][] export = export(source, target);
        // the target installs the wallet: T-INSTALL resets offer to NONE — the armed
        // import of the same head cannot even start again, and a replayed head after a
        // fresh OFFER fails the signature check (TH covers the new LK)
        assertEquals(0x9000, import0(target, source, export[0]).sw());
        assertEquals(0x9000, target.inner(INS_IMPORT, 1, export[1]).sw());
        assertEquals(0x6985, import0(target, source, export[0]).sw(), "offer is NONE");
        target.offer();
        assertEquals(0x6A80, import0(target, source, export[0]).sw(), "export of the stale offer");
        assertEquals(0, pending(target.card));
    }

    @Test
    void exportForAnErasedOfferIsStale() throws Exception {
        Side source = new Side();
        Side target = new Side();
        source.create(Ids.cardId(target.a));
        byte[][] export = export(source, target);
        // the target imports once, the holder erases it, then it offers again: a head made
        // for the pre-erase link key fails check 5 (TH covers the new LK)
        assertEquals(0x9000, import0(target, source, export[0]).sw());
        assertEquals(0x9000, target.inner(INS_IMPORT, 1, export[1]).sw());
        target.session = Vecs.open(target.card);
        assertEquals(0x9000, target.inner(INS_VERIFY, 0, Vecs.accessHashNew()).sw());
        assertEquals(0x9000, target.inner(INS_ERASE, 0, new byte[0]).sw());
        target.session = Vecs.open(target.card);
        target.offer();
        assertEquals(0x6A80, import0(target, source, export[0]).sw(), "export of the erased offer");
        // a fresh export for the new offer works
        byte[][] fresh = export(source, target);
        assertEquals(0x9000, import0(target, source, fresh[0]).sw());
        assertEquals(0x9000, target.inner(INS_IMPORT, 1, fresh[1]).sw());
    }

    @Test
    void replayedPayloadIsRefused() throws Exception {
        Side source = new Side();
        Side target = new Side();
        source.create(Ids.cardId(target.a));
        byte[][] export = export(source, target);
        // a payload that replays under a *different* head is rejected by its tag (kTm of
        // the other pending import), and any continuation after a failed import is gone
        assertEquals(0x9000, import0(target, source, export[0]).sw());
        byte[][] export2 = export(source, target);
        assertEquals(0x9000, import0(target, source, export2[0]).sw());
        assertEquals(
                0x6A80, target.inner(INS_IMPORT, 1, export[1]).sw(), "payload of another head");
        assertEquals(
                0x6985, target.inner(INS_IMPORT, 1, export2[1]).sw(), "no pending after failure");
        assertEquals(0x9000, import0(target, source, export2[0]).sw());
        assertEquals(0x9000, target.inner(INS_IMPORT, 1, export2[1]).sw());
    }

    @Test
    void exportToNonMemberWritesNothing() throws Exception {
        // a refused export must leave the peer slots untouched (§16.1 item 7)
        Side source = new Side();
        Side member = new Side();
        Side stranger = new Side();
        source.create(Ids.cardId(member.a));
        source.verify();
        byte[] before = Internals.peerW(source.card.applet(Spec.WALLET_AID), 0);
        source.export0(export0Data(stranger.cert, stranger.offer()));
        assertTrue(
                Arrays.equals(before, Internals.peerW(source.card.applet(Spec.WALLET_AID), 0)),
                "slot 0 unchanged");
        // … and a member export writes its slot exactly once (the peer's identity point)
        export(source, member);
        assertTrue(
                Arrays.equals(
                        org.qntx.card.host.Crypto.decompress(member.a),
                        Internals.peerW(source.card.applet(Spec.WALLET_AID), 0)),
                "slot 0 holds the member's identity point");
    }

    @Test
    void import0SelfCertIsRefused() throws Exception {
        // A == A check 2 of IMPORT P1=0 on a LOADED card: the sender certificate being the
        // own identity is 6A80 before the head signature is even read
        // a LOADED target: past the A != A check the member lookup would fault on
        // self == found, so 6A80 specifically proves the self-check fired
        Side source = new Side();
        Side target = new Side();
        target.create(Ids.cardId(source.a));
        target.offer();
        assertEquals(
                0x6A80,
                target.inner(INS_IMPORT, 0, export0Data(target.cert, new byte[129])).sw(),
                "own certificate must be refused");
        assertEquals(0, pending(target.card), "pending import left");
    }
}
