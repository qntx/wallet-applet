// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.qntx.card.TransferVecs.Side;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Response;
import org.qntx.card.sim.Rng;
import org.qntx.card.tests.Vecs;

/**
 * {@code transfer.json} replayed through the real commands (architecture §9 T2): the five {@code
 * transfers} rows end to end — {@link Rng#fix} for {@code e}, the vector's link key reflected into
 * the target after its first OFFER — then every {@code rejectedOffers}/{@code rejectedExports}/
 * {@code rejectedPayloads} row at its point, each {@code 6A80} with no pending state and no
 * persistent write beyond the allowed peer {@code setW}.
 */
final class TransferVectorTest {
    private static final int INS_EXPORT = TransferVecs.INS_EXPORT;
    private static final int INS_IMPORT = TransferVecs.INS_IMPORT;

    /** EXPORT0+EXPORT1 on {@code source} for the transfer row; returns {@code head, payload}. */
    private static byte[][] export(Side source, Side target, Map<String, Object> t, byte[] offer)
            throws Exception {
        Rng.fix(Vecs.hex(t, "e"));
        byte[] head;
        try {
            byte[] data = TransferVecs.concat(target.cert(), offer);
            Response h = source.inner(INS_EXPORT, 0, data);
            assertEquals(0x9000, h.sw(), "EXPORT0 " + t.get("name"));
            head = h.data();
        } finally {
            Rng.reset();
        }
        assertArrayEquals(Vecs.hex(t, "E"), Arrays.copyOf(head, 65), "E " + t.get("name"));
        assertTrue(
                Crypto.verify(
                        source.uncompressed(),
                        Vecs.hex(t, "TH"),
                        Arrays.copyOfRange(head, 65, 129)),
                "sig_S " + t.get("name"));
        assertArrayEquals(Vecs.hex(t, "kTe"), TransferVecs.aes(source.applet, "kTe"), "kTe");
        assertArrayEquals(Vecs.hex(t, "kTm"), TransferVecs.aes(source.applet, "kTm"), "kTm");
        Response p = source.inner(INS_EXPORT, 1, Vecs.hex(t, "accessHashT"));
        assertEquals(0x9000, p.sw(), "EXPORT1 " + t.get("name"));
        assertArrayEquals(
                TransferVecs.concat(Vecs.hex(t, "ct"), Vecs.hex(t, "tag")), p.data(), "ct ‖ tag");
        return new byte[][] {head, p.data()};
    }

    /** The full import of the transfer row on {@code target}; asserts WalletInfo and slots. */
    private static void importFull(
            Side target, Side source, Map<String, Object> t, byte[] head, byte[] payload)
            throws Exception {
        Response r = target.inner(INS_IMPORT, 0, TransferVecs.concat(source.cert(), head));
        assertEquals(0x9000, r.sw(), "IMPORT0 " + t.get("name"));
        assertArrayEquals(
                Vecs.hex(t, "kTe"), TransferVecs.aes(target.applet, "kTe"), "kTe (target)");
        r = target.inner(INS_IMPORT, 1, payload);
        assertEquals(0x9000, r.sw(), "IMPORT1 " + t.get("name"));
        assertArrayEquals(Vecs.hex(t, "walletInfo"), r.data(), "WalletInfo");
        assertArrayEquals(
                source.uncompressed(),
                Internals.peerW(target.applet, (Integer) t.get("slotOnTarget")),
                "target peer slot");
        assertArrayEquals(
                target.uncompressed(),
                Internals.peerW(source.applet, (Integer) t.get("slotOnSource")),
                "source peer slot");
    }

    @Test
    void importedWalletTransfersReplay() throws Exception {
        Map<String, Object> t1 = TransferVecs.find("transfers", "imported-to-target");
        Map<String, Object> t2 = TransferVecs.find("transfers", "imported-reseal-target");
        Side source = new Side("source");
        Side target = new Side("target");
        TransferVecs.createWallet(source, TransferVecs.wallet("imported"));

        // BLANK target: the rejected export heads, then the rejected payloads, then success
        byte[] offer = TransferVecs.offerWith(target, t1);
        for (Map<String, Object> r : Vecs.list(TransferVecs.DOC, "rejectedExports")) {
            if (!r.get("transfer").equals("imported-to-target")) {
                continue;
            }
            assertRejectedImport0(target, source, r);
        }
        for (Map<String, Object> r : Vecs.list(TransferVecs.DOC, "rejectedPayloads")) {
            if (!r.get("transfer").equals("imported-to-target")) {
                continue;
            }
            assertRejectedImport1(target, source, t1, r);
        }
        byte[][] out = export(source, target, t1, offer);
        importFull(target, source, t1, out[0], out[1]);
        assertEquals(0, TransferVecs.pending(source.applet));
        assertEquals(0, TransferVecs.pending(target.applet));

        // LOADED source, verified: every rejected offer → 6A80, nothing written, nothing pending
        assertEquals(
                0x9000,
                TransferVecs.verify(
                                source,
                                Vecs.hex(
                                        Vecs.obj(TransferVecs.wallet("imported"), "create"),
                                        "accessHash"))
                        .sw(),
                "VERIFY");
        for (Map<String, Object> r : Vecs.list(TransferVecs.DOC, "rejectedOffers")) {
            byte[] data =
                    TransferVecs.concat(
                            Vecs.hex(r, "cert"), Vecs.hex(r, "LK"), Vecs.hex(r, "signature"));
            Response resp = source.inner(INS_EXPORT, 0, data);
            assertEquals(0x6A80, resp.sw(), "rejectedOffers " + r.get("name"));
            assertEquals(
                    0, TransferVecs.pending(source.applet), "no pending export " + r.get("name"));
            assertTrue(source.card.writes() <= 1, "at most the peer slot write " + r.get("name"));
        }

        // the LOADED re-seal: fresh offer with the reseal link key, reseal payload rows, success
        byte[] offer2 = TransferVecs.offerWith(target, t2);
        byte[][] out2 = export(source, target, t2, offer2);
        for (Map<String, Object> r : Vecs.list(TransferVecs.DOC, "rejectedPayloads")) {
            if (!r.get("transfer").equals("imported-reseal-target")) {
                continue;
            }
            assertRejectedImport1(target, source, t2, r);
        }
        importFull(target, source, t2, out2[0], out2[1]);
        // cert-non-member-loaded: on the still-LOADED target (its offer armed fresh)
        TransferVecs.offerWith(target, t2);
        Map<String, Object> nm = TransferVecs.find("rejectedExports", "cert-non-member-loaded");
        assertRejectedImport0(target, new Side("third"), nm);
    }

    @Test
    void generatedWalletTransfersReplay() throws Exception {
        Side source = new Side("source");
        Side target = new Side("target");
        Side third = new Side("third");
        TransferVecs.createWallet(source, TransferVecs.wallet("generated"));

        Map<String, Object> gt = TransferVecs.find("transfers", "generated-to-target");
        byte[] offer = TransferVecs.offerWith(target, gt);
        byte[][] out = export(source, target, gt, offer);
        importFull(target, source, gt, out[0], out[1]);

        Map<String, Object> gth = TransferVecs.find("transfers", "generated-to-third");
        offer = TransferVecs.offerWith(third, gth);
        out = export(source, third, gth, offer);
        importFull(third, source, gth, out[0], out[1]);

        Map<String, Object> reseal =
                TransferVecs.find("transfers", "generated-reseal-third-from-target");
        // T-INSTALL cleared the session's verified flag: the target must verify again to
        // export, under the access hash the generated-to-target transfer sealed it with
        assertEquals(0x9000, TransferVecs.verify(target, Vecs.hex(gt, "accessHashT")).sw());
        offer = TransferVecs.offerWith(third, reseal);
        out = export(target, third, reseal, offer);
        importFull(third, target, reseal, out[0], out[1]);
    }

    /** A rejectedExports row: 6A80, no pending import, at most the peer-slot write. */
    private static void assertRejectedImport0(Side target, Side source, Map<String, Object> r)
            throws Exception {
        byte[] data =
                TransferVecs.concat(
                        Vecs.hex(r, "cert"), Vecs.hex(r, "E"), Vecs.hex(r, "signature"));
        Response resp = target.inner(INS_IMPORT, 0, data);
        assertEquals(0x6A80, resp.sw(), "rejectedExports " + r.get("name"));
        assertEquals(0, TransferVecs.pending(target.applet), "pending " + r.get("name"));
        assertTrue(target.card.writes() <= 1, "writes " + r.get("name"));
    }

    /**
     * A rejectedPayloads row: after a fresh successful IMPORT0 of the transfer, IMPORT1 returns
     * 6A80 and changes nothing persistent.
     */
    private static void assertRejectedImport1(
            Side target, Side source, Map<String, Object> t, Map<String, Object> r)
            throws Exception {
        byte[] before = Internals.stateArray(target.applet).clone();
        Response head =
                TransferVecs.import0(
                        target, source, t, Vecs.hex(t, "E"), Vecs.hex(t, "exportSignature"));
        assertEquals(0x9000, head.sw(), "re-import0 " + r.get("name"));
        Response resp =
                target.inner(
                        INS_IMPORT, 1, TransferVecs.concat(Vecs.hex(r, "ct"), Vecs.hex(r, "tag")));
        assertEquals(0x6A80, resp.sw(), "rejectedPayloads " + r.get("name"));
        assertEquals(0, TransferVecs.pending(target.applet), "pending " + r.get("name"));
        assertArrayEquals(before, Internals.stateArray(target.applet), "state " + r.get("name"));
    }
}
