// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.qntx.card.TransferVecs.Side;
import org.qntx.card.host.Response;
import org.qntx.card.sim.Fault;
import org.qntx.card.tests.Vecs;

/**
 * Architecture §14.6 T4 — the check-6 point rejections of {@code transfer.json}: every {@code
 * rejectedOffers} check-6 row on a verified LOADED source and every {@code rejectedExports} check-6
 * row on an offered target must fail {@code 6A80}. For IMPORT the rejection happens before the ECDH
 * — {@code Fault.calls("Secp256k1.agree")} stays zero and no pending import is armed.
 */
final class PointTest {

    @Test
    void rejectedOfferPointsFailBeforeAgreement() throws Exception {
        Map<String, Object> t = TransferVecs.find("transfers", "imported-to-target");
        Side source = new Side("source");
        TransferVecs.createWallet(source, TransferVecs.wallet("imported"));
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
            if (((Integer) r.get("check")) != 6) {
                continue;
            }
            try {
                Fault.countCalls();
                Response resp =
                        source.inner(
                                TransferVecs.INS_EXPORT,
                                0,
                                TransferVecs.concat(
                                        Vecs.hex(r, "cert"),
                                        Vecs.hex(r, "LK"),
                                        Vecs.hex(r, "signature")));
                assertEquals(0x6A80, resp.sw(), "rejectedOffers " + r.get("name"));
                assertEquals(
                        0, TransferVecs.pending(source.applet), "pending export " + r.get("name"));
            } finally {
                Fault.reset();
            }
        }
    }

    @Test
    void rejectedExportPointsFailBeforeAgreement() throws Exception {
        Map<String, Object> t = TransferVecs.find("transfers", "imported-to-target");
        Side source = new Side("source");
        Side target = new Side("target");
        TransferVecs.createWallet(source, TransferVecs.wallet("imported"));
        TransferVecs.offerWith(target, t);
        for (Map<String, Object> r : Vecs.list(TransferVecs.DOC, "rejectedExports")) {
            if (((Integer) r.get("check")) != 6
                    || !r.get("transfer").equals("imported-to-target")) {
                continue;
            }
            try {
                Fault.countCalls();
                Response resp =
                        target.inner(
                                TransferVecs.INS_IMPORT,
                                0,
                                TransferVecs.concat(
                                        Vecs.hex(r, "cert"),
                                        Vecs.hex(r, "E"),
                                        Vecs.hex(r, "signature")));
                assertEquals(0x6A80, resp.sw(), "rejectedExports " + r.get("name"));
                assertEquals(
                        0, Fault.calls("Secp256k1.agree"), "agree not reached " + r.get("name"));
                assertEquals(
                        0, TransferVecs.pending(target.applet), "pending import " + r.get("name"));
            } finally {
                Fault.reset();
            }
        }
    }
}
