// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javacard.security.MessageDigest;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.TornException;

/**
 * Replays every sequence of {@code verify-sequence.json}: the §9.5/§9.15 failure limit
 * (architecture §14.4 W3) and the transfer sequences of §16.4/§18. Setup {@code create} is a
 * single-card LOADED wallet; setup {@code set} installs the card under test by transfer from a
 * member card Y. {@code after-T-FAIL} tears are armed on the first persistent write after T-FAIL's
 * commit, its index measured by a dry run instead of a constant. A WAIT step also asserts the 400
 * SHA-256 {@code doFinal} calls of 32 bytes and the absence of persistent writes (§16.1 item 7).
 */
final class FailureLimitTest {

    private static final byte INS_STATUS = 0x20;
    private static final byte INS_CREATE = 0x21;
    private static final byte INS_VERIFY = 0x22;
    private static final byte INS_ERASE = 0x24;
    private static final byte INS_WAIT = 0x25;
    private static final byte INS_OFFER = 0x40;
    private static final byte INS_EXPORT = 0x41;
    private static final byte INS_IMPORT = 0x42;

    private Card card;
    private byte[] cardA;
    private Session session;
    private Card peer;
    private Session peerSession;
    private byte[] peerA;
    private byte[] lastOffer;
    private final List<byte[]> lks = new ArrayList<>();
    private final List<byte[]> exportHeads = new ArrayList<>();
    private final List<byte[]> exportPayloads = new ArrayList<>();
    private int pendingExport = -1;

    /** The {@code create} setup: a LOADED card, fresh session, unverified. */
    private void setupCreate() throws Exception {
        card = Vecs.blankSelf();
        session = Vecs.loadWallet(card);
        lks.clear();
        exportHeads.clear();
        exportPayloads.clear();
        pendingExport = -1;
    }

    /**
     * The {@code set} setup: the member Y is LOADED with the card under test as second member; the
     * card under test (BLANK) answers OFFER and installs Y's wallet over transfer. Afterwards a
     * fresh session on the card under test, which is LOADED with members Y, X.
     */
    private void setupSet() throws Exception {
        card = Vecs.factory();
        cardA = Vecs.cardA(card);
        Vecs.blankFor(card, cardA);
        session = Vecs.open(card);
        peer = Vecs.factory();
        peerA = Vecs.cardA(peer);
        Vecs.blankFor(peer, peerA);
        peerSession = Vecs.open(peer);
        byte[] data = new byte[112];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        System.arraycopy(Ids.cardId(cardA), 0, data, 96, 16);
        require(Vecs.roundtrip(peer, peerSession, INS_CREATE, 1, 0, data), "set CREATE");
        lastOffer = offer();
        doExport(Vecs.accessHash());
        import0(exportHeads.size() - 1);
        import1();
        session = Vecs.open(card);
        lks.clear();
        exportHeads.clear();
        exportPayloads.clear();
        pendingExport = -1;
    }

    private static void require(Response r, String what) {
        if (r.sw() != 0x9000) {
            throw new IllegalStateException(what + ": " + Integer.toHexString(r.sw()));
        }
    }

    private Response inner(int ins, int p1, byte[] data) throws Exception {
        return Vecs.roundtrip(card, session, ins, p1, 0, data);
    }

    private byte[] offer() throws Exception {
        Response r = inner(INS_OFFER, 0, new byte[0]);
        require(r, "setup OFFER");
        return r.data();
    }

    /** A numbered export on Y: fresh OPEN, VERIFY right, EXPORT P1=00 then P1=01. */
    private void doExport(byte[] accessHashTarget) throws Exception {
        peerSession = Vecs.open(peer);
        require(
                Vecs.roundtrip(peer, peerSession, INS_VERIFY, 0, 0, Vecs.accessHash()),
                "export VERIFY");
        byte[] data = new byte[226];
        System.arraycopy(Vecs.certFor(cardA), 0, data, 0, 97);
        System.arraycopy(lastOffer, 0, data, 97, 129);
        Response h = Vecs.roundtrip(peer, peerSession, INS_EXPORT, 0, 0, data);
        require(h, "export P1=00");
        exportHeads.add(h.data());
        Response p = Vecs.roundtrip(peer, peerSession, INS_EXPORT, 1, 0, accessHashTarget);
        require(p, "export P1=01");
        exportPayloads.add(p.data());
    }

    private Response import0(int export) throws Exception {
        byte[] data = new byte[226];
        System.arraycopy(Vecs.certFor(peerA), 0, data, 0, 97);
        System.arraycopy(exportHeads.get(export), 0, data, 97, 129);
        return inner(INS_IMPORT, 0, data);
    }

    private Response import1() throws Exception {
        int i = pendingExport >= 0 ? pendingExport : exportPayloads.size() - 1;
        return inner(INS_IMPORT, 1, exportPayloads.get(i));
    }

    private void assertStatus(String expected) throws Exception {
        Response r = inner(INS_STATUS, 0, new byte[0]);
        assertEquals(0x9000, r.sw());
        assertArrayEquals(Vecs.unhex(expected), r.data(), "status");
    }

    private static byte[] code(String name) {
        return switch (name) {
            case "right" -> Vecs.accessHash();
            case "new" -> Vecs.accessHashNew();
            default -> Vecs.accessHashWrong();
        };
    }

    /**
     * The number of persistent writes T-FAIL makes, measured on a scratch card by a wrong-code
     * VERIFY away from the erase boundary: T-FAIL is the only transaction of such a VERIFY.
     */
    private int tfailWrites() throws Exception {
        Card scratch = Vecs.blankSelf();
        Session s = Vecs.loadWallet(scratch);
        Vecs.roundtrip(scratch, s, INS_VERIFY, 0, 0, Vecs.accessHashWrong());
        return scratch.writes();
    }

    private void verifyTornAfterTFail(byte[] codeBytes) throws Exception {
        card.tearAt(tfailWrites() + 1);
        assertThrows(
                TornException.class,
                () -> card.transmit(session.wrap(INS_VERIFY, 0, 0, codeBytes)));
        card.powerCycle();
        card.transmit(Spec.SELECT);
        session = Vecs.open(card);
    }

    @Test
    void sequences() throws Exception {
        Map<String, Object> doc = Vecs.load("verify-sequence.json");
        for (Map<String, Object> seq : Vecs.list(doc, "sequences")) {
            if ("create".equals(seq.get("setup"))) {
                setupCreate();
            } else {
                setupSet();
            }
            String name = (String) seq.get("name");
            for (Map<String, Object> step : Vecs.list(seq, "steps")) {
                String command = (String) step.get("command");
                int expectedSw =
                        "torn".equals(step.get("sw"))
                                ? 0
                                : Integer.parseInt((String) step.get("sw"), 16);
                int repeat =
                        step.get("repeat") == null ? 1 : ((Number) step.get("repeat")).intValue();
                for (int i = 0; i < repeat; i++) {
                    if ("after-T-FAIL".equals(step.get("tear"))) {
                        verifyTornAfterTFail(code((String) step.get("code")));
                        continue;
                    }
                    String at = name + " " + command;
                    switch (command) {
                        case "OPEN" -> session = Vecs.open(card);
                        case "VERIFY" ->
                                assertEquals(
                                        expectedSw,
                                        inner(INS_VERIFY, 0, code((String) step.get("code"))).sw(),
                                        at);
                        case "WAIT" ->
                                assertEquals(expectedSw, inner(INS_WAIT, 0, new byte[0]).sw(), at);
                        case "ERASE" ->
                                assertEquals(expectedSw, inner(INS_ERASE, 0, new byte[0]).sw(), at);
                        case "OFFER" -> {
                            Response r = inner(INS_OFFER, 0, new byte[0]);
                            assertEquals(expectedSw, r.sw(), at);
                            if (r.sw() == 0x9000) {
                                byte[] lk = Arrays.copyOf(r.data(), 65);
                                if ("new".equals(step.get("lk"))) {
                                    for (byte[] seen : lks) {
                                        assertTrue(
                                                !Arrays.equals(lk, seen),
                                                at + ": LK repeats an earlier offer");
                                    }
                                } else {
                                    assertArrayEquals(lks.get(lks.size() - 1), lk, at + ": LK");
                                }
                                lks.add(lk);
                                lastOffer = r.data();
                            }
                        }
                        case "EXPORT" -> {
                            int before = exportHeads.size();
                            doExport(code((String) step.get("code")));
                            // step sw applies to both EXPORT APDUs; doExport requires 9000
                            assertEquals(0x9000, expectedSw, at);
                            assertEquals(before + 1, exportHeads.size(), at);
                        }
                        case "IMPORT0" -> {
                            // a non-continuation IMPORT0 ends any pending import (§9.2) before
                            // arming its own on success
                            pendingExport = -1;
                            int export =
                                    step.get("export") == null
                                            ? exportHeads.size() - 1
                                            : ((Number) step.get("export")).intValue() - 1;
                            Response r = import0(export);
                            assertEquals(expectedSw, r.sw(), at);
                            if (r.sw() == 0x9000) {
                                pendingExport = export;
                            }
                        }
                        case "IMPORT1" -> {
                            assertEquals(expectedSw, import1().sw(), at);
                            pendingExport = -1; // IMPORT1 completes the pending import (§9.2)
                        }
                        default -> throw new IllegalArgumentException("unknown command " + command);
                    }
                }
                Object status = step.get("status");
                if (status != null) {
                    assertStatus((String) status);
                    // STATUS ends a pending import (§9.2) like every other command
                    pendingExport = -1;
                }
            }
        }
    }

    @Test
    void waitRuns400IterationsAndWritesNothing() throws Exception {
        setupCreate();
        assertEquals(0x9000, inner(INS_WAIT, 0, new byte[0]).sw());
        assertEquals(400, card.digests(MessageDigest.ALG_SHA_256), "WAIT's 400 doFinal calls");
        assertEquals(400 * 32, card.digestBytes(MessageDigest.ALG_SHA_256));
        assertEquals(0, card.writes(), "WAIT has no persistent write (§16.1 item 7)");
        assertEquals(0, card.commits().size());
    }
}
