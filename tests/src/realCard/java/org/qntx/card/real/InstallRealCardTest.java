// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.qntx.card.host.Open;
import org.qntx.card.host.Session;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The real-card gate of the §4.3 bounded initialisation and the §8.5 selection-epoch reload
 * (architecture.md §10, §12): the production CAP must install on card A (its install-journal charge
 * is bounded by the memprobe twin of the same sources), GET_IDENTITY drives the initialisation
 * steps with every other command gated by {@code 6283}, and OPEN must work across repeated select
 * epochs and a power cycle. The init journal lands in {@code <out>/init.json}.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
final class InstallRealCardTest {
    /** §16.6: each §4.3 step MUST complete within 500 ms. */
    private static final long STEP_LIMIT_NS = 500_000_000L;

    /**
     * The production CAP must never carry the memprobe instrumentation — it is built from the
     * untouched applet sources and the memprobe lives only in the patched copy. Runs without a
     * reader: the assertion is on the artifact, not the card.
     */
    @Test
    @Order(0)
    void productionCapContainsNoMemProbe() throws Exception {
        byte[] cap = Files.readAllBytes(Fixture.productionCap());
        byte[] needle = "MemProbe".getBytes();
        outer:
        for (int i = 0; i + needle.length <= cap.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (cap[i + j] != needle[j]) {
                    continue outer;
                }
            }
            throw new AssertionError("qntx-card.cap contains the MemProbe instrumentation");
        }
    }

    @Test
    @Order(1)
    void productionCapInstallsAndInitialises() throws Exception {
        Fixture.require();
        Fixture.connect();
        Fixture.card()
                .reinstall(
                        Fixture.productionCap(),
                        RealCard.PACKAGE_AID,
                        RealCard.PACKAGE_AID,
                        RealCard.APPLET_AID,
                        RealCard.NDEF_INSTANCE_AID);
        Fixture.markInstalled(Fixture.CapKind.PROD);
        Fixture.select();
        RealCard card = Fixture.card();
        // §4.3: while uninitialised every outer command other than GET_IDENTITY answers 6283
        for (int ins : new int[] {0x10, 0x12, (byte) 0xE2 & 0xFF}) {
            assertEquals(
                    0x6283,
                    RealCard.sw(card.transmit(new byte[] {(byte) 0x80, (byte) ins, 0, 0, 0})),
                    String.format("init gate on outer INS %02X", ins));
        }
        // GET_IDENTITY drives one step per call, each within the §16.6 bound; the last
        // step's call completes initialisation and returns A in the same response
        List<Long> steps = new ArrayList<>();
        byte[] a = null;
        for (int i = 0; i < 16 && a == null; i++) {
            RealCard.Timed t = card.timed(Fixture.GET_IDENTITY);
            int sw = RealCard.sw(t.rapdu());
            if (sw == 0x6283) {
                steps.add(t.nanos());
                continue;
            }
            assertEquals(0x9000, sw, "final GET_IDENTITY");
            a = java.util.Arrays.copyOf(t.rapdu(), t.rapdu().length - 2);
            steps.add(t.nanos());
        }
        assertTrue(a != null && a.length == 33, "initialisation did not finish within 16 steps");
        for (int i = 0; i < steps.size(); i++) {
            long ms = steps.get(i) / 1_000_000;
            assertTrue(steps.get(i) <= STEP_LIMIT_NS, "init step " + i + " took " + ms + " ms");
        }
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("initStepsMs", steps.stream().map(n -> n / 1e6).toList());
        doc.put("initStepCount", steps.size());
        doc.put("capSha256", sha256(Fixture.productionCap()));
        Files.writeString(
                Fixture.out().resolve("init.json"),
                com.fasterxml.jackson.jr.ob.JSON.std.asString(doc));
    }

    @Test
    @Order(2)
    void installJournalChargeFitsCardA() throws Exception {
        Fixture.require();
        Fixture.connect();
        // the memprobe build is the production sources plus the report hooks: the journal
        // charge it measures is the production charge (the hooks write only transient state)
        Fixture.card()
                .reinstall(
                        Fixture.capPath(Fixture.CapKind.MEM),
                        RealCard.PACKAGE_AID,
                        RealCard.PACKAGE_AID,
                        RealCard.APPLET_AID,
                        RealCard.NDEF_INSTANCE_AID);
        Fixture.markInstalled(Fixture.CapKind.MEM);
        Fixture.select();
        MemoryRealCardTest.Report rep = MemoryRealCardTest.probe();
        int charge = rep.maxCommit() - rep.ctorUnused();
        Map<String, Object> journal = new LinkedHashMap<>();
        journal.put("maxCommitCapacity", rep.maxCommit());
        journal.put("unusedCommitAtInstallEnd", rep.ctorUnused());
        journal.put("installJournalCharge", charge);
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("journal", journal);
        Files.writeString(
                Fixture.out().resolve("install-journal.json"),
                com.fasterxml.jackson.jr.ob.JSON.std.asString(doc));
        // §3 item 8 + the F1 bound: ≤ 60 % of the commit capacity, ≥ 40 % headroom
        assertTrue(
                charge <= rep.maxCommit() * 6 / 10,
                "install journal charge " + charge + " > 60% of " + rep.maxCommit());
        // leave the production CAP installed for the epoch checks and the suites that follow
        Fixture.ensureInstalled(Fixture.CapKind.PROD);
    }

    @Test
    @Order(3)
    void personaliseAndOpenAcrossEpochs() throws Exception {
        Fixture.require();
        Fixture.ensureStrictFactory();
        Fixture.card().ok(Fixture.personalizeApdu());
        Fixture.ensureFactoryField(Fixture.Life.BLANK);
        RealCard card = Fixture.card();
        // OPEN in the first selection epoch, then again across three re-SELECTs — the F2
        // reload of the transient EC domains must keep every epoch usable (§8.5)
        assertOpen();
        for (int i = 0; i < 3; i++) {
            assertEquals(0x9000, RealCard.sw(card.transmit(Spec.SELECT)), "re-SELECT " + i);
            assertOpen();
        }
        // and once more across a field power cycle
        card.reset();
        Fixture.select();
        assertOpen();
        Session s = Fixture.open();
        // VERIFY is a LOADED-state command (§9.5); on a BLANK card a STATUS proves the epoch
        assertEquals(0x9000, Fixture.cmd(s, 0x20, 0, 0, new byte[0]).sw(), "STATUS in BLANK");
        s.close();
    }

    private static String sha256(java.nio.file.Path path) throws Exception {
        byte[] digest =
                java.security.MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path));
        StringBuilder h = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            h.append(String.format("%02x", b));
        }
        return h.toString();
    }

    private static void assertOpen() throws Exception {
        assertEquals(
                0x9000,
                RealCard.sw(Fixture.card().transmit(Open.request(Vecs.RND).apdu())),
                "OPEN in the current selection epoch");
    }

    @AfterAll
    static void cleanUpCard() throws Exception {
        if (Fixture.available()) {
            Fixture.cleanupCard();
        }
    }
}
