// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.tests.Vecs;

/**
 * Admission item 8 and the install-time memory accounting (protocol.md §3, §16.6, architecture.md
 * §10) against the memprobe build: available memory of the three types at install start/end and at
 * every §4.3 initialisation step, {@code getMaxCommitCapacity()}, the {@code
 * getUnusedCommitCapacity()} at the end of the install transaction (the install journal charge) and
 * before each commit of the named §4.3 transactions. Consumption is page-granular: {@code used =
 * maxCommit − min(unused)}.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
final class MemoryRealCardTest {
    /** The parsed {@code 80 FE 00 00 00} report of the memprobe build. */
    record Report(
            long[] installStart,
            long[] installEnd,
            long[][] initSteps,
            long[] initEnd,
            long[] current,
            int maxCommit,
            int ctorUnused,
            int fault,
            int stage,
            int[] unused) {
        // wire layout (see MemProbe javadoc): install-start/end triples, seven init-step
        // triples, init-end triple, current triple, then u16 max, u16 ctor-unused, u16 fault,
        // u16 stage, u8 count, count × u16 unused; triple order [0] persistent, [1] reset,
        // [2] deselect
        static Report parse(byte[] r) {
            long[] s = triple(r, 0);
            long[] e = triple(r, 12);
            long[][] steps = new long[7][];
            for (int i = 0; i < 7; i++) {
                steps[i] = triple(r, 24 + 12 * i);
            }
            long[] ie = triple(r, 108);
            long[] c = triple(r, 120);
            int max = u16(r, 132);
            int ctor = u16(r, 134);
            int fault = u16(r, 136);
            int stage = u16(r, 138);
            int count = r[140] & 0xFF;
            int[] unused = new int[count];
            for (int i = 0; i < count; i++) {
                unused[i] = u16(r, 141 + 2 * i);
            }
            return new Report(s, e, steps, ie, c, max, ctor, fault, stage, unused);
        }

        private static long[] triple(byte[] r, int off) {
            return new long[] {u32(r, off), u32(r, off + 4), u32(r, off + 8)};
        }

        /** Consumption attributed to the reported command: max − min(unused). */
        int used() {
            int min = maxCommit;
            for (int u : unused) {
                min = Math.min(min, u);
            }
            return unused.length == 0 ? 0 : maxCommit - min;
        }
    }

    private static int u16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    private static long u32(byte[] b, int off) {
        return ((long) u16(b, off) << 16) | u16(b, off + 2);
    }

    static Report probe() {
        byte[] r = Fixture.card().ok(new byte[] {(byte) 0x80, (byte) 0xFE, 0, 0, 0});
        return Report.parse(r);
    }

    private static final Map<String, Map<String, Object>> rows = new LinkedHashMap<>();

    private Session session;

    private void record(String tx, Report r) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("commits", r.unused().length);
        row.put("unusedBeforeCommits", r.unused());
        row.put("maxCommit", r.maxCommit());
        row.put("usedEstimate", r.used());
        rows.put(tx, row);
    }

    private Response inner(int ins, int p1, byte[] data) throws Exception {
        return Fixture.cmd(session, ins, p1, 0, data);
    }

    @Test
    @Order(1)
    void memProbeInstallInitAndPersonalise() throws Exception {
        Fixture.require();
        Fixture.ensureInstalled(Fixture.CapKind.MEM);
        // drive §4.3 initialisation so the per-step triples are all recorded, then read
        Fixture.select();
        Fixture.driveInit();
        Report base = probe();
        String[] names = {"persistent", "transientReset", "transientDeselect"};
        Map<String, Object> install = new LinkedHashMap<>();
        for (int i = 0; i < 3; i++) {
            install.put(names[i] + "Start", base.installStart()[i]);
            install.put(names[i] + "End", base.installEnd()[i]);
            install.put(names[i] + "Delta", base.installStart()[i] - base.installEnd()[i]);
        }
        install.put("maxCommitCapacity", base.maxCommit());
        install.put("unusedCommitAtInstallEnd", base.ctorUnused());
        long journalCharge = base.maxCommit() - base.ctorUnused();
        install.put("journalCharge", journalCharge);
        rows.put("T-INSTALL", install);
        // §3 item 8 + the F1 bound: the constructor's object graph must fit the install
        // journal with headroom — at most 60 % of the commit capacity
        assertTrue(
                journalCharge <= base.maxCommit() * 6 / 10,
                "install journal charge " + journalCharge + " > 60% of " + base.maxCommit());
        // per §4.3 step memory deltas: each step's reads were taken before it ran, so
        // step i consumed steps[i] − steps[i + 1] (steps[6] − initEnd for the last)
        for (int i = 0; i < base.initSteps().length; i++) {
            long[] next =
                    i + 1 < base.initSteps().length ? base.initSteps()[i + 1] : base.initEnd();
            Map<String, Object> step = new LinkedHashMap<>();
            for (int t = 0; t < 3; t++) {
                step.put(names[t] + "Delta", base.initSteps()[i][t] - next[t]);
            }
            rows.put("T-INIT-" + i, step);
        }
        Map<String, Object> init = new LinkedHashMap<>();
        for (int i = 0; i < 3; i++) {
            init.put(names[i] + "Start", base.initSteps()[0][i]);
            init.put(names[i] + "End", base.initEnd()[i]);
            init.put(names[i] + "Delta", base.initSteps()[0][i] - base.initEnd()[i]);
        }
        rows.put("T-INIT", init);
        // §3 item 8 + §16.6: once the object graph is fully built at least 15 % of the
        // DESELECT pool is free; the pool is the DESELECT memory available at install start
        long pool = base.installStart()[2];
        assertTrue(
                base.initEnd()[2] >= 0.15 * pool,
                "CLEAR_ON_DESELECT after init " + base.initEnd()[2] + " < 15% of pool " + pool);
        // T-PERSO
        Fixture.card().ok(Fixture.personalizeApdu());
        Fixture.ensureFactoryField(Fixture.Life.BLANK);
        record("T-PERSO", probe());
        session = Fixture.open();
    }

    @Test
    @Order(2)
    void createGenerateThenErase() throws Exception {
        Fixture.require();
        session = Fixture.open();
        // T-CREATE P1 = 0, m = 0: accessHash ‖ hostEntropy
        byte[] data = new byte[64];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.entropy(), 0, data, 32, 32);
        assertEquals(0x9000, inner(0x21, 0, data).sw(), "CREATE P1=0 m=0");
        Fixture.ensureFactoryField(Fixture.Life.LOADED);
        record("T-CREATE-P0-m0", probe());
        // T-ERASE under the CREATE-verified session; the populated linkKey slot makes this
        // the link-key-overwrite charge of §4.2
        assertEquals(0x9000, inner(0x24, 0, new byte[0]).sw(), "ERASE");
        Fixture.ensureFactoryField(Fixture.Life.BLANK);
        record("T-ERASE", probe());
    }

    @Test
    @Order(3)
    void createImportWithTwoMembers() throws Exception {
        Fixture.require();
        session = Fixture.open();
        // T-CREATE P1 = 1, m = 2: accessHash ‖ seed ‖ two member IDs (§9.4)
        byte[] data = new byte[96 + 32];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        byte[] own = org.qntx.card.host.Ids.cardId(Fixture.cardA());
        byte[] m1 = own.clone();
        byte[] m2 = own.clone();
        m1[0] ^= (byte) 0xA5;
        m2[0] ^= (byte) 0x5A;
        System.arraycopy(m1, 0, data, 96, 16);
        System.arraycopy(m2, 0, data, 112, 16);
        assertEquals(0x9000, inner(0x21, 1, data).sw(), "CREATE P1=1 m=2");
        Fixture.ensureFactoryField(Fixture.Life.LOADED);
        record("T-CREATE-P1-m2", probe());
    }

    @Test
    @Order(4)
    void failOkAndChangeTransactions() throws Exception {
        Fixture.require();
        session = Fixture.open();
        // T-FAIL: a wrong VERIFY commits the counted failure
        assertEquals(0x63C9, inner(0x22, 0, Vecs.accessHashWrong()).sw(), "T-FAIL VERIFY");
        record("T-FAIL", probe());
        // T-OK: a right VERIFY commits the reset
        assertEquals(0x9000, inner(0x22, 0, Vecs.accessHash()).sw(), "T-OK VERIFY");
        record("T-OK", probe());
        // T-CHANGE: rewrap under the verified session
        assertEquals(0x9000, inner(0x23, 0, Vecs.accessHashNew()).sw(), "CHANGE");
        record("T-CHANGE", probe());
        session = Fixture.open();
        assertEquals(0x9000, inner(0x22, 0, Vecs.accessHashNew()).sw());
        assertEquals(0x9000, inner(0x23, 0, Vecs.accessHash()).sw(), "CHANGE back");
    }

    @Test
    @Order(5)
    void offerCommitsTheLinkKeyPair() throws Exception {
        Fixture.require();
        session = Fixture.open();
        Fixture.verify(session);
        // T-OFFER: offer = NONE → a new linkKey pair commits before LK is output (§9.12)
        Response lk = inner(0x40, 0, new byte[0]);
        assertEquals(0x9000, lk.sw(), "OFFER");
        assertEquals(129, lk.data().length, "OFFER returns LK(65) ‖ sig(64)");
        record("T-OFFER", probe());
        // offer = VALID: the stored LK answers again without a commit
        Response again = inner(0x40, 0, new byte[0]);
        assertEquals(0x9000, again.sw(), "OFFER with offer = VALID");
        // the signature is fresh each time; the stored LK is what must be equal (§9.12)
        assertArrayEquals(
                Arrays.copyOf(lk.data(), 65),
                Arrays.copyOf(again.data(), 65),
                "stored LK is returned again");
        assertEquals(0, probe().unused().length, "OFFER with offer = VALID commits nothing");
    }

    @Test
    @Order(6)
    void edCounterTransaction() throws Exception {
        Fixture.require();
        session = Fixture.open();
        Fixture.verify(session);
        // T-EDCTR: the Ed25519 begin commits edCounter before r is computed (§12.3)
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw(), "ed begin");
        record("T-EDCTR", probe());
        assertEquals(0x9000, inner(0x33, 2, new byte[0]).sw(), "ed finish closes the stream");
    }

    @Test
    @Order(6)
    void writeReportAndAssertBudgets() throws Exception {
        Fixture.require();
        Report end = probe();
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("transactions", rows);
        Map<String, Object> after = new LinkedHashMap<>();
        String[] names = {"persistent", "transientReset", "transientDeselect"};
        for (int i = 0; i < 3; i++) {
            after.put(names[i], end.current()[i]);
        }
        doc.put("availableNow", after);
        // no allocation after the object graph: pools available now are ≥ the init-end
        // values (init end is the point the graph finished building)
        for (int i = 0; i < 3; i++) {
            assertTrue(
                    end.current()[i] >= end.initEnd()[i],
                    names[i]
                            + " pool shrank after init: "
                            + end.current()[i]
                            + " < "
                            + end.initEnd()[i]);
        }
        // §3 item 8: every named transaction consumed at most half the commit capacity
        for (Map.Entry<String, Map<String, Object>> e : rows.entrySet()) {
            Object used = e.getValue().get("usedEstimate");
            if (used != null) {
                assertTrue(
                        (Integer) used <= end.maxCommit() / 2,
                        e.getKey() + " used " + used + " > 50% of " + end.maxCommit());
            }
        }
        Files.writeString(
                Fixture.out().resolve("memory.json"),
                com.fasterxml.jackson.jr.ob.JSON.std.asString(doc));
    }

    @AfterAll
    static void cleanUpCard() throws Exception {
        if (Fixture.available()) {
            Fixture.cleanupCard();
        }
    }
}
