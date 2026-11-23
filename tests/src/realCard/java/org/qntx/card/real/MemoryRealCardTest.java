// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
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
 * §10) against the memprobe build: available memory of the three types before and after {@code
 * install}, {@code getMaxCommitCapacity()}, and the {@code getUnusedCommitCapacity()} seen
 * immediately before each commit of the named §4.3 transactions. Consumption is page-granular:
 * {@code used = maxCommit − min(unused)}.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
final class MemoryRealCardTest {
    /** The parsed {@code 80 FE 00 00 00} report of the memprobe build. */
    record Report(
            long[] installStart,
            long[] installEnd,
            long[] lazyStart,
            long[] lazyEnd,
            long[] current,
            int maxCommit,
            int fault,
            int stage,
            int[] unused) {
        // wire layout (see MemProbe javadoc): five 3-u32 triples, then u16 max, u16 fault,
        // u16 stage, u8 count, count × u16 unused; triple order [0] persistent, [1] reset,
        // [2] deselect
        static Report parse(byte[] r) {
            long[] s = triple(r, 0);
            long[] e = triple(r, 12);
            long[] ls = triple(r, 24);
            long[] le = triple(r, 36);
            long[] c = triple(r, 48);
            int max = u16(r, 60);
            int fault = u16(r, 62);
            int stage = u16(r, 64);
            int count = r[66] & 0xFF;
            int[] unused = new int[count];
            for (int i = 0; i < count; i++) {
                unused[i] = u16(r, 67 + 2 * i);
            }
            return new Report(s, e, ls, le, c, max, fault, stage, unused);
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

    private static Report report() {
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
        Response r = Fixture.cmd(session, ins, p1, 0, data);
        return r;
    }

    @Test
    @Order(1)
    void memProbeInstallAndPersonalise() throws Exception {
        Fixture.require();
        Fixture.ensureInstalled(Fixture.CapKind.MEM);
        // the first SELECT fires the deferred construction (lazyInit) of the memprobe build
        Fixture.card().ok(RealCard.SELECT);
        Report base = report();
        String[] names = {"persistent", "transientReset", "transientDeselect"};
        Map<String, Object> install = new LinkedHashMap<>();
        for (int i = 0; i < 3; i++) {
            install.put(names[i] + "Start", base.installStart()[i]);
            install.put(names[i] + "End", base.installEnd()[i]);
            install.put(names[i] + "Delta", base.installStart()[i] - base.installEnd()[i]);
        }
        install.put("maxCommitCapacity", base.maxCommit());
        rows.put("T-INSTALL", install);
        Map<String, Object> lazy = new LinkedHashMap<>();
        for (int i = 0; i < 3; i++) {
            lazy.put(names[i] + "Start", base.lazyStart()[i]);
            lazy.put(names[i] + "End", base.lazyEnd()[i]);
            lazy.put(names[i] + "Delta", base.lazyStart()[i] - base.lazyEnd()[i]);
        }
        rows.put("T-LAZY-INIT", lazy);
        // §3 item 8 + §16.6: after the object graph is built at least 15 % of the DESELECT
        // pool is free; the pool is the DESELECT memory available at install start
        long pool = base.installStart()[2];
        assertTrue(
                base.lazyEnd()[2] >= 0.15 * pool,
                "CLEAR_ON_DESELECT after init " + base.lazyEnd()[2] + " < 15% of pool " + pool);
        // T-PERSO
        Fixture.card().ok(Fixture.personalizeApdu());
        Fixture.ensureFactoryField(Fixture.Life.BLANK);
        record("T-PERSO", report());
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
        record("T-CREATE-P0-m0", report());
        // T-ERASE under the CREATE-verified session
        assertEquals(0x9000, inner(0x24, 0, new byte[0]).sw(), "ERASE");
        Fixture.ensureFactoryField(Fixture.Life.BLANK);
        record("T-ERASE", report());
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
        record("T-CREATE-P1-m2", report());
    }

    @Test
    @Order(4)
    void failOkAndChangeTransactions() throws Exception {
        Fixture.require();
        session = Fixture.open();
        // T-FAIL: a wrong VERIFY commits the counted failure
        assertEquals(0x63C9, inner(0x22, 0, Vecs.accessHashWrong()).sw(), "T-FAIL VERIFY");
        record("T-FAIL", report());
        // T-OK: a right VERIFY commits the reset
        assertEquals(0x9000, inner(0x22, 0, Vecs.accessHash()).sw(), "T-OK VERIFY");
        record("T-OK", report());
        // T-CHANGE: rewrap under the verified session
        assertEquals(0x9000, inner(0x23, 0, Vecs.accessHashNew()).sw(), "CHANGE");
        record("T-CHANGE", report());
        session = Fixture.open();
        assertEquals(0x9000, inner(0x22, 0, Vecs.accessHashNew()).sw());
        assertEquals(0x9000, inner(0x23, 0, Vecs.accessHash()).sw(), "CHANGE back");
    }

    @Test
    @Order(5)
    void edCounterTransaction() throws Exception {
        Fixture.require();
        session = Fixture.open();
        Fixture.verify(session);
        // T-EDCTR: the Ed25519 begin commits edCounter before r is computed (§12.3)
        assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw(), "ed begin");
        record("T-EDCTR", report());
        assertEquals(0x9000, inner(0x33, 2, new byte[0]).sw(), "ed finish closes the stream");
    }

    @Test
    @Order(6)
    void writeReportAndAssertBudgets() throws Exception {
        Fixture.require();
        Report end = report();
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("transactions", rows);
        Map<String, Object> after = new LinkedHashMap<>();
        String[] names = {"persistent", "transientReset", "transientDeselect"};
        for (int i = 0; i < 3; i++) {
            after.put(names[i], end.current()[i]);
        }
        doc.put("availableNow", after);
        // no allocation after the object graph: pools available now are ≥ the lazyInit-end
        // values (on the lazy build the graph itself legitimately consumes between install and
        // first use, so the reference point is lazyInit end)
        for (int i = 0; i < 3; i++) {
            assertTrue(
                    end.current()[i] >= end.lazyEnd()[i],
                    names[i]
                            + " pool shrank after lazyInit: "
                            + end.current()[i]
                            + " < "
                            + end.lazyEnd()[i]);
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
