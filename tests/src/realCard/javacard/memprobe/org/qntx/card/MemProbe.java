// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;

/**
 * Test-only instrumentation of the memprobe build (architecture.md §10, admission item 8 of
 * protocol.md §3). The {@code memProbeCap} task patches it into a copy of the applet sources: it
 * records {@link JCSystem#getAvailableMemory(short[], short, byte)} for the three memory types at
 * the start and end of {@code install}, {@link JCSystem#getMaxCommitCapacity()}, and the {@link
 * JCSystem#getUnusedCommitCapacity()} seen by every {@link #commit()} — one entry per named
 * transaction of §4.3, read immediately before the commit.
 *
 * <p>Outer command {@code 80 FE 00 00 00} returns the report:
 *
 * <pre>
 * install-start PERSISTENT ‖ TRANSIENT_RESET ‖ TRANSIENT_DESELECT   (3 × u32)
 * install-end   PERSISTENT ‖ TRANSIENT_RESET ‖ TRANSIENT_DESELECT   (3 × u32)
 * current       PERSISTENT ‖ TRANSIENT_RESET ‖ TRANSIENT_DESELECT   (3 × u32)
 * maxCommitCapacity                                               (u16)
 * count                                                         (u8, ≤ 8)
 * unusedCommitCapacity before each commit of the previous command (count × u16)
 * </pre>
 *
 * <p>The commit log lives in a transient array so it is never journaled; {@link #begin} clears it
 * for every command except the report command itself. This class exists only in the memprobe CAP;
 * {@code memProbeCap} fails the build if {@code qntx-card.cap} references it.
 */
final class MemProbe {
    private static final byte INS_REPORT = (byte) 0xFE;
    private static final short MAX_COMMITS = 8;

    // layout: install-start triple [0..6), install-end triple [6..12), max commit [12],
    // current triple [13..19); each getAvailableMemory result is a big-endian u32 in two shorts
    private static final short[] mem = new short[19];
    private static final short OFF_END = 6;
    private static final short OFF_MAX = 12;
    private static final short OFF_CURRENT = 13;
    private static short[] commits;

    private MemProbe() {}

    /** First statement of {@code install}: baselines before the applet allocates. */
    static void installStart() {
        JCSystem.getAvailableMemory(mem, (short) 0, JCSystem.MEMORY_TYPE_PERSISTENT);
        JCSystem.getAvailableMemory(mem, (short) 2, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        JCSystem.getAvailableMemory(mem, (short) 4, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        commits =
                JCSystem.makeTransientShortArray(
                        (short) (1 + MAX_COMMITS), JCSystem.CLEAR_ON_DESELECT);
        commits[0] = 0;
    }

    /** After {@code register}: the end of the install window. */
    static void installEnd() {
        JCSystem.getAvailableMemory(mem, OFF_END, JCSystem.MEMORY_TYPE_PERSISTENT);
        JCSystem.getAvailableMemory(
                mem, (short) (OFF_END + 2), JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        JCSystem.getAvailableMemory(
                mem, (short) (OFF_END + 4), JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        mem[OFF_MAX] = JCSystem.getMaxCommitCapacity();
    }

    /**
     * Replaces {@code JCSystem.commitTransaction()} verbatim at the seven §4.3 sites: the unused
     * commit capacity is logged first, so each entry is what the transaction consumed against the
     * previous read (page-granular, §3 item 8).
     */
    static void commit() {
        short c = commits[0];
        if (c < MAX_COMMITS) {
            commits[(short) (c + 1)] = JCSystem.getUnusedCommitCapacity();
        }
        commits[0] = (short) (c + 1);
        JCSystem.commitTransaction();
    }

    /** Runs before {@code receiveAll}: a new command clears the log unless it is the report. */
    static void begin(byte[] buf) {
        if (buf[ISO7816.OFFSET_INS] != INS_REPORT) {
            commits[0] = 0;
        }
    }

    /** The report APDU body described in the class javadoc; returns the response length. */
    static short report(APDU apdu) {
        JCSystem.getAvailableMemory(mem, OFF_CURRENT, JCSystem.MEMORY_TYPE_PERSISTENT);
        JCSystem.getAvailableMemory(
                mem, (short) (OFF_CURRENT + 2), JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        JCSystem.getAvailableMemory(
                mem, (short) (OFF_CURRENT + 4), JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        byte[] out = apdu.getBuffer();
        short off = 0;
        // install-start triple, install-end triple, current triple, max capacity
        for (short i = 0; i < OFF_MAX; i++) {
            out[off++] = (byte) (mem[i] >> 8);
            out[off++] = (byte) mem[i];
        }
        for (short i = OFF_CURRENT; i < (short) mem.length; i++) {
            out[off++] = (byte) (mem[i] >> 8);
            out[off++] = (byte) mem[i];
        }
        out[off++] = (byte) (mem[OFF_MAX] >> 8);
        out[off++] = (byte) mem[OFF_MAX];
        short c = commits[0];
        if (c > MAX_COMMITS) {
            c = MAX_COMMITS;
        }
        out[off++] = (byte) commits[0];
        for (short i = 0; i < c; i++) {
            out[off++] = (byte) (commits[(short) (i + 1)] >> 8);
            out[off++] = (byte) commits[(short) (i + 1)];
        }
        return off;
    }
}
