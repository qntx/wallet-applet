// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.APDU;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.TransactionException;
import javacard.security.CryptoException;

/**
 * Test-only instrumentation of the memprobe build (architecture.md §10, admission item 8 of
 * protocol.md §3). The {@code memProbeCap} task patches it into a copy of the applet sources that
 * also carries the lazy-construction patch: it records {@link JCSystem#getAvailableMemory(short[],
 * short, byte)} for the three memory types at the start and end of the real {@code install}
 * (trivial on the lazy build) and of {@code lazyInit} (the deferred object graph), {@link
 * JCSystem#getMaxCommitCapacity()}, and the {@link JCSystem#getUnusedCommitCapacity()} seen by
 * every {@link #commit()} — one entry per named transaction of §4.3, read immediately before the
 * commit.
 *
 * <p>Outer command {@code 80 FE 00 00 00} returns the report:
 *
 * <pre>
 * install-start  PERSISTENT ‖ TRANSIENT_RESET ‖ TRANSIENT_DESELECT  (3 × u32)
 * install-end    PERSISTENT ‖ TRANSIENT_RESET ‖ TRANSIENT_DESELECT  (3 × u32)
 * lazyInit-start PERSISTENT ‖ TRANSIENT_RESET ‖ TRANSIENT_DESELECT  (3 × u32)
 * lazyInit-end   PERSISTENT ‖ TRANSIENT_RESET ‖ TRANSIENT_DESELECT  (3 × u32)
 * current        PERSISTENT ‖ TRANSIENT_RESET ‖ TRANSIENT_DESELECT  (3 × u32)
 * maxCommitCapacity                                               (u16)
 * last fault code of {@link #fault}                                 (u16)
 * last stage marker of {@link #stage}                               (u16)
 * count                                                         (u8, ≤ 8)
 * unusedCommitCapacity before each commit of the previous command (count × u16)
 * </pre>
 *
 * <p>The commit log lives in a transient array so it is never journaled; {@link #begin} clears it
 * for every command except the report command itself. This class exists only in the memprobe CAP;
 * {@code memProbeCap} fails the build if a release CAP references it.
 */
final class MemProbe {
    private static final byte INS_REPORT = (byte) 0xFE;
    private static final short MAX_COMMITS = 8;

    // layout in shorts (each getAvailableMemory result is a big-endian u32 in two shorts):
    // install-start triple [0..6), install-end triple [6..12), max commit [12],
    // current triple [13..19), lazyInit-start triple [19..25), lazyInit-end triple [25..31)
    private static final short[] mem = new short[31];
    private static final short OFF_END = 6;
    private static final short OFF_MAX = 12;
    private static final short OFF_CURRENT = 13;
    private static final short OFF_LAZY = 19;
    private static final short OFF_LAZY_END = 25;
    private static short[] commits;
    private static short fault;
    private static short stage;

    private MemProbe() {}

    /**
     * Records the exception {@code process()} caught in its §16.3 catch-all so the host can tell a
     * 6F00 apart from a platform fault: 01‖reason CryptoException, 02‖reason TransactionException,
     * 03‖reason SystemException, 04‖reason other CardRuntimeException, 05FF anything else. (Small
     * constants only — this JCRE has no {@code int}.)
     */
    static void fault(Exception e) {
        if (e instanceof CryptoException) {
            fault = (short) (0x0100 + ((CryptoException) e).getReason());
            return;
        }
        if (e instanceof TransactionException) {
            fault = (short) (0x0200 + ((TransactionException) e).getReason());
            return;
        }
        if (e instanceof SystemException) {
            fault = (short) (0x0300 + ((SystemException) e).getReason());
            return;
        }
        if (e instanceof CardRuntimeException) {
            fault = (short) (0x0400 + ((CardRuntimeException) e).getReason());
            return;
        }
        fault = (short) 0x05FF;
    }

    /** Last stage marker passed — localizes the call a fault came from (bisect only). */
    static void stage(short s) {
        stage = s;
    }

    private static void triple(short off) {
        JCSystem.getAvailableMemory(mem, off, JCSystem.MEMORY_TYPE_PERSISTENT);
        JCSystem.getAvailableMemory(mem, (short) (off + 2), JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        JCSystem.getAvailableMemory(
                mem, (short) (off + 4), JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
    }

    /** First statement of {@code install}: baselines before the applet allocates. */
    static void installStart() {
        triple((short) 0);
        commits =
                JCSystem.makeTransientShortArray(
                        (short) (1 + MAX_COMMITS), JCSystem.CLEAR_ON_DESELECT);
        commits[0] = 0;
    }

    /** After {@code register}: the end of the install window (trivial on the lazy build). */
    static void installEnd() {
        triple(OFF_END);
        mem[OFF_MAX] = JCSystem.getMaxCommitCapacity();
    }

    /** First statement of {@code lazyInit} past the guard: the object graph starts here. */
    static void lazyStart() {
        triple(OFF_LAZY);
    }

    /** Last statement of {@code lazyInit}: the deferred graph is fully allocated. */
    static void lazyEnd() {
        triple(OFF_LAZY_END);
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
        triple(OFF_CURRENT);
        byte[] out = apdu.getBuffer();
        short off = 0;
        // install-start, install-end, lazyInit-start, lazyInit-end, current triples
        for (short i = 0; i < OFF_MAX; i++) {
            out[off++] = (byte) (mem[i] >> 8);
            out[off++] = (byte) mem[i];
        }
        for (short i = OFF_LAZY; i < (short) mem.length; i++) {
            out[off++] = (byte) (mem[i] >> 8);
            out[off++] = (byte) mem[i];
        }
        for (short i = OFF_CURRENT; i < OFF_LAZY; i++) {
            out[off++] = (byte) (mem[i] >> 8);
            out[off++] = (byte) mem[i];
        }
        out[off++] = (byte) (mem[OFF_MAX] >> 8);
        out[off++] = (byte) mem[OFF_MAX];
        out[off++] = (byte) (fault >> 8);
        out[off++] = (byte) fault;
        out[off++] = (byte) (stage >> 8);
        out[off++] = (byte) stage;
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
