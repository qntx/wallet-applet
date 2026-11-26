// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javacard.security.CryptoException;

/**
 * Fault injection over the agent's woven call sites (architecture spec section 9): every call made
 * by instrumented code to an instrumented method returning {@code short} is routed through {@link
 * #ret}, so a test can arm the n-th call of a method to return a chosen value or to throw. This is
 * the hand-written-fault infrastructure the §16.2 item 4 double checks are tested against.
 *
 * <p>Method keys are {@code "SimpleClass.method"} — e.g. {@code "State.life"}, {@code
 * "Bytes.equal"}, {@code "Identity.verify"} — regardless of the caller. Counting runs only while a
 * fault is armed so the unwoven fast path is a single flag check.
 *
 * <p>Void methods are covered by {@link #armSkip} over the agent's woven guard: the n-th call is
 * skipped entirely. {@link #armStore} faults the value a persistent {@code Util.setShort} writes.
 *
 * <p>When the agent runs with the {@code sites} argument, every conditional branch and every invoke
 * instruction of an instrumented method is guarded by {@link #site}: {@link #armSite} picks the
 * n-th execution of one site ({@code 0} for every execution) and a mode — {@link #SITE_SKIP} or
 * {@link #SITE_INVERT} for branches, {@link #SITE_SKIP} for invokes. {@link #armVerifyTrue} forces
 * the n-th {@code verify}/{@code verifyPreComputedHash} of a wrapped ECDSA engine to return {@code
 * true} regardless of the signature.
 */
public final class Fault {

    private static final class Slot {
        int calls;
        final Set<Integer> nth = new HashSet<>();
        short value;
        boolean throwing;
        boolean skipping;
    }

    /** {@link #armSite} mode: skip the instruction — branch operands or invoke arguments popped. */
    public static final int SITE_SKIP = 1;

    /** {@link #armSite} mode: run the negated branch to the same target (branches only). */
    public static final int SITE_INVERT = 2;

    /** {@link #armSite} mode of a branch site: take the branch regardless of the condition. */
    public static final int SITE_TAKE = 3;

    /** {@link #armSite} mode of a branch site: fall through regardless of the condition. */
    public static final int SITE_FALL = 4;

    /** {@link #armSite} mode of an invoke site: pop the arguments and push the armed value. */
    public static final int SITE_FORCED = 5;

    /** {@link #armSite} mode of a data site: the loaded value is replaced by 0. */
    public static final int SITE_ZERO = 6;

    /** {@link #armSite} mode of a data site: the loaded value is replaced by -1. */
    public static final int SITE_ONES = 7;

    /** {@link #armSite} mode of a data site: the loaded value is XORed with 1. */
    public static final int SITE_FLIP = 8;

    /** The {@link #calls} key the ECDSA verify wrapper counts under. */
    public static final String ECDSA_VERIFY = "ECDSA.verify";

    /**
     * The watchdog's dedicated error: thrown when the armed hit budget is exceeded so the sweep
     * records the attempt as a hang instead of a verdict.
     */
    public static final class Hang extends Error {
        public Hang() {
            super("fault watchdog: site-hit budget exceeded");
        }
    }

    private static final class SiteSlot {
        int seen;
        final int nth;
        final int mode;
        final short value;

        SiteSlot(int nth, int mode, short value) {
            this.nth = nth;
            this.mode = mode;
            this.value = value;
        }
    }

    private static final Map<String, Slot> armed = new HashMap<>();
    private static final Map<String, Integer> counts = new HashMap<>();
    private static final Map<String, SiteSlot> armedSites = new HashMap<>();
    private static final Map<String, Integer> sites = new HashMap<>();
    private static volatile boolean active;
    private static int storeArmed;
    private static int storeSeen;
    private static short storeValue;
    private static int ecdsaFlipArmed;
    private static int ecdsaCalls;
    private static int verifyTrueArmed;
    private static int verifyTrueSeen;
    private static long hitBudget;
    private static long hits;

    private Fault() {}

    /**
     * Makes the {@code nth} call (1-based, counted since arming or the last {@link #reset}) of
     * {@code method} return {@code value} instead of its real result. Repeated calls accumulate
     * positions, so several evaluations of one method can be forced in a single command.
     */
    public static void arm(String method, int nth, short value) {
        Slot s = armed.computeIfAbsent(method, k -> new Slot());
        s.calls = 0;
        s.nth.add(nth);
        s.value = value;
        s.throwing = false;
        s.skipping = false;
        active = true;
    }

    /**
     * Makes the {@code nth} call of {@code method} throw {@link CryptoException} ({@code
     * ILLEGAL_VALUE}) instead of returning.
     */
    public static void armThrow(String method, int nth) {
        Slot s = armed.computeIfAbsent(method, k -> new Slot());
        s.calls = 0;
        s.nth.add(nth);
        s.throwing = true;
        s.skipping = false;
        active = true;
    }

    /**
     * Makes the {@code nth} call (counted since arming) of the <em>void</em> method {@code method}
     * return without running its body — the agent's woven guard pops the arguments and continues.
     * {@code JCSystem.beginTransaction}/{@code commitTransaction}/{@code abortTransaction} are also
     * woven, so a skipped commit leaves the transaction open.
     */
    public static void armSkip(String method, int nth) {
        Slot s = armed.computeIfAbsent(method, k -> new Slot());
        s.calls = 0;
        s.nth.add(nth);
        s.throwing = false;
        s.skipping = true;
        active = true;
    }

    /**
     * Makes the {@code nth} persistent {@code Util.setShort} (counted since arming; only writes to
     * applet persistent arrays count) store {@code value} instead of its argument.
     */
    public static void armStore(int nth, short value) {
        storeArmed = nth;
        storeSeen = 0;
        storeValue = value;
        active = true;
    }

    /**
     * Makes the {@code nth} {@code sign}/{@code signPreComputedHash} call — counted since arming
     * across every {@code ALG_ECDSA_SHA_256} engine instrumented code holds — write a corrupted
     * signature: the last byte of the DER output ({@code s}'s trailing byte) XOR {@code 0x01},
     * which the applet's self-verify before output must reject (spec/protocol.md §9.9). The {@link
     * Memory#signature} delegate wraps every ECDSA engine unconditionally, so arming acts on
     * engines created at install (e.g. the shared engine OPEN already used); while nothing is armed
     * it is a pure pass-through. {@link #reset} disarms.
     */
    public static void armEcdsaFlip(int nth) {
        ecdsaFlipArmed = nth;
        ecdsaCalls = 0;
        active = true;
    }

    /**
     * Arms the n-th execution (counted since arming) of instruction site {@code key} — {@code
     * "Class.method#b<k>"} or {@code "Class.method#i<k>"} — with {@code mode} ({@link #SITE_SKIP}
     * or, for branches, {@link #SITE_INVERT}); {@code nth = 0} faults every execution, a persistent
     * mutant. Only works when the agent runs with the {@code sites} argument.
     */
    public static void armSite(String key, int nth, int mode) {
        armedSites.put(key, new SiteSlot(nth, mode, (short) 0));
        active = true;
    }

    /**
     * Like {@link #armSite} but carries the value the site pushes: the {@link #SITE_FORCED} mode of
     * an invoke site pops the arguments and returns {@code value} instead of calling the method.
     */
    public static void armSite(String key, int nth, int mode, short value) {
        armedSites.put(key, new SiteSlot(nth, mode, value));
        active = true;
    }

    /**
     * The per-attempt watchdog (architecture §6): {@code hits} site and call hits after arming
     * throw {@link Hang}, which the sweep records as a hang. {@code budget = 0} disarms.
     */
    public static void watchdog(long budget) {
        hitBudget = budget;
        hits = 0;
    }

    private static void hit() {
        if (hitBudget != 0 && ++hits > hitBudget) {
            throw new Hang();
        }
    }

    /**
     * Makes the {@code nth} {@code verify}/{@code verifyPreComputedHash} call — counted since
     * arming across every wrapped {@code ALG_ECDSA_SHA_256} engine — return {@code true} regardless
     * of the signature: a data fault on the verification result. {@code nth = 0} faults every call.
     */
    public static void armVerifyTrue(int nth) {
        verifyTrueArmed = nth == 0 ? -1 : nth;
        verifyTrueSeen = 0;
        active = true;
    }

    /**
     * Turns call counting on ({@link #calls}) without arming a fault; {@link #reset} turns it off.
     */
    public static void countCalls() {
        armed.clear();
        counts.clear();
        sites.clear();
        active = true;
    }

    /** Calls of {@code method} since {@link #reset}; counting is on only while a fault is armed. */
    public static int calls(String method) {
        return counts.getOrDefault(method, 0);
    }

    /** Every woven-call count since {@link #reset} (the map {@link #calls} reads). */
    public static Map<String, Integer> callCounts() {
        return Collections.unmodifiableMap(counts);
    }

    /** Executions of every instruction site since {@link #reset} (agent argument {@code sites}). */
    public static Map<String, Integer> siteCounts() {
        return Collections.unmodifiableMap(sites);
    }

    /** Disarms every method and site and clears the call and site counters. */
    public static void reset() {
        armed.clear();
        counts.clear();
        armedSites.clear();
        sites.clear();
        active = false;
        storeArmed = 0;
        ecdsaFlipArmed = 0;
        verifyTrueArmed = 0;
        verifyTrueSeen = 0;
        hitBudget = 0;
        hits = 0;
    }

    /**
     * The {@link FlippingSignature} hook: {@code true} when this {@code sign}/{@code
     * signPreComputedHash} call is the armed {@code nth} one since {@link #armEcdsaFlip}; {@code
     * false} fast when nothing is armed.
     */
    static boolean ecdsaFlip() {
        if (ecdsaFlipArmed == 0) {
            return false;
        }
        return ++ecdsaCalls == ecdsaFlipArmed;
    }

    /**
     * The woven guard of void calls: {@code true} means skip the call. Counts on the same counters
     * as {@link #ret}, returns {@code false} fast when nothing is armed.
     */
    public static boolean skip(String method) {
        if (!active) {
            return false;
        }
        hit();
        counts.merge(method, 1, Integer::sum);
        Slot s = armed.get(method);
        return s != null && s.skipping && s.nth.contains(++s.calls);
    }

    /**
     * Called by {@link Nvm#setShort} before a persistent store: returns the argument, or the armed
     * fault value on the n-th persistent store since arming.
     */
    public static short storeValue(short value) {
        if (storeArmed != 0 && ++storeSeen == storeArmed) {
            return storeValue;
        }
        return value;
    }

    /**
     * The woven guard of an instruction site: {@code 0} normal, {@link #SITE_SKIP} or {@link
     * #SITE_INVERT} on the armed occurrence. Counts the execution whenever Fault is active; the
     * unwoven fast path is one volatile read.
     */
    public static int site(String key) {
        if (!active) {
            return 0;
        }
        hit();
        sites.merge(key, 1, Integer::sum);
        SiteSlot s = armedSites.get(key);
        if (s == null) {
            return 0;
        }
        if (s.nth == 0) {
            return s.mode;
        }
        return ++s.seen == s.nth ? s.mode : 0;
    }

    /**
     * The armed value of a {@link #SITE_FORCED} invoke site; only called on the forced path, after
     * {@link #site} already returned the mode for {@code key}.
     */
    public static short forced(String key) {
        SiteSlot s = armedSites.get(key);
        return s != null ? s.value : 0;
    }

    /**
     * The woven guard of a data site (a primitive load): the loaded {@code value}, or the armed
     * fault — {@link #SITE_ZERO}, {@link #SITE_ONES} or {@link #SITE_FLIP} — on the armed
     * occurrence. Counts the site while active; the fast path is one volatile read.
     */
    public static int data(int value, String key) {
        if (!active) {
            return value;
        }
        hit();
        sites.merge(key, 1, Integer::sum);
        SiteSlot s = armedSites.get(key);
        if (s == null || (s.nth != 0 && ++s.seen != s.nth)) {
            return value;
        }
        return switch (s.mode) {
            case SITE_ZERO -> 0;
            case SITE_ONES -> -1;
            case SITE_FLIP -> value ^ 1;
            default -> value;
        };
    }

    /**
     * The {@link FlippingSignature} verify hook: {@code true} when this {@code verify}/{@code
     * verifyPreComputedHash} call is armed to succeed regardless — counted under {@link
     * #ECDSA_VERIFY} so a counting run enumerates the verify occurrences.
     */
    static boolean verifyTrue() {
        if (!active) {
            return false;
        }
        counts.merge(ECDSA_VERIFY, 1, Integer::sum);
        if (verifyTrueArmed == -1) {
            return true;
        }
        return verifyTrueArmed > 0 && ++verifyTrueSeen == verifyTrueArmed;
    }

    /** The woven entry point: the untouched result normally, the armed fault on the n-th call. */
    public static short ret(short value, String method) {
        if (!active) {
            return value;
        }
        hit();
        counts.merge(method, 1, Integer::sum);
        Slot s = armed.get(method);
        if (s == null || !s.nth.contains(++s.calls)) {
            return value;
        }
        if (s.throwing) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        return s.value;
    }
}
