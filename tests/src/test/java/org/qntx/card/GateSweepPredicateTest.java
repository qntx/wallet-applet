// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Fault;
import org.qntx.card.sim.Rng;
import org.qntx.card.tests.EmuMember;
import org.qntx.card.tests.Vecs;

/**
 * Self-check of the {@link GateSweepTest} release predicates: for every scenario a known
 * multi-fault combination that defeats the gate is injected and the scenario's own {@code
 * released()} predicate must report a release. A scenario whose predicate can never fire would make
 * its whole sweep vacuous — a REFUSED outcome here is a bug in the predicate, not in the applet.
 * The faults are persistent, deliberate releases (never the single fault the sweep refuses); they
 * run only inside the {@code gateSweep} task.
 */
final class GateSweepPredicateTest {
    @AfterEach
    void disarm() {
        Fault.reset();
        Rng.reset();
    }

    /** Runs {@code f}'s attack once under {@code arm} and requires the release predicate. */
    private static void released(String name, GateSweepTest.Factory f, Runnable arm)
            throws Exception {
        GateSweepTest.Run r = f.fresh();
        arm.run();
        try {
            r.run();
        } catch (Throwable t) {
            // the sw trail of a failed release attempt still lands in the message below
        }
        Fault.reset();
        assertTrue(
                r.released(),
                name
                        + ": the release predicate did not fire under a known multi-fault (sw: "
                        + r.swSequence()
                        + ")");
    }

    /**
     * Skips the {@code caller} invokes where the unfaulted run dies — each probe round finds the
     * last executed invoke site (the refusal is thrown inside that callee), adds it to the skip set
     * and probes again until the run releases or stops dying at a {@code caller} invoke. A site
     * skip pushes a zero of the return type; for {@code memberSlot} that is slot 0, so the genuine
     * setPeer/sig_T path then runs. This releases only under the sites weave.
     */
    private static void releasedSkippingLastInvoke(
            String name, GateSweepTest.Factory f, String caller, Runnable extraArms)
            throws Exception {
        Set<String> skips = new TreeSet<>();
        GateSweepTest.Run r = null;
        for (int round = 0; round < 8; round++) {
            r = f.fresh();
            Fault.countCalls();
            for (String site : skips) {
                Fault.armSite(site, 0, Fault.SITE_SKIP);
            }
            if (extraArms != null) {
                extraArms.run();
            }
            try {
                r.run();
            } catch (Throwable ignored) {
                // the refusal is expected — it pins the next site
            }
            // this class is instrumented too: its own site() calls keep mutating the counts
            // while the map is read, so snapshot with retries until no key is added mid-copy
            Map<String, Integer> snap;
            for (; ; ) {
                try {
                    snap = new TreeMap<>(Fault.siteCounts());
                    break;
                } catch (java.util.ConcurrentModificationException ignored) {
                }
            }
            Fault.reset();
            if (r.released()) {
                break;
            }
            int max = 0;
            String last = null;
            for (String key : snap.keySet()) {
                if (key.startsWith(caller + "#i")) {
                    int index = Integer.parseInt(key.substring(caller.length() + 2));
                    if (index > max) {
                        max = index;
                        last = key;
                    }
                }
            }
            if (last == null || !skips.add(last)) {
                // died somewhere other than a caller invoke, or at an already-skipped site
                break;
            }
            r = null;
        }
        Fault.reset();
        assertNotNull(r, name + ": the probe ran out of rounds without releasing");
        assertTrue(
                r.released(),
                name + ": skipping " + skips + " did not release (sw: " + r.swSequence() + ")");
    }

    private static void verifiedWords() {
        for (int i = 1; i <= 8; i++) {
            Fault.arm("Session.verified", i, Const.VERIFIED_YES);
            Fault.arm("Session.verifiedShadow", i, Const.VERIFIED_YES);
        }
    }

    /** Skips {@code reseal} and forces the second-evaluation reads of origin, members and fp. */
    private static void loadedImportGuards() {
        Fault.armSkip("Transfer.reseal", 1);
        Fault.arm("State.origin", 1, Const.ORIGIN_IMPORTED);
        Fault.arm("State.origin", 2, Const.ORIGIN_IMPORTED);
        for (int i = 1; i <= 4; i++) {
            Fault.arm("State.equal", i, Const.CHECK_OK);
        }
    }

    @Test
    void sxPredicate() throws Exception {
        // forcing both offerSignature verifications releases the seed to the attacker
        released(
                "SX", GateSweepTest.exportToAttacker(BigInteger.ONE), () -> Fault.armVerifyTrue(0));
    }

    @Test
    void sxkPredicate() throws Exception {
        released(
                "SXk",
                GateSweepTest.exportToAttacker(GateSweepTest.KNOWN_K),
                () -> Fault.armVerifyTrue(0));
    }

    @Test
    void sxnPredicate() throws Exception {
        // a non-member: skipping the memberSlot invoke at both evaluations yields slot 0;
        // the genuine setPeer then writes the attacker key and its genuine sig_T verifies
        releasedSkippingLastInvoke(
                "SXn", GateSweepTest.exportToNonMember(new EmuMember()), "Transfer.export0", null);
    }

    @Test
    void sxcPredicate() throws Exception {
        // a forged certificate plus a non-member: both verifyCert returns forced to
        // CHECK_OK and both memberSlot invocations skipped to slot 0
        releasedSkippingLastInvoke(
                "SXc",
                GateSweepTest.exportToNonMember(new EmuMember(Vecs.ca2Private())),
                "Transfer.export0",
                () -> {
                    Fault.arm("Identity.verifyCert", 1, Const.CHECK_OK);
                    Fault.arm("Identity.verifyCert", 2, Const.CHECK_OK);
                });
    }

    @Test
    void spPredicate() throws Exception {
        // the endPending of the refused P1=01 — and of the attack's beginDispatch — is skipped
        // inside the setup hook (an earlier arm is wiped by the Card constructor's Fault.reset):
        // K_te/K_tm keep the pending-import keys the attacker's import0 derived — one of the two
        // candidates the SP predicate tries; the forced pending words then pass the gate
        released(
                "SP",
                GateSweepTest.exportNoPending(
                        () -> {
                            for (int i = 1; i <= 8; i++) {
                                Fault.armSkip("Session.endPending", i);
                            }
                        }),
                () -> {
                    Fault.arm("Session.pending", 1, Const.PENDING_EXPORT);
                    Fault.arm("Session.pending", 2, Const.PENDING_EXPORT);
                    Fault.arm("Session.pendingExportShadow", 1, Const.PENDING_EXPORT);
                    Fault.arm("Session.pendingExportShadow", 2, Const.PENDING_EXPORT);
                });
    }

    @Test
    void siPredicate() throws Exception {
        // forcing both sig_S verifications installs the attacker payload
        released(
                "SI",
                GateSweepTest.importAttackerSeed(BigInteger.ONE),
                () -> Fault.armVerifyTrue(0));
    }

    @Test
    void sirPredicate() throws Exception {
        // a LOADED target with a different wallet: reseal and the twice-read guards are
        // forced, T-INSTALL writes the foreign members
        released(
                "SIr", GateSweepTest.importDifferentWallet(), GateSweepPredicateTest::importGuards);
    }

    @Test
    void simPredicate() throws Exception {
        // SIm's gate is the IMPORT P1=01 MAC: the record here is sealed under the real
        // pending keys so decryption yields a well-formed different-wallet payload; both
        // mac evaluations are forced on top of the reseal faults so the released effect is
        // reached through the same guards as SIr
        released(
                "SIm",
                GateSweepTest.importDifferentWallet(),
                () -> {
                    Fault.arm("Transfer.mac", 1, Const.CHECK_OK);
                    Fault.arm("Transfer.mac", 2, Const.CHECK_OK);
                    importGuards();
                });
    }

    private static void importGuards() {
        loadedImportGuards();
    }

    @Test
    void svf0Predicate() throws Exception {
        svPredicate("SV-f0", GateSweepTest.verifyWrong(0, 0));
    }

    @Test
    void svfFPredicate() throws Exception {
        svPredicate("SV-fF", GateSweepTest.verifyWrong(3, 15));
    }

    @Test
    void svfL1Predicate() throws Exception {
        svPredicate("SV-fL1", GateSweepTest.verifyWrong(9, 15));
    }

    private static void svPredicate(String name, GateSweepTest.Factory f) throws Exception {
        // every Bytes.equal in the attack returns CHECK_OK: both match evaluations and both
        // fingerprint comparisons pass, T-OK sets the verified words, the probe verifies
        released(
                name,
                f,
                () -> {
                    for (int i = 1; i <= 16; i++) {
                        Fault.arm("Bytes.equal", i, Const.CHECK_OK);
                    }
                });
    }

    @Test
    void scPredicate() throws Exception {
        released(
                "SC",
                GateSweepTest.unverifiedEffect(GateSweepTest.INS_CHANGE, Vecs.accessHashNew()),
                GateSweepPredicateTest::verifiedWords);
    }

    @Test
    void sePredicate() throws Exception {
        released(
                "SE",
                GateSweepTest.unverifiedEffect(GateSweepTest.INS_ERASE, GateSweepTest.EMPTY),
                GateSweepPredicateTest::verifiedWords);
    }

    @Test
    void ssPredicate() throws Exception {
        released(
                "SS-pubkey",
                GateSweepTest.unverifiedSign(new int[][] {{GateSweepTest.INS_PUBLIC_KEY, 0}}),
                GateSweepPredicateTest::verifiedWords);
        released(
                "SS-ecdsa",
                GateSweepTest.unverifiedSign(new int[][] {{GateSweepTest.INS_SIGN_ECDSA, 0}}),
                GateSweepPredicateTest::verifiedWords);
        released(
                "SS-bip340",
                GateSweepTest.unverifiedSign(new int[][] {{GateSweepTest.INS_SIGN_BIP340, 0}}),
                GateSweepPredicateTest::verifiedWords);
        released(
                "SS-ed25519",
                GateSweepTest.unverifiedSign(
                        new int[][] {
                            {GateSweepTest.INS_SIGN_ED25519, 0}, {GateSweepTest.INS_SIGN_ED25519, 2}
                        }),
                GateSweepPredicateTest::verifiedWords);
    }
}
