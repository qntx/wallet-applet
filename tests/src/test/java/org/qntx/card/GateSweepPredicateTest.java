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

    // ── legitimate-flow predicates (architecture §6) ──────────────────────

    /** Every early {@code Bytes.equal} call returns CHECK_OK — a forced comparison. */
    private static void forcedEquals() {
        for (int i = 1; i <= 16; i++) {
            Fault.arm("Bytes.equal", i, Const.CHECK_OK);
        }
    }

    /** Like {@link #released} but judges the run by {@code outcome() == RELEASED}. */
    private static void releasedOutcome(String name, GateSweepTest.Factory f, Runnable arm)
            throws Exception {
        GateSweepTest.Run r = f.fresh();
        arm.run();
        try {
            r.run();
        } catch (Throwable t) {
            // the sw trail of a failed release attempt still lands in the message below
        }
        Fault.reset();
        org.junit.jupiter.api.Assertions.assertEquals(
                GateSweepTest.RELEASED,
                r.outcome(),
                name
                        + ": the release predicate did not fire under a known multi-fault (sw: "
                        + r.swSequence()
                        + ")");
    }

    /**
     * Probes the {@code sitePrefix#i<k>} invoke sites one at a time: each is skipped (at occurrence
     * {@code nth}) together with {@code extraArms} until the scenario's outcome is RELEASED — used
     * when the faulted API call (an {@code arrayCopy} or {@code nextBytes} inside the gate method)
     * is not nameable through {@code Fault.armSkip}.
     */
    private static void releasedSkippingInvoke(
            String name, GateSweepTest.Factory f, String sitePrefix, int nth, Runnable extraArms)
            throws Exception {
        GateSweepTest.Run probe = f.fresh();
        Fault.countCalls();
        try {
            probe.run();
        } catch (Throwable ignored) {
        }
        Map<String, Integer> sites = new TreeMap<>(Fault.siteCounts());
        Fault.reset();
        Map<String, Integer> outcomes = new TreeMap<>();
        Map<String, String> sws = new TreeMap<>();
        for (String key : sites.keySet()) {
            if (!key.startsWith(sitePrefix + "#i")) {
                continue;
            }
            GateSweepTest.Run r = f.fresh();
            Fault.armSite(key, nth, Fault.SITE_SKIP);
            if (extraArms != null) {
                extraArms.run();
            }
            try {
                r.run();
            } catch (Throwable ignored) {
            }
            Fault.reset();
            int outcome;
            try {
                outcome = r.outcome();
            } catch (Throwable t) {
                outcome = GateSweepTest.ERROR;
            }
            outcomes.put(key, outcome);
            sws.put(key, r.swSequence());
            if (outcome == GateSweepTest.RELEASED) {
                return;
            }
        }
        org.junit.jupiter.api.Assertions.fail(
                name
                        + ": no skipped "
                        + sitePrefix
                        + " invoke made the release predicate fire (outcomes: "
                        + outcomes
                        + ", sws: "
                        + sws
                        + ")");
    }

    @Test
    void sxePredicate() throws Exception {
        // both derivations' Kdf.kdf skipped (the Kdf invoke inside transferKey is a void
        // call — the arm is an invoke-site skip), the cross-derivation compare forced: the
        // record goes out under whatever scratch the unwritten key buffers held — public or
        // zero material the candidate set covers
        releasedSkippingInvoke("SXe", GateSweepTest.exportLegit(), "Transfer.transferKey", 0, null);
    }

    @Test
    void siePredicate() throws Exception {
        releasedSkippingInvoke("SIe", GateSweepTest.importLegit(), "Transfer.transferKey", 0, null);
    }

    @Test
    void sxePublicEphemeralPredicate() throws Exception {
        // row E8: ZERO on the first mul's scalar-offset load (Secp256k1.mul#d1, the iload of
        // sOff — once per mul call, so nth=1 is the E = e·G one) reads the scalar from
        // h[0..32) = the offer hash SHA-256("qntx-card/v1/offer"‖LK_T), a public value: the
        // output E is then public-scalar while the Z product stays consistent, which the key
        // candidates cannot see — the ephemeral clause must fire. The wrong scalar desyncs
        // K1 from K2, so loadKeys' K1=K2 compare (i1) and the read-back compare (i7) are
        // forced on top.
        releasedOutcome(
                "SXe-eph",
                GateSweepTest.exportLegit(),
                () -> {
                    Fault.armSite("Secp256k1.mul#d1", 1, Fault.SITE_ZERO);
                    Fault.armSite("Transfer.loadKeys#i1", 0, Fault.SITE_FORCED, Const.CHECK_OK);
                    Fault.armSite("Transfer.loadKeys#i7", 0, Fault.SITE_FORCED, Const.CHECK_OK);
                });
    }

    @Test
    void soPublicEphemeralPredicate() throws Exception {
        // row E8 on OPEN: the card's draw lands on x = 1 — cardEph = G, a public scalar,
        // and Z = hostEph stays consistent, so the session opens and the response keys are
        // the host's — only the ephemeral clause can see the release
        releasedOutcome("SO-eph", GateSweepTest.openTwiceWith((i, k) -> k == 31 ? 1 : 0), () -> {});
    }

    @Test
    void sinPredicate() throws Exception {
        // the staged access-hash copy inside install skipped, its comparison forced: the
        // installed wallet opens under the stale (public) hash the copy would have replaced
        releasedOutcome(
                "SIn",
                GateSweepTest.installLegit(),
                () -> {
                    // the staged access-hash copy (i2) skipped, its site-forced comparison
                    // (i9, the second Bytes.equal of install) — the wallet seals under the
                    // stale staged hash, SHA-256(A_T) in the candidate set
                    Fault.armSite("Wallet.install#i2", 0, Fault.SITE_SKIP);
                    Fault.armSite("Wallet.install#i9", 0, Fault.SITE_FORCED, Const.CHECK_OK);
                });
    }

    @Test
    void sciPredicate() throws Exception {
        releasedOutcome(
                "SCi",
                GateSweepTest.createImport(),
                () -> {
                    // the P1=01 access-hash copy (i29) skipped, its staged comparison (i32,
                    // the last Bytes.equal of create) forced — sealed under the stale hash
                    Fault.armSite("Wallet.create#i29", 0, Fault.SITE_SKIP);
                    Fault.armSite("Wallet.create#i32", 0, Fault.SITE_FORCED, Const.CHECK_OK);
                });
    }

    @Test
    void schPredicate() throws Exception {
        // A committed CHANGE bound to a public hash: send SHA-256(A) as the new access hash
        // inside a record with a corrupted session tag, and force the unwrap's two tag
        // compares (Session.unwrap#i11, #i13) — the forged CHANGE is accepted and the wallet
        // is bound to a hash an outsider computes. Skipping the staged access-hash copy, by
        // contrast, commits under whatever session material W_H held — never a public
        // candidate (the session machinery rewrites W[0..32) every command), so that fault is
        // DEVIATED, not RELEASED, and cannot drive this self-check.
        Object[] f = GateSweepTest.loaded(new EmuMember());
        org.qntx.card.sim.Card card = (org.qntx.card.sim.Card) f[0];
        org.qntx.card.host.Session session = (org.qntx.card.host.Session) f[1];
        byte[] a = (byte[]) f[2];
        byte[] sha256A = org.qntx.card.host.Crypto.sha256(a);
        GateSweepTest.Run r =
                new GateSweepTest.Run() {
                    @Override
                    void run() throws Exception {
                        byte[] forged = session.wrap(GateSweepTest.INS_CHANGE, 0, 0, sha256A);
                        forged[forged.length - 1] ^= 1;
                        byte[] rapdu = card.transmit(forged);
                        try {
                            sws.add(session.unwrap(rapdu).sw());
                        } catch (Exception e) {
                            sws.add(-1);
                        }
                    }

                    @Override
                    int outcome() throws Exception {
                        byte[][] bound = new byte[1][];
                        byte[] keys =
                                GateSweepTest.accessBound(card, java.util.List.of(sha256A), bound);
                        return keys != null ? GateSweepTest.RELEASED : GateSweepTest.REFUSED;
                    }
                };
        Fault.armSite("Session.unwrap#i11", 0, Fault.SITE_FORCED, Const.CHECK_OK);
        Fault.armSite("Session.unwrap#i13", 0, Fault.SITE_FORCED, Const.CHECK_OK);
        try {
            r.run();
        } catch (Throwable ignored) {
        } finally {
            Fault.reset();
        }
        org.junit.jupiter.api.Assertions.assertEquals(
                GateSweepTest.RELEASED, r.outcome(), "SCh: forced tag compare did not release");
    }

    @Test
    void scrPredicate() throws Exception {
        // nextBytes skipped leaves the wiped 0³² as t; the zero check and the double
        // derivation's comparison are forced — the stored seed is the computable zero-t
        // candidate
        releasedSkippingInvoke(
                "SCr",
                GateSweepTest.createGenerate(),
                "Wallet.create",
                0,
                () -> {
                    for (int i = 1; i <= 16; i++) {
                        Fault.arm("Bytes.isZero", i, Const.CHECK_FAIL);
                        Fault.arm("Bytes.equal", i, Const.CHECK_OK);
                    }
                });
    }

    @Test
    void soPredicate() throws Exception {
        // the second block of both KDF derivations skipped (the second doFinal inside each
        // Kdf.kdf call), the cross-comparison forced: the response keys are stale scratch —
        // identical under both RNG blocks, so the equal-keys clause fires
        // the shared-secret agree skipped leaves a stale Z — both RNG blocks then derive
        // the same card keys (the equal-keys clause), or the second block of both KDF
        // derivations skipped leaves stale response keys; either must release
        // skip kre.setKey (the third AESKey.setKey invoke of Session.open, i30): kre keeps
        // the 0¹⁶ teardown wrote; force the read-back comparison (the last Bytes.equal of
        // open, i36 — equal(P,64,P,0,64)) to CHECK_OK → the card answers under K_re = 0¹⁶
        // (public) with a correct K_rm → R-O
        releasedOutcome(
                "SO",
                GateSweepTest.openTwice(),
                () -> {
                    Fault.armSite("Session.open#i30", 0, Fault.SITE_SKIP);
                    Fault.armSite("Session.open#i36", 0, Fault.SITE_FORCED, Const.CHECK_OK);
                });
    }

    @Test
    void watchdogHangsOnStalledLoop() throws Exception {
        // a Derivation.master invoke skipped every time spins CREATE P1=00's draw loop
        // forever — the site-hit watchdog must fire so the sweep records HANG (G-07 already
        // bounds the receive loop, so no receive-path fault can produce this). The loop is
        // found by probing Wallet.create's invoke sites for the one that hangs.
        GateSweepTest.Run probe = GateSweepTest.createGenerate().fresh();
        Fault.countCalls();
        try {
            probe.run();
        } catch (Throwable ignored) {
        }
        Set<String> keys = new TreeSet<>(Fault.siteCounts().keySet());
        Fault.reset();
        for (String key : keys) {
            if (!key.startsWith("Wallet.create#i")) {
                continue;
            }
            GateSweepTest.Attempt a =
                    GateSweepTest.attempt(
                            GateSweepTest.createGenerate(),
                            () -> Fault.armSite(key, 0, Fault.SITE_SKIP),
                            200_000);
            if (a.outcome() == GateSweepTest.HANG) {
                return;
            }
        }
        org.junit.jupiter.api.Assertions.fail(
                "no skipped Wallet.create invoke tripped the watchdog (sites: " + keys + ")");
    }
}
