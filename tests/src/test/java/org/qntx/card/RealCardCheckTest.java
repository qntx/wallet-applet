// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;

/**
 * The record gate's rejections ({@link RealCardCheck#violations}): a good record-3 passes and every
 * tampered one — a duplicate, missing, unknown or out-of-order header key, a malformed field, a
 * wrong CAP or git tree, a non-ancestor commit, non-release {@code params}, a failure, a missing or
 * extra class, a SKIP outside {@link RealCardCheck#SKIPPABLE}, a SKIP without a reason, a {@code
 * skipped} count that does not match the reason lines, a skipped install suite, an old-format
 * record — is refused. The trees and ancestor verdict are passed in, so nothing here depends on
 * this checkout or on the committed {@code realcard/*.txt}.
 */
final class RealCardCheckTest {
    private static final String CAP = "a".repeat(64);
    private static final String COMMIT = "d".repeat(40);
    private static final Map<String, String> TREES = trees();
    private static final Predicate<String> ANCESTOR = c -> true;
    private static final List<String> SUITE =
            List.of(
                    "org.qntx.card.real.AdmissionRealCardTest",
                    "org.qntx.card.real.CoreRealCardTest",
                    "org.qntx.card.real.InstallRealCardTest",
                    "org.qntx.card.real.NvmRealCardTest");

    private static Map<String, String> trees() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("tree-tests", "b".repeat(40));
        m.put("tree-applet", "c".repeat(40));
        m.put("tree-host", "1".repeat(40));
        m.put("tree-sim", "2".repeat(40));
        m.put("tree-buildSrc", "3".repeat(40));
        return m;
    }

    /** The good record's header, {@link RealCardCheck#HEADER_KEYS} in order. */
    private static String header() {
        return "cap "
                + CAP
                + "\n"
                + "commit "
                + COMMIT
                + "\n"
                + "tree-tests "
                + TREES.get("tree-tests")
                + "\n"
                + "tree-applet "
                + TREES.get("tree-applet")
                + "\n"
                + "tree-host "
                + TREES.get("tree-host")
                + "\n"
                + "tree-sim "
                + TREES.get("tree-sim")
                + "\n"
                + "tree-buildSrc "
                + TREES.get("tree-buildSrc")
                + "\n"
                + "params "
                + RealCardCheck.RELEASE_PARAMS
                + "\n"
                + "date 2026-11-25T12:00:00Z\n"
                + "reader reader0\n"
                + "atr 3B8580018073C821100E\n"
                + "cplc 9F7F2A\n"
                + "identify DF28\n"
                + "apdu-log-sha256 "
                + "e".repeat(64)
                + "\n"
                + "passed 100\n"
                + "failed 0\n"
                + "skipped 1\n";
    }

    private static final String GOOD_CLASSES =
            "class org.qntx.card.real.AdmissionRealCardTest PASS\n"
                    + "class org.qntx.card.real.CoreRealCardTest PASS\n"
                    + "class org.qntx.card.real.InstallRealCardTest PASS\n"
                    + "class org.qntx.card.real.NvmRealCardTest SKIP\n"
                    + "  skip sacrificialCard: hardware row unavailable\n";

    private static String record(String header, String classes) {
        return RealCardCheck.MAGIC + "\n" + header + classes + "\ntiming table\n";
    }

    private static List<String> check(String record) {
        return RealCardCheck.violations(record, CAP, TREES, ANCESTOR, SUITE);
    }

    @Test
    void goodRecordPasses() {
        assertTrue(check(record(header(), GOOD_CLASSES)).isEmpty());
    }

    @Test
    void duplicateHeaderKeyRejected() {
        // a second `failed` line with a clean value must not mask the earlier `failed 1`
        String h = header().replace("failed 0\n", "failed 1\nfailed 0\n");
        assertFalse(check(record(h, GOOD_CLASSES)).isEmpty());
    }

    @Test
    void missingHeaderKeyRejected() {
        for (String key : RealCardCheck.HEADER_KEYS) {
            String h =
                    header().lines()
                            .filter(l -> !l.startsWith(key + " "))
                            .reduce("", (a, b) -> a + b + "\n");
            assertFalse(
                    check(record(h, GOOD_CLASSES)).isEmpty(),
                    "missing " + key + " must be refused");
        }
    }

    @Test
    void unknownHeaderKeyRejected() {
        String h =
                header().replace(
                                "date 2026-11-25T12:00:00Z\n",
                                "bogus x\n" + "date 2026-11-25T12:00:00Z\n");
        assertFalse(check(record(h, GOOD_CLASSES)).isEmpty());
    }

    @Test
    void outOfOrderHeaderKeyRejected() {
        String h =
                header().replace(
                                "reader reader0\natr 3B8580018073C821100E\n",
                                "atr 3B8580018073C821100E\nreader reader0\n");
        assertFalse(check(record(h, GOOD_CLASSES)).isEmpty());
    }

    @Test
    void wrongCapRejected() {
        String h = header().replace("cap " + CAP, "cap " + "f".repeat(64));
        assertFalse(check(record(h, GOOD_CLASSES)).isEmpty());
    }

    @Test
    void wrongTreeRejected() {
        for (String key :
                List.of("tree-tests", "tree-applet", "tree-host", "tree-sim", "tree-buildSrc")) {
            String h = header().replace(key + " " + TREES.get(key), key + " " + "0".repeat(40));
            assertFalse(
                    check(record(h, GOOD_CLASSES)).isEmpty(), "wrong " + key + " must be refused");
        }
    }

    @Test
    void nonAncestorCommitRejected() {
        List<String> v =
                RealCardCheck.violations(
                        record(header(), GOOD_CLASSES), CAP, TREES, c -> false, SUITE);
        assertFalse(v.isEmpty());
    }

    @Test
    void nonReleaseParamsRejected() {
        String h =
                header().replace(
                                "params " + RealCardCheck.RELEASE_PARAMS,
                                "params differential=10 sequences=80 prims=all keep=false"
                                        + " cap=tree memcap=tree probecap=tree");
        assertFalse(check(record(h, GOOD_CLASSES)).isEmpty());
    }

    @Test
    void failedOneRejected() {
        String h = header().replace("failed 0\n", "failed 1\n");
        assertFalse(check(record(h, GOOD_CLASSES)).isEmpty());
    }

    @Test
    void skippedCountMismatchRejected() {
        String h = header().replace("skipped 1\n", "skipped 0\n");
        assertFalse(check(record(h, GOOD_CLASSES)).isEmpty());
        String h2 = header().replace("skipped 1\n", "skipped 2\n");
        assertFalse(check(record(h2, GOOD_CLASSES)).isEmpty());
    }

    @Test
    void malformedHexRejected() {
        String h = header().replace("commit " + COMMIT, "commit " + "z".repeat(40));
        assertFalse(check(record(h, GOOD_CLASSES)).isEmpty());
        String h2 = header().replace("cap " + CAP, "cap " + "A".repeat(64));
        assertFalse(check(record(h2, GOOD_CLASSES)).isEmpty());
    }

    @Test
    void badDateRejected() {
        String h = header().replace("date 2026-11-25T12:00:00Z", "date yesterday");
        assertFalse(check(record(h, GOOD_CLASSES)).isEmpty());
    }

    @Test
    void missingClassRejected() {
        String classes =
                GOOD_CLASSES.replace("class org.qntx.card.real.CoreRealCardTest PASS\n", "");
        assertFalse(check(record(header(), classes)).isEmpty());
    }

    @Test
    void extraClassRejected() {
        String classes = GOOD_CLASSES + "class org.qntx.card.real.MadeUpRealCardTest PASS\n";
        assertFalse(check(record(header(), classes)).isEmpty());
    }

    @Test
    void skipOutsideAllowedSetRejected() {
        String classes =
                GOOD_CLASSES.replace(
                        "class org.qntx.card.real.CoreRealCardTest PASS\n",
                        "class org.qntx.card.real.CoreRealCardTest SKIP\n"
                                + "  skip reason: why not\n");
        String h = header().replace("skipped 1\n", "skipped 2\n");
        assertFalse(check(record(h, classes)).isEmpty());
    }

    @Test
    void installSkipRejected() {
        String classes =
                GOOD_CLASSES.replace(
                        "class org.qntx.card.real.InstallRealCardTest PASS\n",
                        "class org.qntx.card.real.InstallRealCardTest SKIP\n"
                                + "  skip reader: not run\n");
        String h = header().replace("skipped 1\n", "skipped 2\n");
        assertFalse(check(record(h, classes)).isEmpty());
    }

    @Test
    void skipWithoutReasonRejected() {
        String classes =
                GOOD_CLASSES.replace("  skip sacrificialCard: hardware row unavailable\n", "");
        assertFalse(check(record(header(), classes)).isEmpty());
    }

    @Test
    void failVerdictRejected() {
        String classes =
                GOOD_CLASSES.replace(
                        "class org.qntx.card.real.CoreRealCardTest PASS",
                        "class org.qntx.card.real.CoreRealCardTest FAIL");
        assertFalse(check(record(header(), classes)).isEmpty());
    }

    @Test
    void oldFormatRejected() {
        String old =
                "qntx-card real-card record 2\n"
                        + "cap "
                        + CAP
                        + "\n"
                        + "commit "
                        + COMMIT
                        + "\n"
                        + "tree-tests "
                        + TREES.get("tree-tests")
                        + "\n"
                        + "tree-applet "
                        + TREES.get("tree-applet")
                        + "\n"
                        + "date 2026-11-25T12:00:00Z\n"
                        + "reader reader0\n"
                        + "atr 3B8580018073C821100E\n"
                        + "cplc 9F7F2A\n"
                        + "identify DF28\n"
                        + "apdu-log-sha256 "
                        + "e".repeat(64)
                        + "\n"
                        + "passed 100\n"
                        + "failed 0\n"
                        + "skipped 1\n"
                        + GOOD_CLASSES;
        assertFalse(check(old).isEmpty());
    }
}
