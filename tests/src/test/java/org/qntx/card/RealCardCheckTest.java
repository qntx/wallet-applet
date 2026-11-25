// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The record gate's rejections ({@link RealCardCheck#violations}): a good record passes and every
 * tampered one — wrong CAP, wrong tree, a failure, a missing or extra class, a SKIP without a
 * reason, a skipped install suite, an old-format record — is refused.
 */
final class RealCardCheckTest {
    private static final String CAP = "a".repeat(64);
    private static final String TT = "b".repeat(40);
    private static final String TA = "c".repeat(40);
    private static final List<String> SUITE =
            List.of(
                    "org.qntx.card.real.AdmissionRealCardTest",
                    "org.qntx.card.real.CoreRealCardTest",
                    "org.qntx.card.real.InstallRealCardTest",
                    "org.qntx.card.real.TimingRealCardTest");

    private static String record(
            String cap, String treeTests, String treeApplet, String failed, String classes) {
        return "qntx-card real-card record 2\n"
                + "cap "
                + cap
                + "\n"
                + "commit "
                + "d".repeat(40)
                + "\n"
                + "tree-tests "
                + treeTests
                + "\n"
                + "tree-applet "
                + treeApplet
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
                + "failed "
                + failed
                + "\n"
                + "skipped 2\n"
                + classes
                + "\ntiming table\n";
    }

    private static final String GOOD_CLASSES =
            "class org.qntx.card.real.AdmissionRealCardTest PASS\n"
                    + "class org.qntx.card.real.CoreRealCardTest PASS\n"
                    + "class org.qntx.card.real.InstallRealCardTest PASS\n"
                    + "class org.qntx.card.real.TimingRealCardTest SKIP\n"
                    + "  skip cardGone: hardware endurance row unavailable\n";

    private static List<String> check(String record) {
        return RealCardCheck.violations(record, CAP, TT, TA, SUITE);
    }

    @Test
    void goodRecordPasses() {
        assertTrue(check(record(CAP, TT, TA, "0", GOOD_CLASSES)).isEmpty());
    }

    @Test
    void wrongCapRejected() {
        assertFalse(check(record("f".repeat(64), TT, TA, "0", GOOD_CLASSES)).isEmpty());
    }

    @Test
    void wrongTreeRejected() {
        assertFalse(check(record(CAP, "0".repeat(40), TA, "0", GOOD_CLASSES)).isEmpty());
        assertFalse(check(record(CAP, TT, "0".repeat(40), "0", GOOD_CLASSES)).isEmpty());
    }

    @Test
    void failedOneRejected() {
        assertFalse(check(record(CAP, TT, TA, "1", GOOD_CLASSES)).isEmpty());
    }

    @Test
    void missingClassRejected() {
        String classes =
                GOOD_CLASSES.replace("class org.qntx.card.real.CoreRealCardTest PASS\n", "");
        assertFalse(check(record(CAP, TT, TA, "0", classes)).isEmpty());
    }

    @Test
    void extraClassRejected() {
        String classes = GOOD_CLASSES + "class org.qntx.card.real.MadeUpRealCardTest PASS\n";
        assertFalse(check(record(CAP, TT, TA, "0", classes)).isEmpty());
    }

    @Test
    void skipWithoutReasonRejected() {
        String classes =
                GOOD_CLASSES.replace("  skip cardGone: hardware endurance row unavailable\n", "");
        assertFalse(check(record(CAP, TT, TA, "0", classes)).isEmpty());
    }

    @Test
    void installSkipRejected() {
        String classes =
                GOOD_CLASSES.replace(
                        "class org.qntx.card.real.InstallRealCardTest PASS\n",
                        "class org.qntx.card.real.InstallRealCardTest SKIP\n"
                                + "  skip reader: not run\n");
        assertFalse(check(record(CAP, TT, TA, "0", classes)).isEmpty());
    }

    @Test
    void failVerdictRejected() {
        String classes =
                GOOD_CLASSES.replace(
                        "class org.qntx.card.real.CoreRealCardTest PASS",
                        "class org.qntx.card.real.CoreRealCardTest FAIL");
        assertFalse(check(record(CAP, TT, TA, "0", classes)).isEmpty());
    }

    @Test
    void oldFormatRejected() {
        String old =
                "qntx-card real-card record\n"
                        + "cap "
                        + CAP
                        + "\n"
                        + "date 2026-11-24T12:00:00Z\n"
                        + "reader reader0\n"
                        + "passed 100\n"
                        + "failed 0\n"
                        + "skipped 2\n"
                        + "PASS org.qntx.card.real.InstallRealCardTest\n";
        assertFalse(check(old).isEmpty());
    }
}
