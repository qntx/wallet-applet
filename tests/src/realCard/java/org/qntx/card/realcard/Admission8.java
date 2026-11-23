// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Admission 8 (protocol §3 item 8): every named transaction of §4.3 consumes at most 50 % of {@code
 * getMaxCommitCapacity}, measured with {@code getUnusedCommitCapacity} inside the replica, and at
 * least 15 % of the transient pool remains after the product applet is installed (the pool measured
 * on card A, architecture §10).
 */
final class Admission8 extends Suite {
    private static final String[] NAMES = {
        "T-PERSO",
        "T-CREATE",
        "T-INSTALL",
        "T-OFFER",
        "T-CHANGE",
        "T-ERASE",
        "T-FAIL",
        "T-OK",
        "T-EDCTR",
    };

    /**
     * The transient pool of the baseline chip: 3,990 B on the simulator (CardRuntime), ≈4,130 B
     * measured on development card A (architecture §10). The only figure a card reports is the
     * remaining pool, so the fraction is computed against the batch's known pool.
     */
    private static long pool() {
        return reader.isSim() ? 3990 : 4130;
    }

    @Test
    void everyTransactionWithinHalfCommit() {
        Probe probe = Suite.prepareProbe();
        for (int id = 0; id < NAMES.length; id++) {
            byte[] r = probe.replica(id);
            int used = Apdu.u16(r, 0);
            int max = Apdu.u16(r, 2);
            Results.row(
                    "Admission 8",
                    NAMES[id],
                    used * 2 <= max ? "pass" : "fail",
                    "commit " + used + " of " + max);
            assertTrue(
                    used * 2 <= max,
                    NAMES[id] + " uses " + used + " commit bytes, more than half of " + max);
        }
    }

    @Test
    void transientPoolRemainsAfterInstall() {
        Probe probe = Suite.prepareProbe();
        byte[] info = probe.info();
        long deselect = Apdu.u16(info, 0);
        long reset = Apdu.u16(info, 4);
        long persistent = Apdu.u16(info, 8);
        // the pool figure captured at probe install, before the probe's own transient objects
        long afterInstall = Apdu.u16(info, 23);
        long pool = pool();
        long pct = afterInstall * 100 / pool;
        Results.row(
                "Admission 8",
                "transient pool",
                pct >= 15 ? "pass" : "fail",
                "post-install deselect "
                        + afterInstall
                        + " of pool "
                        + pool
                        + " = "
                        + pct
                        + "%"
                        + " (now "
                        + deselect
                        + ", reset "
                        + reset
                        + ", persistent "
                        + persistent
                        + ")");
        assertTrue(pct >= 15, "transient remainder " + pct + "% of pool " + pool + " < 15%");
    }
}
