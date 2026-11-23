// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;

/**
 * Base class of every real-card test class: the shared gate. Without {@code -PrealCard=<reader>}
 * the assumption fails in {@code @BeforeAll}, every test of the class is reported skipped as "not
 * run", and no reader is opened. {@code -PrealCard=sim} connects the in-process simulator
 * self-check.
 */
abstract class Suite {
    protected static Reader reader;

    @BeforeAll
    static void connect() {
        String spec = System.getProperty("realCard");
        Assumptions.assumeTrue(
                spec != null && !spec.isEmpty(),
                "not run: -PrealCard=<reader> is not set "
                        + "(architecture §10 real-card suite; never run in CI)");
        reader = Readers.create(spec);
        Results.open(reader);
    }

    @AfterAll
    static void disconnect() {
        if (reader != null) {
            reader.close();
            reader = null;
        }
        Results.close();
    }

    /** Skips a sub-check the simulator provably cannot model; fails on hardware. */
    static void simOnly(String reason) {
        Assumptions.assumeFalse(reader.isSim(), "simulator does not model this: " + reason);
    }

    /** Selects the probe, loads both curve domains and runs object setup (all-zero statuses). */
    static Probe prepareProbe() {
        Probe probe = Probe.open(reader);
        probe.domain(0, Curve.SECP256K1.domainBlob());
        probe.domain(1, Curve.WEI25519.domainBlob());
        byte[] statuses = probe.setup();
        for (int i = 0; i < statuses.length; i++) {
            if (statuses[i] != 0) {
                throw new IllegalStateException(
                        "probe setup item "
                                + i
                                + " failed: "
                                + Integer.toHexString(statuses[i] & 0xFF));
            }
        }
        return probe;
    }
}
