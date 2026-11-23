// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * The Tearing row (architecture §10): field cuts at programmable instants during {@code VERIFY},
 * {@code CREATE}, {@code IMPORT} and {@code ERASE} need a programmable reader. No supported driver
 * exists in this suite — the row is listed and skipped until {@code -PrealCardTear= <driver>} names
 * one.
 */
final class Tearing extends Suite {
    @Test
    void fieldCuts() {
        String driver = System.getProperty("realCardTear");
        String reason =
                driver == null || driver.isEmpty()
                        ? "not run: -PrealCardTear=<driver> is not set; "
                                + "no supported programmable-reader driver exists"
                        : "not run: programmable-reader driver '" + driver + "' is not supported";
        Results.row("Tearing", "field cuts", "skip", reason);
        Assumptions.abort(reason);
    }
}
