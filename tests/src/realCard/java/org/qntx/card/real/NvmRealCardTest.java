// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * The NVM-endurance row of architecture.md §10: write times of the transactions and endurance after
 * 10⁶ {@code setW} on one key object, 10⁶ T-FAIL/T-OK and 10⁵ T-OFFER, with all other transactions
 * still committing afterwards. Deferred — it needs a sacrificial card and must never run on a
 * development card (REALCARD.md); the row reports {@code unavailable} until a sacrificial unit
 * exists. Mandatory before the protocol freeze.
 */
final class NvmRealCardTest {
    @Test
    void enduranceOnASacrificialCard() {
        Fixture.require();
        Assumptions.assumeTrue(
                false, "unavailable: no sacrificial card (never a development card, §10)");
    }
}
