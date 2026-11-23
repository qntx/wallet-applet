// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * The tearing row of architecture.md §10: a field cut at programmable instants during VERIFY,
 * CREATE, IMPORT and ERASE must leave every named transaction's post-state as its protocol section
 * lists. Deferred — it needs a programmable reader, and none is supported yet; the row reports
 * {@code unavailable} until one exists. Mandatory before the protocol freeze.
 */
final class TearingRealCardTest {
    @Test
    void fieldCutAtProgrammableInstants() {
        Fixture.require();
        Assumptions.assumeTrue(false, "unavailable: no programmable reader yet (§10)");
    }
}
