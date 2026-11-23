// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * The B2 flow row of architecture.md §10: taps and seconds of the wallet flows on the reference
 * phones. Deferred — it needs the phone harness, which does not exist yet; the row reports {@code
 * unavailable} until it lands. Mandatory before the protocol freeze.
 */
final class FlowRealCardTest {
    @Test
    void flowsOnTheReferencePhones() {
        Fixture.require();
        Assumptions.assumeTrue(false, "unavailable: no phone harness yet (§10, before freeze)");
    }
}
