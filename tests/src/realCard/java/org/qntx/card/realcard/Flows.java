// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * The Flows row (architecture §10): the phone flows of B2 — iOS and Android taps, the weakest
 * usable coupling, the iOS single-connection limit and the alertMessage length — run in the
 * qntx/wallet harness, never in this suite. Listed here so the batch record has the row.
 */
final class Flows extends Suite {
    @Test
    void phoneFlows() {
        Results.row(
                "Flows",
                "phone flows",
                "skip",
                "phone flows run in the qntx/wallet harness (architecture §10 Flows; FROZEN M1–M6)");
        Assumptions.abort(
                "phone flows run in the qntx/wallet harness (architecture §10 Flows; FROZEN M1–M6)");
    }
}
