// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.qntx.card.NdefApplet;
import org.qntx.card.WalletApplet;
import org.qntx.card.sim.Card;

/** Transient memory after install stays within the architecture.md §5.1 budget rule. */
final class MemoryBudgetTest {
    private static final int BUDGET = 3390;

    @Test
    void installedAppletStaysWithinTheTransientBudget() throws IOException {
        Card card = new Card();
        card.install(Spec.WALLET_AID, WalletApplet.class);
        // §15's largest message charges the NDEF row of the §5.1 table
        card.install(Spec.NDEF_AID, NdefApplet.class, new byte[100]);
        Path reports = Path.of(System.getProperty("qntx.reports"));
        Files.createDirectories(reports);
        Files.writeString(reports.resolve("memory.txt"), card.memoryReport());
        assertTrue(card.transientUsed() <= BUDGET, card.memoryReport());
    }
}
