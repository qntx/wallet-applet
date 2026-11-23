// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javacard.framework.TransactionException;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The simulator's install journal (architecture §8 patch 2): persistent writes during {@code
 * install()} charge card A's 5,120 B journal like an open transaction; above it install fails with
 * {@code BUFFER_FULL}. §4.3 requires install to consume at most 60 % (3,072 B).
 */
final class InstallJournalTest {

    private static final int INSTALL_BUDGET = 3072;

    @Test
    void walletInstallFitsTheInstallJournal() {
        Card card = new Card();
        card.install(Spec.WALLET_AID, WalletApplet.class);
        assertTrue(
                card.installBytes() <= INSTALL_BUDGET,
                "wallet install charge " + card.installBytes());
    }

    @Test
    void ndefInstallFitsTheInstallJournal() {
        Card card = new Card();
        card.install(Spec.NDEF_AID, NdefApplet.class, new byte[100]);
        assertTrue(
                card.installBytes() <= INSTALL_BUDGET,
                "NDEF install charge " + card.installBytes());
    }

    /**
     * The pre-F1 constructor — the shape the real finding reported — does not fit card A's journal:
     * {@link LegacyInstallApplet} performs exactly its writes and install must fail.
     */
    @Test
    void thePreF1ConstructorWouldNotFitTheInstallJournal() {
        Card card = new Card();
        TransactionException e =
                assertThrows(
                        TransactionException.class,
                        () -> card.install(Vecs.unhex("F0716E7478FF"), LegacyInstallApplet.class));
        assertEquals(TransactionException.BUFFER_FULL, e.getReason());
    }
}
