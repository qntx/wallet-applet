// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * The production CAP must install and select on the card under test (architecture.md §10 admission
 * prerequisite, protocol.md §3). This always uses {@code qntx.cap} — never the {@code
 * -PrealCardWallet=lazy} substitute — so a platform that cannot instantiate the applet inside the
 * JCRE install journal keeps failing here. On card A (5,120-byte commit buffer) the install dies
 * inside the constructor's object graph with {@code TransactionException} BUFFER_FULL, surfaced by
 * GPPro as a {@code 0x6F00} INSTALL status; that is the recorded Critical finding and this test is
 * its failing evidence.
 */
final class InstallRealCardTest {
    @Test
    void productionCapInstallsAndSelects() throws Exception {
        Fixture.require();
        Fixture.connect();
        Fixture.card()
                .reinstall(
                        Fixture.productionCap(),
                        RealCard.PACKAGE_AID,
                        RealCard.PACKAGE_AID,
                        RealCard.APPLET_AID);
        Fixture.markInstalled(Fixture.CapKind.PROD);
        assertEquals(
                0x9000,
                RealCard.sw(Fixture.card().transmit(RealCard.SELECT)),
                "SELECT after production install");
    }
}
