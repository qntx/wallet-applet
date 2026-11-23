// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * Admission 9 (protocol §3 item 9): one {@code WAIT} unit takes 0.9–1.1 s on a contactless reader —
 * the median of 9. On a contact reader, or when the transport cannot say whether it is contactless
 * without {@code -PrealCardContactless=true}, the row is skipped with a reason.
 */
final class Admission9 extends Suite {
    @Test
    void waitUnitWithinBounds() throws Exception {
        Boolean contactless = reader.contactless();
        if (contactless == null) {
            if (!"true".equals(System.getProperty("realCardContactless"))) {
                String reason =
                        "contactless cannot be determined; pass -PrealCardContactless=true "
                                + "or run on a contactless reader";
                Results.row("Admission 9", "WAIT timing", "skip", reason);
                Assumptions.abort(reason);
            }
        } else if (!contactless) {
            String reason = "contact reader — WAIT timing needs contactless";
            Results.row("Admission 9", "WAIT timing", "skip", reason);
            Assumptions.abort(reason);
        }

        // WAIT is only defined on a LOADED card; create, measure, then erase back to BLANK
        WalletSession session = WalletSession.open(reader, new SecureRandom());
        try {
            byte[] accessHash = session.accessHash("realCard-h3");
            byte[] create = new byte[64];
            System.arraycopy(accessHash, 0, create, 0, 32);
            byte[] entropy = new byte[32];
            new SecureRandom().nextBytes(entropy);
            System.arraycopy(entropy, 0, create, 32, 32);
            session.innerOk(WalletSession.INS_CREATE, 0, 0, create);

            long[] times = new long[9];
            for (int i = 0; i < times.length; i++) {
                long t0 = System.nanoTime();
                session.innerOk(WalletSession.INS_WAIT, 0, 0);
                times[i] = (System.nanoTime() - t0) / 1_000_000;
            }
            Arrays.sort(times);
            long median = times[4];
            Results.row(
                    "Admission 9",
                    "WAIT unit",
                    median >= 900 && median <= 1100 ? "pass" : "fail",
                    "median " + median + " ms of " + Arrays.toString(times) + " (ref 965 ms)");
            assertTrue(
                    median >= 900 && median <= 1100,
                    "WAIT median " + median + " ms outside [900, 1100]");
        } finally {
            // leave the card in BLANK
            try {
                session.innerOk(WalletSession.INS_ERASE, 0, 0);
            } catch (RuntimeException ignored) {
                // an unverified or broken session may refuse ERASE; the batch record notes it
            }
        }
    }
}
