// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * The NVM row (architecture §10): endurance on a sacrificial card — 10⁶ {@code setW} on one key
 * object, 10⁶ T-FAIL/T-OK and 10⁵ T-OFFER — after which every named-transaction replica must still
 * commit. Destructive: runs only when {@code -PrealCardSacrificial=<CPLC IC serial>} matches the
 * card's CPLC, and refuses development card A (IC type {@code D321}, serial {@code 49917821},
 * {@code $A/audit-impl/evidence/README.md}) unconditionally.
 */
final class Nvm extends Suite {
    private static final String DEV_A_TYPE = "d321";
    private static final String DEV_A_SERIAL = "49917821";
    private static final int SETW = 1_000_000;
    private static final int FAIL_OK = 1_000_000;
    private static final int OFFER = 100_000;

    @Test
    void enduranceOnSacrificialCard() {
        String want = System.getProperty("realCardSacrificial");
        if (want == null || want.isEmpty()) {
            skip(
                    "not run: -PrealCardSacrificial=<CPLC IC serial> is not set "
                            + "(destructive; sacrificial card only)");
        }
        byte[] cplc = reader.cplc();
        if (cplc == null) {
            skip(
                    "cannot read the card CPLC on "
                            + reader.describe()
                            + "; the serial cannot be matched");
        }
        String icType = Apdu.hex(new byte[] {cplc[2], cplc[3]});
        String serial = Apdu.hex(new byte[] {cplc[12], cplc[13], cplc[14], cplc[15]});
        if (DEV_A_TYPE.equals(icType) && DEV_A_SERIAL.equals(serial)) {
            skip("refusing development card A (D321/49917821, $A/audit-impl/evidence/README.md)");
        }
        if (!serial.equalsIgnoreCase(want.trim())) {
            skip("CPLC IC serial " + serial + " != -PrealCardSacrificial=" + want);
        }

        Probe probe = Suite.prepareProbe();
        loop(probe, 16, SETW, operand65(), "setW");
        loop(probe, 19, FAIL_OK, Apdu.EMPTY, "T-FAIL/T-OK");
        loop(probe, 30, OFFER, Apdu.EMPTY, "T-OFFER");

        String[] names = {
            "T-PERSO",
            "T-CREATE",
            "T-INSTALL",
            "T-OFFER",
            "T-CHANGE",
            "T-ERASE",
            "T-FAIL",
            "T-OK",
            "T-EDCTR"
        };
        for (int id = 0; id < names.length; id++) {
            byte[] r = probe.replica(id);
            Results.row(
                    "Nvm",
                    "after endurance " + names[id],
                    "pass",
                    "commit " + Apdu.u16(r, 0) + " of " + Apdu.u16(r, 2));
        }
        Results.row("Nvm", "endurance", "pass", "all replicas still commit");
    }

    private static void loop(Probe probe, int op, int total, byte[] operand, String name) {
        int done = 0;
        long t0 = System.nanoTime();
        while (done < total) {
            int reps = Math.min(255, total - done);
            Probe.Rsp r = probe.bench(op, reps, operand);
            assertEquals(0x9000, r.sw(), name + " bench at " + done);
            done += reps;
        }
        Results.row(
                "Nvm",
                name,
                "pass",
                total + " ops in " + (System.nanoTime() - t0) / 1_000_000 + " ms");
    }

    private static byte[] operand65() {
        byte[] w = new byte[65];
        w[0] = 4;
        return w;
    }

    private static void skip(String reason) {
        Results.row("Nvm", "endurance", "skip", reason);
        Assumptions.abort(reason);
    }
}
