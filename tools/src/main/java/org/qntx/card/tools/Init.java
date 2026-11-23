// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tools;

import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;

/**
 * The §4.3/§14.3 initialisation drive, shared by {@code install} and {@code personalise}: repeat
 * {@code SELECT} + {@code GET_IDENTITY} until it answers other than {@code 6283}, bounded at 16
 * repetitions — a card that still answers {@code 6283} after that is failed.
 */
final class Init {

    /** §14.3 bound on the number of SELECT + GET_IDENTITY rounds. */
    static final int MAX_STEPS = 16;

    private Init() {}

    /**
     * Drives initialisation to completion and returns the last GET_IDENTITY response (the one that
     * carries {@code A} and {@code 9000}). When {@code out} is non-null, each round's wall time and
     * the step count are printed to it.
     */
    static byte[] drive(BIBO bibo, PrintStream out) throws BIBOException, IOException {
        var durations = new ArrayList<Long>();
        byte[] rapdu;
        while (true) {
            byte[] select = bibo.transceive(Apdu.SELECT_WALLET);
            if (Apdu.sw(select) != 0x9000) {
                throw new IOException("SELECT wallet failed: " + Apdu.status(select));
            }
            long t0 = System.nanoTime();
            rapdu = bibo.transceive(Apdu.GET_IDENTITY);
            durations.add((System.nanoTime() - t0) / 1_000_000);
            if (Apdu.sw(rapdu) != 0x6283) {
                break;
            }
            if (durations.size() >= MAX_STEPS) {
                throw new IOException(
                        "card did not finish initialisation within " + MAX_STEPS + " steps");
            }
        }
        if (Apdu.sw(rapdu) != 0x9000) {
            throw new IOException("GET_IDENTITY failed: " + Apdu.status(rapdu));
        }
        if (out != null) {
            for (int i = 0; i < durations.size(); i++) {
                out.println(
                        "init step "
                                + (i + 1)
                                + "/"
                                + durations.size()
                                + ": "
                                + durations.get(i)
                                + " ms");
            }
        }
        return rapdu;
    }
}
