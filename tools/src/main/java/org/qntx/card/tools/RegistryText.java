// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tools;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import pro.javacard.gp.GPRegistry;
import pro.javacard.gp.GPRegistryEntry;

/**
 * The registry text format used for batch baselines: one sorted line per entry, {@code <ISD|SSD|
 * APP|PKG> <AID uppercase hex> <lifecycle 2 hex>}, LF-separated.
 */
final class RegistryText {

    private RegistryText() {}

    static List<String> lines(GPRegistry registry) {
        List<String> lines = new ArrayList<>();
        for (GPRegistryEntry entry : registry) {
            lines.add(
                    entry.getType().name()
                            + " "
                            + entry.getAID().toString().toUpperCase(Locale.ROOT)
                            + " "
                            + String.format("%02X", entry.getLifeCycle() & 0xFF));
        }
        lines.sort(String::compareTo);
        return lines;
    }

    static List<String> read(Path baseline) throws IOException {
        List<String> lines = new ArrayList<>();
        for (String line : Files.readAllLines(baseline)) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                lines.add(trimmed);
            }
        }
        lines.sort(String::compareTo);
        return lines;
    }

    /**
     * The admission baseline plus exactly the qntx CAP: {@code PKG F0716E747800} LOADED (0x01) and
     * the wallet/NDEF instances SELECTABLE (0x07) — GP 2.3.1 Table 11-3/11-7 lifecycle values, the
     * same bytes the card A trace and the simulator return.
     */
    static List<String> plusCap(List<String> baseline) {
        List<String> expected = new ArrayList<>(baseline);
        expected.add("PKG F0716E747800 01");
        expected.add("APP F0716E74780101 07");
        expected.add("APP D2760000850101 07");
        expected.sort(String::compareTo);
        return expected;
    }
}
