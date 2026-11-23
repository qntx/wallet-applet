// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * One JSON line per row of the suite in {@code <reports>/realcard/results.jsonl}, mirrored to
 * stdout. Simulator rows carry {@code "reader":"sim"} so a self-check can never be read as hardware
 * evidence.
 */
final class Results {
    private static PrintWriter writer;
    private static String reader;
    private static String cplc;
    private static boolean started;

    private Results() {}

    static synchronized void open(Reader r) {
        try {
            Path dir = Path.of(System.getProperty("qntx.reports", "build/reports"), "realcard");
            Files.createDirectories(dir);
            if (writer == null) {
                writer =
                        new PrintWriter(
                                Files.newBufferedWriter(
                                        dir.resolve("results.jsonl"),
                                        StandardOpenOption.CREATE,
                                        StandardOpenOption.TRUNCATE_EXISTING));
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        reader = r.describe();
        byte[] c = r.cplc();
        cplc = c == null ? null : Apdu.hex(c);
        if (!started) {
            started = true;
            row("run", "reader", "info", "opened");
        }
    }

    static synchronized void row(String row, String name, String verdict, String detail) {
        String line =
                "{\"row\":\""
                        + esc(row)
                        + "\",\"name\":\""
                        + esc(name)
                        + "\",\"verdict\":\""
                        + verdict
                        + "\",\"reader\":\""
                        + esc(reader)
                        + "\""
                        + (cplc != null ? ",\"cplc\":\"" + cplc + "\"" : "")
                        + (detail != null ? ",\"detail\":\"" + esc(detail) + "\"" : "")
                        + "}";
        writer.println(line);
        writer.flush();
        System.out.println(
                "REALCARD "
                        + row
                        + " | "
                        + name
                        + " | "
                        + verdict
                        + (detail != null ? " | " + detail : ""));
    }

    static synchronized void close() {
        if (writer != null) {
            writer.flush();
        }
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
