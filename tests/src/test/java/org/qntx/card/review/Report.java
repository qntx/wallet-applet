// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * The conformance record: one row per matrix cell (or sub-case), appended to conformance.csv as it
 * is produced so a crash mid-run still leaves a complete trace of what ran. The summary (counts +
 * every DIVERGE row with detail) is written at the end.
 */
final class Report {

    static final class Row {
        final String cell, setup, command, expected, observed, verdict, note;

        Row(
                String cell,
                String setup,
                String command,
                String expected,
                String observed,
                String verdict,
                String note) {
            this.cell = cell;
            this.setup = setup;
            this.command = command;
            this.expected = expected;
            this.observed = observed;
            this.verdict = verdict;
            this.note = note;
        }
    }

    private final Path csvPath;
    private final Path summaryPath;
    private final List<Row> rows = new ArrayList<>();
    private PrintWriter csv;

    Report(Path dir) {
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        this.csvPath = dir.resolve("conformance.csv");
        this.summaryPath = dir.resolve("conformance-summary.md");
        try {
            csv = new PrintWriter(Files.newBufferedWriter(csvPath, StandardCharsets.UTF_8));
            csv.println("cell,setup,command,expected,observed,verdict,note");
            csv.flush();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return '"' + s.replace("\"", "\"\"") + '"';
        }
        return s;
    }

    /** PASS row: observed equals expected. */
    void pass(String cell, String setup, String command, String expected, String observed) {
        row(
                cell,
                setup,
                command,
                expected,
                observed,
                expected.equals(observed) ? "PASS" : "DIVERGE",
                "");
    }

    void diverge(
            String cell,
            String setup,
            String command,
            String expected,
            String observed,
            String note) {
        row(cell, setup, command, expected, observed, "DIVERGE", note);
    }

    void skip(String cell, String setup, String command, String expected, String note) {
        row(cell, setup, command, expected, "", "NOT_CHECKABLE", note);
    }

    void row(
            String cell,
            String setup,
            String command,
            String expected,
            String observed,
            String verdict,
            String note) {
        Row r = new Row(cell, setup, command, expected, observed, verdict, note);
        rows.add(r);
        csv.println(
                String.join(
                        ",",
                        esc(cell),
                        esc(setup),
                        esc(command),
                        esc(expected),
                        esc(observed),
                        esc(verdict),
                        esc(note)));
        csv.flush();
    }

    void finish(String header) {
        csv.close();
        StringBuilder sb = new StringBuilder();
        sb.append("# Conformance summary\n\n").append(header).append("\n\n");
        int pass = 0, diverge = 0, nc = 0;
        for (Row r : rows) {
            if (r.verdict.equals("PASS")) {
                pass++;
            } else if (r.verdict.equals("DIVERGE")) {
                diverge++;
            } else {
                nc++;
            }
        }
        sb.append("Rows: ")
                .append(rows.size())
                .append(" — PASS ")
                .append(pass)
                .append(", DIVERGE ")
                .append(diverge)
                .append(", NOT_CHECKABLE ")
                .append(nc)
                .append("\n\n");
        if (diverge > 0) {
            sb.append("## Divergences\n\n");
            for (Row r : rows) {
                if (r.verdict.equals("DIVERGE")) {
                    sb.append("- **")
                            .append(r.cell)
                            .append("** (")
                            .append(r.setup)
                            .append(")\n")
                            .append("  - command: ")
                            .append(r.command)
                            .append("\n")
                            .append("  - expected: ")
                            .append(r.expected)
                            .append("\n")
                            .append("  - observed: ")
                            .append(r.observed)
                            .append("\n");
                    if (!r.note.isEmpty()) {
                        sb.append("  - note: ").append(r.note).append("\n");
                    }
                }
            }
        }
        try {
            Files.writeString(summaryPath, sb.toString(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
