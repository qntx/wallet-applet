// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The {@code checkRealCardRecord} gate (architecture §10, release.yml): decides whether a {@code
 * realcard/<cap-sha256>.txt} record proves a passing real-card run of the CAP and tree being
 * checked. The checks run as a pure function over the record text so the {@code test} task can
 * exercise every rejection; {@link #main} wires it to the repository for the Gradle task.
 */
public final class RealCardCheck {
    private RealCardCheck() {}

    static final String INSTALL_CLASS = "org.qntx.card.real.InstallRealCardTest";

    /**
     * The violations of a {@code qntx-card real-card record 2} text: empty when the record names
     * {@code capSha}, the git trees {@code treeTests}/{@code treeApplet}, zero failures and exactly
     * {@code suite}'s classes in order, every verdict PASS or SKIP and every SKIP carrying a reason
     * line, with {@link #INSTALL_CLASS} a PASS.
     */
    public static List<String> violations(
            String record, String capSha, String treeTests, String treeApplet, List<String> suite) {
        List<String> problems = new ArrayList<>();
        String[] lines = record.split("\n", -1);
        if (lines.length == 0 || !lines[0].equals("qntx-card real-card record 2")) {
            problems.add("first line is not 'qntx-card real-card record 2'");
            return problems;
        }
        Map<String, String> fields = new LinkedHashMap<>();
        List<String[]> classes = new ArrayList<>();
        Map<String, Integer> skipReasons = new HashMap<>();
        String currentClass = null;
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty()) {
                break; // the timing table follows a blank line and is not checked
            }
            if (line.startsWith("  skip ")) {
                if (currentClass == null) {
                    problems.add("skip reason before the first class line: " + line);
                } else {
                    skipReasons.merge(currentClass, 1, Integer::sum);
                }
                continue;
            }
            if (line.startsWith("class ")) {
                String rest = line.substring(6);
                int sp = rest.lastIndexOf(' ');
                if (sp <= 0) {
                    problems.add("malformed class line: " + line);
                    continue;
                }
                String name = rest.substring(0, sp);
                classes.add(new String[] {name, rest.substring(sp + 1)});
                currentClass = name;
                continue;
            }
            int sp = line.indexOf(' ');
            if (sp <= 0) {
                problems.add("malformed header line: " + line);
                continue;
            }
            fields.put(line.substring(0, sp), line.substring(sp + 1));
            currentClass = null;
        }
        if (!capSha.equals(fields.get("cap"))) {
            problems.add("cap is " + fields.get("cap") + ", not the built " + capSha);
        }
        if (!treeTests.equals(fields.get("tree-tests"))) {
            problems.add("tree-tests is " + fields.get("tree-tests") + ", not " + treeTests);
        }
        if (!treeApplet.equals(fields.get("tree-applet"))) {
            problems.add("tree-applet is " + fields.get("tree-applet") + ", not " + treeApplet);
        }
        if (!"0".equals(fields.get("failed"))) {
            problems.add("failed is " + fields.get("failed") + ", not 0");
        }
        List<String> names = new ArrayList<>();
        for (String[] c : classes) {
            names.add(c[0]);
        }
        if (!names.equals(suite)) {
            problems.add(
                    "the class lines "
                            + names
                            + " are not realcard/suite.txt "
                            + suite
                            + " in order");
        }
        for (String[] c : classes) {
            String verdict = c[1];
            if (verdict.equals("PASS")) {
                continue;
            }
            if (verdict.equals("SKIP")) {
                if (skipReasons.getOrDefault(c[0], 0) < 1) {
                    problems.add("SKIP class " + c[0] + " has no skip reason line");
                }
                continue;
            }
            problems.add("class " + c[0] + " is " + verdict + ", not PASS or SKIP");
        }
        for (String name : skipReasons.keySet()) {
            if (!names.contains(name)) {
                problems.add("skip reason for a class with no class line: " + name);
            }
        }
        boolean installPass = false;
        for (String[] c : classes) {
            if (c[0].equals(INSTALL_CLASS)) {
                installPass = c[1].equals("PASS");
            }
        }
        if (!installPass) {
            problems.add(INSTALL_CLASS + " is not PASS");
        }
        return problems;
    }

    /**
     * {@code checkRealCardRecord <repoRoot> <capFile>}: locates {@code realcard/<sha256 of
     * capFile>.txt}, checks it against the built CAP and {@code git rev-parse HEAD:tests /
     * HEAD:applet} and exits non-zero listing every violation.
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("usage: RealCardCheck <repoRoot> <capFile>");
            System.exit(2);
        }
        Path root = Path.of(args[0]);
        Path capFile = Path.of(args[1]);
        String capSha =
                HexFormat.of()
                        .formatHex(
                                MessageDigest.getInstance("SHA-256")
                                        .digest(Files.readAllBytes(capFile)));
        Path record = root.resolve("realcard/" + capSha + ".txt");
        if (!record.toFile().isFile()) {
            System.err.println("no committed real-card record " + record);
            System.exit(1);
        }
        String text = Files.readString(record);
        List<String> suite = Files.readAllLines(root.resolve("realcard/suite.txt"));
        List<String> problems =
                violations(text, capSha, git(root, "HEAD:tests"), git(root, "HEAD:applet"), suite);
        if (!problems.isEmpty()) {
            System.err.println("real-card record " + record + " does not prove this build:");
            for (String p : problems) {
                System.err.println("  " + p);
            }
            System.exit(1);
        }
        System.out.println("real-card record realcard/" + capSha + ".txt proves this build");
    }

    private static String git(Path root, String object) throws IOException {
        Process p =
                new ProcessBuilder("git", "rev-parse", object)
                        .directory(root.toFile())
                        .redirectErrorStream(true)
                        .start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        try {
            if (p.waitFor() != 0) {
                throw new IOException("git rev-parse " + object + " failed: " + out);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("git rev-parse " + object + " interrupted");
        }
        return out;
    }
}
