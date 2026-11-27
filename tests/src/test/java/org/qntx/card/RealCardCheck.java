// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * The {@code checkRealCardRecord} gate (architecture §10, release.yml): decides whether a {@code
 * realcard/<cap-sha256>.txt} record is consistent with the CAP and tree being checked. The checks
 * run as a pure function over the record text so the {@code test} task can exercise every
 * rejection; {@link #main} wires it to the repository for the Gradle task.
 */
public final class RealCardCheck {
    private RealCardCheck() {}

    static final String MAGIC = "qntx-card real-card record 3";

    static final String INSTALL_CLASS = "org.qntx.card.real.InstallRealCardTest";

    /** The only classes a release record may SKIP: the rows hardware still cannot host (§10). */
    static final List<String> SKIPPABLE =
            List.of(
                    "org.qntx.card.real.FlowRealCardTest",
                    "org.qntx.card.real.NvmRealCardTest",
                    "org.qntx.card.real.TearingRealCardTest");

    /**
     * The only {@code params} a release record may carry: the realCard task's release defaults —
     * 1000 differential signatures per scheme, the full §4.2 decision over 80 sequences, the whole
     * primitive table, no {@code -PrealCardKeep}, and all three CAPs built from the tree.
     */
    static final String RELEASE_PARAMS =
            "differential=1000 sequences=80 prims=all keep=false"
                    + " cap=tree memcap=tree probecap=tree";

    /** The record-3 header keys, each once, in this order (§10). */
    static final List<String> HEADER_KEYS =
            List.of(
                    "cap",
                    "commit",
                    "tree-tests",
                    "tree-applet",
                    "tree-host",
                    "tree-sim",
                    "tree-buildSrc",
                    "params",
                    "date",
                    "reader",
                    "atr",
                    "cplc",
                    "identify",
                    "apdu-log-sha256",
                    "passed",
                    "failed",
                    "skipped");

    /**
     * The violations of a {@code qntx-card real-card record 3} text: empty when the record names
     * {@code capSha}, the git {@code trees} (keys {@code tree-tests}, {@code tree-applet}, {@code
     * tree-host}, {@code tree-sim}, {@code tree-buildSrc}), a {@code commit} for which {@code
     * commitIsAncestor} holds, the {@link #RELEASE_PARAMS}, zero failures, at least one pass and
     * exactly {@code suite}'s classes in order, every verdict PASS or SKIP with SKIP confined to
     * {@link #SKIPPABLE} and every SKIP carrying a reason line, the {@code skipped} count equal to
     * the number of reason lines, and {@link #INSTALL_CLASS} a PASS.
     */
    public static List<String> violations(
            String record,
            String capSha,
            Map<String, String> trees,
            Predicate<String> commitIsAncestor,
            List<String> suite) {
        List<String> problems = new ArrayList<>();
        String[] lines = record.split("\n", -1);
        if (lines.length == 0 || !lines[0].equals(MAGIC)) {
            problems.add("first line is not '" + MAGIC + "'");
            return problems;
        }
        Map<String, String> fields = new LinkedHashMap<>();
        List<String[]> classes = new ArrayList<>();
        Map<String, Integer> skipReasons = new HashMap<>();
        int expected = 0;
        boolean classesStarted = false;
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
                classesStarted = true;
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
            String key = sp <= 0 ? line : line.substring(0, sp);
            if (classesStarted) {
                problems.add("header line after the class lines: " + line);
                continue;
            }
            if (sp <= 0) {
                problems.add("malformed header line: " + line);
                continue;
            }
            if (!HEADER_KEYS.contains(key)) {
                problems.add("unknown header key " + key);
                continue;
            }
            if (fields.containsKey(key)) {
                problems.add("duplicate header key " + key);
                continue;
            }
            if (!key.equals(HEADER_KEYS.get(expected))) {
                problems.add(
                        "header key "
                                + key
                                + " is out of order (expected "
                                + HEADER_KEYS.get(expected)
                                + ")");
                expected = HEADER_KEYS.indexOf(key) + 1;
            } else {
                expected++;
            }
            fields.put(key, line.substring(sp + 1));
            currentClass = null;
        }
        for (String key : HEADER_KEYS) {
            if (!fields.containsKey(key)) {
                problems.add("missing header key " + key);
            }
        }
        checkFormat(fields, problems, "cap", "[0-9a-f]{64}");
        checkFormat(fields, problems, "commit", "[0-9a-f]{40}");
        for (String key :
                List.of("tree-tests", "tree-applet", "tree-host", "tree-sim", "tree-buildSrc")) {
            checkFormat(fields, problems, key, "[0-9a-f]{40}");
        }
        String date = fields.get("date");
        if (date != null) {
            try {
                Instant.parse(date);
            } catch (DateTimeParseException e) {
                problems.add("date " + date + " is not an ISO-8601 instant");
            }
        }
        if (fields.containsKey("reader") && fields.get("reader").isBlank()) {
            problems.add("reader is empty");
        }
        checkFormat(fields, problems, "atr", "[0-9a-fA-F]+");
        checkFormat(fields, problems, "cplc", "[0-9a-fA-F]+");
        checkFormat(fields, problems, "identify", "[0-9a-fA-F]+");
        checkFormat(fields, problems, "apdu-log-sha256", "[0-9a-f]{64}");
        checkFormat(fields, problems, "passed", "[0-9]+");
        checkFormat(fields, problems, "failed", "[0-9]+");
        checkFormat(fields, problems, "skipped", "[0-9]+");

        if (!capSha.equals(fields.get("cap"))) {
            problems.add("cap is " + fields.get("cap") + ", not the built " + capSha);
        }
        for (Map.Entry<String, String> e : trees.entrySet()) {
            if (!e.getValue().equals(fields.get(e.getKey()))) {
                problems.add(
                        e.getKey() + " is " + fields.get(e.getKey()) + ", not " + e.getValue());
            }
        }
        String commit = fields.get("commit");
        if (commit != null && commit.matches("[0-9a-f]{40}") && !commitIsAncestor.test(commit)) {
            problems.add("commit " + commit + " is not an ancestor of HEAD");
        }
        if (!RELEASE_PARAMS.equals(fields.get("params"))) {
            problems.add(
                    "params is " + fields.get("params") + ", not the release " + RELEASE_PARAMS);
        }
        if (fields.containsKey("failed")
                && fields.get("failed").matches("[0-9]+")
                && Integer.parseInt(fields.get("failed")) != 0) {
            problems.add("failed is " + fields.get("failed") + ", not 0");
        }
        if (fields.containsKey("passed")
                && fields.get("passed").matches("[0-9]+")
                && Integer.parseInt(fields.get("passed")) < 1) {
            problems.add("passed is " + fields.get("passed") + ", less than 1");
        }
        int reasons = 0;
        for (int n : skipReasons.values()) {
            reasons += n;
        }
        if (fields.containsKey("skipped")
                && fields.get("skipped").matches("[0-9]+")
                && Integer.parseInt(fields.get("skipped")) != reasons) {
            problems.add(
                    "skipped is "
                            + fields.get("skipped")
                            + ", not the "
                            + reasons
                            + " skip reason lines");
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
            int n = skipReasons.getOrDefault(c[0], 0);
            if (verdict.equals("PASS")) {
                if (n > 0) {
                    problems.add("PASS class " + c[0] + " has a skip reason line");
                }
                continue;
            }
            if (verdict.equals("SKIP")) {
                if (!SKIPPABLE.contains(c[0])) {
                    problems.add("SKIP is allowed only for " + SKIPPABLE + ", not " + c[0]);
                }
                if (n < 1) {
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

    private static void checkFormat(
            Map<String, String> fields, List<String> problems, String key, String pattern) {
        String v = fields.get(key);
        if (v != null && !v.matches(pattern)) {
            problems.add(key + " " + v + " does not match " + pattern);
        }
    }

    /**
     * {@code checkRealCardRecord <repoRoot> <capFile>}: locates {@code realcard/<sha256 of
     * capFile>.txt}, checks it against the built CAP, the {@code HEAD:} trees of tests, applet,
     * host, sim and buildSrc, and {@code git merge-base --is-ancestor <commit> HEAD}, and exits
     * non-zero listing every violation.
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
        Map<String, String> trees = new LinkedHashMap<>();
        for (String dir : List.of("tests", "applet", "host", "sim", "buildSrc")) {
            trees.put("tree-" + dir, git(root, "rev-parse", "HEAD:" + dir));
        }
        List<String> problems =
                violations(
                        text,
                        capSha,
                        trees,
                        commit -> {
                            try {
                                return isAncestor(root, commit);
                            } catch (IOException e) {
                                throw new java.io.UncheckedIOException(e);
                            }
                        },
                        suite);
        if (!problems.isEmpty()) {
            System.err.println(
                    "real-card record " + record + " is not consistent with this build:");
            for (String p : problems) {
                System.err.println("  " + p);
            }
            System.exit(1);
        }
        System.out.println(
                "real-card record realcard/" + capSha + ".txt is consistent with this build");
    }

    private static String git(Path root, String... args) throws IOException {
        String[] cmd = new String[args.length + 1];
        cmd[0] = "git";
        System.arraycopy(args, 0, cmd, 1, args.length);
        Process p =
                new ProcessBuilder(cmd).directory(root.toFile()).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        try {
            if (p.waitFor() != 0) {
                throw new IOException("git " + String.join(" ", args) + " failed: " + out);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("git " + String.join(" ", args) + " interrupted");
        }
        return out;
    }

    private static boolean isAncestor(Path root, String commit) throws IOException {
        Process p =
                new ProcessBuilder("git", "merge-base", "--is-ancestor", commit, "HEAD")
                        .directory(root.toFile())
                        .redirectErrorStream(true)
                        .start();
        try {
            return p.waitFor() == 0;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("git merge-base --is-ancestor interrupted");
        }
    }
}
