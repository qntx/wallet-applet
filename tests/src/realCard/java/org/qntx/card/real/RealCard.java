// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.TerminalFactory;

/**
 * The physical-card transport of the real-card suite (architecture.md §10): short APDUs over PC/SC
 * to the reader named by {@code -PrealCard}, every exchange logged to {@code <out>/apdu.log}, plus
 * the card-management calls that must go through the audited GlobalPlatformPro wrapper (never
 * through this code with keys).
 */
public final class RealCard implements AutoCloseable {
    /** Card A's identity; any other ATR stops the suite (handoff "already settled"). */
    public static final String EXPECTED_ATR = "3B8580018073C821100E";

    /** §6 SELECT of the production and memprobe builds (same instance AID). */
    public static final byte[] SELECT = HexFormat.of().parseHex("00A4040007F0716E7478010100");

    /** SELECT of the admission probe instance. */
    public static final byte[] SELECT_PROBE = HexFormat.of().parseHex("00A4040007F0716E7478FF0100");

    /** §2 package AID (production and memprobe builds). */
    public static final String PACKAGE_AID = "F0716E747800";

    /** §2 instance AID. */
    public static final String APPLET_AID = "F0716E74780101";

    /** Admission probe package/instance AIDs (test-only, §14.3). */
    public static final String PROBE_PACKAGE_AID = "F0716E7478FF";

    public static final String PROBE_APPLET_AID = "F0716E7478FF01";

    static {
        // macOS JDKs do not always find the framework on their own
        java.io.File pcsc =
                new java.io.File("/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC");
        if (pcsc.isFile()) {
            System.setProperty("sun.security.smartcardio.library", pcsc.getAbsolutePath());
        }
    }

    /** A response plus the wall-clock time of the transmit call only. */
    public record Timed(byte[] rapdu, long nanos) {}

    private final String reader;
    private final String gp;
    private final Path out;
    private Card card;
    private int gpSeq;
    private int apduSeq;
    private Set<String> baselineAids;

    private RealCard(String reader, String gp, Path out) {
        this.reader = reader;
        this.gp = gp;
        this.out = out;
    }

    /** Connects ({@code T=*}) to the reader named by {@code qntx.reader} and checks the ATR. */
    public static RealCard connect() throws Exception {
        String reader = System.getProperty("qntx.reader", "");
        String gp = System.getProperty("qntx.gp", "");
        Path out = Path.of(System.getProperty("qntx.realcard.out", "build/realcard"));
        Files.createDirectories(out);
        RealCard rc = new RealCard(reader, gp, out);
        rc.open();
        return rc;
    }

    private void open() throws Exception {
        TerminalFactory factory = TerminalFactory.getDefault();
        CardTerminals terminals = factory.terminals();
        CardTerminal found = null;
        for (CardTerminal t : terminals.list()) {
            if (t.getName().equals(reader)) {
                found = t;
                break;
            }
        }
        if (found == null) {
            List<String> names = new ArrayList<>();
            for (CardTerminal t : terminals.list()) {
                names.add(t.getName());
            }
            throw new IllegalStateException("reader '" + reader + "' not found; have " + names);
        }
        card = found.connect("*");
        checkAtr();
    }

    /** The card's ATR as uppercase hex. */
    public String atr() {
        return HexFormat.of().formatHex(card.getATR().getBytes()).toUpperCase();
    }

    private void checkAtr() {
        String atr = atr();
        if (!atr.equals(EXPECTED_ATR)) {
            throw new IllegalStateException(
                    "card ATR " + atr + " is not card A (" + EXPECTED_ATR + ") — stopping");
        }
    }

    /** Sends {@code apdu} and returns the raw R-APDU including the status word. */
    public byte[] transmit(byte[] apdu) {
        return timed(apdu).rapdu();
    }

    /** {@link #transmit} plus the nanoseconds around the transmit call itself (§16.6). */
    public Timed timed(byte[] apdu) {
        try {
            long t0 = System.nanoTime();
            byte[] rapdu = card.getBasicChannel().transmit(new CommandAPDU(apdu)).getBytes();
            long nanos = System.nanoTime() - t0;
            log(apdu, rapdu);
            if (apdu.length >= 5 && apdu[0] == 0 && apdu[1] == (byte) 0xA4) {
                // a select-by-name deselects the wallet; the fixture tracks the D2 epoch
                Fixture.noteSelect(apdu);
            }
            return new Timed(rapdu, nanos);
        } catch (javax.smartcardio.CardException e) {
            throw new IllegalStateException("transmit failed: " + e, e);
        }
    }

    private void log(byte[] apdu, byte[] rapdu) {
        try {
            String line =
                    String.format(
                            "#%04d > %s%n#%04d < %s%n",
                            apduSeq,
                            HexFormat.of().formatHex(apdu).toUpperCase(),
                            apduSeq,
                            HexFormat.of().formatHex(rapdu).toUpperCase());
            apduSeq++;
            Files.writeString(
                    out.resolve("apdu.log"),
                    line,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * A field power cycle ({@code disconnect(true)} + reconnect) — the suite's "power-up" of the
     * RNG reset check and its cold-cache reset; re-checks the ATR.
     */
    public void reset() throws Exception {
        card.disconnect(true);
        open();
        Fixture.noteReset();
    }

    /** Runs the GP wrapper; output lands in {@code <out>/gp-<seq>-<label>.log}. */
    public String gp(String label, String... args) throws Exception {
        if (gp.isEmpty()) {
            throw new IllegalStateException("no GP wrapper: pass -PrealCardGp=<gp.sh>");
        }
        List<String> cmd = new ArrayList<>();
        cmd.add(gp);
        cmd.addAll(List.of(args));
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String output = new String(p.getInputStream().readAllBytes());
        int code = p.waitFor();
        Path log = out.resolve(String.format("gp-%02d-%s.log", gpSeq++, label));
        Files.writeString(log, output);
        if (code != 0) {
            // surface the card status word so a failure names e.g. the 0x6F00 of a refused
            // INSTALL without opening the log first
            java.util.regex.Matcher m =
                    java.util.regex.Pattern.compile("0x[0-9A-Fa-f]{4}").matcher(output);
            String sw = "";
            while (m.find()) {
                sw = " — last card status " + m.group();
            }
            throw new IllegalStateException(
                    "gp " + label + " exited " + code + sw + " — see " + log);
        }
        return output;
    }

    /** The set of {@code PKG:}/{@code APP:} AIDs in a {@code -l} listing. */
    private static Set<String> aidsOf(String listing) {
        Set<String> aids = new TreeSet<>();
        for (String line : listing.split("\n")) {
            line = line.trim();
            if (line.startsWith("PKG:") || line.startsWith("APP:") || line.startsWith("ISD:")) {
                String[] parts = line.substring(4).trim().split("[ \t]");
                if (parts.length > 0 && !parts[0].isEmpty()) {
                    aids.add(parts[0].toUpperCase());
                }
            }
        }
        return aids;
    }

    /** Every AID the suite may put on the card — never part of the baseline. */
    private static final Set<String> OUR_AIDS =
            Set.of(PACKAGE_AID, APPLET_AID, PROBE_PACKAGE_AID, PROBE_APPLET_AID);

    /**
     * The first listing of this run minus our own AIDs — the baseline every reinstall is checked
     * against. The listing may already contain qntx leftovers from a previous suite; those are
     * deleted by {@link #reinstall} and must not be expected back.
     */
    private Set<String> baseline() throws Exception {
        if (baselineAids == null) {
            Set<String> aids = aidsOf(gp("list", "-l"));
            aids.removeAll(OUR_AIDS);
            baselineAids = aids;
        }
        return baselineAids;
    }

    /**
     * Deletes every qntx AID present in {@code before}. Instances go first: a package delete is
     * refused while an instance is still active (6985). If an instance delete itself is refused as
     * "still active" — card A keeps the flag once a used applet was never deselected — the package
     * delete still cascades it, so a failed instance delete is not fatal.
     */
    private void deletePresentAids(Set<String> before) throws Exception {
        for (String aid : List.of(APPLET_AID, PROBE_APPLET_AID, PACKAGE_AID, PROBE_PACKAGE_AID)) {
            if (!before.contains(aid)) {
                continue;
            }
            try {
                gp("delete", "--delete", aid);
            } catch (IllegalStateException first) {
                try {
                    gp("delete", "--delete", aid, "--force");
                } catch (IllegalStateException forced) {
                    // a stuck instance goes away with the cascading package delete below
                    if (!aid.equals(PACKAGE_AID) && !aid.equals(PROBE_PACKAGE_AID)) {
                        continue;
                    }
                    throw forced;
                }
            }
        }
    }

    /** Deletes every qntx package/instance on the card — the teardown end state (§14.3). */
    public void deleteOurs() throws Exception {
        deletePresentAids(aidsOf(gp("list", "-l")));
    }

    /**
     * Deletes both qntx packages that are present, installs {@code cap} and asserts the registry is
     * the baseline plus exactly {@code extraAids} (architecture.md §14.3 step 6). Deleting both
     * keeps the check valid when switching between the production/memprobe and probe packages.
     */
    public void reinstall(Path cap, String packageAid, String... extraAids) throws Exception {
        Set<String> before = aidsOf(gp("list", "-l"));
        baseline();
        deletePresentAids(before);
        gp("install", "--install", cap.toAbsolutePath().toString());
        Set<String> after = aidsOf(gp("list", "-l"));
        Set<String> expected = new TreeSet<>(baselineAids);
        expected.addAll(List.of(extraAids));
        if (!after.equals(expected)) {
            Set<String> missing = new TreeSet<>(expected);
            missing.removeAll(after);
            Set<String> extra = new TreeSet<>(after);
            extra.removeAll(expected);
            throw new IllegalStateException(
                    "registry drift: missing " + missing + ", extra " + extra);
        }
    }

    /** Sends {@code apdu} and requires {@code 9000}, returning the response data. */
    public byte[] ok(byte[] apdu) {
        byte[] r = transmit(apdu);
        int sw = sw(r);
        if (sw != 0x9000) {
            throw new IllegalStateException(
                    "expected 9000, got "
                            + String.format("%04X", sw)
                            + " for "
                            + HexFormat.of().formatHex(apdu).toUpperCase());
        }
        return java.util.Arrays.copyOf(r, r.length - 2);
    }

    public static int sw(byte[] rapdu) {
        return ((rapdu[rapdu.length - 2] & 0xFF) << 8) | (rapdu[rapdu.length - 1] & 0xFF);
    }

    @Override
    public void close() {
        if (card != null) {
            try {
                card.disconnect(false);
            } catch (javax.smartcardio.CardException ignored) {
            }
        }
    }
}
