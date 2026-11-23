// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tools;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import pro.javacard.capfile.AID;
import pro.javacard.capfile.CAPFile;
import pro.javacard.gp.GPData.LFDBH;
import pro.javacard.gp.GPRegistryEntry.Privilege;

/**
 * {@code qntx-card install}: protocol.md §14.3 steps 2, 3 and 6 — hash-check and load the CAP,
 * install both applets, verify the registry against the batch baseline, in the order the brief
 * mandates; the first failure stops the run with a one-line reason.
 */
@Command(name = "install", description = "Load and install the qntx CAP on a card.")
final class InstallCmd implements Callable<Integer> {

    private static final byte[] PACKAGE_AID = HexFormat.of().parseHex("F0716E747800");
    private static final byte[] WALLET_AID = HexFormat.of().parseHex("F0716E74780101");
    private static final byte[] NDEF_CLASS_AID = HexFormat.of().parseHex("F0716E74780201");
    private static final byte[] NDEF_AID = HexFormat.of().parseHex("D2760000850101");

    private final Ctx ctx;

    InstallCmd(Ctx ctx) {
        this.ctx = ctx;
    }

    @Mixin Transport transport;

    @Option(names = "--cap", required = true, description = "CAP file to load")
    Path cap;

    @Option(
            names = "--cap-sha256",
            required = true,
            description = "expected SHA-256 of the CAP file, hex")
    String capSha256;

    @Option(names = "--scp", required = true, description = "03 or 02-55")
    String scp;

    @Option(names = "--baseline", required = true, description = "admission registry baseline file")
    Path baseline;

    @Option(names = "--ndef", required = true, description = "NDEF message, hex, 1-100 bytes")
    String ndef;

    @Override
    public Integer call() {
        try {
            return run();
        } catch (Exception e) {
            return ctx.fail("install: " + RegistryCmd.message(e));
        }
    }

    private int run() throws Exception {
        // §14.3 step 2: the load file hash is checked before any card contact
        byte[] capBytes = Files.readAllBytes(cap);
        String actual =
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(capBytes));
        if (!actual.equalsIgnoreCase(capSha256.trim())) {
            return ctx.fail("install: CAP SHA-256 does not match --cap-sha256");
        }
        CAPFile capFile = CAPFile.fromBytes(capBytes);
        if (!Arrays.equals(capFile.getPackageAID().getBytes(), PACKAGE_AID)) {
            return ctx.fail("install: CAP package AID is not F0716E747800");
        }
        var applets = new TreeSet<String>();
        for (AID applet : capFile.getAppletAIDs()) {
            applets.add(applet.toString());
        }
        if (!applets.equals(new TreeSet<>(List.of("F0716E74780101", "F0716E74780201")))) {
            return ctx.fail("install: CAP applets are not F0716E74780101 and F0716E74780201");
        }
        byte[] ndefMessage;
        try {
            ndefMessage = HexFormat.of().parseHex(ndef.trim());
        } catch (IllegalArgumentException e) {
            return ctx.fail("install: --ndef is not hex");
        }
        if (ndefMessage.length < 1 || ndefMessage.length > 100) {
            return ctx.fail("install: --ndef message must be 1-100 bytes");
        }
        var baselineLines = RegistryText.read(baseline);

        try (Transport t = transport) {
            var session =
                    Gp.open(
                            transport.open(),
                            Gp.isdKeys(ctx.env().apply(Gp.ISD_KEY_ENV)),
                            Gp.scp(scp));
            // §14.3 step 6: the registry must equal the admission baseline before the load
            if (!RegistryText.lines(session.getRegistry()).equals(baselineLines)) {
                return ctx.fail("install: registry does not equal the baseline");
            }
            session.loadCapFile(capFile, null, LFDBH.SHA256);
            var pkg = new AID(PACKAGE_AID);
            session.installAndMakeSelectable(
                    pkg,
                    new AID(WALLET_AID),
                    new AID(WALLET_AID),
                    EnumSet.noneOf(Privilege.class),
                    null);
            session.installAndMakeSelectable(
                    pkg,
                    new AID(NDEF_CLASS_AID),
                    new AID(NDEF_AID),
                    EnumSet.noneOf(Privilege.class),
                    c9(ndefMessage));
            // step 6 again: the registry is the baseline plus exactly the load file and the
            // two instances (PKG LOADED 0x01, APP SELECTABLE 0x07 per the card A formats)
            if (!RegistryText.lines(session.getRegistry())
                    .equals(RegistryText.plusCap(baselineLines))) {
                return ctx.fail("install: registry after install is not the baseline plus the CAP");
            }
            ctx.out().println("installed " + capFile.getPackageAID());
            return 0;
        }
    }

    /**
     * Explicitly encoded install parameters {@code C9 ‖ BER length ‖ msg}. GlobalPlatformPro's
     * {@code buildInstallData} (GPSession.java, #360 fix-up) wraps plain params in C9 itself, but
     * only after parsing them as TLV and skipping the wrap when a C9 tag is found anywhere in the
     * parse — an NDEF message that happens to parse as TLV containing C9 would then reach the
     * applet unwrapped or truncated. Encoding C9 here makes the wire bytes independent of what the
     * message looks like.
     */
    private static byte[] c9(byte[] message) {
        var out = new ByteArrayOutputStream();
        out.write(0xC9);
        if (message.length < 0x80) {
            out.write(message.length);
        } else if (message.length <= 0xFF) {
            out.write(0x81);
            out.write(message.length);
        } else {
            out.write(0x82);
            out.write(message.length >>> 8);
            out.write(message.length);
        }
        out.writeBytes(message);
        return out.toByteArray();
    }
}
