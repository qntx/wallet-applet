// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import java.io.ByteArrayOutputStream;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Card-side GlobalPlatform registry (GP 2.3.1 §11.3.5): the ISD entry, loaded packages and
 * selectable applications, encoded for GET STATUS exactly the way card A answers GPPro (audit trace
 * {@code gp-list-before.out}: {@code E3 ‖ 4F aid ‖ 9F70 lifecycle ‖ C5 privileges ‖ [CE version] ‖
 * [84 module]* ‖ [C4 source] ‖ CC parent}).
 */
final class Registry {

    /** ISD entry, byte-identical to card A's GET STATUS 0x80 response. */
    static final byte[] ISD_ENTRY =
            HexFormat.of()
                    .parseHex(
                            "E3264F08A0000001510000009F700101C5039EFE80C407A0000001515350CC08A000000151000000");

    private static final byte[] ISD_AID = HexFormat.of().parseHex("A000000151000000");

    record Package(byte[] aid, byte[] version, List<byte[]> modules) {}

    record App(byte[] aid, byte[] packageAid) {}

    private final Map<String, Package> packages = new LinkedHashMap<>();
    private final Map<String, App> apps = new LinkedHashMap<>();

    void addPackage(byte[] aid, byte[] version, List<byte[]> modules) {
        packages.put(HexFormat.of().formatHex(aid), new Package(aid, version, modules));
    }

    boolean hasPackage(byte[] aid) {
        return packages.containsKey(HexFormat.of().formatHex(aid));
    }

    void addApp(byte[] aid, byte[] packageAid) {
        apps.put(HexFormat.of().formatHex(aid), new App(aid, packageAid));
    }

    boolean hasApp(byte[] aid) {
        return apps.containsKey(HexFormat.of().formatHex(aid));
    }

    byte[] isdStatus() {
        return ISD_ENTRY;
    }

    byte[] appStatus() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (App app : apps.values()) {
            // SELECTABLE 0x07, no privileges, parent ISD (GP 2.3.1 Table 11-31)
            ByteArrayOutputStream entry = new ByteArrayOutputStream();
            entry.writeBytes(tag(0x4F, app.aid()));
            entry.writeBytes(tag(0x9F70, new byte[] {0x07}));
            entry.writeBytes(tag(0xC5, new byte[] {0, 0, 0}));
            entry.writeBytes(tag(0xCC, ISD_AID));
            out.writeBytes(tag(0xE3, entry.toByteArray()));
        }
        return out.toByteArray();
    }

    byte[] packageStatus(boolean withModules) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Package pkg : packages.values()) {
            // LOADED 0x01, optional CE version and 84 modules (card A trace format)
            ByteArrayOutputStream entry = new ByteArrayOutputStream();
            entry.writeBytes(tag(0x4F, pkg.aid()));
            entry.writeBytes(tag(0x9F70, new byte[] {0x01}));
            entry.writeBytes(tag(0xCE, pkg.version()));
            if (withModules) {
                for (byte[] module : pkg.modules()) {
                    entry.writeBytes(tag(0x84, module));
                }
            }
            entry.writeBytes(tag(0xCC, ISD_AID));
            out.writeBytes(tag(0xE3, entry.toByteArray()));
        }
        return out.toByteArray();
    }

    private static byte[] tag(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (tag > 0xFF) {
            out.write((tag >> 8) & 0xFF);
        }
        out.write(tag & 0xFF);
        out.write(content.length);
        out.writeBytes(content);
        return out.toByteArray();
    }
}
