// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipInputStream;
import javacard.framework.Applet;
import org.qntx.card.NdefApplet;
import org.qntx.card.WalletApplet;

/**
 * The simulated issuer security domain (architecture.md §8): a test double of the GP 2.3.1 card
 * manager card A runs, implementing exactly the commands the release tools issue — SELECT,
 * INITIALIZE UPDATE / EXTERNAL AUTHENTICATE over {@link Scp03} (SCP03, {@code i = 0x00}), GET DATA
 * (CPLC), GET STATUS, INSTALL [for load] + LOAD with component verification against the embedded
 * CAP, INSTALL [for install and make selectable], and PUT KEY. Wire formats mirror
 * GlobalPlatformPro's host side; the card-side inverses cite the GPPro source lines that produce
 * each byte pattern.
 */
final class Isd {

    /** Card A's ISD AID and SELECT FCI (audit trace gp-list-before.out). */
    static final byte[] AID = HexFormat.of().parseHex("A000000151000000");

    static final byte[] FCI = HexFormat.of().parseHex("6F108408A000000151000000A5049F6501FF");

    private static final byte[] WALLET_CLASS_AID = HexFormat.of().parseHex("F0716E74780101");
    private static final byte[] NDEF_CLASS_AID = HexFormat.of().parseHex("F0716E74780201");
    private static final byte[] SELECT_ALL = {0x4F, 0x00};
    private static final byte[] EMPTY = new byte[0];

    // optional CAP components (JCVM 3.0.5 §6.3): GPPro's CAPFile.getCode() emits neither
    private static final String[] OPTIONAL_COMPONENTS = {"Descriptor", "Debug"};

    private final Card card;
    private final Registry registry = new Registry();
    private final Scp03 channel = new Scp03();
    private final byte[] cplc;

    /**
     * Diversification data returned in INITIALIZE UPDATE (Amendment D §6.2.1): a real card's KDD
     * carries its serial, so the test double fabricates one from its own CPLC bytes rather than
     * replaying card A's.
     */
    private final byte[] kdd;

    private boolean selected;

    private byte[] pendingPackage;
    private byte[] pendingHash;
    private final ByteArrayOutputStream loadBlock = new ByteArrayOutputStream();
    private int loadSeq;

    Isd(Card card, int index, boolean populated) {
        this.card = card;
        cplc = cplc(index);
        kdd = kdd(cplc);
        // the ISD is the default-selected application after power-up, like a real
        // GP card manager, so GET DATA and INITIALIZE UPDATE work without a SELECT
        selected = true;
        if (populated) {
            registry.addPackage(cap.packageAid(), cap.packageVersion(), cap.moduleAids());
        }
    }

    /**
     * Registers an installed applet instance (server card setup and INSTALL both go through it).
     */
    void registerApp(byte[] instanceAid) {
        registry.addApp(instanceAid, cap.packageAid());
    }

    Card card() {
        return card;
    }

    /**
     * One command APDU to the card manager: an ISO SELECT by name routes to the ISD (empty or its
     * AID) or to jcardsim (anything else); while the ISD is selected everything else is a card
     * manager command. Any SELECT is a new channel context: the secure channel closes (Amendment D
     * §6.2.3.4).
     */
    byte[] transmit(byte[] command) {
        if (command.length >= 4 && isSelect(command)) {
            byte[] aid = selectAid(command);
            channel.close();
            if (aid.length == 0 || Arrays.equals(aid, AID)) {
                card.deselectApplet();
                selected = true;
                return ok(FCI);
            }
            selected = false;
            return card.transmit(command);
        }
        return selected ? process(command) : card.transmit(command);
    }

    /** Power cycle: the secure channel dies and the default-selected ISD takes the channel. */
    void reset() {
        selected = true;
        channel.close();
    }

    private byte[] process(byte[] command) {
        if (command.length < 4) {
            return sw(0x6D00);
        }
        int cla = command[0] & 0xFF;
        int ins = command[1] & 0xFF;
        int p1 = command[2] & 0xFF;
        int p2 = command[3] & 0xFF;
        if (!channel.isOpen()) {
            if (cla == 0x80 && ins == 0x50) {
                return initUpdate(p1, p2, data(command));
            }
            if (cla == 0x84 && ins == 0x82) {
                return extAuth(p1, data(command));
            }
            if ((cla == 0x00 || cla == 0x80) && ins == 0xCA) {
                return getData(p1, p2);
            }
            // Everything the tools do besides GET DATA needs the channel open (GP 2.3.1 §11.3.4)
            if (cla == 0x84 || ins == 0xE6 || ins == 0xE8 || ins == 0xF2 || ins == 0xD8) {
                channel.close();
                return sw(0x6982);
            }
            return sw(0x6D00);
        }
        if (cla != 0x84) {
            channel.close();
            return sw(0x6982);
        }
        byte[] inner;
        try {
            inner = channel.unwrap(command, 8);
        } catch (IllegalArgumentException e) {
            // valid C-MAC over undecryptable padding is a data error, not an auth failure
            channel.close();
            return sw(0x6A80);
        }
        if (inner == null) {
            channel.close();
            return sw(0x6982);
        }
        return dispatch(inner);
    }

    /** One unwrapped secured command: {@code ins ‖ p1 ‖ p2 ‖ data}. */
    private byte[] dispatch(byte[] inner) {
        int ins = inner[0] & 0xFF;
        int p1 = inner[1] & 0xFF;
        int p2 = inner[2] & 0xFF;
        byte[] data = Arrays.copyOfRange(inner, 3, inner.length);
        return switch (ins) {
            case 0xE6 -> install(p1, data);
            case 0xE8 -> load(p1, p2, data);
            case 0xF2 -> getStatus(p1, p2, data);
            case 0xD8 -> putKey(p1, p2, data);
            case 0xCA -> getData(p1, p2);
            case 0xA4 -> {
                // A secured SELECT ends the channel and selects like an open SELECT
                channel.close();
                selected = false;
                byte[] select = new byte[5 + data.length];
                select[1] = (byte) 0xA4;
                select[2] = 0x04;
                select[4] = (byte) data.length;
                System.arraycopy(data, 0, select, 5, data.length);
                yield transmit(select);
            }
            default -> sw(0x6D00);
        };
    }

    private byte[] initUpdate(int kvn, int p2, byte[] hostChallenge) {
        if (p2 != 0) {
            return sw(0x6A86);
        }
        if (hostChallenge.length != 8) {
            return sw(0x6700);
        }
        byte[] response = channel.initUpdate(kdd, kvn, hostChallenge);
        return response == null ? sw(0x6A88) : ok(response);
    }

    private byte[] extAuth(int securityLevel, byte[] data) {
        return channel.extAuth(data, securityLevel) ? sw(0x9000) : sw(0x6982);
    }

    /**
     * GET DATA CPLC: {@code 9F7F 2A ‖ 42 bytes} (GP 2.3.1 Table 11-41; GPData.getCPLC). The bytes
     * are fabricated — card A's real CPLC is not public — but the IC serial at offset 12 differs
     * per simulated card.
     */
    private byte[] getData(int p1, int p2) {
        if ((p1 << 8 | p2) != 0x9F7F) {
            return sw(0x6A88);
        }
        byte[] out = new byte[3 + cplc.length];
        out[0] = (byte) 0x9F;
        out[1] = 0x7F;
        out[2] = (byte) cplc.length;
        System.arraycopy(cplc, 0, out, 3, cplc.length);
        return ok(out);
    }

    private byte[] getStatus(int p1, int p2, byte[] data) {
        if (p2 != 0x02 && p2 != 0x03) {
            return sw(0x6A86);
        }
        if (!Arrays.equals(data, SELECT_ALL)) {
            return sw(0x6A80);
        }
        byte[] entries =
                switch (p1) {
                    case 0x80 -> registry.isdStatus();
                    case 0x40 -> registry.appStatus();
                    case 0x20 -> registry.packageStatus(false);
                    case 0x10 -> registry.packageStatus(true);
                    default -> null;
                };
        if (entries == null) {
            return sw(0x6A86);
        }
        return entries.length == 0 ? sw(0x6A88) : ok(entries);
    }

    private byte[] install(int p1, byte[] data) {
        return switch (p1) {
            case 0x02 -> installForLoad(data);
            case 0x0C -> installAndMakeSelectable(data);
            default -> sw(0x6A80);
        };
    }

    /**
     * INSTALL [for load]: {@code aid ‖ sdAid ‖ lfdbh ‖ params}, each length-prefixed (GPPro
     * GPSession.loadCapFile, GPSession.java:589-608). Only the first three fields matter to the
     * card manager.
     */
    private byte[] installForLoad(byte[] data) {
        int[] pos = {0};
        byte[] pkg = field(data, pos);
        byte[] sd = field(data, pos);
        byte[] hash = field(data, pos);
        if (pkg == null || sd == null || hash == null || pkg.length == 0) {
            return sw(0x6A80);
        }
        if (pendingPackage != null || registry.hasPackage(pkg)) {
            return sw(0x6985);
        }
        pendingPackage = pkg;
        pendingHash = hash.length == 0 ? null : hash;
        loadBlock.reset();
        loadSeq = 0;
        return sw(0x9000);
    }

    /**
     * LOAD: blocks numbered by P2, last block {@code P1 & 0x80} (GP 2.3.1 §11.6.2.3). The assembled
     * {@code C4} value must be the byte-identical concatenation of every component of the CAP
     * embedded in this jar except Descriptor and Debug — the exact byte sequence GPPro's {@code
     * CAPFile.getCode()} produces — and, when INSTALL [for load] carried an LFDBH, its SHA-256 must
     * match.
     */
    private byte[] load(int p1, int seq, byte[] data) {
        if (pendingPackage == null) {
            return sw(0x6985);
        }
        if (seq != loadSeq) {
            return sw(0x6A80);
        }
        loadBlock.writeBytes(data);
        loadSeq++;
        if ((p1 & 0x80) == 0) {
            return sw(0x9000);
        }
        byte[] pkg = pendingPackage;
        byte[] hash = pendingHash;
        pendingPackage = null;
        pendingHash = null;
        try {
            byte[] code = loadFileData(loadBlock.toByteArray());
            if (code == null || !cap.isLoad(code)) {
                return sw(0x6A80);
            }
            if (hash != null && !Arrays.equals(sha256(code), hash)) {
                return sw(0x6A80);
            }
            registry.addPackage(pkg, cap.packageVersion(), cap.moduleAids());
            return sw(0x9000);
        } finally {
            loadBlock.reset();
        }
    }

    /**
     * INSTALL [for install and make selectable]: {@code package ‖ class ‖ instance ‖ privileges ‖
     * params} (GPSession.buildInstallData, GPSession.java:657-698); the applet's install data is
     * the content of the {@code C9} TLV inside params.
     */
    private byte[] installAndMakeSelectable(byte[] data) {
        int[] pos = {0};
        byte[] pkg = field(data, pos);
        byte[] classAid = field(data, pos);
        byte[] instanceAid = field(data, pos);
        byte[] privileges = field(data, pos);
        // parameters are a BER-LV, then an optional empty install token (GP 2.3.1 Table 11-33;
        // GPPro's buildInstallData ends with encodeLength(params) ‖ params, GPSession.java:699-701)
        byte[] params = lv(data, pos);
        byte[] token = pos[0] == data.length ? EMPTY : lv(data, pos);
        if (pkg == null
                || classAid == null
                || instanceAid == null
                || privileges == null
                || params == null
                || token == null
                || token.length != 0
                || pos[0] != data.length) {
            return sw(0x6A80);
        }
        if (!registry.hasPackage(pkg)) {
            return sw(0x6A80);
        }
        Class<? extends Applet> appletClass =
                Arrays.equals(classAid, WALLET_CLASS_AID)
                        ? WalletApplet.class
                        : Arrays.equals(classAid, NDEF_CLASS_AID) ? NdefApplet.class : null;
        if (appletClass == null || instanceAid.length == 0) {
            return sw(0x6A80);
        }
        if (registry.hasApp(instanceAid)) {
            return sw(0x6985);
        }
        for (byte privilege : privileges) {
            if (privilege != 0) {
                return sw(0x6A80);
            }
        }
        try {
            card.install(instanceAid, appletClass, c9Value(params));
        } catch (RuntimeException e) {
            return sw(0x6A80);
        }
        registry.addApp(instanceAid, pkg);
        return sw(0x9000);
    }

    /**
     * PUT KEY replacing all three AES keys in one command ({@code 80 D8 kvn 81}), as GPPro's {@code
     * putKeys(keys, true)} encodes it (GPSession.java:921-953); the response is {@code kvn ‖ three
     * KCVs}.
     */
    private byte[] putKey(int p1, int p2, byte[] data) {
        if (p2 != 0x81 || data.length == 0 || (data[0] & 0xFF) != p1) {
            return sw(0x6A80);
        }
        byte[][] keys = channel.putKeys(data);
        return keys == null ? sw(0x6A80) : ok(channel.kcvs(keys));
    }

    /**
     * The {@code C4} component of an assembled load block; a leading {@code E2} DAP block (GP 2.2.1
     * Table 11-58) is skipped. Anything else is malformed.
     */
    private static byte[] loadFileData(byte[] block) {
        int pos = 0;
        if (pos + 3 <= block.length && (block[pos] & 0xFF) == 0xE2) {
            int len = berLength(block, pos + 1);
            if (len < 0) {
                return null;
            }
            pos += lengthBytes(block, pos + 1) + 1 + len;
        }
        if (pos + 3 > block.length || (block[pos] & 0xFF) != 0xC4) {
            return null;
        }
        int len = berLength(block, pos + 1);
        if (len < 0 || pos + 1 + lengthBytes(block, pos + 1) + len != block.length) {
            return null;
        }
        return Arrays.copyOfRange(block, pos + 1 + lengthBytes(block, pos + 1), block.length);
    }

    /** BER length at {@code off}; returns -1 on malformed input. */
    private static int berLength(byte[] data, int off) {
        int first = data[off] & 0xFF;
        if (first < 0x80) {
            return first;
        }
        int n = first & 0x7F;
        if (n < 1 || n > 2 || off + 1 + n > data.length) {
            return -1;
        }
        int len = 0;
        for (int i = 0; i < n; i++) {
            len = len << 8 | data[off + 1 + i] & 0xFF;
        }
        return len;
    }

    private static int lengthBytes(byte[] data, int off) {
        int first = data[off] & 0xFF;
        return first < 0x80 ? 1 : 1 + (first & 0x7F);
    }

    /** Length-prefixed field (one-byte length) at {@code pos}; {@code null} on truncation. */
    private static byte[] field(byte[] data, int[] pos) {
        if (pos[0] >= data.length) {
            return null;
        }
        int len = data[pos[0]++] & 0xFF;
        if (pos[0] + len > data.length) {
            return null;
        }
        byte[] out = Arrays.copyOfRange(data, pos[0], pos[0] + len);
        pos[0] += len;
        return out;
    }

    /** GP's multi-byte length field followed by its content ({@code GPUtils.encodeLength}). */
    private static byte[] lv(byte[] data, int[] pos) {
        if (pos[0] >= data.length) {
            return null;
        }
        int len = berLength(data, pos[0]);
        if (len < 0) {
            return null;
        }
        pos[0] += lengthBytes(data, pos[0]);
        if (pos[0] + len > data.length) {
            return null;
        }
        byte[] out = Arrays.copyOfRange(data, pos[0], pos[0] + len);
        pos[0] += len;
        return out;
    }

    /** One {@link #lv} field that must consume the data; an absent field is {@link #EMPTY}. */
    private static byte[] rest(byte[] data, int[] pos) {
        if (pos[0] > data.length) {
            return null;
        }
        if (pos[0] == data.length) {
            return EMPTY;
        }
        byte[] out = lv(data, pos);
        return pos[0] == data.length ? out : null;
    }

    /** The value of the {@code C9} application-parameters TLV inside install params. */
    private static byte[] c9Value(byte[] params) {
        int pos = 0;
        while (pos + 2 <= params.length) {
            int tag = params[pos++] & 0xFF;
            if ((tag & 0x1F) == 0x1F) {
                do {
                    if (pos >= params.length) {
                        return EMPTY;
                    }
                } while ((params[pos++] & 0x80) != 0);
            }
            int len = berLength(params, pos);
            if (len < 0) {
                return EMPTY;
            }
            pos += lengthBytes(params, pos);
            if (pos + len > params.length) {
                return EMPTY;
            }
            if (tag == 0xC9) {
                return Arrays.copyOfRange(params, pos, pos + len);
            }
            pos += len;
        }
        return EMPTY;
    }

    /**
     * jcardsim's SELECT-by-name predicate ({@code SimulatorRuntime.isAppletSelectionApdu}): CLA
     * channel bits masked, {@code INS A4 P1 04}, P2 option bits masked.
     */
    private static boolean isSelect(byte[] command) {
        return (command[0] & 0xFC) == 0
                && command[1] == (byte) 0xA4
                && command[2] == 0x04
                && (command[3] & 0xE3) == 0;
    }

    /** The AID data of a SELECT-by-name APDU; a 5-byte command selects the empty AID. */
    private static byte[] selectAid(byte[] command) {
        if (command.length <= 5) {
            return EMPTY;
        }
        int lc = command[4] & 0xFF;
        return Arrays.copyOfRange(command, 5, Math.min(5 + lc, command.length));
    }

    /** Command data: short or extended Lc, trailing Le ignored. */
    private static byte[] data(byte[] command) {
        if (command.length <= 5) {
            return EMPTY;
        }
        int off;
        int lc;
        if (command[4] == 0) {
            if (command.length < 7) {
                return EMPTY;
            }
            off = 7;
            lc = (command[5] & 0xFF) << 8 | command[6] & 0xFF;
        } else {
            off = 5;
            lc = command[4] & 0xFF;
        }
        return Arrays.copyOfRange(command, off, Math.min(off + lc, command.length));
    }

    private static byte[] cplc(int index) {
        byte[] cplc = new byte[42];
        // "QX" fabricator/type marks the test double; serial = base + card index
        cplc[0] = 0x51;
        cplc[1] = 0x58;
        cplc[2] = 0x51;
        cplc[3] = 0x58;
        int serial = 0x51585400 + index;
        cplc[12] = (byte) (serial >>> 24);
        cplc[13] = (byte) (serial >>> 16);
        cplc[14] = (byte) (serial >>> 8);
        cplc[15] = (byte) serial;
        return cplc;
    }

    /** Fabricated 10-byte KDD: the CPLC's fabricator mark and serial, padded with zeros. */
    private static byte[] kdd(byte[] cplc) {
        byte[] kdd = new byte[10];
        kdd[0] = cplc[0];
        kdd[1] = cplc[1];
        System.arraycopy(cplc, 12, kdd, 2, 4);
        return kdd;
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] ok(byte[] data) {
        byte[] out = Arrays.copyOf(data, data.length + 2);
        out[out.length - 2] = (byte) 0x90;
        return out;
    }

    private static byte[] sw(int sw) {
        return new byte[] {(byte) (sw >>> 8), (byte) sw};
    }

    /**
     * The CAP embedded in the jar (resource copied from {@code :applet:cap}): its components keyed
     * by tag for load validation, plus the package identity for registry entries. Parsed once.
     */
    private record Cap(
            byte[] packageAid,
            byte[] packageVersion,
            List<byte[]> moduleAids,
            Map<Integer, byte[]> components,
            Set<Integer> required) {

        private static Cap parse() {
            Map<String, byte[]> files = new HashMap<>();
            byte[] manifest = null;
            try (InputStream in = Isd.class.getResourceAsStream("/qntx-card.cap")) {
                if (in == null) {
                    throw new IllegalStateException("qntx-card.cap missing from sim resources");
                }
                try (ZipInputStream zip = new ZipInputStream(in)) {
                    for (var entry = zip.getNextEntry();
                            entry != null;
                            entry = zip.getNextEntry()) {
                        String name = entry.getName();
                        if (name.endsWith(".cap")) {
                            files.put(
                                    name.substring(name.lastIndexOf('/') + 1, name.length() - 4),
                                    zip.readAllBytes());
                        } else if (name.equals("META-INF/MANIFEST.MF")) {
                            manifest = zip.readAllBytes();
                        }
                    }
                }
            } catch (IOException e) {
                throw new IllegalStateException("cannot read embedded qntx-card.cap", e);
            }
            // a CAP component is `u1 tag ‖ u2 size ‖ info` (JCVM 3.0.5 §6.3)
            Map<Integer, byte[]> components = new HashMap<>();
            Set<Integer> required = new HashSet<>();
            for (var file : files.entrySet()) {
                int tag = file.getValue()[0] & 0xFF;
                components.put(tag, file.getValue());
                if (Arrays.stream(OPTIONAL_COMPONENTS).noneMatch(file.getKey()::equals)) {
                    required.add(tag);
                }
            }
            return new Cap(
                    packageAid(manifest),
                    packageVersion(manifest),
                    moduleAids(manifest),
                    components,
                    required);
        }

        /**
         * {@code data} is a valid load block for this CAP: a concatenation of components ({@code u1
         * tag ‖ u2 size ‖ info}) each byte-identical to the component with the same tag and
         * together covering every component of this CAP except Descriptor and Debug — what GPPro's
         * {@code CAPFile.getCode()} emits. Order is unconstrained; modified, unknown or missing
         * required components are rejected.
         */
        boolean isLoad(byte[] data) {
            Set<Integer> seen = new HashSet<>();
            int pos = 0;
            while (pos < data.length) {
                if (pos + 3 > data.length) {
                    return false;
                }
                int tag = data[pos] & 0xFF;
                int len = ((data[pos + 1] & 0xFF) << 8) | (data[pos + 2] & 0xFF);
                if (pos + 3 + len > data.length) {
                    return false;
                }
                byte[] component = components.get(tag);
                if (component == null
                        || !Arrays.equals(
                                component, 0, component.length, data, pos, pos + 3 + len)) {
                    return false;
                }
                seen.add(tag);
                pos += 3 + len;
            }
            return seen.containsAll(required);
        }

        private static byte[] packageAid(byte[] manifest) {
            return manifestAid(manifest, "Java-Card-Package-AID: ");
        }

        private static byte[] packageVersion(byte[] manifest) {
            String text = new String(manifest, java.nio.charset.StandardCharsets.UTF_8);
            for (String line : text.split("\r?\n")) {
                if (line.startsWith("Java-Card-Package-Version: ")) {
                    String[] parts = line.substring(27).trim().split("\\.");
                    return new byte[] {
                        (byte) Integer.parseInt(parts[0]), (byte) Integer.parseInt(parts[1])
                    };
                }
            }
            throw new IllegalStateException("no Java-Card-Package-Version in CAP manifest");
        }

        private static List<byte[]> moduleAids(byte[] manifest) {
            String text = new String(manifest, java.nio.charset.StandardCharsets.UTF_8);
            List<byte[]> aids = new ArrayList<>();
            for (String line : text.split("\r?\n")) {
                if (line.startsWith("Java-Card-Applet-") && line.contains("-AID: ")) {
                    aids.add(manifestAid(manifest, line.substring(0, line.indexOf(": ") + 2)));
                }
            }
            return aids;
        }

        private static byte[] manifestAid(byte[] manifest, String key) {
            String text = new String(manifest, java.nio.charset.StandardCharsets.UTF_8);
            for (String line : text.split("\r?\n")) {
                if (line.startsWith(key)) {
                    String[] parts = line.substring(key.length()).trim().split(":");
                    byte[] aid = new byte[parts.length];
                    for (int i = 0; i < parts.length; i++) {
                        aid[i] = (byte) Integer.parseInt(parts[i].replace("0x", ""), 16);
                    }
                    return aid;
                }
            }
            throw new IllegalStateException("no " + key + " in CAP manifest");
        }
    }

    private static final Cap cap = Cap.parse();
}
