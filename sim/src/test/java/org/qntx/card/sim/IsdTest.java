// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.qntx.card.WalletApplet;
import pro.javacard.capfile.CAPFile;
import pro.javacard.gp.GPData;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPRegistry;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.GPSession.APDUMode;
import pro.javacard.gp.keys.PlaintextKeys;

/**
 * GlobalPlatformPro is the independent oracle of the simulated ISD (architecture.md §8): it opens
 * the real SCP03 handshake, verifies the card cryptogram itself, wraps every secured command and
 * parses the registry — so every byte the ISD emits is validated by code the tools run against a
 * real card manager.
 */
class IsdTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] ISD = Isd.AID;
    private static final byte[] KEY = Scp03.TEST_KEY;
    private static final byte[] PKG = HEX.parseHex("F0716E747800");
    private static final byte[] WALLET = HEX.parseHex("F0716E74780101");
    private static final byte[] NDEF_CLASS = HEX.parseHex("F0716E74780201");
    private static final byte[] NDEF = HEX.parseHex("D2760000850101");
    private static final byte[] NDEF_MSG = HEX.parseHex("D1010C5402656E716E74782063617264");
    private static final byte[] SELECT_WALLET = {
        0x00, (byte) 0xA4, 0x04, 0x00, 0x07, (byte) 0xF0, 0x71, 0x6E, 0x74, 0x78, 0x01, 0x01, 0x00
    };
    private static final byte[] GET_IDENTITY = {(byte) 0x80, (byte) 0xE0, 0x00, 0x00, 0x00};
    // BitField.encode(EnumSet.copyOf(privileges)) throws on an empty collection
    private static final java.util.EnumSet<pro.javacard.gp.GPRegistryEntry.Privilege> NO_PRIVS =
            java.util.EnumSet.noneOf(pro.javacard.gp.GPRegistryEntry.Privilege.class);

    private static BIBO bibo(Isd isd) {
        return isd::transmit;
    }

    private static GPSession connect(Isd isd) throws GPException {
        return GPSession.connect(new APDUBIBO(bibo(isd)), new pro.javacard.capfile.AID(ISD));
    }

    private static PlaintextKeys keys(byte[] key, int kvn) {
        return PlaintextKeys.fromBytes(key, key, key, null, null, null, kvn).orElseThrow();
    }

    private static void open(GPSession session, int kvn) throws GPException {
        open(session, keys(KEY, kvn));
    }

    private static void open(GPSession session, PlaintextKeys keys) throws GPException {
        session.openSecureChannel(
                keys,
                GPSecureChannelVersion.valueOf(3),
                null,
                EnumSet.of(APDUMode.MAC, APDUMode.ENC));
    }

    private static Isd empty() {
        return new Isd(new Card(), 0, false);
    }

    private static Isd populated() {
        Isd isd = new Isd(new Card(), 0, true);
        isd.card().install(WALLET, WalletApplet.class);
        isd.registerApp(WALLET);
        isd.card().install(NDEF, org.qntx.card.NdefApplet.class, NDEF_MSG);
        isd.registerApp(NDEF);
        return isd;
    }

    private static CAPFile cap() throws Exception {
        try (InputStream in = IsdTest.class.getResourceAsStream("/qntx-card.cap")) {
            return CAPFile.fromStream(in);
        }
    }

    private static int sw(byte[] response) {
        return (response[response.length - 2] & 0xFF) << 8 | response[response.length - 1] & 0xFF;
    }

    private static byte[] data(byte[] response) {
        return Arrays.copyOf(response, response.length - 2);
    }

    private static byte[] hex(String s) {
        return HEX.parseHex(s.replace(" ", ""));
    }

    @Test
    void selectByEmptyAidReturnsFci() {
        Isd isd = empty();
        byte[] response = bibo(isd).transceive(hex("00A4040000"));
        assertEquals(0x9000, sw(response));
        assertArrayEquals(Isd.FCI, data(response));
        response = bibo(isd).transceive(concat(hex("00A4040008"), ISD, new byte[] {0x00}));
        assertEquals(0x9000, sw(response));
        assertArrayEquals(Isd.FCI, data(response));
    }

    @Test
    void scp03HandshakeAndEmptyRegistry() throws Exception {
        Isd isd = empty();
        GPSession session = connect(isd);
        // GPPro verifies the card cryptogram itself before EXTERNAL AUTHENTICATE
        open(session, 0x30);
        assertEquals(GPSecureChannelVersion.valueOf(3).scp, session.getSecureChannel().scp);
        GPRegistry registry = session.getRegistry();
        assertTrue(registry.getISD().isPresent());
        assertArrayEquals(ISD, registry.getISD().get().getAID().getBytes());
        assertTrue(registry.allPackages().isEmpty());
        assertTrue(registry.allApplets().isEmpty());
    }

    @Test
    void scp03CmacOnlyLevel() throws Exception {
        Isd isd = empty();
        GPSession session = connect(isd);
        session.openSecureChannel(
                keys(KEY, 0x30), GPSecureChannelVersion.valueOf(3), null, EnumSet.of(APDUMode.MAC));
        assertTrue(session.getRegistry().getISD().isPresent());
    }

    @Test
    void cplcUnsecuredAndSecured() throws Exception {
        Isd isd = empty();
        byte[] response = bibo(isd).transceive(hex("80CA9F7F00"));
        assertEquals(0x9000, sw(response));
        byte[] cplc = data(response);
        assertEquals((byte) 0x9F, cplc[0]);
        assertEquals(0x7F, cplc[1]);
        assertEquals(42, cplc[2]);
        assertEquals(45, cplc.length);
        // IC serial at offset 12 of the CPLC = base + card index (index 0 here)
        int serial =
                (cplc[3 + 12] & 0xFF) << 24
                        | (cplc[3 + 13] & 0xFF) << 16
                        | (cplc[3 + 14] & 0xFF) << 8
                        | (cplc[3 + 15] & 0xFF);
        assertEquals(0x51585400, serial);

        GPSession session = connect(isd);
        open(session, 0x30);
        var wrapped = session.transmit(new CommandAPDU(0x80, 0xCA, 0x9F, 0x7F));
        assertEquals(0x9000, wrapped.getSW());
        assertArrayEquals(cplc, wrapped.getData());
    }

    @Test
    void unknownGetDataTagFails() {
        assertEquals(0x6A88, sw(bibo(empty()).transceive(hex("80CA9F7E00"))));
    }

    @Test
    void factoryRegistry() throws Exception {
        Isd isd = populated();
        GPSession session = connect(isd);
        open(session, 0x30);
        GPRegistry registry = session.getRegistry();
        assertTrue(registry.getISD().isPresent());
        assertEquals(List.of(new pro.javacard.capfile.AID(PKG)), registry.allPackageAIDs());
        var appletAids = registry.allAppletAIDs();
        assertTrue(appletAids.contains(new pro.javacard.capfile.AID(WALLET)));
        assertTrue(appletAids.contains(new pro.javacard.capfile.AID(NDEF)));
        // the applets are actually installed and selectable
        assertEquals(0x9000, sw(bibo(isd).transceive(SELECT_WALLET)));
        assertEquals(33, data(bibo(isd).transceive(GET_IDENTITY)).length);
    }

    @Test
    void loadAndInstallOverGp() throws Exception {
        Isd isd = empty();
        GPSession session = connect(isd);
        open(session, 0x30);
        var pkgAid = new pro.javacard.capfile.AID(PKG);
        session.loadCapFile(cap(), null, GPData.LFDBH.SHA256);
        session.installAndMakeSelectable(
                pkgAid,
                new pro.javacard.capfile.AID(WALLET),
                new pro.javacard.capfile.AID(WALLET),
                NO_PRIVS,
                null);
        session.installAndMakeSelectable(
                pkgAid,
                new pro.javacard.capfile.AID(NDEF_CLASS),
                new pro.javacard.capfile.AID(NDEF),
                NO_PRIVS,
                NDEF_MSG);
        GPRegistry registry = session.getRegistry();
        assertTrue(registry.allPackageAIDs().contains(pkgAid));
        var aids = registry.allAppletAIDs();
        assertTrue(aids.contains(new pro.javacard.capfile.AID(WALLET)));
        assertTrue(aids.contains(new pro.javacard.capfile.AID(NDEF)));
        // the installed applets answer over jcardsim like server-installed ones
        assertEquals(0x9000, sw(bibo(isd).transceive(SELECT_WALLET)));
        assertEquals(33, data(bibo(isd).transceive(GET_IDENTITY)).length);
        byte[] selectNdef = concat(hex("00A4040007"), NDEF, new byte[] {0x00});
        assertEquals(0x9000, sw(bibo(isd).transceive(selectNdef)));
    }

    @Test
    void initUpdateWithUnknownKvnFails() {
        assertEquals(
                0x6A88,
                sw(bibo(empty()).transceive(hex("80503100 08 0000000000000000".replace(" ", "")))));
    }

    @Test
    void wrongKeyRejectedBeforeExtAuth() {
        Isd isd = empty();
        assertThrows(
                GPException.class,
                () -> {
                    GPSession session = connect(isd);
                    open(session, keys(hex("404142434445464748494A4B4C4D4E41"), 0x30));
                });
    }

    @Test
    void badExtAuthCryptogramClosesChannel() throws Exception {
        Isd isd = empty();
        BIBO bibo = bibo(isd);
        assertEquals(0x9000, sw(bibo.transceive(hex("00A4040000"))));
        assertEquals(
                0x9000, sw(bibo.transceive(hex("80500000 08 0102030405060708".replace(" ", "")))));
        // zero cryptogram + zero MAC: rejected, channel closes
        assertEquals(
                0x6982,
                sw(
                        bibo.transceive(
                                hex(
                                        "84820100 10 0000000000000000 0000000000000000"
                                                .replace(" ", "")))));
        // a further secured-looking command is not accepted either
        assertEquals(
                0x6982,
                sw(bibo.transceive(hex("84F28002 0A 4F00 0000000000000000".replace(" ", "")))));
    }

    @Test
    void badCmacOnSecuredCommandClosesChannel() throws Exception {
        Isd isd = empty();
        GPSession session = connect(isd);
        open(session, 0x30);
        BIBO bibo = bibo(isd);
        assertEquals(
                0x6982,
                sw(bibo.transceive(hex("84F28002 0A 4F00 0000000000000000".replace(" ", "")))));
        // channel is closed afterwards: even a properly wrapped command is refused now
        var response = session.transmit(new CommandAPDU(0x80, 0xCA, 0x9F, 0x7F));
        assertEquals(0x6982, response.getSW());
    }

    @Test
    void unsecuredManagementCommandsRejected() {
        Isd isd = empty();
        BIBO bibo = bibo(isd);
        assertEquals(0x9000, sw(bibo.transceive(hex("00A4040000"))));
        // unsecured INSTALL [for load]
        assertEquals(
                0x6982,
                sw(
                        bibo.transceive(
                                hex("80E60200 0C 06F0716E747800 02A000 00 00".replace(" ", "")))));
        // unsecured LOAD / GET STATUS / PUT KEY
        assertEquals(0x6982, sw(bibo.transceive(hex("80E88000 03 C400"))));
        assertEquals(0x6982, sw(bibo.transceive(hex("80F28002 02 4F00"))));
        assertEquals(0x6982, sw(bibo.transceive(hex("80D83081 00"))));
    }

    @Test
    void unknownInstructionRejected() {
        Isd isd = empty();
        BIBO bibo = bibo(isd);
        assertEquals(0x9000, sw(bibo.transceive(hex("00A4040000"))));
        assertEquals(0x6D00, sw(bibo.transceive(hex("00990000 00"))));
    }

    @Test
    void modifiedComponentRejected() throws Exception {
        Isd isd = empty();
        GPSession session = connect(isd);
        open(session, 0x30);
        byte[] code = cap().getCode();
        byte[] hash = sha256(code);
        code[42] ^= 0x01;
        assertEquals(0x6A80, gpLoad(session, code, hash));
        assertTrue(session.getRegistry().allPackages().isEmpty());
    }

    @Test
    void wrongLfdbhRejected() throws Exception {
        Isd isd = empty();
        GPSession session = connect(isd);
        open(session, 0x30);
        assertEquals(0x6A80, gpLoad(session, cap().getCode(), new byte[32]));
    }

    /**
     * INSTALL [for load] + LOAD of {@code C4 ‖ code} in SecureChannelWrapper-sized blocks, the
     * split GPSession.loadCapFile performs (GPSession.java:589-620); returns the final sw.
     */
    private static int gpLoad(GPSession session, byte[] code, byte[] hash) throws Exception {
        int sw =
                session.transmit(
                                new CommandAPDU(
                                        0x80, 0xE6, 0x02, 0x00, installForLoadData(PKG, hash)))
                        .getSW();
        if (sw != 0x9000) {
            return sw;
        }
        byte[] block = tlv(0xC4, code);
        int seq = 0;
        for (int off = 0; off < block.length; off += 239) {
            int n = Math.min(239, block.length - off);
            sw =
                    session.transmit(
                                    new CommandAPDU(
                                            0x80,
                                            0xE8,
                                            off + n == block.length ? 0x80 : 0x00,
                                            seq++,
                                            Arrays.copyOfRange(block, off, off + n)))
                            .getSW();
            if (sw != 0x9000) {
                return sw;
            }
        }
        return sw;
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    @Test
    void secondLoadRejected() throws Exception {
        Isd isd = populated();
        GPSession session = connect(isd);
        open(session, 0x30);
        var response =
                session.transmit(
                        new CommandAPDU(
                                0x80, 0xE6, 0x02, 0x00, installForLoadData(PKG, new byte[0])));
        assertEquals(0x6985, response.getSW());
    }

    @Test
    void installValidatesPackageClassInstanceAndParams() throws Exception {
        Isd isd = empty();
        GPSession session = connect(isd);
        open(session, 0x30);
        session.loadCapFile(cap(), null, GPData.LFDBH.SHA256);
        var pkg = new pro.javacard.capfile.AID(PKG);
        var unknown = new pro.javacard.capfile.AID(hex("F0716E74780099"));
        // class AID not in the package
        var response =
                session.transmit(
                        new CommandAPDU(
                                0x80,
                                0xE6,
                                0x0C,
                                0x00,
                                installData(PKG, hex("F0716E74780099"), WALLET, new byte[0])));
        assertEquals(0x6A80, response.getSW());
        // package not loaded
        response =
                session.transmit(
                        new CommandAPDU(
                                0x80,
                                0xE6,
                                0x0C,
                                0x00,
                                installData(hex("F0716E74780099"), WALLET, WALLET, new byte[0])));
        assertEquals(0x6A80, response.getSW());
        // privileges must be empty/zero
        response =
                session.transmit(
                        new CommandAPDU(
                                0x80,
                                0xE6,
                                0x0C,
                                0x00,
                                installDataWithPrivs(
                                        PKG, WALLET, WALLET, new byte[] {(byte) 0x80})));
        assertEquals(0x6A80, response.getSW());
        // NDEF message too long → applet install fails → 6A80, no registry entry
        response =
                session.transmit(
                        new CommandAPDU(
                                0x80,
                                0xE6,
                                0x0C,
                                0x00,
                                installData(PKG, NDEF_CLASS, NDEF, c9Params(new byte[101]))));
        assertEquals(0x6A80, response.getSW());
        assertTrue(session.getRegistry().allAppletAIDs().isEmpty());
        // a second install of the same instance → 6985
        session.installAndMakeSelectable(
                pkg,
                new pro.javacard.capfile.AID(WALLET),
                new pro.javacard.capfile.AID(WALLET),
                NO_PRIVS,
                null);
        response =
                session.transmit(
                        new CommandAPDU(
                                0x80,
                                0xE6,
                                0x0C,
                                0x00,
                                installData(PKG, WALLET, WALLET, new byte[0])));
        assertEquals(0x6985, response.getSW());
    }

    @Test
    void putKeyRotatesAndRetiresTheOldKeys() throws Exception {
        Isd isd = empty();
        GPSession session = connect(isd);
        open(session, 0x30);
        byte[] fresh = hex("4142434445464748494A4B4C4D4E4F40");
        session.putKeys(keys(fresh, 0x31), true);
        // the old KVN/key no longer opens a channel
        assertThrows(GPException.class, () -> open(session, 0x30));
        // the new set does
        open(session, keys(fresh, 0x31));
        assertTrue(session.getRegistry().getISD().isPresent());
    }

    @Test
    void putKeyWithBadKcvRejected() throws Exception {
        Isd isd = empty();
        GPSession session = connect(isd);
        open(session, 0x30);
        byte[] fresh = hex("4142434445464748494A4B4C4D4E4F40");
        byte[] kcv = aesCbc(oneBytes(), fresh);
        kcv = Arrays.copyOf(kcv, 3);
        kcv[0] ^= 0x01;
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        data.write(0x31);
        for (int i = 0; i < 3; i++) {
            data.writeBytes(encodeAesKey(fresh, kcv));
        }
        var response =
                session.transmit(new CommandAPDU(0x80, 0xD8, 0x31, 0x81, data.toByteArray()));
        assertEquals(0x6A80, response.getSW());
        // the key set is unchanged
        session.getRegistry();
    }

    private static byte[] encodeAesKey(byte[] key, byte[] kcv) {
        byte[] cgram = aesCbc(key, KEY);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x88);
        out.write(cgram.length + 1);
        out.write(key.length);
        out.writeBytes(cgram);
        out.write(kcv.length);
        out.writeBytes(kcv);
        return out.toByteArray();
    }

    private static byte[] oneBytes() {
        byte[] b = new byte[16];
        Arrays.fill(b, (byte) 0x01);
        return b;
    }

    private static byte[] aesCbc(byte[] data, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new IvParameterSpec(new byte[16]));
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** {@code aid ‖ sd ‖ lfdbh ‖ params} of GPSession.loadCapFile (GPSession.java:594-608). */
    private static byte[] installForLoadData(byte[] pkg, byte[] hash) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(pkg.length);
        out.writeBytes(pkg);
        out.write(ISD.length);
        out.writeBytes(ISD);
        out.write(hash.length);
        out.writeBytes(hash);
        out.write(0x00);
        return out.toByteArray();
    }

    /** {@code pkg ‖ class ‖ instance ‖ privs ‖ params} of GPSession.buildInstallData. */
    private static byte[] installData(
            byte[] pkg, byte[] classAid, byte[] instanceAid, byte[] params) {
        return installDataWithPrivsAndParams(pkg, classAid, instanceAid, new byte[0], params);
    }

    private static byte[] installDataWithPrivs(
            byte[] pkg, byte[] classAid, byte[] instanceAid, byte[] privs) {
        return installDataWithPrivsAndParams(
                pkg, classAid, instanceAid, privs, c9Params(new byte[0]));
    }

    private static byte[] installDataWithPrivsAndParams(
            byte[] pkg, byte[] classAid, byte[] instanceAid, byte[] privs, byte[] params) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] field : new byte[][] {pkg, classAid, instanceAid, privs}) {
            out.write(field.length);
            out.writeBytes(field);
        }
        if (params.length < 0x80) {
            out.write(params.length);
        } else {
            out.write(0x81);
            out.write(params.length);
        }
        out.writeBytes(params);
        return out.toByteArray();
    }

    private static byte[] c9Params(byte[] value) {
        return tlv(0xC9, value);
    }

    private static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        if (value.length < 0x80) {
            out.write(value.length);
        } else if (value.length < 0x100) {
            out.write(0x81);
            out.write(value.length);
        } else {
            out.write(0x82);
            out.write(value.length >>> 8);
            out.write(value.length);
        }
        out.writeBytes(value);
        return out.toByteArray();
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }
}
