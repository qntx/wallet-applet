// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.AESKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.Internals;
import org.qntx.card.NdefApplet;
import org.qntx.card.WalletApplet;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;

/**
 * The NDEF applet's §15 table (architecture.md §14.7 R1): file content and every status word in the
 * checking order, all expectations hand-built here rather than read back from the applet.
 */
final class NdefTest {
    private static final byte[] MSG1 = {0x55};

    private static final byte[] MSG100 = new byte[100];

    static {
        for (int i = 0; i < MSG100.length; i++) {
            MSG100[i] = (byte) (i + 1);
        }
    }

    private Card card;

    @BeforeEach
    void install() {
        card = new Card();
    }

    private void installNdef(byte[] msg) {
        card.install(Spec.NDEF_AID, NdefApplet.class, msg);
        assertArrayEquals(Spec.SW_OK, card.transmit(Spec.SELECT_NDEF), "SELECT NDEF AID");
    }

    /** §15 SELECT file. */
    private static byte[] selectFile(String fid) {
        return Spec.hex("00A4000C02" + fid);
    }

    /** §15 READ BINARY. */
    private static byte[] read(int off, int le) {
        return new byte[] {0x00, (byte) 0xB0, (byte) (off >> 8), (byte) off, (byte) le};
    }

    private static int sw(byte[] rapdu) {
        return ((rapdu[rapdu.length - 2] & 0xFF) << 8) | (rapdu[rapdu.length - 1] & 0xFF);
    }

    /** §15 capability container, built here. */
    private static byte[] cc(int msgLen) {
        byte[] cc = {
            0x00,
            0x0F,
            0x20,
            0x00,
            (byte) 0xFF,
            0x00,
            (byte) 0xFF,
            0x04,
            0x06,
            (byte) 0xE1,
            0x04,
            0x00,
            0x00,
            0x00,
            (byte) 0xFF,
        };
        cc[11] = (byte) ((msgLen + 2) >> 8);
        cc[12] = (byte) (msgLen + 2);
        return cc;
    }

    /** §15 NDEF file: {@code u16(|msg|) ‖ msg}, built here. */
    private static byte[] ndefFile(byte[] msg) {
        byte[] file = new byte[msg.length + 2];
        file[0] = (byte) (msg.length >> 8);
        file[1] = (byte) msg.length;
        System.arraycopy(msg, 0, file, 2, msg.length);
        return file;
    }

    private static byte[] ok(byte[] data) {
        byte[] rapdu = new byte[data.length + 2];
        System.arraycopy(data, 0, rapdu, 0, data.length);
        rapdu[data.length] = (byte) 0x90;
        return rapdu;
    }

    @Test
    void capabilityContainerBytesAreExact() {
        installNdef(MSG1);
        assertArrayEquals(Spec.SW_OK, card.transmit(selectFile("E103")));
        assertArrayEquals(ok(cc(1)), card.transmit(read(0, 0)), "CC for a one-byte message");
        card = new Card();
        installNdef(MSG100);
        assertArrayEquals(Spec.SW_OK, card.transmit(selectFile("E103")));
        assertArrayEquals(ok(cc(100)), card.transmit(read(0, 0)), "CC for a 100-byte message");
    }

    @Test
    void ndefFileIsTheMessageWithItsLengthPrefix() {
        installNdef(MSG1);
        assertArrayEquals(Spec.SW_OK, card.transmit(selectFile("E104")));
        assertArrayEquals(ok(ndefFile(MSG1)), card.transmit(read(0, 0)));
        card = new Card();
        installNdef(MSG100);
        assertArrayEquals(Spec.SW_OK, card.transmit(selectFile("E104")));
        assertArrayEquals(ok(ndefFile(MSG100)), card.transmit(read(0, 0)));
    }

    @Test
    void installRejectsEmptyAndOversizedMessages() {
        ISOException empty =
                assertThrows(
                        ISOException.class,
                        () -> card.install(Spec.NDEF_AID, NdefApplet.class, new byte[0]));
        assertEquals(ISO7816.SW_WRONG_DATA, empty.getReason());
        // a second install of the same class needs a fresh card: loadApplet registers the
        // load file even when the constructor throws, so every attempt below is a new card
        card = new Card();
        ISOException oversized =
                assertThrows(
                        ISOException.class,
                        () -> card.install(Spec.NDEF_AID, NdefApplet.class, new byte[101]));
        assertEquals(ISO7816.SW_WRONG_DATA, oversized.getReason());
        card = new Card();
        installNdef(MSG1);
        card = new Card();
        installNdef(MSG100);
    }

    @Test
    void selectFileAcceptsOnlyTheTwoFileIds() {
        installNdef(MSG1);
        // a failed SELECT file leaves the selection unchanged: nothing selected stays none
        assertEquals(0x6A82, sw(card.transmit(selectFile("E102"))), "unknown FID");
        assertEquals(0x6985, sw(card.transmit(read(0, 0))), "still no file");
        assertArrayEquals(Spec.SW_OK, card.transmit(selectFile("E103")));
        // once a file is selected, bad FIDs and bad lengths leave it selected
        assertEquals(0x6A82, sw(card.transmit(selectFile("E102"))));
        assertEquals(0x6A82, sw(card.transmit(Spec.hex("00A4000C01E1"))), "one-byte data");
        assertEquals(0x6A82, sw(card.transmit(Spec.hex("00A4000C03E10300"))), "three-byte data");
        assertEquals(0x6A82, sw(card.transmit(Spec.hex("00A4000C00"))), "empty data");
        assertArrayEquals(ok(cc(1)), card.transmit(read(0, 0)), "E103 still selected");
        assertArrayEquals(Spec.SW_OK, card.transmit(selectFile("E104")));
        assertArrayEquals(ok(ndefFile(MSG1)), card.transmit(read(0, 0)));
    }

    @Test
    void selectFileChecksP1P2BeforeTheFileId() {
        installNdef(MSG1);
        for (String p1p2 : new String[] {"0400", "0000", "020C"}) {
            byte[] apdu = Spec.hex("00A4" + p1p2 + "02E103");
            assertEquals(0x6A86, sw(card.transmit(apdu)), "P1P2 = " + p1p2);
        }
    }

    @Test
    void everyCommandNeedsClass00() {
        installNdef(MSG1);
        assertEquals(0x6E00, sw(card.transmit(Spec.hex("80A4000C02E103"))), "SELECT file");
        assertEquals(0x6E00, sw(card.transmit(Spec.hex("80B0000000"))), "READ BINARY");
        assertEquals(0x6E00, sw(card.transmit(Spec.hex("80D6000000"))), "UPDATE BINARY");
        assertEquals(0x6E00, sw(card.transmit(Spec.hex("8099000000"))), "unknown INS");
    }

    @Test
    void readBinaryNeedsASelectedFileFirst() {
        installNdef(MSG1);
        assertEquals(0x6985, sw(card.transmit(read(0, 0))), "no file selected");
        // the no-file check runs before the offset check
        assertEquals(0x6985, sw(card.transmit(read(0xFFFF, 0))), "still no file selected");
    }

    @Test
    void updateBinaryIsAlwaysRejected() {
        installNdef(MSG1);
        assertEquals(0x6985, sw(card.transmit(Spec.hex("00D6000000"))), "before a select");
        assertArrayEquals(Spec.SW_OK, card.transmit(selectFile("E104")));
        assertEquals(0x6985, sw(card.transmit(Spec.hex("00D6000000"))), "after a select");
        assertEquals(0x6985, sw(card.transmit(Spec.hex("00D6000002AABB"))), "with data");
    }

    @Test
    void offsetsBeyondTheFileEndAre6B00() {
        installNdef(MSG100);
        assertArrayEquals(Spec.SW_OK, card.transmit(selectFile("E103")));
        assertEquals(0x6B00, sw(card.transmit(read(16, 0))), "off = size + 1");
        assertEquals(0x6B00, sw(card.transmit(read(0x8000, 0))), "off = 0x8000");
        assertArrayEquals(Spec.SW_OK, card.transmit(selectFile("E104")));
        assertEquals(0x6B00, sw(card.transmit(read(103, 0))), "off = size + 1");
        assertEquals(0x6B00, sw(card.transmit(read(0x8000, 0))), "off = 0x8000");
    }

    @Test
    void unknownInsIs6D00() {
        installNdef(MSG1);
        assertEquals(0x6D00, sw(card.transmit(Spec.hex("0099000000"))));
    }

    @Test
    void readBinaryOffsetsAndLe() {
        installNdef(MSG100);
        byte[] file = ndefFile(MSG100);
        assertArrayEquals(Spec.SW_OK, card.transmit(selectFile("E104")));
        assertArrayEquals(ok(file), card.transmit(read(0, 0)), "off = 0");
        assertArrayEquals(ok(slice(file, 50)), card.transmit(read(50, 0)), "middle");
        assertArrayEquals(ok(slice(file, 101)), card.transmit(read(101, 0)), "off = size - 1");
        assertArrayEquals(Spec.SW_OK, card.transmit(read(102, 0)), "off = size returns nothing");
        assertArrayEquals(ok(new byte[] {file[0]}), card.transmit(read(0, 1)), "Le = 1 truncates");
        assertArrayEquals(ok(Arrays.copyOf(file, 15)), card.transmit(read(0, 15)), "Le = 15");
        assertArrayEquals(ok(file), card.transmit(read(0, 0)), "Le = 00 is 256, whole file");
    }

    @Test
    void aLongFileReassemblesFromReads() {
        installNdef(MSG100);
        assertArrayEquals(Spec.SW_OK, card.transmit(selectFile("E104")));
        ByteArrayOutputStream back = new ByteArrayOutputStream();
        for (int off = 0; off < 102; off += 20) {
            byte[] rapdu = card.transmit(read(off, 20));
            assertEquals(0x9000, sw(rapdu), "read at " + off);
            back.write(rapdu, 0, rapdu.length - 2);
        }
        assertArrayEquals(ndefFile(MSG100), back.toByteArray());
    }

    @Test
    void selectByAidResetsTheSelection() {
        installNdef(MSG1);
        assertArrayEquals(Spec.SW_OK, card.transmit(selectFile("E103")));
        assertArrayEquals(ok(cc(1)), card.transmit(read(0, 0)));
        // §15: every SELECT by AID resets the selection, including one of this applet
        assertArrayEquals(Spec.SW_OK, card.transmit(Spec.SELECT_NDEF));
        assertEquals(0x6985, sw(card.transmit(read(0, 0))), "selection reset");
    }

    @Test
    void noNdefCommandWritesPersistentMemory() {
        installNdef(MSG1);
        byte[][] commands = {
            Spec.SELECT_NDEF,
            selectFile("E103"),
            read(0, 0),
            selectFile("E104"),
            read(0, 0),
            Spec.hex("00A4000C02E102"),
            Spec.hex("00D6000000"),
            Spec.hex("0099000000"),
            Spec.hex("80B0000000"),
        };
        for (byte[] apdu : commands) {
            card.transmit(apdu);
            assertEquals(0, card.writes(), "writes of " + HexFormat.of().formatHex(apdu));
        }
    }

    /** ndef.json (§18): every message, every READ BINARY row and every rejected install length. */
    @Test
    void replaysNdefJson() {
        Map<String, Object> doc = Vecs.load("ndef.json");
        for (Map<String, Object> m : Vecs.list(doc, "messages")) {
            card = new Card();
            byte[] msg = Vecs.hex(m, "msg");
            card.install(Spec.NDEF_AID, NdefApplet.class, msg);
            assertArrayEquals(Spec.SW_OK, card.transmit(Spec.SELECT_NDEF));
            assertArrayEquals(Spec.SW_OK, card.transmit(selectFile("E103")));
            assertArrayEquals(
                    ok(Vecs.hex(m, "cc")), card.transmit(read(0, 0)), "cc of |msg|=" + msg.length);
            assertArrayEquals(Spec.SW_OK, card.transmit(selectFile("E104")));
            assertArrayEquals(
                    ok(Vecs.hex(m, "ndefFile")),
                    card.transmit(read(0, 0)),
                    "ndef of |msg|=" + msg.length);
        }
        card = new Card();
        byte[] msg16 = Vecs.hex(Vecs.list(doc, "messages").get(1), "msg");
        card.install(Spec.NDEF_AID, NdefApplet.class, msg16);
        assertArrayEquals(Spec.SW_OK, card.transmit(Spec.SELECT_NDEF));
        String selected = "";
        for (Map<String, Object> r : Vecs.list(doc, "reads")) {
            String file = (String) r.get("file");
            if (!file.equals(selected)) {
                assertArrayEquals(
                        Spec.SW_OK, card.transmit(selectFile(file.equals("cc") ? "E103" : "E104")));
                selected = file;
            }
            int off = ((Number) r.get("off")).intValue();
            int le = ((Number) r.get("le")).intValue();
            byte[] expected = Vecs.unhex((String) r.get("data") + r.get("sw"));
            assertArrayEquals(expected, card.transmit(read(off, le)), r.toString());
        }
        for (Object len : (List<Object>) doc.get("rejectedInstall")) {
            int n = ((Number) len).intValue();
            Card fresh = new Card();
            assertThrows(
                    ISOException.class,
                    () -> fresh.install(Spec.NDEF_AID, NdefApplet.class, new byte[n]),
                    "rejected install length " + n);
        }
    }

    @Test
    void aWalletSessionDoesNotSurviveSelectingTheNdefApplet() throws Exception {
        card.install(Spec.WALLET_AID, WalletApplet.class);
        card.install(Spec.NDEF_AID, NdefApplet.class, MSG1);
        card.transmit(Spec.SELECT);
        Vecs.driveInit(card);
        Vecs.blankFor(card, Vecs.cardA(card));
        Session session = Vecs.open(card);
        assertArrayEquals(Spec.SW_OK, card.transmit(Spec.SELECT_NDEF));
        assertArrayEquals(Spec.SW_OK, card.transmit(Spec.SELECT));
        byte[] record = session.wrap(0x20, 0, 0, new byte[0]);
        byte[] rapdu = card.transmit(record);
        assertEquals(0x6985, Vecs.sw(rapdu), "§13.1: SESSION with no open session");
    }

    @Test
    void selectingNdefRunsTheWalletTeardown() throws Exception {
        // §8.5: the NDEF applet shares the wallet's context, so the platform keeps
        // CLEAR_ON_DESELECT memory across the switch — the applet's deselect() is what wipes
        // the session. A verified session with a live Ed25519 stream and a completed WAIT is
        // torn down while NDEF holds the channel, and the deselect writes nothing persistent.
        card.install(Spec.WALLET_AID, WalletApplet.class);
        card.install(Spec.NDEF_AID, NdefApplet.class, MSG1);
        card.transmit(Spec.SELECT);
        Vecs.driveInit(card);
        Vecs.blankFor(card, Vecs.cardA(card));
        Session session = Vecs.loadWallet(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x25, 0, 0, new byte[0]).sw());
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x33, 0, 0, Vecs.pathEdSolana()).sw());
        Applet wallet = card.applet(Spec.WALLET_AID);
        byte[] stream = Internals.edStreamBytes(wallet);
        assertNotEquals(0, stream[0] | stream[1] | stream[64], "no live stream before SELECT");
        assertArrayEquals(Spec.SW_OK, card.transmit(Spec.SELECT_NDEF));
        assertEquals(0, card.writes(), "the deselect teardown writes nothing persistent");
        assertArrayEquals(new byte[14], Internals.words(wallet), "session words not cleared");
        byte[] key = new byte[16];
        for (String name : new String[] {"kce", "kcm", "kre", "krm"}) {
            Internals.sessionKey(wallet, name).getKey(key, (short) 0);
            assertArrayEquals(new byte[16], key, name + " not wiped");
        }
        assertArrayEquals(new byte[64], Internals.seedBytes(wallet), "seed not wiped");
        assertArrayEquals(new byte[170], Internals.secpCacheBytes(wallet), "secpCache not wiped");
        assertArrayEquals(new byte[105], Internals.edCacheBytes(wallet), "edCache not wiped");
        assertArrayEquals(new byte[194], Internals.edStreamBytes(wallet), "edStream not wiped");
        // kTe/kTm are TYPE_AES_TRANSIENT_DESELECT: the platform clears them on the
        // deselection itself, after endPending's random overwrite (§16.2 item 4)
        ((AESKey) Internals.memField(wallet, "kTe")).getKey(key, (short) 0);
        assertArrayEquals(new byte[16], key, "kTe not cleared");
        ((AESKey) Internals.memField(wallet, "kTm")).getKey(key, (short) 0);
        assertArrayEquals(new byte[16], key, "kTm not cleared");
        assertArrayEquals(
                new byte[16], (byte[]) Internals.memField(wallet, "sender"), "sender not wiped");
        assertArrayEquals(Spec.SW_OK, card.transmit(Spec.SELECT));
        byte[] record = session.wrap(0x20, 0, 0, new byte[0]);
        assertEquals(0x6985, Vecs.sw(card.transmit(record)), "the old session is gone");
    }

    private static byte[] slice(byte[] file, int off) {
        byte[] out = new byte[file.length - off];
        System.arraycopy(file, off, out, 0, out.length);
        return out;
    }
}
