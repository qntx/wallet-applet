// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Field;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.tests.Vecs;

/**
 * Review finding R-12 (§16.3 item 3): an exception escaping {@code Session.wrap} — the record
 * encryption or the response MAC — used to leave the decrypted inner command in the APDU buffer:
 * CREATE {@code P1 = 0x01}'s seed, or the decrypted payload of an IMPORT {@code P1 = 0x01} whose
 * checks failed after decryption. {@code WalletApplet.process} now wipes the whole buffer on every
 * exceptional exit. Each test injects the throw at wrap's {@code Bytes.pad} call — the command's
 * only pad, dry-run counted — and scans {@link Card#apduBuffer()} for 16-byte windows of the
 * secret.
 */
final class ApduResidueTest {
    private static final int INS_CREATE = 0x21;
    private static final int INS_VERIFY = 0x22;
    private static final int INS_OFFER = 0x40;
    private static final int INS_EXPORT = 0x41;
    private static final int INS_IMPORT = 0x42;

    private static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] part : parts) {
            len += part.length;
        }
        byte[] out = new byte[len];
        int off = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, off, part.length);
            off += part.length;
        }
        return out;
    }

    private static byte[] slice(byte[] a, int off, int len) {
        byte[] out = new byte[len];
        System.arraycopy(a, off, out, 0, len);
        return out;
    }

    private static BigInteger scalar() {
        BigInteger d;
        do {
            d = new BigInteger(256, Vecs.RND);
        } while (d.signum() == 0 || d.compareTo(Crypto.N) >= 0);
        return d;
    }

    /** {@code Bytes.pad} calls during one session command; the wrap pad is the last one. */
    private static int padCalls(Card card, Session session, int ins, int p1, byte[] data)
            throws Exception {
        try {
            Fault.countCalls();
            Vecs.roundtrip(card, session, ins, p1, 0, data);
            return Fault.calls("Bytes.pad");
        } finally {
            Fault.reset();
        }
    }

    /** No 16-byte window of {@code secret} may survive in the APDU buffer (§16.3 item 3). */
    private static void assertAbsent(Card card, byte[] secret, String what) {
        byte[] buf = card.apduBuffer();
        for (int off = 0; off + 16 <= secret.length; off++) {
            int hit = indexOf(buf, secret, off);
            assertEquals(-1, hit, what + ": 16-byte window at APDU buffer offset " + hit);
        }
    }

    private static int indexOf(byte[] hay, byte[] needle, int off) {
        for (int i = 0; i + 16 <= hay.length; i++) {
            boolean eq = true;
            for (int j = 0; j < 16; j++) {
                if (hay[i + j] != needle[off + j]) {
                    eq = false;
                    break;
                }
            }
            if (eq) {
                return i;
            }
        }
        return -1;
    }

    @Test
    void createExceptionLeavesNoPlaintext() throws Exception {
        byte[] data = concat(Vecs.accessHash(), Vecs.seed());
        Card dry = Vecs.blankSelf();
        assertEquals(
                1,
                padCalls(dry, Vecs.open(dry), INS_CREATE, 1, data),
                "the wrap pad is the command's only Bytes.pad call");

        Card card = Vecs.blankSelf();
        Session session = Vecs.open(card);
        byte[] rapdu;
        try {
            Fault.armThrow("Bytes.pad", 1);
            rapdu = card.transmit(session.wrap(INS_CREATE, 1, 0, data));
        } finally {
            Fault.reset();
        }
        assertEquals(0x6F00, Vecs.sw(rapdu), "CREATE must end outer 6F00");
        assertAbsent(card, Vecs.seed(), "CREATE P1=01 seed");
    }

    /** A BLANK target with a pending import whose record the host sealed itself. */
    private static final class Rig {
        final Card card;
        final Session session;
        final byte[] record;

        Rig() throws Exception {
            card = Vecs.factory();
            byte[] aT = Vecs.cardA(card);
            Vecs.blankFor(card, aT);
            session = Vecs.open(card);
            Response offer = Vecs.roundtrip(card, session, INS_OFFER, 0, 0, new byte[0]);
            assertEquals(0x9000, offer.sw(), "OFFER");
            byte[] lkT = slice(offer.data(), 0, 65);
            // the host is the source member: own CA-issued cert, E = e·G with e known,
            // sig_S over the export transcript — enough for a genuine pending import
            BigInteger idS = scalar();
            byte[] aS = Crypto.compress(Crypto.publicKey(idS));
            BigInteger e = scalar();
            byte[] epk = Crypto.publicKey(e);
            byte[] m = concat(Const.LABEL_EXPORT, aS, aT, lkT, epk);
            byte[] head = concat(Vecs.certFor(aS), epk, Crypto.sign(idS, Crypto.sha256(m)));
            assertEquals(
                    0x9000, Vecs.roundtrip(card, session, INS_IMPORT, 0, 0, head).sw(), "IMPORT0");
            // a record the card decrypts then refuses (the member list lacks the
            // sender): origin ‖ seed ‖ accessHash_T ‖ c ‖ ID(A_T) ‖ zeros — the 6A80
            // leaves the decrypted payload in the buffer for wrap's tail wipe (§9.14)
            byte[] z = slice(Crypto.multiply(e, lkT), 1, 32);
            byte[] keys = Crypto.kdf(z, Const.LABEL_KDF_TRANSFER, Crypto.sha256(m), 32);
            byte[] payload =
                    concat(
                            new byte[] {0x02},
                            Vecs.seed(),
                            Vecs.accessHashNew(),
                            new byte[] {0x02},
                            Ids.cardId(aT),
                            new byte[16]);
            byte[] ct =
                    Crypto.aesCbc(slice(keys, 0, 16), new byte[16], Crypto.m2pad(payload), true);
            record = concat(ct, Crypto.cmac(slice(keys, 16, 16), ct));
        }
    }

    @Test
    void importExceptionLeavesNoPlaintext() throws Exception {
        Rig dry = new Rig();
        assertEquals(
                1,
                padCalls(dry.card, dry.session, INS_IMPORT, 1, dry.record),
                "the wrap pad is the command's only Bytes.pad call");

        Rig rig = new Rig();
        byte[] rapdu;
        try {
            Fault.armThrow("Bytes.pad", 1);
            rapdu = rig.card.transmit(rig.session.wrap(INS_IMPORT, 1, 0, rig.record));
        } finally {
            Fault.reset();
        }
        assertEquals(0x6F00, Vecs.sw(rapdu), "IMPORT must end outer 6F00");
        assertAbsent(rig.card, Vecs.seed(), "IMPORT P1=01 payload seed");
    }

    private static byte[] field(Object o, String name) {
        try {
            Field f = o.getClass().getDeclaredField(name);
            f.setAccessible(true);
            return (byte[]) f.get(o);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void badPaddingLeavesNoPlaintext() throws Exception {
        // §8.3 step 5: a well-formed record whose plaintext is not M2 — the tag checks,
        // the decryption runs in place, unpad fails and the torn 6982 leaves the whole
        // buffer for process()'s wipe (§16.3 item 3)
        Card card = Vecs.blankSelf();
        Session session = Vecs.open(card);
        byte[] kce = field(session, "kce");
        byte[] kcm = field(session, "kcm");
        byte[] pattern = new byte[32];
        for (int i = 0; i < pattern.length; i++) {
            pattern[i] = (byte) (0x30 + i);
        }
        // 48 B of padding-free plaintext ending in zeros: the last non-zero byte is not
        // 0x80, so M2 unpad must fail after the record decrypts in place
        byte[] plain = concat(pattern, new byte[16]);
        byte[] seed = new byte[16];
        seed[0] = 0x01;
        byte[] iv = Crypto.aesBlock(kce, seed);
        byte[] ct = Crypto.aesCbc(kce, iv, plain, true);
        byte[] tag = new byte[8];
        System.arraycopy(Crypto.cmac(kcm, Crypto.u16(0), ct), 0, tag, 0, 8);
        byte[] apdu = new byte[5 + ct.length + 8 + 1];
        apdu[0] = (byte) 0x80;
        apdu[1] = 0x12;
        apdu[4] = (byte) (ct.length + 8);
        System.arraycopy(ct, 0, apdu, 5, ct.length);
        System.arraycopy(tag, 0, apdu, 5 + ct.length, 8);
        assertEquals(0x6982, Vecs.sw(card.transmit(apdu)));
        assertAbsent(card, pattern, "bad-padding record plaintext");
    }

    /**
     * A LOADED target (imported wallet, members: source ‖ target) holding a pending import of the
     * source's genuine next export.
     */
    private static final class LoadRig {
        final Card target;
        final Session session;
        final byte[] payload;

        LoadRig() throws Exception {
            Card source = Vecs.factory();
            byte[] aS = Vecs.cardA(source);
            byte[] certS = Vecs.certFor(aS);
            Vecs.blankFor(source, aS);
            Session sS = Vecs.open(source);
            target = Vecs.factory();
            byte[] aT = Vecs.cardA(target);
            byte[] certT = Vecs.certFor(aT);
            Vecs.blankFor(target, aT);
            session = Vecs.open(target);
            assertEquals(
                    0x9000,
                    Vecs.roundtrip(
                                    source,
                                    sS,
                                    INS_CREATE,
                                    1,
                                    0,
                                    concat(Vecs.accessHash(), Vecs.seed(), Ids.cardId(aT)))
                            .sw(),
                    "CREATE");
            assertEquals(
                    0x9000,
                    Vecs.roundtrip(source, sS, INS_VERIFY, 0, 0, Vecs.accessHash()).sw(),
                    "VERIFY");
            Response offer = Vecs.roundtrip(target, session, INS_OFFER, 0, 0, new byte[0]);
            assertEquals(0x9000, offer.sw(), "OFFER");
            Response head =
                    Vecs.roundtrip(source, sS, INS_EXPORT, 0, 0, concat(certT, offer.data()));
            assertEquals(0x9000, head.sw(), "EXPORT0");
            Response pay = Vecs.roundtrip(source, sS, INS_EXPORT, 1, 0, Vecs.accessHashNew());
            assertEquals(0x9000, pay.sw(), "EXPORT1");
            assertEquals(
                    0x9000,
                    Vecs.roundtrip(target, session, INS_IMPORT, 0, 0, concat(certS, head.data()))
                            .sw(),
                    "IMPORT0");
            assertEquals(
                    0x9000,
                    Vecs.roundtrip(target, session, INS_IMPORT, 1, 0, pay.data()).sw(),
                    "IMPORT1");
            // the LOADED target offers again and a second genuine export arms the
            // pending import under test
            offer = Vecs.roundtrip(target, session, INS_OFFER, 0, 0, new byte[0]);
            assertEquals(0x9000, offer.sw(), "OFFER");
            head = Vecs.roundtrip(source, sS, INS_EXPORT, 0, 0, concat(certT, offer.data()));
            assertEquals(0x9000, head.sw(), "EXPORT0");
            pay = Vecs.roundtrip(source, sS, INS_EXPORT, 1, 0, Vecs.accessHashNew());
            assertEquals(0x9000, pay.sw(), "EXPORT1");
            assertEquals(
                    0x9000,
                    Vecs.roundtrip(target, session, INS_IMPORT, 0, 0, concat(certS, head.data()))
                            .sw(),
                    "IMPORT0");
            payload = pay.data();
        }
    }

    @Test
    void import1GuardFaultLeavesNoPlaintext() throws Exception {
        // the T-INSTALL guard (§16.2 item 4) recomputes the stored members against the
        // decrypted payload twice; forcing the first recompute to disagree is an inner
        // 6F00 — the plaintext is covered by wrap's tail wipe (§16.3 item 3)
        LoadRig rig = new LoadRig();
        byte[] rapdu;
        try {
            Fault.arm("State.equal", 3, Const.CHECK_FAIL);
            rapdu = rig.target.transmit(rig.session.wrap(INS_IMPORT, 1, 0, rig.payload));
        } finally {
            Fault.reset();
        }
        assertEquals(
                0x6F00, rig.session.unwrap(rapdu).sw(), "the recomputed members check must fault");
        assertAbsent(rig.target, Vecs.seed(), "IMPORT P1=01 payload seed");
    }
}
