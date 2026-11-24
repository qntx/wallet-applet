// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
    private static final int INS_OFFER = 0x40;
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
}
