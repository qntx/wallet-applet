// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import java.math.BigInteger;
import java.util.Arrays;
import org.qntx.card.host.Certificates;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Transfer;

/**
 * A host-emulated member card under the ca1 test CA (§11): own secp256k1 identity key pair and
 * certificate, a link key pair, and the transfer protocol parts a host plays for the member — the
 * OFFER bytes {@code LK ‖ sig_T} a target authenticates in {@code EXPORT P1=0x00}, the {@code
 * cert_S ‖ E ‖ sig_S} head and sealed payload of an {@code IMPORT}, and the decrypt-check of an
 * exported record. Two cards are not needed to time or verify the wire protocol of §9.12–9.14: one
 * real (or simulated) card and this emulation suffice.
 */
public final class EmuMember {
    /** The §9.13 transfer KDF label, ASCII without terminator. */
    public static final byte[] LABEL_KDF_TRANSFER = "qntx-card/v1/kdf-transfer".getBytes();

    /** Identity private key {@code m}. */
    public final BigInteger id;

    /** Compressed identity key {@code A_M} (33 bytes). */
    public final byte[] a;

    /** {@code cert_M} (97 bytes) under the CA private key given at construction. */
    public final byte[] cert;

    /** {@code ID(A_M)} (16 bytes) — what a member list carries. */
    public final byte[] cardId;

    private BigInteger link;
    private byte[] lk;

    /** A member with a ca1-issued certificate — the CA of the test and real-card fixtures. */
    public EmuMember() {
        this(Vecs.caPrivate());
    }

    public EmuMember(BigInteger caPrivate) {
        id = randomScalar();
        a = Crypto.compress(Crypto.publicKey(id));
        cert = Certificates.issue(caPrivate, a);
        cardId = Ids.cardId(a);
    }

    /**
     * Rolls a fresh link pair and returns the {@code OFFER} response the card would give: {@code
     * LK(65) ‖ Sign(m, "qntx-card/v1/offer" ‖ LK)(64)} (§9.12, §9.13 step 5).
     */
    public byte[] newOffer() {
        link = randomScalar();
        lk = Crypto.publicKey(link);
        return concat(lk, Crypto.sign(id, Crypto.sha256(Transfer.LABEL_OFFER, lk)));
    }

    /** The current link public key {@code LK} (65 bytes), set by {@link #newOffer()}. */
    public byte[] lk() {
        return lk;
    }

    /** {@code EXPORT P1=0x00} command data for the card: {@code cert ‖ LK ‖ sig_T} (§9.13). */
    public byte[] exportRequest() {
        return concat(cert, newOffer());
    }

    /**
     * {@code IMPORT P1=0x00} command data the member plays as source S — {@code cert_S ‖ E ‖ sig_S}
     * with {@code E = e·G} and {@code sig_S} over {@link #transcript} (§9.14) — plus the host-drawn
     * {@code e(32)} needed for the shared secret: {@code {data(226), e(32)}}.
     */
    public byte[][] importHead(byte[] targetA33, byte[] targetLk) {
        BigInteger e = randomScalar();
        byte[] ep = Crypto.publicKey(e);
        byte[] m = transcript(a, targetA33, targetLk, ep);
        return new byte[][] {concat(cert, ep, Crypto.sign(id, Crypto.sha256(m))), fixed(e)};
    }

    /** The export transcript {@code "qntx-card/v1/export" ‖ A_S ‖ A_T ‖ LK_T ‖ E} (§9.13). */
    public static byte[] transcript(byte[] aS, byte[] aT, byte[] lkT, byte[] e) {
        return concat(Transfer.LABEL_EXPORT, aS, aT, lkT, e);
    }

    /** x-coordinate of {@code scalar · point65} (32 bytes) — the §9.13/§9.14 shared secret Z. */
    public static byte[] ecdhX(BigInteger scalar, byte[] point65) {
        return Arrays.copyOfRange(Crypto.multiply(scalar, point65), 1, 33);
    }

    /** Z of the target side: x-coordinate of {@code link · E} (§9.13/§9.14). */
    public byte[] z(byte[] e65) {
        return ecdhX(link, e65);
    }

    /** {@code K_te ‖ K_tm = KDF(Z, "qntx-card/v1/kdf-transfer", SHA-256(M), 32)} (§9.13). */
    public static byte[][] transferKeys(byte[] z, byte[] m) {
        byte[] k = Crypto.kdf(z, LABEL_KDF_TRANSFER, Crypto.sha256(m), 32);
        return new byte[][] {Arrays.copyOf(k, 16), Arrays.copyOfRange(k, 16, 32)};
    }

    /**
     * The {@code ct ‖ tag} of a pending-import record ({@code IMPORT P1=0x01} command data): {@code
     * CBC(K_te, 0¹⁶, M2(payload))} and its {@code CMAC(K_tm)} (§9.13/§9.14).
     */
    public static byte[] sealRecord(byte[] z, byte[] m, byte[] payload) {
        byte[][] keys = transferKeys(z, m);
        byte[] ct = Crypto.aesCbc(keys[0], new byte[16], Crypto.m2pad(payload), true);
        return concat(ct, Crypto.cmac(keys[1], ct));
    }

    /**
     * Opens an exported record {@code ct ‖ tag} the way the target would: checks the CMAC, then
     * decrypts and unpads — {@code null} when either fails (§9.13/§9.14).
     */
    public static byte[] unsealRecord(byte[] z, byte[] m, byte[] record) {
        byte[][] keys = transferKeys(z, m);
        byte[] ct = Arrays.copyOf(record, record.length - 16);
        byte[] tag = Arrays.copyOfRange(record, record.length - 16, record.length);
        if (!Arrays.equals(Crypto.cmac(keys[1], ct), tag)) {
            return null;
        }
        return Crypto.m2unpad(Crypto.aesCbc(keys[0], new byte[16], ct, false));
    }

    /**
     * The transferred payload {@code origin ‖ seed(64) ‖ accessHash_T(32) ‖ c ‖ IDs} (§9.13):
     * {@code ids} is the source's member list, own ID first, {@code c} of 2 or 3.
     */
    public static byte[] payload(int origin, byte[] seed, byte[] accessHashT, byte[]... ids) {
        if (ids.length < 2 || ids.length > 3) {
            throw new IllegalArgumentException("c must be 2 or 3");
        }
        byte[] out = new byte[98 + 16 * ids.length];
        out[0] = (byte) origin;
        System.arraycopy(seed, 0, out, 1, 64);
        System.arraycopy(accessHashT, 0, out, 65, 32);
        out[97] = (byte) ids.length;
        for (int i = 0; i < ids.length; i++) {
            System.arraycopy(ids[i], 0, out, 98 + 16 * i, 16);
        }
        return out;
    }

    private static BigInteger randomScalar() {
        BigInteger k;
        do {
            k = new BigInteger(256, Vecs.RND);
        } while (k.signum() == 0 || k.compareTo(Crypto.N) >= 0);
        return k;
    }

    private static byte[] fixed(BigInteger v) {
        byte[] out = new byte[32];
        byte[] raw = v.toByteArray();
        int src = Math.max(0, raw.length - 32);
        int n = Math.min(32, raw.length);
        System.arraycopy(raw, src, out, 32 - n, n);
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }
}
