// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

/**
 * secp256k1 domain (SEC 2 v2 §2.4.1), scalar multiplication through the shared {@link Mem#plainXy}
 * {@code ALG_EC_SVDP_DH_PLAIN_XY} engine, compression, the explicit on-curve check of §16.5 and the
 * DER ⇄ {@code r ‖ s} codec of §1. Owns the shared {@code ALG_ECDSA_SHA_256} engine and the
 * transient private key every scalar multiplication is loaded into.
 */
final class Secp256k1 {
    /** Field prime {@code p}. */
    static final byte[] P = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFC, (byte) 0x2F,
    };

    /** Curve coefficient {@code a = 0}. */
    private static final byte[] A = new byte[32];

    /** Curve coefficient {@code b = 7}. */
    private static final byte[] B = {7};

    /** {@code b} as a 32-byte operand of {@link ModArith} for {@code x³ + 7}. */
    private static final byte[] B32 = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        7
    };

    /** Generator {@code G}, uncompressed. */
    static final byte[] G = {
        (byte) 0x04, (byte) 0x79, (byte) 0xBE, (byte) 0x66, (byte) 0x7E, (byte) 0xF9,
        (byte) 0xDC, (byte) 0xBB, (byte) 0xAC, (byte) 0x55, (byte) 0xA0, (byte) 0x62,
        (byte) 0x95, (byte) 0xCE, (byte) 0x87, (byte) 0x0B, (byte) 0x07, (byte) 0x02,
        (byte) 0x9B, (byte) 0xFC, (byte) 0xDB, (byte) 0x2D, (byte) 0xCE, (byte) 0x28,
        (byte) 0xD9, (byte) 0x59, (byte) 0xF2, (byte) 0x81, (byte) 0x5B, (byte) 0x16,
        (byte) 0xF8, (byte) 0x17, (byte) 0x98, (byte) 0x48, (byte) 0x3A, (byte) 0xDA,
        (byte) 0x77, (byte) 0x26, (byte) 0xA3, (byte) 0xC4, (byte) 0x65, (byte) 0x5D,
        (byte) 0xA4, (byte) 0xFB, (byte) 0xFC, (byte) 0x0E, (byte) 0x11, (byte) 0x08,
        (byte) 0xA8, (byte) 0xFD, (byte) 0x17, (byte) 0xB4, (byte) 0x48, (byte) 0xA6,
        (byte) 0x85, (byte) 0x54, (byte) 0x19, (byte) 0x9C, (byte) 0x47, (byte) 0xD0,
        (byte) 0x8F, (byte) 0xFB, (byte) 0x10, (byte) 0xD4, (byte) 0xB8,
    };

    /** Group order {@code n}. */
    static final byte[] N = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xBA, (byte) 0xAE,
        (byte) 0xDC, (byte) 0xE6, (byte) 0xAF, (byte) 0x48, (byte) 0xA0, (byte) 0x3B,
        (byte) 0xBF, (byte) 0xD2, (byte) 0x5E, (byte) 0x8C, (byte) 0xD0, (byte) 0x36,
        (byte) 0x41, (byte) 0x41,
    };

    /**
     * {@link Mem#P} offsets of the {@link #onCurve} operands (all of {@link Mem#W} is ModArith's).
     */
    private static final short P_Y2 = 0;

    private static final short P_X2 = 32;
    private static final short P_RHS = 64;

    private final Mem mem;
    private final ModArith modArith;

    /** Shared with {@link Identity}: the only ECDSA engine (architecture.md §5.1). */
    final Signature ecdsa;

    /** Single-use scalar slot of {@link #mul}; wiped by {@link #wipeScalar}. */
    private final ECPrivateKey ephKey;

    Secp256k1(Mem mem, ModArith modArith) {
        this.mem = mem;
        this.modArith = modArith;
        ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        ephKey =
                (ECPrivateKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                                KeyBuilder.LENGTH_EC_FP_256,
                                false);
    }

    /**
     * Loads the secp256k1 domain into the transient scalar key. A {@code CLEAR_ON_DESELECT} EC
     * key's domain parameters die with the selection epoch (§8.5), so {@link WalletApplet#select()}
     * calls this on every selection before any signing path can run; the writes land on the
     * transient object only, nothing persistent.
     */
    void loadEphDomain() {
        setDomain(ephKey);
    }

    /** Loads the SEC 2 §2.4.1 parameters onto a key object. */
    static void setDomain(ECKey key) {
        key.setFieldFP(P, (short) 0, (short) P.length);
        key.setA(A, (short) 0, (short) A.length);
        key.setB(B, (short) 0, (short) B.length);
        key.setG(G, (short) 0, (short) G.length);
        key.setR(N, (short) 0, (short) N.length);
        key.setK((short) 1);
    }

    /** A fresh scalar {@code 1 ≤ int ≤ n − 1} (§8.1), redrawn while out of range. */
    void randomScalar(byte[] out, short off) {
        for (; ; ) {
            mem.random.nextBytes(out, off, (short) 32);
            short any = 0;
            for (short i = 0; i < 32; i++) {
                any |= out[(short) (off + i)];
            }
            if (any != 0 && compare(out, off, N, (short) 0) < 0) {
                return;
            }
        }
    }

    /**
     * {@code out = scalar·point} (65-byte uncompressed) via PLAIN_XY; returns the written length.
     * Loads the scalar into the transient key; a {@code CryptoException} (invalid point, §3 item 3)
     * propagates to the caller, which maps it.
     */
    short mul(byte[] scalar, short sOff, byte[] point, short pOff, byte[] out, short oOff) {
        ephKey.setS(scalar, sOff, (short) 32);
        mem.plainXy.init(ephKey);
        return mem.plainXy.generateSecret(point, pOff, Const.POINT_LEN, out, oOff);
    }

    /** Overwrites the transient scalar slot; no {@code clearKey} anywhere (architecture.md §4). */
    void wipeScalar() {
        ephKey.setS(Const.ZEROS, (short) 0, (short) 32);
    }

    /**
     * {@code out = s·G + H} (65-byte uncompressed) via the shared {@link Mem#paceGm} engine: {@code
     * h} is the 65-byte uncompressed point and {@code s} the 32-byte scalar loaded into {@link
     * #ephKey} (overwritten in a {@code finally}). The output must not overlap {@code h} ({@code
     * generateSecret} reads its input point). A {@code CryptoException} propagates — §16.2 item 8
     * maps it to {@code 6F00} inside a signing command.
     */
    short mulAdd(byte[] s, short sOff, byte[] h, short hOff, byte[] out, short oOff) {
        try {
            ephKey.setS(s, sOff, (short) 32);
            mem.paceGm.init(ephKey);
            return mem.paceGm.generateSecret(h, hOff, Const.POINT_LEN, out, oOff);
        } finally {
            ephKey.setS(Const.ZEROS, (short) 0, (short) 32);
        }
    }

    /**
     * Signs the 32-byte precomputed {@code hash} under {@code scalar} (§12.1): {@code
     * signPreComputedHash} on the shared ECDSA engine, DER into {@link Mem#W_DER}, decoded to
     * {@code r(32) ‖ s(32)} at {@code rs}. The scalar slot is overwritten in a {@code finally}.
     */
    void sign(byte[] scalar, short sOff, byte[] hash, short hOff, byte[] rs, short rsOff) {
        try {
            ephKey.setS(scalar, sOff, (short) 32);
            ecdsa.init(ephKey, Signature.MODE_SIGN);
            short derLen = ecdsa.signPreComputedHash(hash, hOff, Const.HASH_LEN, mem.W, Mem.W_DER);
            derToRs(mem.W, Mem.W_DER, derLen, rs, rsOff);
        } finally {
            ephKey.setS(Const.ZEROS, (short) 0, (short) 32);
        }
    }

    /**
     * Verifies {@code r ‖ s} over a 32-byte precomputed hash; {@code CHECK_MALFORMED} on an
     * out-of-range scalar (it cannot have come from a signature), {@code CHECK_FAIL} on a bad
     * signature or a {@link CryptoException} from the engine.
     */
    short verifyHash(ECPublicKey key, byte[] hash, short hOff, byte[] rs, short rsOff) {
        short derLen = rsToDer(rs, rsOff, mem.W, Mem.W_DER);
        if (derLen == 0) {
            return Const.CHECK_MALFORMED;
        }
        try {
            ecdsa.init(key, Signature.MODE_VERIFY);
            return ecdsa.verifyPreComputedHash(hash, hOff, Const.HASH_LEN, mem.W, Mem.W_DER, derLen)
                    ? Const.CHECK_OK
                    : Const.CHECK_FAIL;
        } catch (CryptoException e) {
            return Const.CHECK_FAIL;
        }
    }

    /**
     * SEC 1 §2.3.4 decompression of {@code 02 ‖ x} / {@code 03 ‖ x} into the 65-byte uncompressed
     * {@code out} (§10.5): {@code x < p}, {@code y = (x³ + 7)^((p+1)/4)} with the {@code y² ≡ z}
     * residue check and the prefix parity fix. The residue check makes the result a validated curve
     * point; a non-residue {@code x} is {@code CHECK_FAIL}.
     */
    short decompress(byte[] in, short iOff, byte[] out, short oOff) {
        byte prefix = in[iOff];
        if (prefix != 0x02 && prefix != 0x03) {
            return Const.CHECK_FAIL;
        }
        if (compare(in, (short) (iOff + 1), P, (short) 0) >= 0) {
            return Const.CHECK_FAIL;
        }
        byte[] p = mem.P;
        modArith.mul(ModArith.MOD_P, in, (short) (iOff + 1), in, (short) (iOff + 1), p, P_X2);
        modArith.mul(ModArith.MOD_P, p, P_X2, in, (short) (iOff + 1), p, P_RHS);
        modArith.addMod(ModArith.MOD_P, p, P_RHS, B32, (short) 0, p, P_Y2); // P_Y2 = z
        modArith.sqrt(p, P_Y2, p, P_X2); // P_X2 = y
        modArith.square(ModArith.MOD_P, p, P_X2, p, P_RHS);
        if (Bytes.equal(p, P_RHS, p, P_Y2, (short) 32) != Const.CHECK_OK) {
            return Const.CHECK_FAIL;
        }
        if ((short) (p[(short) (P_X2 + 31)] & 0x01) != (short) (prefix & 0x01)) {
            modArith.subMod(ModArith.MOD_P, P, (short) 0, p, P_X2, p, P_Y2);
            Util.arrayCopy(p, P_Y2, p, P_X2, (short) 32);
        }
        out[oOff] = 0x04;
        Util.arrayCopy(in, (short) (iOff + 1), out, (short) (oOff + 1), (short) 32);
        Util.arrayCopy(p, P_X2, out, (short) (oOff + 33), (short) 32);
        return Const.CHECK_OK;
    }

    /**
     * {@code out = x-coordinate of key·point} (32 bytes), the ECDH shared secret of §9.13–9.14.
     * PLAIN_XY rejects an invalid {@code point} itself (§16.5); a {@code CryptoException} maps to
     * {@code CHECK_FAIL}. The key object is the caller's — the link pair's private half or the
     * transient {@link #ephKey} slot, never copied out.
     */
    short agree(ECPrivateKey key, byte[] point, short pOff, byte[] out, short oOff) {
        try {
            mem.plainXy.init(key);
            mem.plainXy.generateSecret(point, pOff, Const.POINT_LEN, mem.P, P_Y2);
            Util.arrayCopy(mem.P, (short) (P_Y2 + 1), out, oOff, (short) 32);
            return Const.CHECK_OK;
        } catch (CryptoException e) {
            return Const.CHECK_FAIL;
        }
    }

    /** The single-use scalar slot, still loaded after {@link #mul} — for {@link #agree}. */
    ECPrivateKey ephKey() {
        return ephKey;
    }

    /** SEC 1 §2.3.3 compression of an uncompressed point. */
    void compress(byte[] point, short pOff, byte[] out, short oOff) {
        out[oOff] = (point[(short) (pOff + 64)] & 0x01) == 0 ? (byte) 0x02 : (byte) 0x03;
        Util.arrayCopy(point, (short) (pOff + 1), out, (short) (oOff + 1), (short) 32);
    }

    /**
     * The explicit on-curve check of §16.5 ({@code setW} does not check points): {@code point[0] =
     * 0x04}, both coordinates {@code < p} and {@code y² ≡ x³ + 7 (mod p)}. Coded result.
     */
    short onCurve(byte[] point, short off) {
        if (point[off] != 0x04) {
            return Const.CHECK_FAIL;
        }
        if (compare(point, (short) (off + 1), P, (short) 0) >= 0
                || compare(point, (short) (off + 33), P, (short) 0) >= 0) {
            return Const.CHECK_FAIL;
        }
        byte[] p = mem.P;
        modArith.square(ModArith.MOD_P, point, (short) (off + 33), p, P_Y2);
        modArith.mul(ModArith.MOD_P, point, (short) (off + 1), point, (short) (off + 1), p, P_X2);
        modArith.mul(ModArith.MOD_P, p, P_X2, point, (short) (off + 1), p, P_RHS);
        modArith.addMod(ModArith.MOD_P, p, P_RHS, B32, (short) 0, p, P_X2);
        return Bytes.equal(p, P_Y2, p, P_X2, (short) 32);
    }

    /**
     * Strict DER decode of the platform's ECDSA output into {@code r(32) ‖ s(32)}: SEQUENCE of two
     * positive INTEGERs of at most 33 bytes, a leading 0x00 only when the high bit needs it.
     * Anything unexpected is a platform fault ({@code 6F00}).
     */
    void derToRs(byte[] der, short dOff, short dLen, byte[] out, short oOff) {
        Util.arrayFillNonAtomic(out, oOff, (short) 64, (byte) 0);
        short i = dOff;
        short end = (short) (dOff + dLen);
        if (dLen < 8
                || der[i] != 0x30
                || (short) (der[(short) (i + 1)] & 0xFF) != (short) (dLen - 2)) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        i += 2;
        i = integer(der, i, end, out, (short) (oOff + 32));
        i = integer(der, i, end, out, (short) (oOff + 64));
        if (i != end) {
            ISOException.throwIt(Const.SW_FAULT);
        }
    }

    /**
     * {@code r(32) ‖ s(32)} to DER; returns the DER length or 0 when {@code r} or {@code s} is
     * outside {@code [1, n−1]} (§1 {@code Verify} fails then; callers map 0 to CHECK_FAIL).
     */
    short rsToDer(byte[] rs, short rsOff, byte[] out, short oOff) {
        if (inRange(rs, rsOff) != Const.CHECK_OK
                || inRange(rs, (short) (rsOff + 32)) != Const.CHECK_OK) {
            return 0;
        }
        short rLen = intLen(rs, rsOff);
        short sLen = intLen(rs, (short) (rsOff + 32));
        short i = oOff;
        out[i] = 0x30;
        i++;
        out[i] = (byte) (2 + rLen + 2 + sLen);
        i++;
        i = putInt(rs, rsOff, out, i);
        i = putInt(rs, (short) (rsOff + 32), out, i);
        return (short) (i - oOff);
    }

    /** Writes one INTEGER element of the 32-byte {@code v}; returns the next offset. */
    private static short putInt(byte[] v, short vOff, byte[] out, short i) {
        short i0 = firstSignificant(v, vOff);
        short sigLen = (short) (32 - i0);
        short signByte = (short) ((v[(short) (vOff + i0)] & 0x80) >>> 7);
        out[i] = 0x02;
        i++;
        out[i] = (byte) (sigLen + signByte);
        i++;
        if (signByte != 0) {
            out[i] = 0;
            i++;
        }
        Util.arrayCopy(v, (short) (vOff + i0), out, i, sigLen);
        i += sigLen;
        return i;
    }

    /** DER INTEGER payload length of a 32-byte value: no leading zeros, sign byte when needed. */
    private static short intLen(byte[] v, short off) {
        short i0 = firstSignificant(v, off);
        return (short) (32 - i0 + ((v[(short) (off + i0)] & 0x80) != 0 ? 1 : 0));
    }

    /** Index of the first non-zero byte of the 32-byte value at {@code v[off..off+32)}. */
    private static short firstSignificant(byte[] v, short off) {
        short i = 0;
        while (i < 31 && v[(short) (off + i)] == 0) {
            i++;
        }
        return i;
    }

    /** {@code CHECK_OK} when the 32-byte value is in {@code [1, n−1]}. */
    private static short inRange(byte[] v, short off) {
        short any = 0;
        for (short i = 0; i < 32; i++) {
            any |= v[(short) (off + i)];
        }
        return any != 0 && compare(v, off, N, (short) 0) < 0 ? Const.CHECK_OK : Const.CHECK_FAIL;
    }

    /**
     * Parses one DER INTEGER into the right-aligned 32-byte slot {@code out}; -32 shift of next.
     */
    private static short integer(byte[] der, short i, short end, byte[] out, short outEnd) {
        if ((short) (i + 2) > end || der[i] != 0x02) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        short len = (short) (der[(short) (i + 1)] & 0xFF);
        i += 2;
        if (len < 1 || len > 33 || (short) (i + len) > end) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (len > 1 && der[i] == 0 && (der[(short) (i + 1)] & 0x80) == 0) {
            // non-minimal positive encoding
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (len == 33 && der[i] != 0) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (len != 33 && (short) (der[i] & 0x80) != 0) {
            // a negative INTEGER: the sign byte is missing
            ISOException.throwIt(Const.SW_FAULT);
        }
        short skip = (short) (len == 33 ? 1 : 0);
        Util.arrayCopy(
                der,
                (short) (i + skip),
                out,
                (short) (outEnd - (short) (len - skip)),
                (short) (len - skip));
        return (short) (i + len);
    }

    /** Lexicographic compare of two 32-byte big-endian values; <0, 0, >0. */
    private static short compare(byte[] a, short aOff, byte[] b, short bOff) {
        for (short i = 0; i < 32; i++) {
            short d = (short) ((a[(short) (aOff + i)] & 0xFF) - (b[(short) (bOff + i)] & 0xFF));
            if (d != 0) {
                return d;
            }
        }
        return 0;
    }
}
