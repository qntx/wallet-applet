// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review3;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;

/**
 * The host-side primitives of spec/protocol.md §1, §5 and §10, implemented from the spec text on
 * top of JCA and BouncyCastle: hex/concatenation, SHA-256/SHA-512, HMAC-SHA512, AES-128-CBC,
 * AES-CMAC, M2 padding, the one-step KDF and KDF108, secp256k1 ECDSA over a precomputed hash in the
 * {@code r(32) ‖ s(32)} wire form, compressed/decompressed point encodings, the ECDH x-coordinate
 * agreement, the card ID and BIP-32 derivation. Used by every review3 host class and self-tested
 * against the spec's own vector files (§18).
 */
final class H3 {

    /** secp256k1 field prime {@code p} (§1). */
    static final BigInteger P =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);

    /** secp256k1 group order {@code n} (§1). */
    static final BigInteger N =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    private static final X9ECParameters SECP = SECNamedCurves.getByName("secp256k1");

    private static final ECDomainParameters DOMAIN =
            new ECDomainParameters(SECP.getCurve(), SECP.getG(), SECP.getN(), SECP.getH());

    private static final byte[] ZERO16 = new byte[16];

    private static final SecureRandom RNG = new SecureRandom();

    private H3() {}

    // ---------------------------------------------------------------- bytes

    /** Lowercase hex of {@code b}, the vector-file encoding of §18. */
    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte x : b) {
            s.append(Character.forDigit((x >> 4) & 0xF, 16));
            s.append(Character.forDigit(x & 0xF, 16));
        }
        return s.toString();
    }

    /** Parses lowercase hex; fails on an odd length or a non-hex character. */
    static byte[] unhex(String s) {
        if ((s.length() & 1) != 0) {
            throw new IllegalArgumentException("odd hex length");
        }
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int hi = Character.digit(s.charAt(2 * i), 16);
            int lo = Character.digit(s.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("non-hex character");
            }
            b[i] = (byte) ((hi << 4) | lo);
        }
        return b;
    }

    /** {@code a ‖ b ‖ …} — the spec's {@code ‖} (§1). */
    static byte[] cat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    /** The ASCII bytes of a quoted spec label (§1). */
    static byte[] label(String s) {
        return s.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    /** Big-endian {@code u16} (§1). */
    static byte[] u16(int v) {
        return new byte[] {(byte) (v >>> 8), (byte) v};
    }

    /** Big-endian {@code u32} (§1). */
    static byte[] u32(long v) {
        return new byte[] {(byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v};
    }

    /** Big-endian 32-byte encoding of {@code v} (a scalar or field element). */
    static byte[] u256(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b.length == 32) {
            return b;
        }
        byte[] out = new byte[32];
        if (b.length > 32) {
            System.arraycopy(b, b.length - 32, out, 0, 32);
        } else {
            System.arraycopy(b, 0, out, 32 - b.length, b.length);
        }
        return out;
    }

    // ---------------------------------------------------------------- digests

    static byte[] sha256(byte[] x) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(x);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] sha512(byte[] x) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(x);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** RFC 2104 HMAC-SHA512 (§1). */
    static byte[] hmacSha512(byte[] key, byte[] msg) {
        try {
            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(new SecretKeySpec(key, "HmacSHA512"));
            return mac.doFinal(msg);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    // ---------------------------------------------------------------- AES / CMAC

    /** {@code AES(K, X)}: one 16-byte block of AES-128 encryption (§1). */
    static byte[] aesBlock(byte[] key, byte[] block) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            return c.doFinal(block);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** {@code CBC(K, IV, X)}: AES-128-CBC encryption without padding (§1). */
    static byte[] cbcEnc(byte[] key, byte[] iv, byte[] x) {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return c.doFinal(x);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** {@code CBC⁻¹(K, IV, X)}: AES-128-CBC decryption without padding. */
    static byte[] cbcDec(byte[] key, byte[] iv, byte[] x) {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return c.doFinal(x);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** {@code CMAC(K, M)}: AES-CMAC with a 128-bit key and the full 16-byte output (§1). */
    static byte[] cmac(byte[] key, byte[] msg) {
        CMac mac = new CMac(new AESEngine());
        mac.init(new KeyParameter(key));
        mac.update(msg, 0, msg.length);
        byte[] out = new byte[16];
        mac.doFinal(out, 0);
        return out;
    }

    // ---------------------------------------------------------------- M2 padding (§1)

    /** {@code M2(X)}: ISO/IEC 9797-1 padding method 2, {@code X ‖ 0x80 ‖ 0ᵏ} (§1). */
    static byte[] m2(byte[] x) {
        int pad = 16 - (x.length % 16);
        byte[] out = Arrays.copyOf(x, x.length + pad);
        out[x.length] = (byte) 0x80;
        return out;
    }

    /**
     * {@code unM2(Y)} (§1): strips the M2 padding. Fails (returns {@code null}) when {@code Y} is
     * empty, not a multiple of 16, or lacks the {@code 0x80} within the last 16 bytes.
     */
    static byte[] unM2(byte[] y) {
        if (y == null || y.length == 0 || (y.length & 0xF) != 0) {
            return null;
        }
        for (int i = y.length - 1; i >= y.length - 16; i--) {
            if (y[i] == (byte) 0x80) {
                return Arrays.copyOf(y, i);
            }
            if (y[i] != 0) {
                return null;
            }
        }
        return null;
    }

    // ---------------------------------------------------------------- KDFs (§1)

    /**
     * {@code KDF(Z, label, ctx, len)}: NIST SP 800-56C Rev. 2 §4.1 option 1 with H = SHA-256 and
     * FixedInfo {@code = label ‖ ctx} (§1). {@code len ≤ 64}.
     */
    static byte[] kdf(byte[] z, byte[] label, byte[] ctx, int len) {
        if (len > 64) {
            throw new IllegalArgumentException("KDF len > 64");
        }
        byte[] fixed = cat(label, ctx);
        byte[] out = new byte[(len + 31) & ~31];
        for (long i = 1; i * 32 <= out.length; i++) {
            byte[] block = sha256(cat(u32(i), z, fixed));
            System.arraycopy(block, 0, out, (int) (i - 1) * 32, 32);
        }
        return Arrays.copyOf(out, len);
    }

    /**
     * {@code KDF108(K, label, ctx)}: SP 800-108r1 §4.1 counter mode, PRF = CMAC, r = 8, 256 bits
     * (§1): {@code CMAC(K, 0x01 ‖ label ‖ 0x00 ‖ ctx ‖ 0x0100) ‖ CMAC(K, 0x02 ‖ …)}.
     */
    static byte[] kdf108(byte[] k, byte[] label, byte[] ctx) {
        byte[] suffix = cat(new byte[] {0}, ctx, new byte[] {1, 0});
        byte[] i1 = cat(new byte[] {1}, label, suffix);
        byte[] i2 = cat(new byte[] {2}, label, suffix);
        return cat(cmac(k, i1), cmac(k, i2));
    }

    // ---------------------------------------------------------------- secp256k1 (§1, §10.5)

    /** A uniform scalar in {@code [1, n − 1]}. */
    static BigInteger randomScalar() {
        for (; ; ) {
            BigInteger d = new BigInteger(256, RNG);
            if (d.signum() > 0 && d.compareTo(N) < 0) {
                return d;
            }
        }
    }

    /** The {@code int(b)} interpretation of big-endian bytes (§1). */
    static BigInteger bigInt(byte[] b) {
        return new BigInteger(1, b);
    }

    /** The uncompressed {@code 0x04 ‖ x ‖ y} encoding of {@code d·G} (65 bytes). */
    static byte[] pubPoint(BigInteger d) {
        return DOMAIN.getG().multiply(d).normalize().getEncoded(false);
    }

    /** Decodes a 65-byte uncompressed point. */
    static ECPoint point(byte[] uncompressed) {
        return DOMAIN.getCurve().decodePoint(uncompressed);
    }

    /** The {@code compressed} encoding {@code 0x02|0x03 ‖ x(32)} of a point (§1). */
    static byte[] compress(ECPoint p) {
        return p.normalize().getEncoded(true);
    }

    /**
     * The decompression of §10.5: {@code x < p}, tag {@code 0x02|0x03}, {@code z = x³ + 7 mod p},
     * {@code y = z^{(p+1)/4}}, square check, parity fix. Returns the 65-byte uncompressed point or
     * {@code null} on any failure.
     */
    static byte[] decompress(byte[] compressed) {
        if (compressed == null
                || compressed.length != 33
                || (compressed[0] != 0x02 && compressed[0] != 0x03)) {
            return null;
        }
        BigInteger x = bigInt(Arrays.copyOfRange(compressed, 1, 33));
        if (x.compareTo(P) >= 0) {
            return null;
        }
        BigInteger z = x.modPow(BigInteger.valueOf(3), P).add(BigInteger.valueOf(7)).mod(P);
        BigInteger y = z.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
        if (!y.modPow(BigInteger.TWO, P).equals(z)) {
            return null;
        }
        if (y.testBit(0) != ((compressed[0] & 1) == 1)) {
            y = P.subtract(y);
        }
        return cat(new byte[] {4}, u256(x), u256(y));
    }

    /** The 32-byte x-coordinate of {@code d·P} — the ECDH shared secret {@code Z} (§8.1, §9.13). */
    static byte[] ecdhX(BigInteger d, byte[] uncompressed) {
        ECPoint q = point(uncompressed).multiply(d).normalize();
        return u256(q.getAffineXCoord().toBigInteger());
    }

    /**
     * {@code Sign(k, M)}'s core: ECDSA over a precomputed 32-byte hash (§1); wire form {@code r(32)
     * ‖ s(32)}, {@code s} not normalised.
     */
    static byte[] ecdsaSign(BigInteger d, byte[] hash32) {
        ECDSASigner s = new ECDSASigner();
        s.init(true, new ECPrivateKeyParameters(d, DOMAIN));
        BigInteger[] rs = s.generateSignature(hash32);
        return cat(u256(rs[0]), u256(rs[1]));
    }

    /**
     * {@code Verify(A, M, sig)}'s core over a precomputed 32-byte hash (§1); {@code pub} is the
     * compressed or uncompressed key. Fails when {@code r} or {@code s} is outside {@code [1, n −
     * 1]}.
     */
    static boolean ecdsaVerify(byte[] pub, byte[] hash32, byte[] sig) {
        if (sig.length != 64) {
            return false;
        }
        BigInteger r = bigInt(Arrays.copyOfRange(sig, 0, 32));
        BigInteger s = bigInt(Arrays.copyOfRange(sig, 32, 64));
        if (r.signum() <= 0 || r.compareTo(N) >= 0 || s.signum() <= 0 || s.compareTo(N) >= 0) {
            return false;
        }
        ECDSASigner v = new ECDSASigner();
        v.init(false, new ECPublicKeyParameters(DOMAIN.getCurve().decodePoint(pub), DOMAIN));
        return v.verifySignature(hash32, r, s);
    }

    /** {@code ID(A) = SHA-256(A)[0..16)} of a compressed identity key (§1). */
    static byte[] cardId(byte[] compressedA) {
        return Arrays.copyOf(sha256(compressedA), 16);
    }

    // ---------------------------------------------------------------- BIP-32 (§10.2–10.3)

    /**
     * §10.2: {@code I = HMAC-SHA512("Bitcoin seed", seed)}. Returns {@code kM(32) ‖ cM(32)}, or
     * {@code null} when the master key is invalid ({@code kM ∉ [1, n − 1]}).
     */
    static byte[] bip32Master(byte[] seed) {
        byte[] i = hmacSha512(label("Bitcoin seed"), seed);
        BigInteger k = bigInt(i, 0, 32);
        if (k.signum() <= 0 || k.compareTo(N) >= 0) {
            return null;
        }
        return i;
    }

    /** §10.2: the compressed BIP-32 master public key of {@code seed}. */
    static byte[] masterPublicKey(byte[] seed) {
        byte[] i = bip32Master(seed);
        if (i == null) {
            throw new IllegalArgumentException("invalid BIP-32 master key");
        }
        return compress(point(pubPoint(bigInt(i, 0, 32))));
    }

    private static BigInteger bigInt(byte[] b, int off, int len) {
        return new BigInteger(1, Arrays.copyOfRange(b, off, off + len));
    }

    /**
     * §10.3 {@code CKDpriv}: {@code (k_par, c_par, i) → (k, c)}. Throws {@link
     * IllegalArgumentException} on an invalid child ({@code int(I_L) ≥ n} or {@code k = 0}, the
     * card's {@code 6A80}).
     */
    static byte[][] ckdPriv(byte[] kPar, byte[] cPar, long index) {
        byte[] data =
                index >= 0x80000000L
                        ? cat(new byte[] {0}, kPar, u32(index))
                        : cat(compress(point(pubPoint(bigInt(kPar)))), u32(index));
        byte[] i = hmacSha512(cPar, data);
        BigInteger il = bigInt(i, 0, 32);
        if (il.compareTo(N) >= 0) {
            throw new IllegalArgumentException("invalid BIP-32 child (IL ≥ n)");
        }
        BigInteger k = il.add(bigInt(kPar)).mod(N);
        if (k.signum() == 0) {
            throw new IllegalArgumentException("invalid BIP-32 child (k = 0)");
        }
        return new byte[][] {u256(k), Arrays.copyOfRange(i, 32, 64)};
    }

    /**
     * §10.3 public derivation for a non-hardened index: {@code (K_par, c_par, i) → (K, c)} with
     * {@code K = int(I_L)·G + K_par}. Throws on a hardened index or an invalid child.
     */
    static byte[][] ckdPub(byte[] pubPar33, byte[] cPar, long index) {
        if (index >= 0x80000000L) {
            throw new IllegalArgumentException("hardened index has no public derivation");
        }
        byte[] i = hmacSha512(cPar, cat(pubPar33, u32(index)));
        BigInteger il = bigInt(i, 0, 32);
        if (il.compareTo(N) >= 0) {
            throw new IllegalArgumentException("invalid BIP-32 child (IL ≥ n)");
        }
        ECPoint k = DOMAIN.getG().multiply(il).add(point(decompressOrThrow(pubPar33))).normalize();
        if (k.isInfinity()) {
            throw new IllegalArgumentException("invalid BIP-32 child (K = ∞)");
        }
        return new byte[][] {compress(k), Arrays.copyOfRange(i, 32, 64)};
    }

    private static byte[] decompressOrThrow(byte[] compressed) {
        byte[] p = decompress(compressed);
        if (p == null) {
            throw new IllegalArgumentException("bad compressed point");
        }
        return p;
    }

    /**
     * §10.3: the node {@code (key, chainCode, compressedPublicKey)} of {@code seed} at {@code path}
     * via {@code CKDpriv}.
     */
    static byte[][] derivePriv(byte[] seed, long[] path) {
        byte[] node = bip32Master(seed);
        if (node == null) {
            throw new IllegalArgumentException("invalid BIP-32 master key");
        }
        byte[] k = Arrays.copyOfRange(node, 0, 32);
        byte[] c = Arrays.copyOfRange(node, 32, 64);
        for (long index : path) {
            byte[][] child = ckdPriv(k, c, index);
            k = child[0];
            c = child[1];
        }
        return new byte[][] {k, c, compress(point(pubPoint(bigInt(k))))};
    }

    // ---------------------------------------------------------------- misc

    /** The {@code u32} path encoding of §9.2: {@code depth(1) ‖ u32(index) …}. */
    static byte[] pathBytes(long... indices) {
        byte[] p = new byte[1 + 4 * indices.length];
        p[0] = (byte) indices.length;
        for (int i = 0; i < indices.length; i++) {
            System.arraycopy(u32(indices[i]), 0, p, 1 + 4 * i, 4);
        }
        return p;
    }

    /** Constant-time equality for tags and MACs (§8.4: the host verifies before decrypting). */
    static boolean equal(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    /** A zero-filled AES-128 key — the all-zero key of the PoC assertions. */
    static byte[] zeros(int n) {
        return new byte[n];
    }
}
