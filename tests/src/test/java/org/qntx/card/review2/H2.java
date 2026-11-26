// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review2;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Second-review independent host primitives, implemented only from spec/protocol.md section 1 (and
 * the public BIP-32/340, SLIP-10, RFC 8032 documents it cites). Shares no code with the reference
 * host or the first review's host.
 */
final class H2 {
    static final SecureRandom RND = new SecureRandom();

    private static final X9ECParameters SEC = SECNamedCurves.getByName("secp256k1");
    static final ECDomainParameters SECP =
            new ECDomainParameters(SEC.getCurve(), SEC.getG(), SEC.getN(), SEC.getH());
    static final BigInteger N = SEC.getN();
    static final BigInteger P = SEC.getCurve().getField().getCharacteristic();

    // Wei25519 (spec section 10.4): Y^2 = X^3 + aW*X + bW over q, base GW, order l.
    private static final BigInteger Q =
            new BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16);
    private static final BigInteger AW =
            new BigInteger("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144", 16);
    private static final BigInteger BW =
            new BigInteger("7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864", 16);
    static final BigInteger ED_ORDER =
            new BigInteger("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16);
    private static final ECCurve WEI = new ECCurve.Fp(Q, AW, BW, ED_ORDER, BigInteger.ONE);
    private static final ECPoint GW =
            WEI.createPoint(
                    new BigInteger(
                            "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a", 16),
                    new BigInteger(
                            "20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9",
                            16));

    // Wei25519 -> edwards25519 constants of spec section 10.4.
    private static final BigInteger A3 =
            new BigInteger("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad2451", 16);
    private static final BigInteger C_SQRT =
            new BigInteger("70d9120b9f5ff9442d84f723fc03b0813a5e2c2eb482e57d3391fb5500ba81e7", 16);

    private H2() {}

    // ----- byte utilities -----------------------------------------------------

    static byte[] hex(String s) {
        if ((s.length() & 1) != 0) {
            throw new IllegalArgumentException("odd hex length");
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(2 * b.length);
        for (byte v : b) {
            sb.append(Character.forDigit((v >> 4) & 0xF, 16))
                    .append(Character.forDigit(v & 0xF, 16));
        }
        return sb.toString();
    }

    static byte[] cat(byte[]... parts) {
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

    static byte[] ascii(String s) {
        return s.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    static byte[] u16(int v) {
        return new byte[] {(byte) (v >> 8), (byte) v};
    }

    static byte[] u32(long v) {
        return new byte[] {(byte) (v >> 24), (byte) (v >> 16), (byte) (v >> 8), (byte) v};
    }

    // ----- hashes and MACs ----------------------------------------------------

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] sha512(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(data);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] hmacSha512(byte[] key, byte[] data) {
        HMac mac = new HMac(new SHA512Digest());
        mac.init(new KeyParameter(key));
        mac.update(data, 0, data.length);
        byte[] out = new byte[64];
        mac.doFinal(out, 0);
        return out;
    }

    // spec section 1: AES-128 of one 16-byte block.
    static byte[] aesBlock(byte[] key16, byte[] block16) {
        AESEngine aes = new AESEngine();
        aes.init(true, new KeyParameter(key16));
        byte[] out = new byte[16];
        aes.processBlock(block16, 0, out, 0);
        return out;
    }

    // spec section 1: AES-128-CBC without padding; |data| a multiple of 16.
    static byte[] cbc(boolean encrypt, byte[] key16, byte[] iv16, byte[] data) {
        CBCBlockCipher cbc = new CBCBlockCipher(new AESEngine());
        cbc.init(encrypt, new ParametersWithIV(new KeyParameter(key16), iv16));
        byte[] out = new byte[data.length];
        for (int off = 0; off < data.length; off += 16) {
            cbc.processBlock(data, off, out, off);
        }
        return out;
    }

    static byte[] cmac(byte[] key16, byte[] msg) {
        CMac mac = new CMac(new AESEngine());
        mac.init(new KeyParameter(key16));
        mac.update(msg, 0, msg.length);
        byte[] out = new byte[16];
        mac.doFinal(out, 0);
        return out;
    }

    // spec section 1: ISO/IEC 9797-1 padding method 2.
    static byte[] m2(byte[] x) {
        int padded = (x.length / 16 + 1) * 16;
        byte[] out = Arrays.copyOf(x, padded);
        out[x.length] = (byte) 0x80;
        return out;
    }

    // spec section 1: inverse of M2; fails (null) on any rule violation.
    static byte[] unM2(byte[] y) {
        if (y.length == 0 || y.length % 16 != 0) {
            return null;
        }
        int i = y.length - 1;
        int zeros = 0;
        while (i >= 0 && y[i] == 0) {
            i--;
            zeros++;
        }
        if (i < 0 || y[i] != (byte) 0x80 || zeros > 15) {
            return null;
        }
        return Arrays.copyOf(y, i);
    }

    // spec section 1: SP 800-56C Rev. 2 one-step KDF, option 1, H = SHA-256.
    static byte[] kdf(byte[] z, String label, byte[] ctx, int len) {
        byte[] fixed = cat(ascii(label), ctx);
        byte[] out = new byte[len];
        int produced = 0;
        for (int counter = 1; produced < len && counter <= 2; counter++) {
            byte[] h = sha256(cat(u32(counter), z, fixed));
            int take = Math.min(h.length, len - produced);
            System.arraycopy(h, 0, out, produced, take);
            produced += take;
        }
        if (produced < len) {
            throw new IllegalArgumentException("len > 64");
        }
        return out;
    }

    // spec section 1: SP 800-108r1 counter KDF, PRF = CMAC, r = 8, 256-bit output.
    static byte[] kdf108(byte[] key16, String label, byte[] ctx) {
        byte[] lab = ascii(label);
        byte[] len = new byte[] {0x01, 0x00};
        byte[] first = cmac(key16, cat(new byte[] {0x01}, lab, new byte[] {0x00}, ctx, len));
        byte[] second = cmac(key16, cat(new byte[] {0x02}, lab, new byte[] {0x00}, ctx, len));
        return cat(first, second);
    }

    // ----- secp256k1 ----------------------------------------------------------

    static BigInteger intbe(byte[] b) {
        return new BigInteger(1, b);
    }

    static byte[] big32(BigInteger v) {
        byte[] raw = v.toByteArray();
        if (raw.length > 32) {
            return Arrays.copyOfRange(raw, raw.length - 32, raw.length);
        }
        byte[] out = new byte[32];
        System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        return out;
    }

    // A fresh valid scalar: redrawn until 1 <= int(x) <= n - 1 (spec section 8.1).
    static BigInteger randomScalar() {
        for (; ; ) {
            BigInteger d = new BigInteger(256, RND);
            if (d.signum() > 0 && d.compareTo(N) < 0) {
                return d;
            }
        }
    }

    static byte[] compress(ECPoint p) {
        return p.normalize().getEncoded(true);
    }

    static byte[] uncompressed(ECPoint p) {
        return p.normalize().getEncoded(false);
    }

    static ECPoint point(byte[] encoded) {
        return SEC.getCurve().decodePoint(encoded).normalize();
    }

    static ECPoint times(byte[] scalar32, ECPoint p) {
        return p.multiply(intbe(scalar32)).normalize();
    }

    // spec section 1: ID(A) = SHA-256(A)[0..16) of the compressed identity key.
    static byte[] cardId(byte[] compressedA) {
        return Arrays.copyOf(sha256(compressedA), 16);
    }

    // Sign(k, M) of spec section 1: r || s over e = SHA-256(M).
    static byte[] sign(BigInteger priv, byte[] message) {
        return signHash(priv, sha256(message));
    }

    static byte[] signHash(BigInteger priv, byte[] hash32) {
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, new ParametersWithRandom(new ECPrivateKeyParameters(priv, SECP), RND));
        BigInteger[] rs = signer.generateSignature(hash32);
        return cat(big32(rs[0]), big32(rs[1]));
    }

    // Verify(A, M, sig) of spec section 1, hash e = SHA-256(M).
    static boolean verify(byte[] pubEncoded, byte[] message, byte[] sig64) {
        return verifyHash(pubEncoded, sha256(message), sig64);
    }

    static boolean verifyHash(byte[] pubEncoded, byte[] hash32, byte[] sig64) {
        if (sig64.length != 64) {
            return false;
        }
        BigInteger r = intbe(Arrays.copyOfRange(sig64, 0, 32));
        BigInteger s = intbe(Arrays.copyOfRange(sig64, 32, 64));
        // spec section 1: r and s outside [1, n - 1] fail.
        if (r.signum() <= 0 || r.compareTo(N) >= 0 || s.signum() <= 0 || s.compareTo(N) >= 0) {
            return false;
        }
        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, new ECPublicKeyParameters(point(pubEncoded), SECP));
        return verifier.verifySignature(hash32, r, s);
    }

    // ----- BIP-32 / SLIP-10 (spec sections 10.2-10.4) ---------------------------

    // spec section 10.2: I = HMAC-SHA512("Bitcoin seed", seed).
    static BigInteger bip32MasterPriv(byte[] seed) {
        return intbe(Arrays.copyOfRange(hmacSha512(ascii("Bitcoin seed"), seed), 0, 32));
    }

    // A valid master has 1 <= kM <= n - 1.
    static boolean bip32MasterValid(byte[] seed) {
        BigInteger k = bip32MasterPriv(seed);
        return k.signum() > 0 && k.compareTo(N) < 0;
    }

    static byte[] bip32MasterPub(byte[] seed) {
        return compress(SECP.getG().multiply(bip32MasterPriv(seed)).normalize());
    }

    // spec section 10.3: one CKDpriv step; returns null on an invalid child.
    static BigInteger[] bip32Child(BigInteger kPar, byte[] cPar, long index) {
        byte[] data;
        if (index >= 0x80000000L) {
            data = cat(new byte[] {0x00}, big32(kPar), u32(index));
        } else {
            data = cat(compress(SECP.getG().multiply(kPar).normalize()), u32(index));
        }
        byte[] i = hmacSha512(cPar, data);
        BigInteger il = intbe(Arrays.copyOfRange(i, 0, 32));
        if (il.compareTo(N) >= 0) {
            return null;
        }
        BigInteger k = il.add(kPar).mod(N);
        if (k.signum() == 0) {
            return null;
        }
        return new BigInteger[] {k, intbe(Arrays.copyOfRange(i, 32, 64))};
    }

    // spec section 10.4: one hardened SLIP-10 step for ed25519.
    static byte[][] slip10Child(byte[] kPar32, byte[] cPar, long hardenedIndex) {
        byte[] i = hmacSha512(cPar, cat(new byte[] {0x00}, kPar32, u32(hardenedIndex)));
        return new byte[][] {Arrays.copyOfRange(i, 0, 32), Arrays.copyOfRange(i, 32, 64)};
    }

    // ----- Wei25519 / ed25519 (spec section 10.4) -------------------------------

    // W(P) = X(32) || Y(32) of a scalar multiple on Wei25519; scalar reduced mod l.
    static byte[] weiPoint(BigInteger scalar) {
        ECPoint p = GW.multiply(scalar.mod(ED_ORDER)).normalize();
        return cat(big32(p.getXCoord().toBigInteger()), big32(p.getYCoord().toBigInteger()));
    }

    // RFC 8032 clamped scalar of a 32-byte secret key.
    static BigInteger edSecretScalar(byte[] sk32) {
        byte[] h = sha512(sk32);
        byte[] a = Arrays.copyOfRange(h, 0, 32);
        a[0] &= (byte) 0xF8;
        a[31] &= 0x7F;
        a[31] |= 0x40;
        // a is a little-endian integer (RFC 8032 section 5.1.5)
        byte[] be = new byte[32];
        for (int i = 0; i < 32; i++) {
            be[i] = a[31 - i];
        }
        return intbe(be);
    }

    // spec section 10.4 mapping of W(P) to the RFC 8032 encoding of the point.
    static byte[] weiToEdwards(byte[] w64) {
        BigInteger x = intbe(Arrays.copyOfRange(w64, 0, 32));
        BigInteger yy = intbe(Arrays.copyOfRange(w64, 32, 64));
        BigInteger u = x.subtract(A3).mod(Q);
        BigInteger y =
                u.subtract(BigInteger.ONE).multiply(u.add(BigInteger.ONE).modInverse(Q)).mod(Q);
        BigInteger ex = C_SQRT.multiply(u).multiply(yy.modInverse(Q)).mod(Q);
        byte[] enc = littleEndian32(y);
        if (ex.testBit(0)) {
            enc[31] |= (byte) 0x80;
        }
        return enc;
    }

    private static byte[] littleEndian32(BigInteger v) {
        byte[] be = big32(v);
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) {
            out[i] = be[31 - i];
        }
        return out;
    }

    static boolean ed25519Verify(byte[] pub32, byte[] msg, byte[] sig64) {
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, new Ed25519PublicKeyParameters(pub32, 0));
        verifier.update(msg, 0, msg.length);
        return verifier.verifySignature(sig64);
    }

    // ----- BIP-340 --------------------------------------------------------------

    static byte[] taggedHash(String tag, byte[] msg) {
        byte[] th = sha256(ascii(tag));
        return sha256(cat(th, th, msg));
    }

    // BIP-340 verification of R_x || s over the even-y key with x = pubX.
    static boolean bip340Verify(byte[] pubX32, byte[] msg32, byte[] sig64) {
        BigInteger rx = intbe(Arrays.copyOfRange(sig64, 0, 32));
        BigInteger s = intbe(Arrays.copyOfRange(sig64, 32, 64));
        if (rx.compareTo(P) >= 0 || s.compareTo(N) >= 0) {
            return false;
        }
        byte[] comp = cat(new byte[] {0x02}, pubX32);
        ECPoint pub;
        try {
            pub = point(comp);
        } catch (IllegalArgumentException e) {
            return false;
        }
        BigInteger e =
                intbe(
                                taggedHash(
                                        "BIP0340/challenge",
                                        cat(Arrays.copyOfRange(sig64, 0, 32), pubX32, msg32)))
                        .mod(N);
        ECPoint rPoint = SECP.getG().multiply(s).subtract(pub.multiply(e)).normalize();
        return !rPoint.isInfinity()
                && !rPoint.getAffineYCoord().toBigInteger().testBit(0)
                && rPoint.getAffineXCoord().toBigInteger().equals(rx);
    }
}
