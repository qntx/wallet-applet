// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

/**
 * Independent host-side cryptography for the conformance review, written from spec/protocol.md
 * only. No code or constants come from org.qntx.card.* (host helpers or applet); the only shared
 * dependency is BouncyCastle as the independent oracle library.
 *
 * <p>Spec references: §1 (KDF, KDF108, CMAC, CBC, M2, labels), §5.2 (certificates), §8 (session
 * keys and records), §10.2–10.4 (BIP-32, SLIP-10, Wei25519), §12 (signing).
 */
final class ReviewHost {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private ReviewHost() {}

    // §1 labels
    static final byte[] LABEL_CERT = "qntx-card/v1/cert".getBytes();
    static final byte[] LABEL_SESSION = "qntx-card/v1/session".getBytes();
    static final byte[] LABEL_KDF_SESSION = "qntx-card/v1/kdf-session".getBytes();
    static final byte[] LABEL_KDF_TRANSFER = "qntx-card/v1/kdf-transfer".getBytes();
    static final byte[] LABEL_OFFER = "qntx-card/v1/offer".getBytes();
    static final byte[] LABEL_EXPORT = "qntx-card/v1/export".getBytes();
    static final byte[] LABEL_WRAP = "qntx-card/v1/wrap".getBytes();
    static final byte[] LABEL_FINGERPRINT = "qntx-card/v1/fingerprint".getBytes();
    static final byte[] LABEL_ED_NONCE = "qntx-card/v1/ed25519-nonce".getBytes();

    static final byte[] AID_WALLET = unhex("F0716E74780101");
    static final byte[] AID_NDEF = unhex("D2760000850101");

    static final byte[] SELECT_WALLET = concat(unhex("00A4040007"), AID_WALLET, new byte[] {0x00});
    static final byte[] SELECT_NDEF = concat(unhex("00A4040007"), AID_NDEF, new byte[] {0x00});

    // secp256k1 domain (SEC 2 v2 §2.4.1)
    static final BigInteger P =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    static final BigInteger N =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    private static final ECCurve K1 = new SecP256K1Curve();
    static final ECPoint G =
            K1.createPoint(
                    new BigInteger(
                            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
                    new BigInteger(
                            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
                            16));
    static final SecureRandom RNG = new SecureRandom();

    // edwards25519 / Wei25519 domain (§10.4)
    static final BigInteger Q = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    static final BigInteger L =
            BigInteger.ONE
                    .shiftLeft(252)
                    .add(new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger A3 =
            new BigInteger("2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2451", 16);
    private static final BigInteger C_W2E =
            new BigInteger("70D9120B9F5FF9442D84F723FC03B0813A5E2C2EB482E57D3391FB5500BA81E7", 16);

    // byte utilities

    static byte[] unhex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }

    static byte[] concat(byte[]... parts) {
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

    static byte[] slice(byte[] b, int off, int len) {
        return Arrays.copyOfRange(b, off, off + len);
    }

    static byte[] utf8(String s) {
        return s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    static byte[] u16(int v) {
        return new byte[] {(byte) (v >>> 8), (byte) v};
    }

    static byte[] u32(long v) {
        return new byte[] {(byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v};
    }

    static int sw(byte[] resp) {
        return ((resp[resp.length - 2] & 0xFF) << 8) | (resp[resp.length - 1] & 0xFF);
    }

    static byte[] respData(byte[] resp) {
        return Arrays.copyOf(resp, resp.length - 2);
    }

    static byte[] b58check(String s) {
        int zeros = 0;
        while (s.charAt(zeros) == '1') {
            zeros++;
        }
        BigInteger v = BigInteger.ZERO;
        for (int i = zeros; i < s.length(); i++) {
            int d =
                    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
                            .indexOf(s.charAt(i));
            v = v.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(d));
        }
        byte[] raw = v.toByteArray();
        int off = raw.length > 1 && raw[0] == 0 ? 1 : 0;
        byte[] b = new byte[zeros + raw.length - off];
        System.arraycopy(raw, off, b, zeros, raw.length - off);
        int n = b.length - 4;
        if (!Arrays.equals(slice(b, n, 4), slice(sha256(sha256(slice(b, 0, n))), 0, 4))) {
            throw new IllegalStateException("bad b58check checksum");
        }
        return b;
    }

    static byte[] i2b(BigInteger v, int len) {
        byte[] out = new byte[len];
        byte[] raw = v.toByteArray();
        int src = Math.max(0, raw.length - len);
        int n = Math.min(len, raw.length);
        System.arraycopy(raw, src, out, len - n, n);
        return out;
    }

    // hashes, MAC, cipher (§1)

    static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest d = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) {
                d.update(p);
            }
            return d.digest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] sha512(byte[]... parts) {
        try {
            MessageDigest d = MessageDigest.getInstance("SHA-512");
            for (byte[] p : parts) {
                d.update(p);
            }
            return d.digest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] hmacSha512(byte[] key, byte[]... parts) {
        try {
            Mac m = Mac.getInstance("HmacSHA512");
            m.init(new SecretKeySpec(key, "HmacSHA512"));
            for (byte[] p : parts) {
                m.update(p);
            }
            return m.doFinal();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** AES-128 single block encryption, AES(K, X) of §1. */
    static byte[] aesBlock(byte[] key, byte[] block) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            return c.doFinal(block);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] cbc(byte[] key, byte[] iv, byte[] data) {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return c.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] cbcInv(byte[] key, byte[] iv, byte[] data) {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return c.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] cmac(byte[] key, byte[]... parts) {
        try {
            Mac m = Mac.getInstance("AESCMAC", BouncyCastleProvider.PROVIDER_NAME);
            m.init(new SecretKeySpec(key, "AES"));
            for (byte[] p : parts) {
                m.update(p);
            }
            return m.doFinal();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** ISO/IEC 9797-1 method 2 padding (§1). */
    static byte[] m2(byte[] x) {
        int pad = 16 - (x.length % 16);
        byte[] out = Arrays.copyOf(x, x.length + pad);
        out[x.length] = (byte) 0x80;
        return out;
    }

    /** Removes M2 padding; null when invalid (§1). */
    static byte[] unM2(byte[] y) {
        if (y.length == 0 || y.length % 16 != 0) {
            return null;
        }
        int i = y.length - 1;
        while (i >= 0 && y[i] == 0) {
            i--;
        }
        if (i < 0 || (y[i] & 0xFF) != 0x80 || y.length - 1 - i > 15) {
            return null;
        }
        return Arrays.copyOf(y, i);
    }

    /** §1 KDF: one-step KDF of SP 800-56C Rev. 2 §4.1 option 1, H = SHA-256. */
    static byte[] kdf(byte[] z, byte[] label, byte[] ctx, int len) {
        byte[] fixed = concat(label, ctx);
        byte[] h1 = sha256(u32(1), z, fixed);
        byte[] h2 = sha256(u32(2), z, fixed);
        byte[] both = concat(h1, h2);
        return Arrays.copyOf(both, len);
    }

    /** §1 KDF108: SP 800-108r1 counter KDF, PRF = CMAC, r = 8, 256-bit output. */
    static byte[] kdf108(byte[] k, byte[] label, byte[] ctx) {
        byte[] suffix = concat(new byte[] {0x00}, ctx, new byte[] {0x01, 0x00});
        byte[] b1 = cmac(k, concat(new byte[] {0x01}, label, suffix));
        byte[] b2 = cmac(k, concat(new byte[] {0x02}, label, suffix));
        return concat(b1, b2);
    }

    // secp256k1

    static ECPoint g() {
        return G;
    }

    /** Big-endian unsigned int of b. */
    static BigInteger b2i(byte[] b) {
        return new BigInteger(1, b);
    }

    /** Uncompressed encoding 0x04 ‖ x ‖ y (65 B). */
    static byte[] uncomp(ECPoint p) {
        p = p.normalize();
        return concat(
                new byte[] {0x04},
                i2b(p.getXCoord().toBigInteger(), 32),
                i2b(p.getYCoord().toBigInteger(), 32));
    }

    /** Compressed encoding 0x02|0x03 ‖ x (33 B), SEC 1 §2.3.3. */
    static byte[] compr(ECPoint p) {
        p = p.normalize();
        return concat(
                new byte[] {p.getYCoord().toBigInteger().testBit(0) ? (byte) 0x03 : (byte) 0x02},
                i2b(p.getXCoord().toBigInteger(), 32));
    }

    /** §10.5 decompression; null on any failure. */
    static ECPoint decompress(byte[] a33) {
        if (a33.length != 33 || (a33[0] != 0x02 && a33[0] != 0x03)) {
            return null;
        }
        BigInteger x = b2i(slice(a33, 1, 32));
        if (x.compareTo(P) >= 0) {
            return null;
        }
        BigInteger z = x.modPow(BigInteger.valueOf(3), P).add(BigInteger.valueOf(7)).mod(P);
        BigInteger y = z.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
        if (!y.modPow(BigInteger.TWO, P).equals(z)) {
            return null;
        }
        if ((y.testBit(0) ? 1 : 0) != (a33[0] & 1)) {
            y = P.subtract(y);
        }
        return K1.createPoint(x, y);
    }

    /** Explicit point check of §14.2/§9.14 step 6: 0x04, coords < p, y² ≡ x³ + 7. */
    static boolean validPoint(byte[] w) {
        if (w.length != 65 || w[0] != 0x04) {
            return false;
        }
        BigInteger x = b2i(slice(w, 1, 32));
        BigInteger y = b2i(slice(w, 33, 32));
        if (x.signum() < 0 || x.compareTo(P) >= 0 || y.compareTo(P) >= 0) {
            return false;
        }
        return y.modPow(BigInteger.TWO, P)
                .equals(x.modPow(BigInteger.valueOf(3), P).add(BigInteger.valueOf(7)).mod(P));
    }

    static ECPoint decode(byte[] pub) {
        return K1.decodePoint(pub);
    }

    /** x-coordinate of d·P, 32 B (§8.1 Z, §9.13 Z). */
    static byte[] ecdhX(BigInteger d, byte[] pub65) {
        ECPoint q = decode(pub65).multiply(d).normalize();
        return i2b(q.getXCoord().toBigInteger(), 32);
    }

    /** §1 Sign: ECDSA over secp256k1 with e = SHA-256(M); wire form r(32) ‖ s(32). */
    static byte[] ecdsaSign(BigInteger d, byte[] msg) {
        return ecdsaSignHash(d, sha256(msg));
    }

    /** §12.1 form: e = int(digest) directly. */
    static byte[] ecdsaSignHash(BigInteger d, byte[] digest) {
        BigInteger e = b2i(digest);
        while (true) {
            BigInteger k = randomScalar();
            ECPoint r1 = G.multiply(k).normalize();
            BigInteger r = r1.getXCoord().toBigInteger().mod(N);
            if (r.signum() == 0) {
                continue;
            }
            BigInteger s = k.modInverse(N).multiply(e.add(r.multiply(d))).mod(N);
            if (s.signum() == 0) {
                continue;
            }
            return concat(i2b(r, 32), i2b(s, 32));
        }
    }

    static BigInteger randomScalar() {
        BigInteger k;
        do {
            k = new BigInteger(256, RNG);
        } while (k.signum() == 0 || k.compareTo(N) >= 0);
        return k;
    }

    /**
     * §1 Verify over the message (e = SHA-256(M)). Public key may be compressed or uncompressed.
     * Fails when r or s is outside [1, n−1] or the point is invalid.
     */
    static boolean ecdsaVerify(byte[] pub, byte[] msg, byte[] sig) {
        return ecdsaVerifyHash(pub, sha256(msg), sig);
    }

    static boolean ecdsaVerifyHash(byte[] pub, byte[] digest, byte[] sig) {
        if (sig.length != 64) {
            return false;
        }
        BigInteger r = b2i(slice(sig, 0, 32));
        BigInteger s = b2i(slice(sig, 32, 32));
        if (r.signum() <= 0 || r.compareTo(N) >= 0 || s.signum() <= 0 || s.compareTo(N) >= 0) {
            return false;
        }
        ECPoint q;
        try {
            q = pub.length == 33 ? decompress(pub) : decode(pub);
            if (q == null) {
                return false;
            }
            q = q.normalize();
        } catch (RuntimeException bad) {
            return false;
        }
        BigInteger e = b2i(digest);
        BigInteger w = s.modInverse(N);
        ECPoint t =
                ECAlgorithms.sumOfTwoMultiplies(G, e.multiply(w).mod(N), q, r.multiply(w).mod(N))
                        .normalize();
        if (t.isInfinity()) {
            return false;
        }
        return t.getXCoord().toBigInteger().mod(N).equals(r);
    }

    /** §5.2 certificate: cert(97) = A(33) ‖ r(32) ‖ s(32) signed over "…/cert" ‖ A. */
    static byte[] cert(byte[] caPriv, byte[] a33) {
        byte[] sig = ecdsaSign(b2i(caPriv), concat(LABEL_CERT, a33));
        return concat(a33, sig);
    }

    static boolean certVerify(byte[] caPub, byte[] cert97) {
        return ecdsaVerify(caPub, concat(LABEL_CERT, slice(cert97, 0, 33)), slice(cert97, 33, 64));
    }

    /** ID(A) = SHA-256(A)[0..16) (§1). */
    static byte[] cardId(byte[] a33) {
        return slice(sha256(a33), 0, 16);
    }

    // BIP-32 / SLIP-10 (§10.2–10.4)

    /** BIP-32 master (§10.2): {kM, cM}; kM null-invalid when outside [1, n−1]. */
    static byte[][] bip32Master(byte[] seed) {
        byte[] i = hmacSha512("Bitcoin seed".getBytes(), seed);
        return new byte[][] {slice(i, 0, 32), slice(i, 32, 32)};
    }

    static boolean bip32MasterValid(byte[] seed) {
        BigInteger k = b2i(bip32Master(seed)[0]);
        return k.signum() > 0 && k.compareTo(N) < 0;
    }

    /** SLIP-10 ed25519 master (§10.4): {kE, cE}. */
    static byte[][] slip10Master(byte[] seed) {
        byte[] i = hmacSha512("ed25519 seed".getBytes(), seed);
        return new byte[][] {slice(i, 0, 32), slice(i, 32, 32)};
    }

    /**
     * §10.3 CKDpriv. Returns {k, c} of the child or null when the child is invalid (int(IL) ≥ n or
     * k = 0).
     */
    static byte[][] ckdPriv(byte[] kPar, byte[] cPar, long index) {
        byte[] data;
        if (index >= 0x8000_0000L) {
            data = concat(new byte[] {0x00}, kPar, u32(index));
        } else {
            data = concat(compr(G.multiply(b2i(kPar))), u32(index));
        }
        byte[] i = hmacSha512(cPar, data);
        BigInteger il = b2i(slice(i, 0, 32));
        if (il.compareTo(N) >= 0) {
            return null;
        }
        BigInteger k = il.add(b2i(kPar)).mod(N);
        if (k.signum() == 0) {
            return null;
        }
        return new byte[][] {i2b(k, 32), slice(i, 32, 32)};
    }

    /** §10.3 child public derivation: K_par + IL·G for a non-hardened index. */
    static byte[] ckdPub(byte[] pub33, byte[] cPar, long index) {
        if (index >= 0x8000_0000L) {
            throw new IllegalArgumentException("hardened needs the private key");
        }
        byte[] i = hmacSha512(cPar, concat(pub33, u32(index)));
        BigInteger il = b2i(slice(i, 0, 32));
        if (il.compareTo(N) >= 0) {
            return null;
        }
        ECPoint k = G.multiply(il).add(decode(pub33)).normalize();
        if (k.isInfinity()) {
            return null;
        }
        return compr(k);
    }

    /** SLIP-10 hardened child (§10.4). Always valid. */
    static byte[][] slip10Ckd(byte[] kPar, byte[] cPar, long index) {
        byte[] i = hmacSha512(cPar, concat(new byte[] {0x00}, kPar, u32(index)));
        return new byte[][] {slice(i, 0, 32), slice(i, 32, 32)};
    }

    static long[] path(long... indices) {
        return indices;
    }

    /** Derives the secp256k1 node {k, c} at path (u32 values; ≥ 0x80000000 hardened). */
    static byte[][] bip32Node(byte[] seed, long[] path) {
        byte[][] node = bip32Master(seed);
        for (long i : path) {
            node = ckdPriv(node[0], node[1], i);
            if (node == null) {
                return null;
            }
        }
        return node;
    }

    /** The secp256k1 leaf private key at path, null on invalid child. */
    static BigInteger bip32Leaf(byte[] seed, long[] path) {
        byte[][] node = bip32Node(seed, path);
        return node == null ? null : b2i(node[0]);
    }

    /** SLIP-10 ed25519 leaf key (RFC 8032 seed) at path. */
    static byte[] slip10Leaf(byte[] seed, long[] path) {
        byte[][] node = slip10Master(seed);
        for (long i : path) {
            if (i < 0x8000_0000L) {
                throw new IllegalArgumentException("SLIP-10 needs hardened indices");
            }
            node = slip10Ckd(node[0], node[1], i);
        }
        return node[0];
    }

    // Ed25519 / Wei25519 (§10.4, RFC 8032)

    /** RFC 8032 encode(A) of the public key for private seed sk. */
    static byte[] edPublic(byte[] sk) {
        return new Ed25519PrivateKeyParameters(sk, 0).generatePublicKey().getEncoded();
    }

    /** RFC 8032 verification via BouncyCastle. */
    static boolean edVerify(byte[] encA, byte[] msg, byte[] sig64) {
        Ed25519Signer v = new Ed25519Signer();
        v.init(false, new Ed25519PublicKeyParameters(encA, 0));
        v.update(msg, 0, msg.length);
        return v.verifySignature(sig64);
    }

    /** The card-side RFC 8032 hash-clamping values for §10.4: {a mod ℓ, prefix}. */
    static byte[][] edScalars(byte[] sk) {
        byte[] h = sha512(sk);
        byte[] a = slice(h, 0, 32);
        a[0] &= (byte) 0xF8;
        a[31] &= (byte) 0x3F;
        a[31] |= (byte) 0x40;
        return new byte[][] {a, slice(h, 32, 32)};
    }

    /** §10.4: Wei25519 point W(P) = X ‖ Y → RFC 8032 encode of the edwards point. */
    static byte[] weiToEdwards(byte[] w) {
        BigInteger x = b2i(slice(w, 0, 32));
        BigInteger yy = b2i(slice(w, 32, 32));
        BigInteger u = x.subtract(A3).mod(Q);
        BigInteger y =
                u.subtract(BigInteger.ONE).multiply(u.add(BigInteger.ONE).modInverse(Q)).mod(Q);
        BigInteger ex = C_W2E.multiply(u).multiply(yy.modInverse(Q)).mod(Q);
        byte[] enc = le32(y);
        if (ex.testBit(0)) {
            enc[31] |= (byte) 0x80;
        }
        return enc;
    }

    static byte[] le32(BigInteger v) {
        byte[] be = i2b(v.mod(BigInteger.ONE.shiftLeft(256)), 32);
        byte[] le = new byte[32];
        for (int i = 0; i < 32; i++) {
            le[i] = be[31 - i];
        }
        return le;
    }

    // BIP-340 / BIP-341 (§12.2)

    static byte[] taggedHash(String tag, byte[]... parts) {
        byte[] h = sha256(tag.getBytes());
        byte[][] all = new byte[parts.length + 2][];
        all[0] = h;
        all[1] = h;
        System.arraycopy(parts, 0, all, 2, parts.length);
        return sha256(all);
    }

    /** BIP-340 lift_x: the point with this x and even y; null if none. */
    static ECPoint liftX(BigInteger x) {
        if (x.compareTo(P) >= 0) {
            return null;
        }
        BigInteger c = x.modPow(BigInteger.valueOf(3), P).add(BigInteger.valueOf(7)).mod(P);
        BigInteger y = c.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
        if (!y.modPow(BigInteger.TWO, P).equals(c)) {
            return null;
        }
        if (y.testBit(0)) {
            y = P.subtract(y);
        }
        return K1.createPoint(x, y);
    }

    /** BIP-340 Default Signing of §12.2 over a 32-byte message. */
    static byte[] bip340Sign(BigInteger d0, byte[] m32, byte[] aux32) {
        ECPoint p = G.multiply(d0).normalize();
        BigInteger d = p.getYCoord().toBigInteger().testBit(0) ? N.subtract(d0) : d0;
        byte[] px = i2b(p.getXCoord().toBigInteger(), 32);
        byte[] t = xor(i2b(d, 32), taggedHash("BIP0340/aux", aux32));
        BigInteger k0 = b2i(taggedHash("BIP0340/nonce", t, px, m32)).mod(N);
        if (k0.signum() == 0) {
            throw new IllegalStateException("zero nonce");
        }
        ECPoint r = G.multiply(k0).normalize();
        BigInteger k = r.getYCoord().toBigInteger().testBit(0) ? N.subtract(k0) : k0;
        byte[] rx = i2b(r.getXCoord().toBigInteger(), 32);
        BigInteger e = b2i(taggedHash("BIP0340/challenge", rx, px, m32)).mod(N);
        return concat(rx, i2b(k.add(e.multiply(d)).mod(N), 32));
    }

    static boolean bip340Verify(byte[] xOnlyPub, byte[] m32, byte[] sig64) {
        BigInteger r = b2i(slice(sig64, 0, 32));
        BigInteger s = b2i(slice(sig64, 32, 32));
        if (r.compareTo(P) >= 0 || s.compareTo(N) >= 0) {
            return false;
        }
        ECPoint p = liftX(b2i(xOnlyPub));
        if (p == null) {
            return false;
        }
        BigInteger e =
                b2i(taggedHash("BIP0340/challenge", slice(sig64, 0, 32), xOnlyPub, m32)).mod(N);
        ECPoint rPoint = ECAlgorithms.sumOfTwoMultiplies(G, s, p, N.subtract(e)).normalize();
        if (rPoint.isInfinity() || rPoint.getYCoord().toBigInteger().testBit(0)) {
            return false;
        }
        return rPoint.getXCoord().toBigInteger().equals(r);
    }

    /** §12.2: the tweaked output key Q = P_even + t·G (x-only), and its signing scalar. */
    static ECPoint taprootQ(BigInteger d0, BigInteger tweak) {
        ECPoint p = G.multiply(d0).normalize();
        BigInteger d = p.getYCoord().toBigInteger().testBit(0) ? N.subtract(d0) : d0;
        ECPoint pe = G.multiply(d).normalize();
        return pe.add(G.multiply(tweak)).normalize();
    }

    static byte[] xor(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }
}
