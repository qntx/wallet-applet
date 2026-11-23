// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * BigInteger affine-curve oracle for the two fields the card uses — secp256k1 (SEC 2 v2 §2.4.1) and
 * Wei25519 (RFC 7748 §4.1 mapped to short Weierstrass form, as in {@code
 * applet-audit/audit-impl/evidence/probe/probe_host.py}). {@code null} is the point at infinity.
 */
final class Curve {
    static final class Point {
        final BigInteger x;
        final BigInteger y;

        Point(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }
    }

    final String name;
    final BigInteger p;
    final BigInteger a;
    final BigInteger b;
    final BigInteger n;
    final Point g;

    private Curve(String name, BigInteger p, BigInteger a, BigInteger b, BigInteger n, Point g) {
        this.name = name;
        this.p = p;
        this.a = a;
        this.b = b;
        this.n = n;
        this.g = g;
    }

    static final Curve SECP256K1;

    static final Curve WEI25519;

    static {
        BigInteger p =
                BigInteger.ONE
                        .shiftLeft(256)
                        .subtract(BigInteger.ONE.shiftLeft(32))
                        .subtract(BigInteger.valueOf(977));
        Point g =
                new Point(
                        new BigInteger(
                                "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                                16),
                        new BigInteger(
                                "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
                                16));
        SECP256K1 =
                new Curve(
                        "secp256k1",
                        p,
                        BigInteger.ZERO,
                        BigInteger.valueOf(7),
                        new BigInteger(
                                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                                16),
                        g);

        BigInteger q = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
        BigInteger l =
                BigInteger.ONE
                        .shiftLeft(252)
                        .add(new BigInteger("27742317777372353535851937790883648493"));
        BigInteger ma = BigInteger.valueOf(486662);
        BigInteger inv3 = BigInteger.valueOf(3).modPow(q.subtract(BigInteger.TWO), q);
        BigInteger wa = BigInteger.valueOf(3).subtract(ma.multiply(ma)).multiply(inv3).mod(q);
        BigInteger wb =
                BigInteger.TWO
                        .multiply(ma.pow(3))
                        .subtract(BigInteger.valueOf(9).multiply(ma))
                        .multiply(BigInteger.valueOf(27).modPow(q.subtract(BigInteger.TWO), q))
                        .mod(q);
        Point wg =
                new Point(
                        BigInteger.valueOf(9).add(ma.multiply(inv3)).mod(q),
                        new BigInteger(
                                "14781619447589544791020593568409986887264606134616475288964881837755586237401"));
        WEI25519 = new Curve("wei25519", q, wa, wb, l, wg);

        if (!SECP256K1.onCurve(SECP256K1.g) || !WEI25519.onCurve(WEI25519.g)) {
            throw new ExceptionInInitializerError("curve constants");
        }
    }

    /** The 195-byte domain blob of probe INS 0x04: {@code p ‖ a ‖ b ‖ G(65) ‖ r ‖ k(u16)}. */
    byte[] domainBlob() {
        byte[] out = new byte[195];
        System.arraycopy(u32(p), 0, out, 0, 32);
        System.arraycopy(u32(a), 0, out, 32, 32);
        System.arraycopy(u32(b), 0, out, 64, 32);
        System.arraycopy(enc(g), 0, out, 96, 65);
        System.arraycopy(u32(n), 0, out, 161, 32);
        out[193] = 0;
        out[194] = 1;
        return out;
    }

    boolean onCurve(Point pt) {
        if (pt == null) {
            return true;
        }
        BigInteger lhs = pt.y.multiply(pt.y).mod(p);
        BigInteger rhs = pt.x.modPow(BigInteger.valueOf(3), p).add(a.multiply(pt.x)).add(b).mod(p);
        return lhs.equals(rhs);
    }

    Point neg(Point pt) {
        return new Point(pt.x, pt.y.negate().mod(p));
    }

    Point add(Point p1, Point p2) {
        if (p1 == null) {
            return p2;
        }
        if (p2 == null) {
            return p1;
        }
        if (p1.x.equals(p2.x) && p1.y.add(p2.y).mod(p).equals(BigInteger.ZERO)) {
            return null;
        }
        BigInteger lambda;
        if (p1.x.equals(p2.x) && p1.y.equals(p2.y)) {
            lambda =
                    BigInteger.valueOf(3)
                            .multiply(p1.x)
                            .multiply(p1.x)
                            .add(a)
                            .multiply(p1.y.add(p1.y).modInverse(p))
                            .mod(p);
        } else {
            lambda = p2.y.subtract(p1.y).multiply(p2.x.subtract(p1.x).mod(p).modInverse(p)).mod(p);
        }
        BigInteger x = lambda.multiply(lambda).subtract(p1.x).subtract(p2.x).mod(p);
        return new Point(x, lambda.multiply(p1.x.subtract(x)).subtract(p1.y).mod(p));
    }

    Point mul(BigInteger k, Point pt) {
        Point r = null;
        Point base = pt;
        BigInteger kk = k;
        while (kk.signum() != 0) {
            if (kk.testBit(0)) {
                r = add(r, base);
            }
            base = add(base, base);
            kk = kk.shiftRight(1);
        }
        return r;
    }

    byte[] enc(Point pt) {
        byte[] out = new byte[65];
        out[0] = 4;
        System.arraycopy(u32(pt.x), 0, out, 1, 32);
        System.arraycopy(u32(pt.y), 0, out, 33, 32);
        return out;
    }

    byte[] comp(Point pt) {
        byte[] out = new byte[33];
        out[0] = pt.y.testBit(0) ? (byte) 3 : (byte) 2;
        System.arraycopy(u32(pt.x), 0, out, 1, 32);
        return out;
    }

    Point dec(byte[] enc65) {
        if (enc65.length != 65 || enc65[0] != 4) {
            throw new IllegalArgumentException("not an uncompressed point");
        }
        return new Point(
                new BigInteger(1, slice(enc65, 1, 33)), new BigInteger(1, slice(enc65, 33, 65)));
    }

    BigInteger scalar(SecureRandom rng) {
        BigInteger k;
        do {
            k = new BigInteger(256, rng);
        } while (k.signum() <= 0 || k.compareTo(n) >= 0);
        return k;
    }

    static byte[] u32(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        int len = Math.min(b.length, 32);
        System.arraycopy(b, b.length - len, out, 32 - len, len);
        return out;
    }

    static byte[] u64(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[64];
        int len = Math.min(b.length, 64);
        System.arraycopy(b, b.length - len, out, 64 - len, len);
        return out;
    }

    private static byte[] slice(byte[] b, int from, int to) {
        byte[] out = new byte[to - from];
        System.arraycopy(b, from, out, 0, out.length);
        return out;
    }
}
