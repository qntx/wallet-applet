// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Crypto;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * {@link ModArith} against {@link BigInteger} for all three moduli — secp256k1 {@code p}, {@code n}
 * and ed25519 {@code ℓ} (architecture §14.4 W7): 10⁵ random {@code mul} and {@code square} rounds
 * per modulus, edge operands, and {@code addMod}, {@code subMod}, {@code half}, {@code below},
 * {@code isZero}, {@code reduce} over random 256-bit inputs.
 */
final class ModArithTest {
    static final int RANDOM_ROUNDS = 100_000;
    private static final SecureRandom RND = new SecureRandom();
    private static final BigInteger P = Crypto.DOMAIN.getCurve().getField().getCharacteristic();
    private static final BigInteger N = Crypto.DOMAIN.getN();
    private static final BigInteger L =
            new BigInteger(
                    "7237005577332262213973186563042994240857116359379907606001950938285454250989");

    private static ModArith modArith() {
        Card card = Vecs.factory();
        return Internals.modArith(card.applet(Spec.WALLET_AID));
    }

    private static byte[] toBytes(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        System.arraycopy(
                b,
                Math.max(0, b.length - 32),
                out,
                Math.max(0, 32 - b.length),
                Math.min(b.length, 32));
        return out;
    }

    private static BigInteger of(byte[] x) {
        return new BigInteger(1, x);
    }

    @Test
    void randomMulSquareAddSubHalf() {
        ModArith m = modArith();
        byte[] moduli = {ModArith.MOD_P, ModArith.MOD_N, ModArith.MOD_L};
        BigInteger[] mods = {P, N, L};
        long t0 = System.currentTimeMillis();
        for (int mi = 0; mi < moduli.length; mi++) {
            BigInteger mod = mods[mi];
            for (int i = 0; i < RANDOM_ROUNDS; i++) {
                byte[] a = toBytes(of(random32()).mod(mod));
                byte[] b = toBytes(of(random32()).mod(mod));
                byte[] out = new byte[32];
                m.mul(moduli[mi], a, (short) 0, b, (short) 0, out, (short) 0);
                assertArrayEquals(
                        toBytes(of(a).multiply(of(b)).mod(mod)), out, "mul " + moduli[mi]);
                m.square(moduli[mi], a, (short) 0, out, (short) 0);
                assertArrayEquals(
                        toBytes(of(a).multiply(of(a)).mod(mod)), out, "square " + moduli[mi]);
                m.addMod(moduli[mi], a, (short) 0, b, (short) 0, out, (short) 0);
                assertArrayEquals(toBytes(of(a).add(of(b)).mod(mod)), out, "addMod " + moduli[mi]);
                m.subMod(moduli[mi], a, (short) 0, b, (short) 0, out, (short) 0);
                assertArrayEquals(
                        toBytes(of(a).subtract(of(b)).mod(mod)), out, "subMod " + moduli[mi]);
                m.half(moduli[mi], a, (short) 0, out, (short) 0);
                BigInteger twoInv = BigInteger.TWO.modInverse(mod);
                assertArrayEquals(
                        toBytes(of(a).multiply(twoInv).mod(mod)), out, "half " + moduli[mi]);
            }
        }
        System.out.println(
                "ModArithTest randomMulSquareAddSubHalf: "
                        + RANDOM_ROUNDS
                        + " rounds x 3 moduli in "
                        + (System.currentTimeMillis() - t0)
                        + " ms");
    }

    @Test
    void edgeOperands() {
        ModArith m = modArith();
        byte[] moduli = {ModArith.MOD_P, ModArith.MOD_N, ModArith.MOD_L};
        BigInteger[] mods = {P, N, L};
        for (int mi = 0; mi < moduli.length; mi++) {
            BigInteger mod = mods[mi];
            byte[][] edges = {
                new byte[32],
                toBytes(BigInteger.ONE),
                toBytes(mod.subtract(BigInteger.ONE)),
                toBytes(mod.subtract(BigInteger.TWO)),
                toBytes(mod.shiftRight(1)),
            };
            for (byte[] a : edges) {
                for (byte[] b : edges) {
                    byte[] out = new byte[32];
                    BigInteger va = of(a);
                    BigInteger vb = of(b);
                    m.mul(moduli[mi], a, (short) 0, b, (short) 0, out, (short) 0);
                    assertArrayEquals(toBytes(va.multiply(vb).mod(mod)), out);
                    m.square(moduli[mi], a, (short) 0, out, (short) 0);
                    assertArrayEquals(toBytes(va.multiply(va).mod(mod)), out);
                    m.addMod(moduli[mi], a, (short) 0, b, (short) 0, out, (short) 0);
                    assertArrayEquals(toBytes(va.add(vb).mod(mod)), out);
                    m.subMod(moduli[mi], a, (short) 0, b, (short) 0, out, (short) 0);
                    assertArrayEquals(toBytes(va.subtract(vb).mod(mod)), out);
                }
            }
        }
    }

    @Test
    void belowIsZeroReduce() {
        ModArith m = modArith();
        byte[] moduli = {ModArith.MOD_P, ModArith.MOD_N, ModArith.MOD_L};
        BigInteger[] mods = {P, N, L};
        byte[][] specials = {
            new byte[32],
            toBytes(BigInteger.ONE),
            toBytes(new BigInteger(256, RND)),
            toBytes(BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE)),
            toBytes(L),
            toBytes(L.multiply(BigInteger.valueOf(4))),
            toBytes(N),
            toBytes(P),
        };
        for (int mi = 0; mi < moduli.length; mi++) {
            BigInteger mod = mods[mi];
            for (byte[] s : specials) {
                // below: coded x < m
                assertEquals(
                        of(s).compareTo(mod) < 0 ? Const.CHECK_OK : Const.CHECK_FAIL,
                        m.below(moduli[mi], s, (short) 0),
                        "below " + moduli[mi]);
                // reduce: any 256-bit input lands below m
                byte[] r = s.clone();
                m.reduce(moduli[mi], r, (short) 0);
                assertArrayEquals(toBytes(of(s).mod(mod)), r, "reduce " + moduli[mi]);
            }
            // random 256-bit inputs
            for (int i = 0; i < 1000; i++) {
                byte[] s = random32();
                assertEquals(
                        of(s).compareTo(mod) < 0 ? Const.CHECK_OK : Const.CHECK_FAIL,
                        m.below(moduli[mi], s, (short) 0));
                byte[] r = s.clone();
                m.reduce(moduli[mi], r, (short) 0);
                assertArrayEquals(toBytes(of(s).mod(mod)), r);
            }
        }
    }

    @Test
    void negateIfSelectsTheAdditiveInverse() {
        ModArith m = modArith();
        byte[] moduli = {ModArith.MOD_P, ModArith.MOD_N, ModArith.MOD_L};
        BigInteger[] mods = {P, N, L};
        for (int mi = 0; mi < moduli.length; mi++) {
            BigInteger mod = mods[mi];
            byte[][] cases = {
                new byte[32],
                toBytes(BigInteger.ONE),
                toBytes(mod.subtract(BigInteger.ONE)),
                toBytes(of(random32()).mod(mod)),
            };
            for (byte[] x : cases) {
                byte[] keep = x.clone();
                m.negateIf(moduli[mi], keep, (short) 0, (short) 0);
                assertArrayEquals(x, keep, "negateIf bit 0 keeps x");
                byte[] neg = x.clone();
                m.negateIf(moduli[mi], neg, (short) 0, (short) 1);
                assertArrayEquals(
                        toBytes(of(x).negate().mod(mod)), neg, "negateIf bit 1 gives m - x");
            }
        }
    }

    @Test
    void shareSplitsAdditivelyModM() {
        ModArith m = modArith();
        byte[] moduli = {ModArith.MOD_P, ModArith.MOD_N, ModArith.MOD_L};
        BigInteger[] mods = {P, N, L};
        for (int mi = 0; mi < moduli.length; mi++) {
            BigInteger mod = mods[mi];
            for (int i = 0; i < 1000; i++) {
                byte[] x = toBytes(of(random32()).mod(mod));
                byte[] s1 = new byte[32];
                byte[] s2 = new byte[32];
                m.share(moduli[mi], x, (short) 0, s1, (short) 0, s2, (short) 0);
                assertEquals(Const.CHECK_OK, m.below(moduli[mi], s1, (short) 0), "share s1 < m");
                assertEquals(Const.CHECK_OK, m.below(moduli[mi], s2, (short) 0), "share s2 < m");
                assertEquals(of(x), of(s1).add(of(s2)).mod(mod), "s1 + s2 = x mod m");
            }
        }
    }

    @Test
    void mulMaskedRecombinesTheMaskedProduct() {
        ModArith m = modArith();
        byte[] moduli = {ModArith.MOD_N, ModArith.MOD_L};
        BigInteger[] mods = {N, L};
        long t0 = System.currentTimeMillis();
        for (int mi = 0; mi < moduli.length; mi++) {
            BigInteger mod = mods[mi];
            BigInteger[][] edges = {
                {BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO},
                {
                    mod.subtract(BigInteger.ONE),
                    mod.subtract(BigInteger.ONE),
                    mod.subtract(BigInteger.ONE)
                },
                {BigInteger.ONE, BigInteger.ONE, BigInteger.ONE},
                {of(random32()).mod(mod), BigInteger.ZERO, of(random32()).mod(mod)},
            };
            for (BigInteger[] e : edges) {
                mulMaskedCheck(m, moduli[mi], mod, e[0], e[1], e[2]);
            }
            for (int i = 0; i < RANDOM_ROUNDS / 10; i++) {
                mulMaskedCheck(
                        m,
                        moduli[mi],
                        mod,
                        of(random32()).mod(mod),
                        of(random32()).mod(mod),
                        of(random32()).mod(mod));
            }
        }
        System.out.println(
                "ModArithTest mulMasked: 2 x 10^4 rounds in "
                        + (System.currentTimeMillis() - t0)
                        + " ms");
    }

    /**
     * One {@code mulMasked} check: {@code x} split by {@code share}, then {@code out = (term +
     * factor·s1 + factor·s2) mod m} must equal {@code (term + factor·x) mod m} exactly.
     */
    private static void mulMaskedCheck(
            ModArith m,
            byte mod,
            BigInteger big,
            BigInteger term,
            BigInteger factor,
            BigInteger x) {
        byte[] a = new byte[192];
        byte[] s1 = new byte[32];
        byte[] s2 = new byte[32];
        m.share(mod, toBytes(x), (short) 0, s1, (short) 0, s2, (short) 0);
        System.arraycopy(toBytes(term), 0, a, 0, 32);
        System.arraycopy(toBytes(factor), 0, a, 32, 32);
        System.arraycopy(s1, 0, a, 64, 32);
        System.arraycopy(s2, 0, a, 96, 32);
        m.mulMasked(
                mod, a, (short) 0, (short) 32, (short) 64, (short) 96, (short) 128, (short) 160);
        assertArrayEquals(
                toBytes(term.add(factor.multiply(x)).mod(big)),
                java.util.Arrays.copyOfRange(a, 128, 160),
                "mulMasked");
    }

    @Test
    void reduce512MatchesBigInteger() {
        ModArith m = modArith();
        long t0 = System.currentTimeMillis();
        byte[][] edges = new byte[5][64];
        java.util.Arrays.fill(edges[1], (byte) 0xFF); // 2^512 - 1
        System.arraycopy(toBytes(L), 0, edges[2], 32, 32); // 1*l
        System.arraycopy(toBytes(L.multiply(BigInteger.valueOf(3))), 0, edges[3], 32, 32); // 3*l
        System.arraycopy(toBytes(L.multiply(N)), 0, edges[4], 32, 32); // l*n
        for (byte[] x : edges) {
            reduce512Check(m, x);
        }
        for (int i = 0; i < RANDOM_ROUNDS / 10; i++) {
            byte[] x = new byte[64];
            RND.nextBytes(x);
            reduce512Check(m, x);
        }
        System.out.println(
                "ModArithTest reduce512: 10^4 rounds in "
                        + (System.currentTimeMillis() - t0)
                        + " ms");
    }

    private static void reduce512Check(ModArith m, byte[] x) {
        byte[] in = x.clone();
        byte[] out = new byte[32];
        m.reduce512(in, (short) 0, out, (short) 0);
        assertArrayEquals(toBytes(new BigInteger(1, x).mod(L)), out, "reduce512");
    }

    /** {@code R256 = 2^256 mod l}, the constant {@code reduce512} multiplies by. */
    @Test
    void reduce512ConstantIsPow256ModL() throws Exception {
        java.lang.reflect.Field f = ModArith.class.getDeclaredField("R256");
        f.setAccessible(true);
        assertArrayEquals(toBytes(BigInteger.TWO.pow(256).mod(L)), (byte[]) f.get(null), "R256");
    }

    @Test
    void reverseFlipsInPlace() {
        byte[] src = {1, 2, 3, 4, 5};
        byte[] dst = new byte[5];
        Bytes.reverse(src, (short) 0, dst, (short) 0, (short) 5);
        assertArrayEquals(new byte[] {5, 4, 3, 2, 1}, dst);
        // a shifted window inside a larger array
        byte[] big = new byte[16];
        RND.nextBytes(big);
        byte[] expect = big.clone();
        for (int i = 0; i < 8; i++) {
            expect[4 + i] = big[4 + 7 - i];
        }
        byte[] out = new byte[16];
        Bytes.reverse(big, (short) 4, out, (short) 4, (short) 8);
        for (int i = 0; i < 8; i++) {
            assertEquals(expect[4 + i], out[4 + i], "reversed window");
        }
        for (int i = 0; i < 4; i++) {
            assertEquals(0, out[i], "outside the window untouched");
        }
    }

    private static byte[] random32() {
        byte[] b = new byte[32];
        RND.nextBytes(b);
        return b;
    }
}
