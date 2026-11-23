// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.qntx.card.host.Crypto;
import org.qntx.card.tests.Vecs;

/**
 * The silicon admission items of protocol.md §3 against the {@code qntx-probe.cap} applet
 * (architecture.md §10): RSA NOPAD below 2²⁵⁶, PACE_GM and PLAIN_XY on secp256k1 and Wei25519,
 * precomputed-hash ECDSA, domain acceptance on persistent and transient keys, transaction
 * participation of the persistent key setters and the RNG statistics. Item 8 (commit capacity) is
 * {@link MemoryRealCardTest}'s memprobe job.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
final class AdmissionRealCardTest {
    private static final SecureRandom RND = Vecs.RND;

    /** secp256k1, P ‖ A ‖ B ‖ G ‖ R ‖ K for the probe's EC_DOMAIN command. */
    private static byte[] secpDomain() {
        byte[] d = new byte[195];
        byte[] p = Vecs.unhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
        byte[] b = new byte[32];
        b[31] = 7;
        byte[] g =
                Vecs.unhex(
                        "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
                                + "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
        byte[] n = Vecs.unhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        System.arraycopy(p, 0, d, 0, 32);
        System.arraycopy(b, 0, d, 64, 32);
        System.arraycopy(g, 0, d, 96, 65);
        System.arraycopy(n, 0, d, 161, 32);
        d[194] = 1;
        return d;
    }

    /** Wei25519 (§10.4) in the same layout; parameters from derivation.json. */
    private static byte[] weiDomain() {
        Map<String, Object> w = Vecs.obj(Vecs.load("derivation.json"), "wei25519");
        byte[] d = new byte[195];
        System.arraycopy(Vecs.hex(w, "q"), 0, d, 0, 32);
        System.arraycopy(Vecs.hex(w, "aW"), 0, d, 32, 32);
        System.arraycopy(Vecs.hex(w, "bW"), 0, d, 64, 32);
        d[96] = 4;
        System.arraycopy(Vecs.hex(w, "gW"), 0, d, 97, 64);
        System.arraycopy(Vecs.hex(w, "order"), 0, d, 161, 32);
        d[194] = 1;
        return d;
    }

    /** Wei25519 as a BouncyCastle curve for the expected values. */
    private static ECCurve.Fp weiCurve() {
        Map<String, Object> w = Vecs.obj(Vecs.load("derivation.json"), "wei25519");
        return new ECCurve.Fp(
                new BigInteger(1, Vecs.hex(w, "q")),
                new BigInteger(1, Vecs.hex(w, "aW")),
                new BigInteger(1, Vecs.hex(w, "bW")),
                new BigInteger(1, Vecs.hex(w, "order")),
                BigInteger.ONE);
    }

    private static byte[] apdu(int ins, int p1, byte[] data) {
        byte[] a = new byte[5 + (data == null ? 0 : data.length)];
        a[0] = (byte) 0x80;
        a[1] = (byte) ins;
        a[2] = (byte) p1;
        if (data != null) {
            a[4] = (byte) data.length;
            System.arraycopy(data, 0, a, 5, data.length);
        }
        return a;
    }

    private static byte[] ok(int ins, int p1, byte[] data) {
        return Fixture.card().ok(apdu(ins, p1, data));
    }

    private static int sw(int ins, int p1, byte[] data) {
        return RealCard.sw(Fixture.card().transmit(apdu(ins, p1, data)));
    }

    /** Random point on the Wei25519 curve as a 65-byte uncompressed encoding. */
    private static byte[] weiPoint(ECCurve.Fp curve, BigInteger s) {
        Map<String, Object> w = Vecs.obj(Vecs.load("derivation.json"), "wei25519");
        byte[] gw = Vecs.hex(w, "gW");
        ECPoint g =
                curve.createPoint(
                        new BigInteger(1, Arrays.copyOf(gw, 32)),
                        new BigInteger(1, Arrays.copyOfRange(gw, 32, 64)));
        return g.multiply(s).normalize().getEncoded(false);
    }

    private static BigInteger randScalar(BigInteger n) {
        BigInteger s;
        do {
            s = new BigInteger(256, RND);
        } while (s.signum() <= 0 || s.compareTo(n) >= 0);
        return s;
    }

    @Test
    @Order(1)
    void probeInstalled() throws Exception {
        Fixture.require();
        Fixture.ensureInstalled(Fixture.CapKind.PROBE);
        Fixture.card().ok(RealCard.SELECT_PROBE);
        byte[] mem = ok(0x40, 0, null);
        assertEquals(12, mem.length, "memory baseline");
        // three 32-bit values: PERSISTENT, TRANSIENT_RESET, TRANSIENT_DESELECT
        for (int i = 0; i < 3; i++) {
            long v = u32(mem, 4 * i);
            assertTrue(v > 0, "memory type " + i + " available");
        }
    }

    private static long u32(byte[] b, int off) {
        return ((b[off] & 0xFFL) << 24)
                | ((b[off + 1] & 0xFFL) << 16)
                | ((b[off + 2] & 0xFFL) << 8)
                | (b[off + 3] & 0xFFL);
    }

    @Test
    @Order(2)
    void platformEnginesAndCommitCapacity() throws Exception {
        Fixture.require();
        Fixture.ensureInstalled(Fixture.CapKind.PROBE);
        Fixture.card().ok(RealCard.SELECT_PROBE);
        // CAPSCAN (probe INS 0x50): the engines/keys the wallet's install allocates beyond the
        // probe's own — each must instantiate, and the commit numbers are recorded for the audit
        byte[] q = new byte[64];
        System.arraycopy(
                Vecs.unhex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED"),
                0,
                q,
                32,
                32);
        for (int p1 = 1; p1 <= 5; p1++) {
            assertEquals(0x9000, sw(0x50, p1, null), "capscan " + p1);
        }
        assertEquals(0x9000, sw(0x50, 6, q), "capscan extra RSA key");
        assertEquals(0x9000, sw(0x50, 8, null), "capscan second transient EC key");
        // capscan 10–14: the session-layer primitives the wallet actually runs —
        // SHA-256 (KDF), SHA-512 (Ed25519), AES-CBC-NOPAD and AES-CMAC-128 (session
        // records) on a TRANSIENT_DESELECT key, and getW (the OPEN response)
        byte[] in16 = new byte[32];
        RND.nextBytes(in16);
        assertArrayEquals(
                MessageDigest.getInstance("SHA-256").digest(in16),
                ok(0x50, 10, in16),
                "capscan SHA-256");
        assertArrayEquals(
                MessageDigest.getInstance("SHA-512").digest(in16),
                ok(0x50, 11, in16),
                "capscan SHA-512");
        byte[] key16 = new byte[16];
        byte[] block16 = new byte[16];
        RND.nextBytes(key16);
        RND.nextBytes(block16);
        byte[] kb = new byte[32];
        System.arraycopy(key16, 0, kb, 0, 16);
        System.arraycopy(block16, 0, kb, 16, 16);
        javax.crypto.Cipher aes =
                javax.crypto.Cipher.getInstance("AES/ECB/NoPadding"); // CBC, IV = 0, one block
        aes.init(
                javax.crypto.Cipher.ENCRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(key16, "AES"));
        assertArrayEquals(aes.doFinal(block16), ok(0x50, 12, kb), "capscan AES-CBC");
        CMac cmac = new CMac(AESEngine.newInstance());
        cmac.init(new KeyParameter(key16));
        byte[] msg32 = new byte[32];
        RND.nextBytes(msg32);
        cmac.update(msg32, 0, 32);
        byte[] tag = new byte[16];
        cmac.doFinal(tag, 0);
        byte[] km = new byte[48];
        System.arraycopy(key16, 0, km, 0, 16);
        System.arraycopy(msg32, 0, km, 16, 32);
        assertArrayEquals(tag, ok(0x50, 13, km), "capscan AES-CMAC");
        byte[] g = Arrays.copyOfRange(secpDomain(), 96, 161);
        assertEquals(0x9000, sw(0x10, 2, secpDomain()), "domain for getW");
        assertEquals(0x9000, sw(0x12, 2, g), "setW for getW");
        assertArrayEquals(g, ok(0x50, 14, null), "capscan getW");
        byte[] commit = ok(0x50, 9, null);
        int maxCommit = ((commit[0] & 0xFF) << 8) | (commit[1] & 0xFF);
        int unusedCommit = ((commit[2] & 0xFF) << 8) | (commit[3] & 0xFF);
        byte[] mem = ok(0x40, 0, null);
        Files.writeString(
                Fixture.out().resolve("commit-capacity.json"),
                "{\"maxCommitCapacity\":"
                        + maxCommit
                        + ",\"unusedCommitCapacity\":"
                        + unusedCommit
                        + ",\"memory\":{\"persistent\":"
                        + u32(mem, 0)
                        + ",\"transientReset\":"
                        + u32(mem, 4)
                        + ",\"transientDeselect\":"
                        + u32(mem, 8)
                        + "}}");
        assertTrue(maxCommit > 0, "commit capacity reported");
    }

    @Test
    @Order(3)
    void ecDomainsAcceptedOnEveryKeyKind() throws Exception {
        Fixture.require();
        Fixture.ensureInstalled(Fixture.CapKind.PROBE);
        Fixture.card().ok(RealCard.SELECT_PROBE);
        // §3 item 5: persistent and TRANSIENT_DESELECT 256-bit EC keys take both domains
        for (int slot : new int[] {0, 1, 2, 3, 4}) {
            assertEquals(0x9000, sw(0x10, slot, secpDomain()), "secp slot " + slot);
            assertEquals(0x9000, sw(0x10, slot, weiDomain()), "wei slot " + slot);
        }
        for (int slot : new int[] {5, 6, 7, 8}) {
            assertEquals(0x9000, sw(0x10, slot, secpDomain()), "pair slot " + slot);
        }
    }

    @Test
    @Order(4)
    void rsaNopadUnder256() throws Exception {
        Fixture.require();
        Fixture.ensureInstalled(Fixture.CapKind.PROBE);
        Fixture.card().ok(RealCard.SELECT_PROBE);
        BigInteger q =
                new BigInteger(
                        1,
                        Vecs.unhex(
                                "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED"));
        BigInteger odd = new BigInteger(256, RND).setBit(255).setBit(0);
        byte[][] moduli = {fixed(q, 64), fixed(odd, 64)};
        byte[][] exps = {{0x02}, fixed(new BigInteger(255, RND).setBit(0), 32)};
        for (int m = 0; m < moduli.length; m++) {
            BigInteger mod = new BigInteger(1, moduli[m]);
            for (int e = 0; e < exps.length; e++) {
                BigInteger exp = new BigInteger(1, exps[e]);
                assertEquals(0x9000, sw(0x01, 0, moduli[m]), "setModulus m" + m);
                assertEquals(0x9000, sw(0x02, 0, exps[e]), "setExponent e" + e);
                // §3 item 1: x < m computes x^e mod m, x ≥ m throws
                for (int i = 0; i < 1000; i++) {
                    byte[] x;
                    BigInteger xi;
                    if (i == 0) {
                        xi = mod;
                    } else if (i == 1) {
                        xi = new BigInteger(256, RND).setBit(255); // ≥ 2²⁵⁵ ≥ m for m = q
                    } else {
                        xi = new BigInteger(mod.bitLength(), RND);
                    }
                    x = fixed(xi, 64);
                    byte[] rapdu = Fixture.card().transmit(apdu(0x03, 0, x));
                    if (xi.compareTo(mod) >= 0) {
                        assertTrue(
                                (RealCard.sw(rapdu) & 0xFF00) == 0x6F00,
                                "x ≥ m must throw, got "
                                        + String.format("%04X", RealCard.sw(rapdu)));
                    } else {
                        assertEquals(0x9000, RealCard.sw(rapdu), "doFinal m" + m + " e" + e);
                        byte[] expected = fixed(xi.modPow(exp, mod), 64);
                        assertArrayEquals(
                                expected,
                                Arrays.copyOf(rapdu, 64),
                                "RSA m" + m + " e" + e + " i" + i);
                    }
                }
            }
        }
    }

    @Test
    @Order(5)
    void paceGmAndPlainXyOnBothCurves() throws Exception {
        Fixture.require();
        Fixture.ensureInstalled(Fixture.CapKind.PROBE);
        Fixture.card().ok(RealCard.SELECT_PROBE);
        BigInteger n = Crypto.N;
        // secp256k1 on slot 0
        assertEquals(0x9000, sw(0x10, 0, secpDomain()));
        for (int i = 0; i < 8; i++) {
            BigInteger s = randScalar(n);
            assertEquals(0x9000, sw(0x11, 0, fixed(s, 32)));
            byte[] h = Crypto.publicKey(randScalar(n));
            byte[] out = ok(0x13, 0, h);
            assertEquals(65, out.length);
            // s·G + H (§3 item 2)
            ECPoint expected = Crypto.G.multiply(s).add(Crypto.DOMAIN.getCurve().decodePoint(h));
            assertArrayEquals(expected.normalize().getEncoded(false), out, "secp PACE_GM " + i);
            byte[] prod = ok(0x14, 0, h);
            ECPoint p = Crypto.DOMAIN.getCurve().decodePoint(h);
            assertArrayEquals(
                    p.multiply(s).normalize().getEncoded(false), prod, "secp PLAIN_XY " + i);
        }
        // the infinite result throws (H = −s·G)
        BigInteger s = randScalar(n);
        assertEquals(0x9000, sw(0x11, 0, fixed(s, 32)));
        byte[] neg = Crypto.G.multiply(s).negate().normalize().getEncoded(false);
        int swInf = sw(0x13, 0, neg);
        assertTrue(
                (swInf & 0xFF00) == 0x6F00, "infinity must throw: " + Integer.toHexString(swInf));
        // invalid inputs to PLAIN_XY throw (§3 item 3): off-curve, coordinate ≥ p, compressed
        byte[] offCurve = Crypto.publicKey(randScalar(n));
        offCurve[64] ^= 1;
        assertTrue((sw(0x14, 0, offCurve) & 0xFF00) == 0x6F00, "off-curve input");
        byte[] coordOver = Crypto.publicKey(randScalar(n));
        Arrays.fill(coordOver, 1, 33, (byte) 0xFF);
        assertTrue((sw(0x14, 0, coordOver) & 0xFF00) == 0x6F00, "x ≥ p input");
        byte[] compressed = Crypto.compress(Crypto.publicKey(randScalar(n)));
        byte[] wrongForm = new byte[65];
        wrongForm[0] = 0x02;
        System.arraycopy(compressed, 1, wrongForm, 1, 32);
        assertTrue((sw(0x14, 0, wrongForm) & 0xFF00) == 0x6F00, "compressed-form input");

        // Wei25519 on slot 1 (persistent) and slot 4 (TRANSIENT_DESELECT)
        ECCurve.Fp curve = weiCurve();
        Map<String, Object> w = Vecs.obj(Vecs.load("derivation.json"), "wei25519");
        BigInteger order = new BigInteger(1, Vecs.hex(w, "order"));
        for (int slot : new int[] {1, 4}) {
            assertEquals(0x9000, sw(0x10, slot, weiDomain()));
            for (int i = 0; i < 4; i++) {
                BigInteger ws = randScalar(order);
                assertEquals(0x9000, sw(0x11, slot, fixed(ws, 32)), "setS slot " + slot);
                byte[] h = weiPoint(curve, randScalar(order));
                byte[] out = ok(0x13, slot, h);
                ECPoint g = curve.decodePoint(weiPoint(curve, BigInteger.ONE));
                ECPoint expected = g.multiply(ws).add(curve.decodePoint(h));
                assertArrayEquals(
                        expected.normalize().getEncoded(false),
                        out,
                        "wei PACE_GM slot " + slot + " " + i);
                byte[] prod = ok(0x14, slot, h);
                assertArrayEquals(
                        curve.decodePoint(h).multiply(ws).normalize().getEncoded(false),
                        prod,
                        "wei PLAIN_XY slot " + slot + " " + i);
            }
        }
    }

    @Test
    @Order(6)
    void precomputedHashEcdsaSignsAndVerifies() throws Exception {
        Fixture.require();
        Fixture.ensureInstalled(Fixture.CapKind.PROBE);
        Fixture.card().ok(RealCard.SELECT_PROBE);
        assertEquals(0x9000, sw(0x10, 0, secpDomain()));
        assertEquals(0x9000, sw(0x10, 2, secpDomain()));
        BigInteger d = randScalar(Crypto.N);
        byte[] w = Crypto.publicKey(d);
        assertEquals(0x9000, sw(0x11, 0, fixed(d, 32)), "setS");
        assertEquals(0x9000, sw(0x12, 2, w), "setW");
        byte[] hash = new byte[32];
        RND.nextBytes(hash);
        // card sign → host verify (§3 item 4)
        byte[] der = ok(0x15, 0, hash);
        assertTrue(der.length >= 8 && (der[0] & 0xFF) == 0x30, "DER signature form");
        BigInteger[] rs = decodeDer(der);
        byte[] rs64 = new byte[64];
        write256(rs[0], rs64, 0);
        write256(rs[1], rs64, 32);
        assertTrue(Crypto.verify(w, hash, rs64), "card signature verifies");
        // host sign → card verify
        byte[] sig = Crypto.sign(d, hash);
        byte[] hostDer =
                der(
                        new BigInteger(1, Arrays.copyOf(sig, 32)),
                        new BigInteger(1, Arrays.copyOfRange(sig, 32, 64)));
        byte[] both = new byte[32 + hostDer.length];
        System.arraycopy(hash, 0, both, 0, 32);
        System.arraycopy(hostDer, 0, both, 32, hostDer.length);
        byte[] verdict = ok(0x16, 2, both);
        assertArrayEquals(new byte[] {1}, verdict, "host signature accepted");
        both[both.length - 1] ^= 1;
        verdict = ok(0x16, 2, both);
        assertArrayEquals(new byte[] {0}, verdict, "corrupt signature rejected");
    }

    @Test
    @Order(7)
    void persistentKeySettersJoinAndAbortTransactions() throws Exception {
        Fixture.require();
        Fixture.ensureInstalled(Fixture.CapKind.PROBE);
        Fixture.card().ok(RealCard.SELECT_PROBE);
        // §3 item 7 (abort variant): old ‖ inside ‖ after, abort restores the previous value
        byte[] k1 = new byte[16];
        byte[] k2 = new byte[16];
        RND.nextBytes(k1);
        RND.nextBytes(k2);
        assertEquals(0x9000, sw(0x22, 0, k1), "AES setKey baseline");
        byte[] triple = ok(0x21, 1, k2);
        assertEquals(48, triple.length);
        assertArrayEquals(k1, Arrays.copyOf(triple, 16), "AES old");
        assertArrayEquals(k2, Arrays.copyOfRange(triple, 16, 32), "AES inside");
        assertArrayEquals(k1, Arrays.copyOfRange(triple, 32, 48), "AES after abort");

        assertEquals(0x9000, sw(0x10, 0, secpDomain()));
        byte[] s1 = fixed(randScalar(Crypto.N), 32);
        byte[] s2 = fixed(randScalar(Crypto.N), 32);
        assertEquals(0x9000, sw(0x11, 0, s1));
        triple = ok(0x21, 2, s2);
        assertArrayEquals(s1, Arrays.copyOf(triple, 32), "S old");
        assertArrayEquals(s2, Arrays.copyOfRange(triple, 32, 64), "S inside");
        assertArrayEquals(s1, Arrays.copyOfRange(triple, 64, 96), "S after abort");

        assertEquals(0x9000, sw(0x10, 2, secpDomain()));
        byte[] w1 = Crypto.publicKey(randScalar(Crypto.N));
        byte[] w2 = Crypto.publicKey(randScalar(Crypto.N));
        assertEquals(0x9000, sw(0x12, 2, w1));
        triple = ok(0x21, 3, w2);
        assertArrayEquals(w1, Arrays.copyOf(triple, 65), "W old");
        assertArrayEquals(w2, Arrays.copyOfRange(triple, 65, 130), "W inside");
        assertArrayEquals(w1, Arrays.copyOfRange(triple, 130, 195), "W after abort");

        byte[] e1 = {0x03};
        byte[] e2 = fixed(new BigInteger(255, RND).setBit(0), 32);
        assertEquals(0x9000, sw(0x02, 0, e1));
        triple = ok(0x21, 4, e2);
        assertEquals(96, triple.length);
        assertEquals(3, triple[0], "old exponent 03");
        assertArrayEquals(e2, Arrays.copyOfRange(triple, 32, 64), "exp inside");
        assertEquals(3, triple[64], "exponent restored after abort");

        // genKeyPair inside a transaction: P1 = 6/7 re-generate an initialised pair and the
        // abort restores the previous S/W; P1 = 5 leaves a fresh pair uninitialised again
        assertEquals(0x9000, sw(0x10, 5, secpDomain()));
        assertEquals(0x9000, sw(0x10, 6, secpDomain()));
        assertEquals(0x9000, sw(0x20, 0, null), "genKeyPair baseline");
        triple = ok(0x21, 6, null);
        assertEquals(96, triple.length);
        byte[] sOld = Arrays.copyOf(triple, 32);
        byte[] sIn = Arrays.copyOfRange(triple, 32, 64);
        byte[] sAfter = Arrays.copyOfRange(triple, 64, 96);
        assertNotEquals(0, new BigInteger(1, sIn).signum(), "inside S nonzero");
        assertTrue(!Arrays.equals(sOld, sIn), "genKeyPair produced a new S inside the tx");
        assertArrayEquals(sOld, sAfter, "abort restored the pair's S");
        triple = ok(0x21, 7, null);
        assertEquals(195, triple.length);
        assertArrayEquals(
                Arrays.copyOf(triple, 65),
                Arrays.copyOfRange(triple, 130, 195),
                "abort restored the pair's W");

        assertEquals(0x9000, sw(0x10, 7, secpDomain()));
        assertEquals(0x9000, sw(0x10, 8, secpDomain()));
        byte[] fresh = ok(0x21, 5, null);
        assertEquals(99, fresh.length);
        assertEquals(1, fresh[0], "initialised inside the transaction");
        assertNotEquals(0, new BigInteger(1, Arrays.copyOfRange(fresh, 1, 33)).signum());
        assertEquals(0, fresh[98], "uninitialised again after the abort");
    }

    @Test
    @Order(8)
    void rngPassesStatisticsAndDoesNotRepeatAcrossPowerUps() throws Exception {
        Fixture.require();
        Fixture.ensureInstalled(Fixture.CapKind.PROBE);
        Fixture.card().ok(RealCard.SELECT_PROBE);
        long want = Fixture.rngBytes();
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        while (buf.size() < want) {
            int n = (int) Math.min(240, want - buf.size());
            buf.write(ok(0x30, n, null));
        }
        byte[] rng = buf.toByteArray();
        Files.write(Fixture.out().resolve("rng.bin"), rng);
        Map<String, Double> p = RngStats.all(rng);
        Map<String, Object> report = new LinkedHashMap<>(p);
        Files.writeString(
                Fixture.out().resolve("rng.json"),
                com.fasterxml.jackson.jr.ob.JSON.std.asString(report));
        for (Map.Entry<String, Double> e : p.entrySet()) {
            assertTrue(e.getValue() >= 0.01, e.getKey() + " p = " + e.getValue());
        }
        // §3 item 6: the first 32 bytes after each of 100 power-ups are pairwise distinct
        java.util.Set<String> firsts = new TreeSet<>();
        for (int i = 0; i < 100; i++) {
            Fixture.card().reset();
            Fixture.card().ok(RealCard.SELECT_PROBE);
            firsts.add(java.util.HexFormat.of().formatHex(ok(0x30, 32, null)));
        }
        assertEquals(100, firsts.size(), "first RNG output repeated across power-ups");
    }

    @AfterAll
    static void cleanUpCard() throws Exception {
        if (Fixture.available()) {
            Fixture.cleanupCard();
        }
    }

    private static byte[] fixed(BigInteger v, int len) {
        byte[] out = new byte[len];
        byte[] b = v.toByteArray();
        System.arraycopy(
                b,
                Math.max(0, b.length - len),
                out,
                Math.max(0, len - b.length),
                Math.min(b.length, len));
        return out;
    }

    private static void write256(BigInteger v, byte[] out, int off) {
        byte[] b = v.toByteArray();
        System.arraycopy(
                b,
                Math.max(0, b.length - 32),
                out,
                off + Math.max(0, 32 - b.length),
                Math.min(b.length, 32));
    }

    private static BigInteger[] decodeDer(byte[] der) throws Exception {
        ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(der));
        return new BigInteger[] {
            ((ASN1Integer) seq.getObjectAt(0)).getValue(),
            ((ASN1Integer) seq.getObjectAt(1)).getValue()
        };
    }

    private static byte[] der(BigInteger r, BigInteger s) throws Exception {
        return new DERSequence(new ASN1Integer[] {new ASN1Integer(r), new ASN1Integer(s)})
                .getEncoded();
    }
}
