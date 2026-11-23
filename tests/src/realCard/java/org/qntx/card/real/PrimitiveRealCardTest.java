// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.qntx.card.host.Crypto;
import org.qntx.card.tests.Vecs;

/**
 * The primitive cost profile (architecture.md §10): probe INS {@code 0x60} runs a platform
 * primitive {@code P1} {@code P2} times; the per-op cost is {@code (t(r) − t(0)) / r} from the
 * medians of {@value #RUNS} runs at {@code r ∈ {0, 4, 16}}. Every primitive uses the exact shape
 * the wallet applet gives the engine (the §8.5 domain reload, the §12 precomputed-hash ECDSA, the
 * ModArith RSA square). Results land in {@code primitives.json}/{@code primitives.md}.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
final class PrimitiveRealCardTest {

    private static final int RUNS = 20;
    private static final int[] RS = {0, 4, 16};

    private record Prim(int p1, String name, byte[] data) {}

    /** {@code 80 INS P1 P2 [Lc data]} — the probe wire format, no Le. */
    private static byte[] apdu(int ins, int p1, int p2, byte[] data) {
        byte[] a = new byte[5 + (data == null ? 0 : data.length)];
        a[0] = (byte) 0x80;
        a[1] = (byte) ins;
        a[2] = (byte) p1;
        a[3] = (byte) p2;
        if (data != null) {
            a[4] = (byte) data.length;
            System.arraycopy(data, 0, a, 5, data.length);
        }
        return a;
    }

    private static byte[] ok(int ins, int p1, byte[] data) throws Exception {
        return Fixture.card().ok(apdu(ins, p1, 0, data));
    }

    /** Median of the nanos collected. */
    private static double median(List<Long> v) {
        long[] s = v.stream().mapToLong(Long::longValue).sorted().toArray();
        return s.length % 2 == 1 ? s[s.length / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2.0;
    }

    @Test
    @Order(1)
    void primitiveProfile() throws Exception {
        Fixture.require();
        Fixture.ensureInstalled(Fixture.CapKind.PROBE);
        Fixture.selectProbe();
        RealCard card = Fixture.card();

        // key material the prims share: a secp256k1 private slot (S, W = s·G), a Wei25519
        // private slot, two public slots and the TRANSIENT_DESELECT key's domain (INS 0x10)
        byte[] secp = AdmissionRealCardTest.secpDomain();
        byte[] wei = AdmissionRealCardTest.weiDomain();
        byte[] g = Arrays.copyOfRange(secp, 96, 161);
        byte[] gW = Arrays.copyOfRange(wei, 96, 161);
        BigInteger s = new BigInteger(255, Vecs.RND).add(BigInteger.ONE);
        byte[] sBytes = new byte[32];
        byte[] sb = s.toByteArray();
        System.arraycopy(
                sb,
                Math.max(0, sb.length - 32),
                sBytes,
                Math.max(0, 32 - sb.length),
                Math.min(32, sb.length));
        byte[] wPoint = Crypto.G.multiply(s).normalize().getEncoded(false);
        byte[] hash = Vecs.digest();
        byte[] key = new byte[16];
        Vecs.RND.nextBytes(key);
        byte[] keyIv = new byte[32];
        Vecs.RND.nextBytes(keyIv); // key(16) ‖ iv(16) for the AES-CBC init-with-IV prim
        byte[] mod = new byte[64];
        byte[] rsaInput = new byte[64];
        Vecs.RND.nextBytes(rsaInput);
        rsaInput[0] &= 0x7F;
        BigInteger m =
                BigInteger.probablePrime(256, Vecs.RND)
                        .multiply(BigInteger.probablePrime(256, Vecs.RND));
        byte[] mb = m.toByteArray();
        System.arraycopy(
                mb,
                Math.max(0, mb.length - 64),
                mod,
                Math.max(0, 64 - mb.length),
                Math.min(64, mb.length));
        // rsa param = modulus(64) ‖ exponent(1) ‖ input(64); RSA input must stay < modulus
        BigInteger x = new BigInteger(1, rsaInput).mod(m);
        byte[] xb = x.toByteArray();
        Arrays.fill(rsaInput, (byte) 0);
        System.arraycopy(
                xb,
                Math.max(0, xb.length - 64),
                rsaInput,
                Math.max(0, 64 - xb.length),
                Math.min(64, xb.length));
        byte[] rsaParam = new byte[129];
        System.arraycopy(mod, 0, rsaParam, 0, 64);
        rsaParam[64] = 2;
        System.arraycopy(rsaInput, 0, rsaParam, 65, 64);

        ok(0x10, 0, secp); // ecPriv[0] ← secp256k1
        ok(0x11, 0, sBytes); // ecPriv[0].S
        ok(0x10, 1, wei); // ecPriv[1] ← Wei25519
        ok(0x11, 1, sBytes); // ecPriv[1].S (scalar field is the same encoding)
        ok(0x10, 2, secp); // ecPub[0] domain
        ok(0x10, 3, secp); // ecPub[1] domain
        ok(0x12, 3, wPoint); // ecPub[1].W = s·G — the verify target of prim 0x10
        ok(0x10, 4, secp); // the TRANSIENT_DESELECT private key's domain
        byte[] sig = ok(0x15, 0, hash); // sign once under ecPriv[0] for the verify prim
        byte[] hashSig = new byte[32 + sig.length];
        System.arraycopy(hash, 0, hashSig, 0, 32);
        System.arraycopy(sig, 0, hashSig, 32, sig.length);

        List<Prim> prims =
                List.of(
                        new Prim(0x01, "AES-CBC init, IV", keyIv),
                        new Prim(0x02, "AES-CBC init, no IV", key),
                        new Prim(0x03, "AES-CBC doFinal 16 B", key),
                        new Prim(0x04, "AES-CBC doFinal 240 B", key),
                        new Prim(0x05, "CMAC-128 init", key),
                        new Prim(0x06, "CMAC update 242 B + sign", key),
                        new Prim(0x07, "SHA-512 update 236 B", null),
                        new Prim(0x08, "SHA-512 doFinal 128 B", null),
                        new Prim(0x09, "SHA-256 doFinal 32 B", null),
                        new Prim(0x0A, "RSA-512 NOPAD square", rsaParam),
                        new Prim(0x0B, "EC setS (transient key)", sBytes),
                        new Prim(0x0C, "PLAIN_XY secp256k1", g),
                        new Prim(0x0D, "PACE_GM secp256k1", g),
                        new Prim(0x0E, "PACE_GM Wei25519", gW),
                        new Prim(0x0F, "signPreComputedHash secp256k1", hash),
                        new Prim(0x10, "verifyPreComputedHash secp256k1", hashSig),
                        new Prim(0x11, "ECPublicKey.setW (persistent)", wPoint),
                        new Prim(0x12, "setDomain secp256k1 (transient)", secp),
                        new Prim(0x13, "setDomain Wei25519 (transient)", wei),
                        new Prim(0x14, "RandomData.nextBytes 32 B", null),
                        new Prim(0x15, "arrayFillNonAtomic 256 B", null),
                        new Prim(0x16, "byte loop ×256", null));

        Map<String, Map<String, Object>> report = new LinkedHashMap<>();
        StringBuilder md =
                new StringBuilder(
                        "| primitive | median dispatch ms | per-op ms (r = 4) | per-op ms (r = 16) |\n");
        md.append("| --- | --- | --- | --- |\n");
        for (Prim prim : prims) {
            Map<Integer, Double> med = new LinkedHashMap<>();
            for (int r : RS) {
                List<Long> nanos = new ArrayList<>(RUNS);
                for (int i = 0; i < RUNS; i++) {
                    RealCard.Timed t = card.timed(apdu(0x60, prim.p1(), r, prim.data()));
                    assertEquals(0x9000, RealCard.sw(t.rapdu()), prim.name() + " r=" + r);
                    nanos.add(t.nanos());
                }
                med.put(r, median(nanos));
            }
            double per4 = (med.get(4) - med.get(0)) / 4;
            double per16 = (med.get(16) - med.get(0)) / 16;
            md.append(
                    String.format(
                            "| %s | %.3f | %.3f | %.3f |\n",
                            prim.name(), med.get(0) / 1e6, per4 / 1e6, per16 / 1e6));
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("dispatchMedianNs", med.get(0));
            row.put("r4MedianNs", med.get(4));
            row.put("r16MedianNs", med.get(16));
            row.put("perOpNsR4", per4);
            row.put("perOpNsR16", per16);
            report.put(prim.name(), row);
        }
        Files.writeString(
                Fixture.out().resolve("primitives.json"),
                com.fasterxml.jackson.jr.ob.JSON.std.asString(report));
        Files.writeString(Fixture.out().resolve("primitives.md"), md.toString());
        // sanity: every per-op cost is positive and under the §16.6 command bound
        for (Map.Entry<String, Map<String, Object>> e : report.entrySet()) {
            Map<String, Object> row = e.getValue();
            assertTrue(
                    (Double) row.get("perOpNsR16") > 0 && (Double) row.get("perOpNsR16") < 1.5e9,
                    e.getKey() + " per-op cost out of range");
        }
    }

    @AfterAll
    static void cleanUpCard() throws Exception {
        if (Fixture.available()) {
            Fixture.cleanupCard();
        }
    }
}
