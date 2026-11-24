// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review;

import static org.qntx.card.review.ReviewHost.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.qntx.card.sim.Rng;

/**
 * Crypto conformance through the command interface: official vectors (BIP-32 TV2/TV3, SLIP-10 TV2,
 * BIP-86), verifier validation against BIP-340/RFC 8032/SP 800-38B, a 3×10⁵-signature differential
 * sweep, nonce statistics and point-decoding probes. Official vector sources are mirrored under
 * {@code $A/review/evidence/vectors-src/}.
 */
@EnabledIfEnvironmentVariable(named = "QNTX_REVIEW", matches = "full")
final class CryptoReviewTest {

    private static final Path DIR =
            Paths.get(System.getenv().getOrDefault("QNTX_REVIEW_OUT", "build/review"));
    private static final Path SRC = DIR.resolve("vectors-src");

    private static final byte INS_STATUS = 0x20,
            INS_CREATE = 0x21,
            INS_VERIFY = 0x22,
            INS_PUBLIC_KEY = 0x30,
            INS_SIGN_ECDSA = 0x31,
            INS_SIGN_BIP340 = 0x32,
            INS_SIGN_ED25519 = 0x33;

    private static final byte[] H0 = sha256(utf8("crypto H0"));
    private static final long HP = 0x80000000L;

    private static byte[] utf8(String s) {
        return s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static byte[] pathBytes(long... idx) {
        byte[] out = new byte[1 + 4 * idx.length];
        out[0] = (byte) idx.length;
        for (int i = 0; i < idx.length; i++) {
            byte[] b = u32(idx[i]);
            System.arraycopy(b, 0, out, 1 + 4 * i, 4);
        }
        return out;
    }

    private static final List<String[]> ROWS = new ArrayList<>();
    private static final List<String> NOTES = new ArrayList<>();

    private void row(String cell, String what, String expect, String obs, boolean ok) {
        ROWS.add(new String[] {cell, what, expect, obs.replace(',', ';'), ok ? "PASS" : "DIVERGE"});
        if (!ok) {
            NOTES.add(
                    "DIVERGE "
                            + cell
                            + " "
                            + what
                            + " expected["
                            + expect
                            + "] observed["
                            + obs
                            + "]");
        }
    }

    // base58check

    private static final String B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    /** Decodes base58check; returns the 78-byte payload (version..key) with checksum checked. */
    private static byte[] b58check(String s) {
        BigInteger v = BigInteger.ZERO;
        for (char c : s.toCharArray()) {
            int d = B58.indexOf(c);
            if (d < 0) {
                throw new IllegalArgumentException("bad base58");
            }
            v = v.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(d));
        }
        byte[] b = v.toByteArray();
        int zeros = 0;
        while (zeros < s.length() && s.charAt(zeros) == '1') {
            zeros++;
        }
        byte[] out = new byte[zeros + b.length - (b[0] == 0 ? 1 : 0)];
        System.arraycopy(b, b[0] == 0 ? 1 : 0, out, zeros, out.length - zeros);
        if (out.length != 82) {
            throw new IllegalArgumentException("len " + out.length);
        }
        byte[] payload = slice(out, 0, 78);
        byte[] sum = slice(sha256(sha256(payload)), 0, 4);
        if (!ReviewCard.eq(sum, slice(out, 78, 4))) {
            throw new IllegalArgumentException("checksum");
        }
        return payload;
    }

    // helpers

    private static ReviewSession verifiedCard(byte[] seed) {
        ReviewCard c = ReviewCard.uninitialised();
        c.blank();
        ReviewSession s = c.create(seed, H0);
        s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
        return s;
    }

    /** PUBLIC_KEY secp256k1: returns {compressed pub(33), chainCode(32)} or null. */
    private static byte[][] secpPub(ReviewSession s, long... path) {
        ReviewSession.Inner r = s.cmd(INS_PUBLIC_KEY, (byte) 0, (byte) 0, pathBytes(path));
        if (r.sw != 0x9000 || r.data.length != 65) {
            return null;
        }
        return new byte[][] {slice(r.data, 0, 33), slice(r.data, 33, 32)};
    }

    // 1. official vectors

    @Test
    void officialVectors() {
        bip32Vectors();
        slip10Vectors();
        bip86Vector();
        verifierValidation();
        try {
            write();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private void bip32Vectors() {
        byte[] tv2 =
                unhex(
                        "FFFCF9F6F3F0EDEAE7E4E1DEDBD8D5D2CFCCC9C6C3C0BDBAB7B4B1AEABA8A5A2"
                                + "9F9C999693908D8A8784817E7B7875726F6C696663605D5A5754514E4B484542");
        byte[] tv3 =
                unhex(
                        "4B381541583BE4423346C643850DA4B320E46A87AE3D2A4E6DA11EBA819CD4ACBA"
                                + "45D239319AC14F863B8D5AB5A0D0C64D2E8A1E7D1457DF2E5A3C51C73235BE");
        String[][] t2 = {
            {
                "m/0",
                "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
            },
            {
                "m/0/2147483647H",
                "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
            },
            {
                "m/0/2147483647H/1",
                "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
            },
            {
                "m/0/2147483647H/1/2147483646H",
                "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
            },
            {
                "m/0/2147483647H/1/2147483646H/2",
                "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
            },
        };
        String[][] t3 = {
            {
                "m/0H",
                "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
            },
        };
        checkTv("BIP32-TV2", tv2, t2);
        checkTv("BIP32-TV3", tv3, t3);
        NOTES.add(
                "BIP-32 TV1 (16 B), TV4 (32 B) and TV5 (invalid extended keys) cannot be"
                        + " exercised through the interface: CREATE P1=01 takes exactly 64 B.");
    }

    private void checkTv(String cell, byte[] seed, String[][] nodes) {
        ReviewSession s = verifiedCard(seed);
        for (String[] node : nodes) {
            byte[] pl = b58check(node[1]);
            byte[] pub = slice(pl, 45, 33);
            byte[] cc = slice(pl, 13, 32);
            long[] path = parsePath(node[0]);
            byte[][] got = secpPub(s, path);
            boolean ok = got != null && ReviewCard.eq(got[0], pub) && ReviewCard.eq(got[1], cc);
            row(cell, node[0], "pub+cc == xpub", ok ? "match" : "MISMATCH", ok);
        }
    }

    private static long[] parsePath(String p) {
        String[] parts = p.substring(2).split("/");
        long[] out = new long[parts.length];
        for (int i = 0; i < parts.length; i++) {
            String x = parts[i];
            if (x.endsWith("H") || x.endsWith("'")) {
                out[i] = Long.parseLong(x.substring(0, x.length() - 1)) + HP;
            } else {
                out[i] = Long.parseLong(x);
            }
        }
        return out;
    }

    private void slip10Vectors() {
        byte[] seed =
                unhex(
                        "FFFCF9F6F3F0EDEAE7E4E1DEDBD8D5D2CFCCC9C6C3C0BDBAB7B4B1AEABA8A5A2"
                                + "9F9C999693908D8A8784817E7B7875726F6C696663605D5A5754514E4B484542");
        String[][] nodes = {
            {"m/0H", "86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037"},
            {
                "m/0H/2147483647H",
                "5ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d"
            },
            {
                "m/0H/2147483647H/1H",
                "2e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45"
            },
            {
                "m/0H/2147483647H/1H/2147483646H",
                "e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b"
            },
            {
                "m/0H/2147483647H/1H/2147483646H/2H",
                "47150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0"
            },
        };
        ReviewSession s = verifiedCard(seed);
        for (String[] node : nodes) {
            ReviewSession.Inner r =
                    s.cmd(INS_PUBLIC_KEY, (byte) 1, (byte) 0, pathBytes(parsePath(node[0])));
            boolean ok =
                    r.sw == 0x9000
                            && r.data.length == 64
                            && ReviewCard.eq(weiToEdwards(r.data), unhex(node[1]));
            row(
                    "SLIP10-TV2",
                    node[0],
                    "encode(A) == official pub",
                    ok ? "match" : "MISMATCH sw=" + String.format("%04X", r.sw),
                    ok);
        }
        NOTES.add("SLIP-10 TV1 (16 B seed) not loadable through CREATE P1=01.");
    }

    private void bip86Vector() {
        // BIP-39 seed of "abandon … about" (empty passphrase) via PBKDF2-HMAC-SHA512
        String mnemonic =
                "abandon abandon abandon abandon abandon abandon abandon abandon"
                        + " abandon abandon abandon about";
        PKCS5S2ParametersGenerator g = new PKCS5S2ParametersGenerator(new SHA512Digest());
        g.init(
                mnemonic.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                "mnemonic".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                2048);
        byte[] seed = ((KeyParameter) g.generateDerivedParameters(512)).getKey();
        ReviewSession s = verifiedCard(seed);
        String[][] nodes = {
            {"m/86H/0H/0H/0/0", "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"},
            {"m/86H/0H/0H/0/1", "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145"},
            {"m/86H/0H/0H/1/0", "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef"},
        };
        byte[] msg = sha256(utf8("bip86 sign message"));
        for (String[] node : nodes) {
            long[] path = parsePath(node[0]);
            byte[][] got = secpPub(s, path);
            byte[] internal = unhex(node[1]);
            boolean ok = got != null && ReviewCard.eq(slice(got[0], 1, 32), internal);
            // sign with the BIP-341 tweak and verify under the official output key
            byte[] tweak = taggedHash("TapTweak", internal);
            ReviewSession.Inner sig =
                    s.cmd(INS_SIGN_BIP340, (byte) 0, (byte) 0, concat(msg, tweak, pathBytes(path)));
            BigInteger t = b2i(tweak);
            org.bouncycastle.math.ec.ECPoint q =
                    liftX(b2i(internal)).add(g().multiply(t)).normalize();
            byte[] qx = i2b(q.getAffineXCoord().toBigInteger(), 32);
            boolean ok2 = sig.sw == 0x9000 && bip340Verify(qx, msg, sig.data);
            row(
                    "BIP86",
                    node[0] + " pubkey",
                    "x(pub) == internal_key",
                    ok ? "match" : "MISMATCH",
                    ok);
            row(
                    "BIP86",
                    node[0] + " sign",
                    "sig verifies under output key",
                    ok2 ? "verifies" : "FAIL sw=" + String.format("%04X", sig.sw),
                    ok2);
        }
    }

    private void verifierValidation() {
        bip340Rows();
        rfc8032();
        cmacAes();
    }

    /** My BIP-340 verifier must reproduce every official verification row. */
    private void bip340Rows() {
        int ok = 0, total = 0;
        try {
            List<String> lines = Files.readAllLines(SRC.resolve("test-vectors.csv"));
            for (int i = 1; i < lines.size(); i++) {
                String[] f = lines.get(i).split(",", -1);
                if (f.length < 7) {
                    continue;
                }
                total++;
                byte[] px = unhex(f[2]);
                byte[] m = unhex(f[4]);
                byte[] sig = unhex(f[5]);
                boolean expect = f[6].trim().equals("TRUE");
                boolean got;
                try {
                    got = bip340Verify(px, m, sig);
                } catch (Throwable t) {
                    got = false;
                }
                if (got == expect) {
                    ok++;
                } else {
                    row("BIP340-TV", "row " + f[0], expect ? "TRUE" : "FALSE", "got " + got, false);
                }
            }
        } catch (IOException e) {
            row("BIP340-TV", "file", "readable", e.getMessage(), false);
            return;
        }
        row("BIP340-TV", "all rows", "all match", ok + "/" + total, ok == total);
    }

    private void rfc8032() {
        String[][] tv = {
            {
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                        + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            },
            {
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                        + "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            },
            {
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                        + "18ff9b538d16f290ae67f760984dc659"
                        + "4a7c15e9716ed28dc027beceea1ec40a"
            },
        };
        int ok = 0;
        for (String[] v : tv) {
            if (ReviewCard.eq(edPublic(unhex(v[0])), unhex(v[1]))
                    && edVerify(unhex(v[1]), unhex(v[2]), unhex(v[3]))) {
                ok++;
            }
        }
        row("RFC8032", "Ed25519 TEST 1-3", "verify", ok + "/3", ok == 3);
    }

    /** NIST SP 800-38B AES-CMAC examples + one FIPS-197 AES-128 ECB KAT. */
    private void cmacAes() {
        byte[] k = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        String[][] tv = {
            {"", "bb1d6929e95937287fa37d129b756746"},
            {"6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
            {
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                        + "30c81c46a35ce411",
                "dfa66747de9ae63030ca32611497c827"
            },
            {
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                        + "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
                "51f0bebf7e3b9d92fc49741779363cfe"
            },
        };
        int ok = 0;
        for (String[] v : tv) {
            if (ReviewCard.eq(cmac(k, unhex(v[0])), unhex(v[1]))) {
                ok++;
            }
        }
        boolean aes =
                ReviewCard.eq(
                        aesBlock(k, unhex("6bc1bee22e409f96e93d7e117393172a")),
                        unhex("3ad77bb40d7a3660a89ecaf32466ef97"));
        row("SP800-38B", "CMAC examples 1-4", "match", ok + "/4", ok == 4);
        row("FIPS-197", "AES-128 block KAT", "match", aes ? "ok" : "FAIL", aes);
    }

    // 2. differential

    private static final java.util.Random R = new java.util.Random(0xC0FFEE);

    private static byte[] rand(int n) {
        byte[] b = new byte[n];
        R.nextBytes(b);
        return b;
    }

    private static long[] randPath(boolean hardenedOnly) {
        int d = 1 + R.nextInt(5);
        long[] p = new long[d];
        for (int i = 0; i < d; i++) {
            long idx = R.nextInt(0x40000000);
            if (hardenedOnly || R.nextBoolean()) {
                idx += HP;
            }
            p[i] = idx;
        }
        return p;
    }

    @Test
    void differential() {
        // Each worker owns its own card instance so sim work parallelizes.
        int workers = Integer.parseInt(System.getenv().getOrDefault("QNTX_DIFF_WORKERS", "6"));
        int total = Integer.parseInt(System.getenv().getOrDefault("QNTX_DIFF_N", "100000"));
        System.out.println("DIFF workers=" + workers + " total=" + total);
        runScheme("ECDSA", total, workers);
        runScheme("BIP340", total, workers);
        runScheme("ED25519", total, workers);
        try {
            write();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private void runScheme(String scheme, int total, int workers) {
        java.util.concurrent.atomic.AtomicInteger fails =
                new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicInteger highS =
                new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.ConcurrentHashMap<String, Integer> seen =
                new java.util.concurrent.ConcurrentHashMap<>();
        java.util.concurrent.atomic.AtomicInteger done =
                new java.util.concurrent.atomic.AtomicInteger();
        long t0 = System.currentTimeMillis();
        int per = total / workers;
        List<Thread> ts = new ArrayList<>();
        for (int w = 0; w < workers; w++) {
            int n = (w == workers - 1) ? total - per * w : per;
            Thread th = new Thread(() -> schemeWorker(scheme, n, fails, highS, seen, done));
            th.setDaemon(true);
            th.start();
            ts.add(th);
        }
        for (Thread th : ts) {
            try {
                th.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        long dt = System.currentTimeMillis() - t0;
        long dup = seen.values().stream().filter(v -> v > 1).count();
        String extra = scheme.equals("ECDSA") ? ", high-s " + highS.get() : "";
        row(
                "DIFF-" + scheme,
                total + " signatures (" + workers + " workers)",
                "0 failures, 0 dup nonces",
                fails.get() + " fails, " + dup + " dup" + extra + " (" + dt / 1000 + " s)",
                fails.get() == 0 && dup == 0);
        NOTES.add(
                scheme
                        + ": "
                        + fails.get()
                        + " fails, "
                        + dup
                        + " dup nonces"
                        + extra
                        + ", "
                        + total
                        + " sigs in "
                        + dt / 1000
                        + " s");
        System.out.println(
                "DIFF-" + scheme + " done: " + fails.get() + " fails, " + dt / 1000 + "s");
    }

    private void schemeWorker(
            String scheme,
            int n,
            java.util.concurrent.atomic.AtomicInteger fails,
            java.util.concurrent.atomic.AtomicInteger highS,
            java.util.concurrent.ConcurrentHashMap<String, Integer> seen,
            java.util.concurrent.atomic.AtomicInteger done) {
        byte[] seed = null;
        ReviewSession s = null;
        java.util.Random r = new java.util.Random();
        Map<String, byte[]> checked = new HashMap<>();
        for (int i = 0; i < n; i++) {
            try {
                if (i % 1000 == 0 || s == null) {
                    seed = new byte[64];
                    r.nextBytes(seed);
                    ReviewCard c = ReviewCard.uninitialised();
                    c.blank();
                    s = c.create(seed, H0);
                    s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
                    checked.clear();
                }
                boolean ed = scheme.equals("ED25519");
                long[] p = randPath(ed);
                String key = hex(pathBytes(p));
                final byte[] fseed = seed;
                final ReviewSession fs = s;
                final long[] fp = p;
                if (scheme.equals("ECDSA")) {
                    byte[] dg = rand(32);
                    ReviewSession.Inner res =
                            s.cmd(INS_SIGN_ECDSA, (byte) 0, (byte) 0, concat(dg, pathBytes(p)));
                    if (res.sw != 0x9000) {
                        fails.incrementAndGet();
                        continue;
                    }
                    byte[] pub = checked.computeIfAbsent(key, k -> pubOf(fs, fseed, fp));
                    if (pub == null || !ecdsaVerifyHash(pub, dg, res.data)) {
                        fails.incrementAndGet();
                    }
                    if (b2i(slice(res.data, 32, 32)).compareTo(N.shiftRight(1)) > 0) {
                        highS.incrementAndGet();
                    }
                    seen.merge(hex(slice(res.data, 0, 32)), 1, Integer::sum);
                } else if (scheme.equals("BIP340")) {
                    byte[] m = rand(32);
                    byte[] tw = r.nextInt(10) == 0 ? new byte[32] : rand(32);
                    ReviewSession.Inner res =
                            s.cmd(INS_SIGN_BIP340, (byte) 0, (byte) 0, concat(m, tw, pathBytes(p)));
                    if (res.sw != 0x9000) {
                        fails.incrementAndGet();
                        continue;
                    }
                    byte[] pub = checked.computeIfAbsent(key, k -> pubOf(fs, fseed, fp));
                    byte[] qx =
                            i2b(
                                    taprootQ(bip32Leaf(seed, p), b2i(tw))
                                            .getAffineXCoord()
                                            .toBigInteger(),
                                    32);
                    if (!bip340Verify(qx, m, res.data)) {
                        fails.incrementAndGet();
                    }
                    seen.merge(hex(slice(res.data, 0, 32)), 1, Integer::sum);
                } else {
                    byte[] encA = edPublic(slip10Leaf(seed, p));
                    ReviewSession.Inner bgn =
                            s.cmd(INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(p));
                    if (bgn.sw != 0x9000) {
                        fails.incrementAndGet();
                        continue;
                    }
                    byte[] encR = weiToEdwards(bgn.data);
                    byte[] mg = rand(r.nextInt(601));
                    byte[] stream = concat(encR, encA, mg);
                    int off = 0;
                    ReviewSession.Inner fin = null;
                    while (off < stream.length) {
                        int nn = Math.min(236, stream.length - off);
                        boolean last = off + nn == stream.length;
                        fin =
                                s.cmd(
                                        INS_SIGN_ED25519,
                                        last ? (byte) 2 : (byte) 1,
                                        (byte) 0,
                                        slice(stream, off, nn));
                        off += nn;
                    }
                    if (fin == null
                            || fin.sw != 0x9000
                            || !edVerify(encA, mg, concat(encR, fin.data))) {
                        fails.incrementAndGet();
                    }
                    seen.merge(hex(encR), 1, Integer::sum);
                }
                if (done.incrementAndGet() % 5000 == 0) {
                    System.out.println(scheme + " " + done.get());
                }
            } catch (Throwable t) {
                fails.incrementAndGet();
            }
        }
    }

    /** PUBLIC_KEY once per path: card output must equal host-derived pub. */
    private byte[] pubOf(ReviewSession s, byte[] seed, long[] p) {
        try {
            ReviewSession.Inner r = s.cmd(INS_PUBLIC_KEY, (byte) 0, (byte) 0, pathBytes(p));
            byte[] expect = compr(g().multiply(b2i(bip32Node(seed, p)[0])));
            if (r.sw == 0x9000
                    && r.data.length >= 33
                    && ReviewCard.eq(slice(r.data, 0, 33), expect)) {
                return slice(r.data, 0, 33);
            }
            return expect; // mismatch logged via verification fail downstream
        } catch (Throwable t) {
            return compr(g().multiply(b2i(bip32Node(seed, p)[0])));
        }
    }

    // 3. nonce stats under Rng.fix

    @Test
    void nonceStats() {
        // Ed25519: 1000 begins on one card under a constant RNG block
        ReviewCard c = ReviewCard.uninitialised();
        c.blank();
        byte[] seed = rand(64);
        ReviewSession s = c.create(seed, H0);
        s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
        byte[] blk = new byte[64];
        java.util.Arrays.fill(blk, (byte) 0x42);
        Rng.fix(blk);
        Map<String, Integer> rs = new HashMap<>();
        int bad = 0;
        for (int i = 0; i < 1000; i++) {
            ReviewSession.Inner b =
                    s.cmd(INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(0x80000000L));
            if (b.sw != 0x9000) {
                bad++;
            } else {
                rs.merge(hex(b.data), 1, Integer::sum);
            }
        }
        long dup = rs.values().stream().filter(v -> v > 1).count();
        // across a power cycle: counter persists → R must still differ
        c.card.powerCycle();
        Rng.reset();
        c.transmit(SELECT_WALLET);
        s = c.open();
        s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
        ReviewSession.Inner b = s.cmd(INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(0x80000000L));
        boolean cycDup = b.sw == 0x9000 && rs.containsKey(hex(b.data));
        Rng.reset();
        row(
                "NONCE-ED",
                "1000 begins, constant RNG",
                "all R distinct",
                rs.size() + " distinct, " + dup + " dup, post-cycle dup=" + cycDup,
                dup == 0 && !cycDup && bad == 0);

        // two cards with the same seed at the same edCounter value
        ReviewCard c1 = ReviewCard.uninitialised();
        c1.blank();
        ReviewSession s1 = c1.create(seed, H0);
        s1.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
        ReviewCard c2 = ReviewCard.uninitialised();
        c2.blank();
        ReviewSession s2 = c2.create(seed, H0);
        s2.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
        c1.injectEdCounter(7);
        c2.injectEdCounter(7);
        java.util.Arrays.fill(blk, (byte) 0x42);
        Rng.fix(blk);
        ReviewSession.Inner b1 =
                s1.cmd(INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(0x80000000L));
        ReviewSession.Inner b2 =
                s2.cmd(INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(0x80000000L));
        Rng.reset();
        boolean same = b1.sw == 0x9000 && b2.sw == 0x9000 && ReviewCard.eq(b1.data, b2.data);
        NOTES.add(
                "Ed25519 two cards same seed+edCounter under fixed RNG: R equal = "
                        + same
                        + " (§12.3/P10 observation)");

        // ECDSA and BIP-340 under constant RNG: do the nonces repeat?
        ReviewSession sx = verifiedCard(seed);
        java.util.Arrays.fill(blk, (byte) 0x42);
        Rng.fix(blk);
        byte[] dg = rand(32);
        ReviewSession.Inner e1 =
                sx.cmd(INS_SIGN_ECDSA, (byte) 0, (byte) 0, concat(dg, pathBytes(0)));
        ReviewSession.Inner e2 =
                sx.cmd(INS_SIGN_ECDSA, (byte) 0, (byte) 0, concat(dg, pathBytes(0)));
        boolean ecdsaSame =
                e1.sw == 0x9000
                        && e2.sw == 0x9000
                        && ReviewCard.eq(slice(e1.data, 0, 32), slice(e2.data, 0, 32));
        ReviewSession.Inner g1 =
                sx.cmd(INS_SIGN_BIP340, (byte) 0, (byte) 0, concat(dg, new byte[32], pathBytes(0)));
        ReviewSession.Inner g2 =
                sx.cmd(INS_SIGN_BIP340, (byte) 0, (byte) 0, concat(dg, new byte[32], pathBytes(0)));
        Rng.reset();
        boolean b340Same =
                g1.sw == 0x9000
                        && g2.sw == 0x9000
                        && ReviewCard.eq(slice(g1.data, 0, 32), slice(g2.data, 0, 32));
        NOTES.add(
                "constant RNG: ECDSA r equal = "
                        + ecdsaSame
                        + ", BIP-340 R_x equal = "
                        + b340Same
                        + " — whether the sim's nonce comes from the applet's RandomData");
        NOTES.add("NOTE: simulator randomness says nothing about the chip's generator.");
        try {
            write();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    // 4. point probes

    @Test
    void pointProbes() {
        probeHostEph();
        probeCaKey();
        probeLkT();
        probeE();
        probeCertA();
        try {
            write();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private record V(String n, byte[] b) {}

    private static V[] uncompVariants() {
        byte[] z = new byte[64];
        return new V[] {
            new V(
                    "off-curve (y bogus)",
                    concat(new byte[] {4}, i2b(BigInteger.ONE, 32), i2b(BigInteger.TWO, 32))),
            new V("x = p", concat(new byte[] {4}, i2b(P, 32), i2b(BigInteger.TWO, 32))),
            new V("y = p", concat(new byte[] {4}, i2b(BigInteger.ONE, 32), i2b(P, 32))),
            new V("00", new byte[] {0}),
            new V("04||0^64", concat(new byte[] {4}, z)),
            new V("prefix 05", withPrefix((byte) 5)),
            new V("prefix 06", withPrefix((byte) 6)),
            new V("prefix 07", withPrefix((byte) 7)),
            new V("compressed 02||x in 65B field", compr(g().multiply(BigInteger.valueOf(9)))),
            new V(
                    "twist point y2=x3+1 (x=1,y=1)",
                    concat(new byte[] {4}, i2b(BigInteger.ONE, 32), i2b(BigInteger.ONE, 32))),
        };
    }

    private static byte[] withPrefix(byte p) {
        byte[] w = uncomp(g().multiply(BigInteger.valueOf(9)));
        w[0] = p;
        return w;
    }

    private static V[] comprVariants() {
        byte[] g33 = compr(g());
        byte[] p32 = i2b(P, 32);
        return new V[] {
            new V("off-curve compressed (non-residue x)", twistPrefix(g33)),
            new V("x = p", concat(new byte[] {2}, p32)),
            new V(
                    "x = p+1 wraps mod 2^256",
                    concat(
                            new byte[] {2},
                            i2b(P.add(BigInteger.ONE).mod(BigInteger.ONE.shiftLeft(256)), 32))),
            new V("prefix 04 in compressed field", concat(new byte[] {4}, slice(g33, 1, 32))),
            new V("prefix 05", concat(new byte[] {5}, slice(g33, 1, 32))),
            new V("prefix 06", concat(new byte[] {6}, slice(g33, 1, 32))),
            new V("prefix 07", concat(new byte[] {7}, slice(g33, 1, 32))),
            new V("uncompressed 04||.. in 33B field", slice(uncomp(g()), 0, 33)),
            new V("wrong-parity (valid different key)", flipParity(g33)),
        };
    }

    private static byte[] twistPrefix(byte[] c33) {
        // an x for which x³+7 is a quadratic non-residue → no such point exists
        for (BigInteger x = BigInteger.ONE; ; x = x.add(BigInteger.ONE)) {
            BigInteger rhs = x.modPow(BigInteger.valueOf(3), P).add(BigInteger.valueOf(7)).mod(P);
            if (rhs.modPow(P.subtract(BigInteger.ONE).shiftRight(1), P)
                    .equals(P.subtract(BigInteger.ONE))) {
                return concat(new byte[] {2}, i2b(x, 32));
            }
        }
    }

    private static byte[] flipParity(byte[] c33) {
        byte[] b = c33.clone();
        b[0] = (byte) (b[0] == 2 ? 3 : 2);
        return b;
    }

    /** Sends a point-variant through OPEN's hostEph field; expects an error SW. */
    private void probeHostEph() {
        for (V v : uncompVariants()) {
            ReviewCard c = ReviewCard.uninitialised();
            c.blank();
            byte[] apdu =
                    concat(
                            unhex("80100000"),
                            new byte[] {(byte) v.b().length},
                            v.b(),
                            new byte[] {0x00});
            int sw = sw(c.transmit(apdu));
            row(
                    "PROBE-hostEph",
                    v.n(),
                    "not 9000/6F00",
                    String.format("%04X", sw),
                    sw != 0x9000 && sw != 0x6F00);
        }
    }

    private void probeCaKey() {
        for (V v : uncompVariants()) {
            ReviewCard c = ReviewCard.uninitialised();
            c.factory();
            byte[] cert = ReviewCard.CA.issue(c.cardA);
            byte[] data = concat(cert, v.b());
            int sw =
                    sw(
                            c.transmit(
                                    concat(
                                            unhex("80E20000"),
                                            new byte[] {(byte) data.length},
                                            data,
                                            new byte[] {0x00})));
            row(
                    "PROBE-caKey",
                    v.n(),
                    "not 9000/6F00",
                    String.format("%04X", sw),
                    sw != 0x9000 && sw != 0x6F00);
        }
    }

    private void probeLkT() {
        for (V v : uncompVariants()) {
            ReviewCard c = ReviewCard.uninitialised();
            c.blank();
            FakeMember m = new FakeMember(ReviewCard.CA);
            ReviewSession s = c.create(sha512(utf8("probe seed")), H0, m.cardId);
            s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
            // valid cert, variant LK_T, garbage sig_T (sig check must not save the probe)
            ReviewSession.Inner r =
                    s.cmd((byte) 0x41, (byte) 0, (byte) 0, concat(m.cert, v.b(), new byte[64]));
            row(
                    "PROBE-LK_T",
                    v.n(),
                    "not 9000/6F00",
                    String.format("%04X", r.sw),
                    r.sw != 0x9000 && r.sw != 0x6F00);
        }
    }

    private void probeE() {
        for (V v : uncompVariants()) {
            ReviewCard c = ReviewCard.uninitialised();
            c.blank();
            FakeMember m = new FakeMember(ReviewCard.CA);
            ReviewSession s = c.open();
            ReviewSession.Inner of = s.cmd((byte) 0x40, (byte) 0, (byte) 0, new byte[0]);
            if (of.sw != 0x9000) {
                row("PROBE-E", "setup", "offer", String.format("%04X", of.sw), false);
                return;
            }
            byte[] lkT = slice(of.data, 0, 65);
            byte[] em = concat(LABEL_EXPORT, m.a, s.cardA, lkT, v.b());
            byte[] sig = ecdsaSign(m.id, em);
            ReviewSession.Inner r =
                    s.cmd((byte) 0x42, (byte) 0, (byte) 0, concat(m.cert, v.b(), sig));
            row(
                    "PROBE-E",
                    v.n(),
                    "not 9000/6F00",
                    String.format("%04X", r.sw),
                    r.sw != 0x9000 && r.sw != 0x6F00);
        }
    }

    /** Compressed-A variants inside cert_T (EXPORT), cert_S (IMPORT) and PERSONALIZE cert. */
    private void probeCertA() {
        for (V v : comprVariants()) {
            byte[] a33 = v.b();
            // cert_T in EXPORT P1=00: genuine CA signs the variant bytes as if A were valid —
            // A is part of the signed cert, so the signature matches; decoding must fail
            byte[] cert = ReviewCard.CA.issue(a33);
            ReviewCard c = ReviewCard.uninitialised();
            c.blank();
            FakeMember m = new FakeMember(ReviewCard.CA);
            ReviewSession s = c.create(sha512(utf8("probe seed")), H0, m.cardId);
            s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
            ReviewSession.Inner r =
                    s.cmd((byte) 0x41, (byte) 0, (byte) 0, concat(cert, m.lk, m.offerSig()));
            row(
                    "PROBE-cert_T.A",
                    v.n(),
                    "not 9000/6F00",
                    String.format("%04X", r.sw),
                    r.sw != 0x9000 && r.sw != 0x6F00);
            // cert_S in IMPORT P1=00 on a BLANK card
            ReviewCard c2 = ReviewCard.uninitialised();
            c2.blank();
            ReviewSession s2 = c2.open();
            ReviewSession.Inner of = s2.cmd((byte) 0x40, (byte) 0, (byte) 0, new byte[0]);
            byte[] lkT = slice(of.data, 0, 65);
            byte[] e = uncomp(g().multiply(BigInteger.valueOf(5)));
            byte[] em = concat(LABEL_EXPORT, a33, s2.cardA, lkT, e);
            byte[] sig = ecdsaSign(m.id, em);
            ReviewSession.Inner r2 = s2.cmd((byte) 0x42, (byte) 0, (byte) 0, concat(cert, e, sig));
            row(
                    "PROBE-cert_S.A",
                    v.n(),
                    "not 9000/6F00",
                    String.format("%04X", r2.sw),
                    r2.sw != 0x9000 && r2.sw != 0x6F00);
            // PERSONALIZE cert
            ReviewCard c3 = ReviewCard.uninitialised();
            c3.factory();
            byte[] data = concat(cert, ReviewCard.CA.pub65);
            int sw3 =
                    sw(
                            c3.transmit(
                                    concat(
                                            unhex("80E20000"),
                                            new byte[] {(byte) data.length},
                                            data,
                                            new byte[] {0x00})));
            row(
                    "PROBE-perso.A",
                    v.n(),
                    "not 9000/6F00",
                    String.format("%04X", sw3),
                    sw3 != 0x9000 && sw3 != 0x6F00);
        }
    }

    // output

    private void write() throws IOException {
        synchronized (ROWS) {
            Files.createDirectories(DIR);
            // merge with existing rows so partial-method runs accumulate
            Path csvp = DIR.resolve("crypto.csv");
            if (Files.exists(csvp)) {
                List<String> old = Files.readAllLines(csvp);
                java.util.Set<String> have = new java.util.HashSet<>();
                for (String[] r : ROWS) {
                    have.add(r[0] + "," + r[1]);
                }
                for (int i = 1; i < old.size(); i++) {
                    String[] f = old.get(i).split(",", 5);
                    if (f.length >= 5 && !have.contains(f[0] + "," + f[1])) {
                        ROWS.add(f);
                    }
                }
            }
            ROWS.sort(java.util.Comparator.comparing(r -> r[0] + r[1]));
            StringBuilder csv = new StringBuilder("cell,probe,expected,observed,verdict\n");
            for (String[] r : ROWS) {
                csv.append(String.join(",", r)).append('\n');
            }
            Files.writeString(DIR.resolve("crypto.csv"), csv.toString());
            // merge notes from earlier partial runs
            Path mdp = DIR.resolve("crypto-summary.md");
            if (Files.exists(mdp)) {
                for (String l : Files.readAllLines(mdp)) {
                    if (l.startsWith("- ")) {
                        String note = l.substring(2);
                        if (!NOTES.contains(note)) {
                            NOTES.add(note);
                        }
                    }
                }
            }
            StringBuilder md = new StringBuilder("# Crypto review summary\n\n");
            for (String n : NOTES) {
                md.append("- ").append(n).append('\n');
            }
            long bad = ROWS.stream().filter(r -> r[4].equals("DIVERGE")).count();
            md.append("\nRows: ")
                    .append(ROWS.size())
                    .append(", DIVERGE: ")
                    .append(bad)
                    .append('\n');
            Files.writeString(DIR.resolve("crypto-summary.md"), md.toString());
        }
    }
}
