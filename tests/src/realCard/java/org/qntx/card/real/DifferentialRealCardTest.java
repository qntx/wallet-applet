// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.qntx.card.host.Bip32;
import org.qntx.card.host.Bip340;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Ecdsa;
import org.qntx.card.host.Ed25519;
import org.qntx.card.host.Paths;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Slip10;
import org.qntx.card.host.Wei25519Map;
import org.qntx.card.tests.Vecs;

/**
 * The differential run of architecture.md §10: {@code qntx.realcard.differential} signatures per
 * scheme (default 1,000) on the LOADED test-seed wallet, random paths inside randomised family
 * templates and depths, all three BIP-340 tweak kinds and the §12.3 message expansion for Ed25519.
 * Every signature is verified in-test against the host-derived key (from {@code Vecs.seed()}, never
 * the card's PUBLIC_KEY) and written to {@code signatures.json} in the {@code
 * spec/vectors/gen/ts/verify.ts} format for the noble cross-check.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
final class DifferentialRealCardTest {
    private static final SecureRandom RND = Vecs.RND;
    private static final HexFormat HEX = HexFormat.of();

    /** secp256k1 family prefixes the random paths grow from (the wallet templates, §9.2). */
    private static final String[] SECP_FAMILIES = {
        "m/44'/60'", "m/44'/195'", "m/84'", "m/86'", "m/44'/1237'", "m/48'/0'/0'/2'", "m/0'"
    };

    /** ed25519 prefixes — hardened only (§10.4). */
    private static final String[] ED_FAMILIES = {"m/44'/501'", "m/44'/1237'", "m/0'"};

    private Session session;

    /** A verified session, reopened when the previous one ended (§8.5). */
    private Session session() throws Exception {
        if (session == null || session.closed()) {
            session = Fixture.verified();
        }
        return session;
    }

    private Response inner(int ins, int p1, byte[] data) throws Exception {
        return Fixture.cmd(session(), ins, p1, 0, data);
    }

    private static String randomSecpPath() {
        StringBuilder p = new StringBuilder(SECP_FAMILIES[RND.nextInt(SECP_FAMILIES.length)]);
        int extra = RND.nextInt(3);
        for (int i = 0; i <= extra; i++) {
            long index = RND.nextInt(1 << 20);
            boolean hardened = RND.nextBoolean();
            p.append('/').append(index);
            if (hardened) {
                p.append('\'');
            }
        }
        return p.toString();
    }

    private static String randomEdPath() {
        StringBuilder p = new StringBuilder(ED_FAMILIES[RND.nextInt(ED_FAMILIES.length)]);
        int extra = RND.nextInt(3);
        for (int i = 0; i <= extra; i++) {
            p.append('/').append(RND.nextInt(1 << 20)).append('\'');
        }
        return p.toString();
    }

    /** The §12.3 message expansion: SHA-512(seed ‖ u32be(i)) blocks, truncated. */
    private static byte[] expandMessage(byte[] seed, int length) {
        byte[] out = new byte[length];
        for (int i = 0, have = 0; have < length; i++, have += 64) {
            byte[] ctr = {(byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i};
            byte[] block = Crypto.sha512(seed, ctr);
            System.arraycopy(block, 0, out, have, Math.min(64, length - have));
        }
        return out;
    }

    @Test
    @Order(1)
    void differentialSignatures() throws Exception {
        Fixture.require();
        Fixture.ensureLoaded();
        int n = Fixture.differential();
        List<Map<String, Object>> ecdsa = new ArrayList<>();
        List<Map<String, Object>> bip340 = new ArrayList<>();
        List<Map<String, Object>> ed25519 = new ArrayList<>();
        byte[] seed = Vecs.seed();
        for (int i = 0; i < n; i++) {
            // ECDSA: random family path and depth, random digest
            String path = randomSecpPath();
            byte[] wire = Paths.wire(path);
            byte[] pub33 = Bip32.derive(seed, path).publicKey();
            byte[] digest = new byte[32];
            RND.nextBytes(digest);
            byte[] data = new byte[32 + wire.length];
            System.arraycopy(digest, 0, data, 0, 32);
            System.arraycopy(wire, 0, data, 32, wire.length);
            Response r = inner(0x31, 0, data);
            assertEquals(0x9000, r.sw(), "SIGN_ECDSA " + path);
            assertEquals(64, r.data().length);
            byte[] pub65 = Crypto.decompress(pub33);
            assertTrue(Ecdsa.verify(pub65, digest, r.data()), "ECDSA verify " + path);
            ecdsa.add(
                    Map.of(
                            "publicKey", HEX.formatHex(pub33),
                            "digest", HEX.formatHex(digest),
                            "signature", HEX.formatHex(r.data())));
        }
        for (int i = 0; i < n; i++) {
            // BIP340: zero, random or BIP-86 tweak (equal thirds)
            String path = randomSecpPath();
            byte[] wire = Paths.wire(path);
            byte[] pub65 = Crypto.decompress(Bip32.derive(seed, path).publicKey());
            byte[] tweak;
            switch (i % 3) {
                case 0 -> tweak = new byte[32];
                case 1 -> {
                    tweak = new byte[32];
                    RND.nextBytes(tweak);
                    if (new java.math.BigInteger(1, tweak).compareTo(Crypto.N) >= 0) {
                        tweak[0] = 0;
                    }
                }
                default -> tweak = Bip340.taggedHash("TapTweak", xOf(pub65));
            }
            byte[] output = Bip340.outputKey(pub65, tweak);
            byte[] message = new byte[32];
            RND.nextBytes(message);
            byte[] data = new byte[64 + wire.length];
            System.arraycopy(message, 0, data, 0, 32);
            System.arraycopy(tweak, 0, data, 32, 32);
            System.arraycopy(wire, 0, data, 64, wire.length);
            Response r = inner(0x32, 0, data);
            assertEquals(0x9000, r.sw(), "SIGN_BIP340 " + path);
            assertEquals(64, r.data().length);
            assertTrue(Bip340.verify(output, message, r.data()), "BIP340 verify " + path);
            bip340.add(
                    Map.of(
                            "outputKey", HEX.formatHex(output),
                            "message", HEX.formatHex(message),
                            "signature", HEX.formatHex(r.data())));
        }
        for (int i = 0; i < n; i++) {
            // Ed25519: §12.3 message expansion, random length and chunk sizes
            String path = randomEdPath();
            byte[] wire = Paths.wire(path);
            byte[] leaf = Slip10.derive(seed, path).privateKey();
            byte[] encodedA = Wei25519Map.encode(Slip10.wei(leaf));
            byte[] messageSeed = new byte[32];
            RND.nextBytes(messageSeed);
            int length = RND.nextInt(4097);
            byte[] message = expandMessage(messageSeed, length);
            Response begin = inner(0x33, 0, wire);
            assertEquals(0x9000, begin.sw(), "ed begin " + path);
            byte[] encodedR = Wei25519Map.encode(begin.data());
            byte[] stream = Ed25519.stream(encodedR, encodedA, message);
            int off = 0;
            while (stream.length - off > 236) {
                int chunk = Math.min(1 + RND.nextInt(236), stream.length - off);
                Response u = inner(0x33, 1, Arrays.copyOfRange(stream, off, off + chunk));
                assertEquals(0x9000, u.sw(), "ed update " + path);
                off += chunk;
            }
            Response fin = inner(0x33, 2, Arrays.copyOfRange(stream, off, stream.length));
            assertEquals(0x9000, fin.sw(), "ed finish " + path);
            byte[] sig = Ed25519.signature(encodedR, fin.data());
            assertTrue(Ed25519.verify(encodedA, message, sig), "ed25519 verify " + path);
            ed25519.add(
                    Map.of(
                            "publicKey", HEX.formatHex(encodedA),
                            "messageSeed", HEX.formatHex(messageSeed),
                            "messageLength", length,
                            "signature", HEX.formatHex(sig)));
        }
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("ecdsa", ecdsa);
        doc.put("bip340", bip340);
        doc.put("ed25519", ed25519);
        Files.writeString(
                Fixture.out().resolve("signatures.json"),
                com.fasterxml.jackson.jr.ob.JSON.std.asString(doc));
    }

    private static byte[] xOf(byte[] pub65) {
        return Arrays.copyOfRange(pub65, 1, 33);
    }
}
