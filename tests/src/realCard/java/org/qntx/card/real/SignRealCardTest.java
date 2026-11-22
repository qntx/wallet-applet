// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.qntx.card.host.Bip340;
import org.qntx.card.host.Ecdsa;
import org.qntx.card.host.Ed25519;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Wei25519Map;
import org.qntx.card.tests.Vecs;

/**
 * The signing commands on card A (§9.9–§9.11). The platform RNG is real, so exact vector signatures
 * cannot be reproduced; every produced signature is verified against the vector's/host's own key
 * material (§12, architecture §10) — the same check the card's self-verification gates on. Includes
 * the {@code Lc = 248} receive case (a 236-byte inner chunk is the largest record that fits).
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
final class SignRealCardTest {
    private Session session;
    private final Set<String> rPoints = new HashSet<>();

    private void verified() throws Exception {
        Fixture.ensureLoaded();
        session = Fixture.verified();
    }

    private Response inner(int ins, int p1, byte[] data) throws Exception {
        return Fixture.cmd(session, ins, p1, 0, data);
    }

    @Test
    @Order(1)
    void signCommandsNeedALoadedVerifiedCard() throws Exception {
        Fixture.require();
        Fixture.ensureLoaded();
        session = Fixture.open();
        byte[] digest = new byte[32];
        Vecs.RND.nextBytes(digest);
        byte[] ecdsa = new byte[32 + Vecs.pathSecpEvm().length];
        System.arraycopy(digest, 0, ecdsa, 0, 32);
        System.arraycopy(Vecs.pathSecpEvm(), 0, ecdsa, 32, Vecs.pathSecpEvm().length);
        assertEquals(0x6982, inner(0x31, 0, ecdsa).sw(), "SIGN_ECDSA unverified");
        assertEquals(0x6982, inner(0x32, 0, new byte[64]).sw(), "SIGN_BIP340 unverified");
        assertEquals(0x6982, inner(0x33, 0, Vecs.pathEdSolana()).sw(), "ed begin unverified");
        Fixture.verify(session);
        assertEquals(0x6A86, inner(0x31, 1, ecdsa).sw(), "SIGN_ECDSA P1");
        assertEquals(0x6A86, inner(0x32, 3, new byte[64]).sw(), "SIGN_BIP340 P1");
        assertEquals(0x6A86, inner(0x33, 3, Vecs.pathEdSolana()).sw(), "ed P1 range");
        assertEquals(0x6985, inner(0x33, 1, new byte[8]).sw(), "update without a stream");
        assertEquals(0x6985, inner(0x33, 2, new byte[0]).sw(), "finish without a stream");
        session.close();
    }

    @Test
    @Order(2)
    void ecdsaSignaturesVerifyUnderTheVectorKeys() throws Exception {
        Fixture.require();
        verified();
        for (Map<String, Object> c : Vecs.list(Vecs.load("ecdsa.json"), "cases")) {
            byte[] digest = Vecs.hex(c, "digest");
            byte[] wire = Vecs.hex(c, "wire");
            byte[] pub = Vecs.hex(c, "publicKeyUncompressed");
            // the card's PUBLIC_KEY agrees with the vector's key
            Response p = inner(0x30, 0, wire);
            assertEquals(0x9000, p.sw(), (String) c.get("name") + " publicKey");
            assertArrayEquals(Vecs.hex(c, "publicKey"), Arrays.copyOf(p.data(), 33));
            byte[] data = new byte[32 + wire.length];
            System.arraycopy(digest, 0, data, 0, 32);
            System.arraycopy(wire, 0, data, 32, wire.length);
            Response r = inner(0x31, 0, data);
            assertEquals(0x9000, r.sw(), (String) c.get("name"));
            byte[] sig = r.data();
            assertEquals(64, sig.length);
            assertTrue(Ecdsa.verify(pub, digest, sig), (String) c.get("name"));
            assertNotEquals(-1, Ecdsa.recoveryId(pub, digest, sig), (String) c.get("name"));
            byte[] low = Ecdsa.lowS(sig);
            assertTrue(Ecdsa.verify(pub, digest, low), (String) c.get("name") + " low-s");
        }
        session.close();
    }

    @Test
    @Order(3)
    void bip340SignaturesVerifyUnderTheVectorOutputKeys() throws Exception {
        Fixture.require();
        verified();
        Map<String, Object> doc = Vecs.load("bip340.json");
        for (Map<String, Object> c : Vecs.list(doc, "cases")) {
            byte[] message = Vecs.hex(c, "message");
            byte[] tweak = Vecs.hex(c, "tweak");
            byte[] wire = Vecs.hex(c, "wire");
            byte[] data = new byte[64 + wire.length];
            System.arraycopy(message, 0, data, 0, 32);
            System.arraycopy(tweak, 0, data, 32, 32);
            System.arraycopy(wire, 0, data, 64, wire.length);
            Response r = inner(0x32, 0, data);
            assertEquals(0x9000, r.sw(), (String) c.get("name"));
            assertEquals(64, r.data().length);
            assertTrue(
                    Bip340.verify(Vecs.hex(c, "outputKey"), message, r.data()),
                    (String) c.get("name"));
        }
        // int(tweak) ≥ n must be refused before any signing happens (§9.10)
        for (Map<String, Object> c : Vecs.list(doc, "invalidTweak")) {
            byte[] tweak = Vecs.hex(c, "tweak");
            byte[] wire = null;
            for (Map<String, Object> e : Vecs.list(doc, "cases")) {
                if (e.get("path").equals(c.get("path"))) {
                    wire = Vecs.hex(e, "wire");
                }
            }
            byte[] data = new byte[64 + wire.length];
            System.arraycopy(Vecs.message(), 0, data, 0, 32);
            System.arraycopy(tweak, 0, data, 32, 32);
            System.arraycopy(wire, 0, data, 64, wire.length);
            assertEquals(0x6A80, inner(0x32, 0, data).sw(), (String) c.get("name"));
        }
        session.close();
    }

    @Test
    @Order(4)
    void bip86SignsUnderThePublishedOutputKeys() throws Exception {
        Fixture.require();
        // the official BIP-86 account needs the vector's own seed: one CREATE cycle
        Map<String, Object> bip86 = Vecs.obj(Vecs.load("bip340.json"), "bip86");
        Fixture.ensureLoaded();
        Session e = Fixture.verified();
        Fixture.erase(e);
        session = Fixture.open();
        byte[] create = new byte[96];
        System.arraycopy(Vecs.accessHash(), 0, create, 0, 32);
        System.arraycopy(Vecs.hex(bip86, "seed"), 0, create, 32, 64);
        assertEquals(0x9000, inner(0x21, 1, create).sw(), "CREATE bip86 seed");
        Fixture.ensureFactoryField(Fixture.Life.LOADED);
        for (Map<String, Object> k : Vecs.list(bip86, "keys")) {
            byte[] wire = Vecs.hex(k, "wire");
            byte[] data = new byte[64 + wire.length];
            System.arraycopy(Vecs.message(), 0, data, 0, 32);
            System.arraycopy(Vecs.hex(k, "tweak"), 0, data, 32, 32);
            System.arraycopy(wire, 0, data, 64, wire.length);
            Response r = inner(0x32, 0, data);
            assertEquals(0x9000, r.sw(), (String) k.get("path"));
            assertTrue(
                    Bip340.verify(Vecs.hex(k, "outputKey"), Vecs.message(), r.data()),
                    (String) k.get("path"));
        }
        session.close();
        // restore the test seed for the following suites
        Fixture.ensureFactoryField(Fixture.Life.LOADED);
        Fixture.ensureLoaded();
    }

    @Test
    @Order(5)
    void ed25519SignaturesVerifyForEveryCase() throws Exception {
        Fixture.require();
        verified();
        for (Map<String, Object> c : Vecs.list(Vecs.load("ed25519.json"), "cases")) {
            byte[] wire = Vecs.hex(c, "wire");
            byte[] message = Vecs.hex(c, "message");
            // PUBLIC_KEY gives W(A); the host encoding is the RFC 8032 public key
            Response p = inner(0x30, 1, wire);
            assertEquals(0x9000, p.sw(), (String) c.get("name") + " publicKey");
            assertArrayEquals(Vecs.hex(c, "wei"), p.data(), (String) c.get("name") + " wei");
            byte[] encodedA = Wei25519Map.encode(p.data());
            assertArrayEquals(
                    Vecs.hex(c, "publicKey"), encodedA, (String) c.get("name") + " encoded A");
            signEd(wire, encodedA, message, 236);
        }
        session.close();
    }

    @Test
    @Order(6)
    void ed25519ChunkBoundaries() throws Exception {
        Fixture.require();
        verified();
        Map<String, Object> c = Vecs.list(Vecs.load("ed25519.json"), "cases").get(2);
        byte[] wire = Vecs.hex(c, "wire");
        byte[] encodedA = Wei25519Map.encode(inner(0x30, 1, wire).data());
        // one-byte updates — every record boundary is exercised
        signEd(wire, encodedA, Vecs.hex(c, "message"), 1);
        // a maximal 236-byte update chunk plus a finish that carries the tail
        byte[] long255 = new byte[3 * 236 + 37];
        Vecs.RND.nextBytes(long255);
        signEd(wire, encodedA, long255, 236);
        // an empty finish: the whole stream inside update chunks
        byte[] exact = new byte[2 * 236];
        Vecs.RND.nextBytes(exact);
        Response begin = inner(0x33, 0, wire);
        assertEquals(0x9000, begin.sw());
        byte[] encodedR = Wei25519Map.encode(begin.data());
        rPoints.add(java.util.HexFormat.of().formatHex(encodedR));
        byte[] stream = Ed25519.stream(encodedR, encodedA, exact);
        int off = 0;
        while (stream.length - off > 0) {
            int len = Math.min(236, stream.length - off);
            Response r = inner(0x33, 1, Arrays.copyOfRange(stream, off, off + len));
            assertEquals(0x9000, r.sw(), "update at " + off);
            off += len;
        }
        Response fin = inner(0x33, 2, new byte[0]);
        assertEquals(0x9000, fin.sw(), "empty finish");
        byte[] sig = Ed25519.signature(encodedR, fin.data());
        assertTrue(Ed25519.verify(encodedA, exact, sig), "empty-finish signature");
        session.close();
    }

    @Test
    @Order(7)
    void ed25519NoncesAreDistinct() {
        Fixture.require();
        // every begin the run produced must carry a different R (§12.3 hedged nonce)
        assertTrue(rPoints.size() >= 6, "collected " + rPoints.size() + " R points");
    }

    /** begin ‖ 236-byte updates ‖ finish, then RFC 8032 verification of the joined signature. */
    private void signEd(byte[] wire, byte[] encodedA, byte[] message, int chunk) throws Exception {
        Response begin = inner(0x33, 0, wire);
        assertEquals(0x9000, begin.sw(), "begin");
        assertEquals(64, begin.data().length);
        byte[] encodedR = Wei25519Map.encode(begin.data());
        rPoints.add(java.util.HexFormat.of().formatHex(encodedR));
        byte[] stream = Ed25519.stream(encodedR, encodedA, message);
        int off = 0;
        while (stream.length - off > 236 || (off == 0 && chunk != 236)) {
            int len = Math.min(chunk, stream.length - off);
            if (len <= 0) {
                break;
            }
            Response r = inner(0x33, 1, Arrays.copyOfRange(stream, off, off + len));
            assertEquals(0x9000, r.sw(), "update at " + off);
            assertEquals(0, r.data().length);
            off += len;
        }
        Response fin = inner(0x33, 2, Arrays.copyOfRange(stream, off, stream.length));
        assertEquals(0x9000, fin.sw(), "finish");
        assertEquals(32, fin.data().length);
        byte[] sig = Ed25519.signature(encodedR, fin.data());
        assertTrue(Ed25519.verify(encodedA, message, sig), "signature verifies");
    }
}
