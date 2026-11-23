// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;
import javacard.framework.Applet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Bip340;
import org.qntx.card.host.Ecdsa;
import org.qntx.card.host.Ed25519;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Wei25519Map;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.sim.Rng;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The signing commands against the committed vectors (architecture §14.4 G1): ECDSA verifies,
 * recovers and low-s-normalises; BIP-340 is exact under a fixed {@code aux}; Ed25519 reproduces the
 * vector {@code W(R)} and {@code le32(S)} byte for byte under a fixed {@code Zr} and counter, over
 * the chunkings the stream protocol allows. Oracles are the vector files plus BouncyCastle — never
 * the applet's own output.
 */
final class SignVectorTest {

    private Card card;
    private Session session;

    @AfterEach
    void disarm() {
        Fault.reset();
        Rng.reset();
    }

    private Applet applet() {
        return card.applet(Spec.WALLET_AID);
    }

    private void verified() throws Exception {
        card = Vecs.blankSelf();
        session = Vecs.loadWallet(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
    }

    private Response inner(int ins, int p1, byte[] data) throws Exception {
        return Vecs.roundtrip(card, session, ins, p1, 0, data);
    }

    /** cert.json's card1/card2 identity private scalar. */
    private static BigInteger identityPrivate(String name) {
        for (Map<String, Object> id : Vecs.list(Vecs.load("cert.json"), "identities")) {
            if (id.get("name").equals(name)) {
                return new BigInteger(1, Vecs.hex(id, "private"));
            }
        }
        throw new IllegalStateException("cert.json lacks identity " + name);
    }

    /** cert.json's card1/card2 identity compressed public key. */
    private static byte[] identityPublic(String name) {
        for (Map<String, Object> id : Vecs.list(Vecs.load("cert.json"), "identities")) {
            if (id.get("name").equals(name)) {
                return Vecs.hex(id, "compressed");
            }
        }
        throw new IllegalStateException("cert.json lacks identity " + name);
    }

    /** A card personalized under the vector identity (its cardId), wallet loaded and verified. */
    private void cardFor(String identity) throws Exception {
        card = Vecs.factory();
        Internals.setIdentity(applet(), identityPrivate(identity));
        session = Vecs.loadWallet(Vecs.blankFor(card, identityPublic(identity)));
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
    }

    /** Pokes the persistent {@code edCounter} — the vector's {@code counter − 1} setup. */
    private void pokeEdCounter(long v) {
        byte[] s = Internals.stateArray(applet());
        for (int i = 0; i < 4; i++) {
            s[State.OFF_EDCOUNTER + 3 - i] = (byte) (v >>> (i * 8));
        }
    }

    @Test
    void ecdsaSignsDigestsThatVerifyRecoverAndNormalise() throws Exception {
        verified();
        for (Map<String, Object> c : Vecs.list(Vecs.load("ecdsa.json"), "cases")) {
            byte[] digest = Vecs.hex(c, "digest");
            byte[] wire = Vecs.hex(c, "wire");
            byte[] pub = Vecs.hex(c, "publicKeyUncompressed");
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
            assertNotEquals(
                    -1, Ecdsa.recoveryId(pub, digest, low), (String) c.get("name") + " low-s");
            // the vector's own pair documents the parity flip of a negated s
            boolean flipped = !Arrays.equals(sig, low);
            int expect = Ecdsa.recoveryId(pub, digest, sig) ^ (flipped ? 1 : 0);
            assertEquals(
                    expect, Ecdsa.recoveryId(pub, digest, low), (String) c.get("name") + " flip");
        }
    }

    @Test
    void bip340SignsTheExactVectorSignatures() throws Exception {
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
            Rng.fix(Vecs.hex(c, "aux"));
            Response r = inner(0x32, 0, data);
            Rng.reset();
            assertEquals(0x9000, r.sw(), (String) c.get("name"));
            assertArrayEquals(Vecs.hex(c, "signature"), r.data(), (String) c.get("name"));
            assertTrue(
                    Bip340.verify(Vecs.hex(c, "outputKey"), message, r.data()),
                    (String) c.get("name"));
        }
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
        // the official BIP-86 account: a card loaded with the vector's own seed signs
        // under each of the three published output keys
        Map<String, Object> bip86 = Vecs.obj(doc, "bip86");
        session = Vecs.open(card = Vecs.blankSelf());
        byte[] create = new byte[96];
        System.arraycopy(Vecs.accessHash(), 0, create, 0, 32);
        System.arraycopy(Vecs.hex(bip86, "seed"), 0, create, 32, 64);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x21, 1, 0, create).sw(), "CREATE");
        session = Vecs.open(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
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
    }

    /** Feeds {@code stream} in {@code sizes} update chunks; the last byte stays for finish. */
    private Response feedStream(byte[] stream, int... sizes) throws Exception {
        int off = 0;
        int i = 0;
        while (stream.length - off > 236 || i < sizes.length) {
            int len = Math.min(i < sizes.length ? sizes[i++] : 236, stream.length - off - 1);
            if (len == 0) {
                continue;
            }
            Response r = inner(0x33, 1, Arrays.copyOfRange(stream, off, off + len));
            assertEquals(0x9000, r.sw(), "update at " + off);
            assertEquals(0, r.data().length);
            off += len;
        }
        return inner(0x33, 2, Arrays.copyOfRange(stream, off, stream.length));
    }

    @Test
    void ed25519StreamsTheExactVectorSignatures() throws Exception {
        Map<String, Object> doc = Vecs.load("ed25519.json");
        // chunk schedules exercise arbitrary splits: the long message takes full 236-byte
        // updates, depth-10 alternates odd sizes and ends mid-chunk
        int[][] schedules = {
            {160}, {60, 100}, {128}, {236, 236, 236, 236, 236, 66}, {160}, {37, 191}
        };
        int i = 0;
        for (Map<String, Object> c : Vecs.list(doc, "cases")) {
            String identity = c.get("name").equals("solana-card2") ? "card2" : "card1";
            cardFor(identity);
            pokeEdCounter(((Number) c.get("counter")).longValue() - 1);
            byte[] message = Vecs.hex(c, "message");
            byte[] encodedA = Vecs.hex(c, "publicKey");
            Rng.fix(Vecs.hex(c, "zr"));
            Response begin = inner(0x33, 0, Vecs.hex(c, "wire"));
            assertEquals(0x9000, begin.sw(), (String) c.get("name"));
            byte[] encodedR = Wei25519Map.encode(begin.data());
            assertArrayEquals(Vecs.hex(c, "encodedR"), encodedR, (String) c.get("name"));
            byte[] stream = Ed25519.stream(encodedR, encodedA, message);
            Response fin = feedStream(stream, schedules[i++ % schedules.length]);
            assertEquals(0x9000, fin.sw(), (String) c.get("name"));
            assertArrayEquals(Vecs.hex(c, "s"), fin.data(), (String) c.get("name"));
            assertArrayEquals(
                    Vecs.hex(c, "signature"),
                    Ed25519.signature(encodedR, fin.data()),
                    (String) c.get("name"));
            assertTrue(
                    Ed25519.verify(encodedA, message, Vecs.hex(c, "signature")),
                    (String) c.get("name") + " verifies");
        }
    }

    @Test
    void ed25519OneByteChunkingReproducesTheVector() throws Exception {
        Map<String, Object> c = Vecs.list(Vecs.load("ed25519.json"), "cases").get(3);
        assertEquals("long-message", c.get("name"));
        cardFor("card1");
        pokeEdCounter(((Number) c.get("counter")).longValue() - 1);
        Rng.fix(Vecs.hex(c, "zr"));
        Response begin = inner(0x33, 0, Vecs.hex(c, "wire"));
        assertEquals(0x9000, begin.sw());
        byte[] encodedR = Wei25519Map.encode(begin.data());
        byte[] stream = Ed25519.stream(encodedR, Vecs.hex(c, "publicKey"), Vecs.hex(c, "message"));
        for (int off = 0; off < stream.length - 1; off++) {
            assertEquals(
                    0x9000,
                    inner(0x33, 1, Arrays.copyOfRange(stream, off, off + 1)).sw(),
                    "byte " + off);
        }
        Response fin = inner(0x33, 2, Arrays.copyOfRange(stream, stream.length - 1, stream.length));
        assertEquals(0x9000, fin.sw());
        assertArrayEquals(Vecs.hex(c, "s"), fin.data());
    }

    @Test
    void ed25519WrongStreamSignsGarbage() throws Exception {
        Map<String, Object> w = Vecs.list(Vecs.load("ed25519.json"), "wrongStream").get(0);
        Map<String, Object> c = null;
        for (Map<String, Object> e : Vecs.list(Vecs.load("ed25519.json"), "cases")) {
            if (e.get("name").equals(w.get("case"))) {
                c = e;
            }
        }
        cardFor("card1");
        pokeEdCounter(((Number) c.get("counter")).longValue() - 1);
        Rng.fix(Vecs.hex(c, "zr"));
        Response begin = inner(0x33, 0, Vecs.hex(c, "wire"));
        assertEquals(0x9000, begin.sw());
        byte[] stream = Vecs.hex(w, "stream");
        Response fin = feedStream(stream, 96, 64);
        assertEquals(0x9000, fin.sw());
        // the card signs whatever stream it was fed (§9.11); the bytes match the vector but the
        // signature is worthless under the card's key
        assertArrayEquals(Vecs.hex(w, "s"), fin.data());
        assertArrayEquals(
                Vecs.hex(w, "signature"),
                Ed25519.signature(Arrays.copyOfRange(stream, 0, 32), fin.data()));
        assertFalse(
                Ed25519.verify(
                        Vecs.hex(c, "publicKey"),
                        Vecs.hex(w, "message"),
                        Vecs.hex(w, "signature")));
    }

    @Test
    void rfc8032AndTheWeiMappingHold() {
        for (Map<String, Object> c : Vecs.list(Vecs.load("ed25519.json"), "rfc8032")) {
            assertArrayEquals(
                    Vecs.hex(c, "publicKey"),
                    Wei25519Map.encode(Vecs.hex(c, "wei")),
                    (String) c.get("name"));
            assertTrue(
                    Ed25519.verify(
                            Vecs.hex(c, "publicKey"),
                            Vecs.hex(c, "message"),
                            Vecs.hex(c, "signature")),
                    (String) c.get("name"));
        }
    }
}
