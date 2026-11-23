// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javacard.framework.Applet;
import javacard.framework.Util;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.AccessCode;
import org.qntx.card.host.Bip32;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Slip10;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * §10.1–§10.4 protocol vectors through the real command path (architecture §14.4 W5): {@code
 * access.json} codes, the {@code wrap.json} wrap pipeline at unit and command level, and {@code
 * derivation.json} BIP-32/SLIP-10 nodes through CREATE + PUBLIC_KEY and through the {@link
 * Derivation} steps directly.
 */
final class VectorTest {

    private Card card;
    private Session session;

    private Applet applet() {
        return card.applet(Spec.WALLET_AID);
    }

    private void loadedWith(byte[] accessHash, byte[] seed) throws Exception {
        card = Vecs.blankSelf();
        session = Vecs.open(card);
        byte[] data = new byte[96];
        System.arraycopy(accessHash, 0, data, 0, 32);
        System.arraycopy(seed, 0, data, 32, 64);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x21, 1, 0, data).sw());
        session = Vecs.open(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, accessHash).sw());
    }

    private Response publicKey(int curve, byte[] wire) throws Exception {
        return Vecs.roundtrip(card, session, 0x30, curve, 0, wire);
    }

    private static byte[] hex(Map<String, Object> obj, String key) {
        return Vecs.hex(obj, key);
    }

    // access.json: valid codes hash with the host, rejected codes throw, and a real code
    // verifies on a card created with hash(code, ID(A)).
    @Test
    void accessJson() throws Exception {
        Map<String, Object> doc = Vecs.load("access.json");
        for (Map<String, Object> c : Vecs.list(doc, "valid")) {
            byte[] cardId = hex(c, "cardId");
            assertArrayEquals(
                    hex(c, "accessHash"),
                    AccessCode.hash((String) c.get("code"), cardId),
                    (String) c.get("name"));
        }
        for (Map<String, Object> c : Vecs.list(doc, "rejected")) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> AccessCode.hash((String) c.get("code"), new byte[16]),
                    (String) c.get("name"));
        }
        // command round trip: CREATE with AccessCode.hash(code, ID(A)) of THIS card
        Map<String, Object> c = Vecs.list(doc, "valid").get(0);
        card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        card = Vecs.blankFor(card, a);
        session = Vecs.open(card);
        byte[] hash = AccessCode.hash((String) c.get("code"), Ids.cardId(a));
        byte[] data = new byte[96];
        System.arraycopy(hash, 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x21, 1, 0, data).sw());
        session = Vecs.open(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, hash).sw());
    }

    // wrap.json: the applet's own wrap pipeline reproduces kEnc, kMac, ct, tag and fp.
    @Test
    void wrapJsonUnit() {
        card = Vecs.blankSelf();
        Applet applet = applet();
        byte[] w = Internals.wBytes(applet);
        byte[] seed = Internals.seedBytes(applet);
        for (Map<String, Object> c : Vecs.list(Vecs.load("wrap.json"), "cases")) {
            Util.arrayFillNonAtomic(w, (short) 0, (short) 224, (byte) 0);
            Util.arrayCopy(hex(c, "accessHash"), (short) 0, w, (short) 0, (short) 32);
            Util.arrayCopy(hex(c, "wrapKey"), (short) 0, w, (short) 64, (short) 16);
            Util.arrayCopy(hex(c, "seed"), (short) 0, seed, (short) 0, (short) 64);
            Internals.invoke(
                    Internals.wallet(applet),
                    "wrap",
                    new Class<?>[] {byte[].class, byte[].class, short.class},
                    w,
                    seed,
                    (short) 0);
            assertArrayEquals(
                    hex(c, "kEnc"), Arrays.copyOfRange(w, 80, 96), c.get("name") + " kEnc");
            assertArrayEquals(
                    hex(c, "kMac"), Arrays.copyOfRange(w, 96, 112), c.get("name") + " kMac");
            assertArrayEquals(hex(c, "ct"), Arrays.copyOfRange(w, 112, 176), c.get("name") + " ct");
            assertArrayEquals(
                    hex(c, "tag"), Arrays.copyOfRange(w, 176, 192), c.get("name") + " tag");
            assertArrayEquals(hex(c, "fp"), Arrays.copyOfRange(w, 192, 224), c.get("name") + " fp");
        }
    }

    // wrap.json command level: swap in the case's wrapKey/ct/tag/fp; the case's accessHash
    // verifies and yields the case seed's master public key; a wrong hash is 63C9.
    @Test
    void wrapJsonCommand() throws Exception {
        for (Map<String, Object> c : Vecs.list(Vecs.load("wrap.json"), "cases")) {
            loadedWith(hex(c, "accessHash"), hex(c, "seed"));
            Applet applet = applet();
            Internals.wrapKey(applet).setKey(hex(c, "wrapKey"), (short) 0);
            byte[] state = Internals.stateArray(applet);
            Util.arrayCopy(hex(c, "fp"), (short) 0, state, State.OFF_FP, (short) 32);
            Util.arrayCopy(hex(c, "ct"), (short) 0, state, State.OFF_CT, (short) 64);
            Util.arrayCopy(hex(c, "tag"), (short) 0, state, State.OFF_TAG, (short) 16);

            session = Vecs.open(card);
            Response r = Vecs.roundtrip(card, session, 0x22, 0, 0, hex(c, "accessHash"));
            assertEquals(0x9000, r.sw(), (String) c.get("name"));
            assertArrayEquals(
                    Bip32.masterPublicKey(hex(c, "seed")),
                    Arrays.copyOf(r.data(), 33),
                    c.get("name") + " master public key");

            session = Vecs.open(card);
            assertEquals(
                    0x63c9, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHashWrong()).sw());
        }
    }

    // derivation.json BIP-32 vectors 2 and 3 and the secp256k1 templates via CREATE P1 = 1
    // and PUBLIC_KEY / WalletInfo.
    @Test
    void bip32Commands() throws Exception {
        Map<String, Object> doc = Vecs.load("derivation.json");
        for (Map<String, Object> v : Vecs.list(doc, "bip32")) {
            if (hex(v, "seed").length != 64) {
                continue;
            }
            byte[] seed = hex(v, "seed");
            loadedWith(Vecs.accessHash(), seed);
            assertArrayEquals(
                    Bip32.masterPublicKey(seed),
                    Arrays.copyOf(
                            Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).data(),
                            33));
            for (Map<String, Object> node : Vecs.list(v, "nodes")) {
                String path = (String) node.get("path");
                if (path.equals("m")) {
                    continue;
                }
                Response r = publicKey(0, Vecs.unhex(wireOf(path)));
                assertEquals(0x9000, r.sw(), path);
                byte[] expected = new byte[65];
                System.arraycopy(hex(node, "publicKey"), 0, expected, 0, 33);
                System.arraycopy(hex(node, "chainCode"), 0, expected, 33, 32);
                assertArrayEquals(expected, r.data(), path);
            }
        }
        byte[] seed = hex(Vecs.obj(doc, "templates"), "seed");
        loadedWith(Vecs.accessHash(), seed);
        for (Map<String, Object> t : Vecs.list(Vecs.obj(doc, "templates"), "secp256k1")) {
            Response r = publicKey(0, hex(t, "wire"));
            assertEquals(0x9000, r.sw(), (String) t.get("name"));
            byte[] expected = new byte[65];
            System.arraycopy(hex(t, "publicKey"), 0, expected, 0, 33);
            System.arraycopy(hex(t, "chainCode"), 0, expected, 33, 32);
            assertArrayEquals(expected, r.data(), (String) t.get("name"));
        }
    }

    // vectors 1 and 4 (16/32-byte seeds) and SLIP-10 vector 1 through Derivation.master +
    // child directly.
    @Test
    void bip32AndSlip10Units() {
        card = Vecs.blankSelf();
        Applet applet = applet();
        Derivation derivation = Internals.derivation(applet);
        byte[] n = (byte[]) Internals.memField(applet, "N");
        Map<String, Object> doc = Vecs.load("derivation.json");
        for (Map<String, Object> v : Vecs.list(doc, "bip32")) {
            byte[] seed = hex(v, "seed");
            if (seed.length == 64) {
                continue;
            }
            assertEquals(
                    Const.CHECK_OK,
                    derivation.master(seed, (short) 0, (short) seed.length, n, (short) 0));
            List<Map<String, Object>> nodes = Vecs.list(v, "nodes");
            assertArrayEquals(hex(nodes.get(0), "privateKey"), Arrays.copyOf(n, 32));
            assertArrayEquals(hex(nodes.get(0), "chainCode"), Arrays.copyOfRange(n, 32, 64));
            for (int i = 1; i < nodes.size(); i++) {
                byte[] wire = Vecs.unhex(lastIndexWire((String) nodes.get(i).get("path")));
                short ok = derivation.child(wire, (short) 0, Derivation.CURVE_SECP, n, (short) -1);
                assertEquals(Const.CHECK_OK, ok, (String) nodes.get(i).get("path"));
                assertArrayEquals(hex(nodes.get(i), "privateKey"), Arrays.copyOf(n, 32));
                assertArrayEquals(hex(nodes.get(i), "chainCode"), Arrays.copyOfRange(n, 32, 64));
            }
        }
        // SLIP-10 vector 1: master = HMAC("ed25519 seed", seed); every step hardened
        Map<String, Object> v1 = Vecs.list(doc, "slip10").get(0);
        byte[] seed = hex(v1, "seed");
        byte[] key = "ed25519 seed".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        Internals.invoke(
                derivation,
                "hmac",
                new Class<?>[] {
                    byte[].class, short.class, short.class,
                    byte[].class, short.class, short.class,
                    byte[].class, short.class
                },
                key,
                (short) 0,
                (short) key.length,
                seed,
                (short) 0,
                (short) seed.length,
                n,
                (short) 0);
        List<Map<String, Object>> nodes = Vecs.list(v1, "nodes");
        assertArrayEquals(hex(nodes.get(0), "privateKey"), Arrays.copyOf(n, 32));
        assertArrayEquals(hex(nodes.get(0), "chainCode"), Arrays.copyOfRange(n, 32, 64));
        for (int i = 1; i < nodes.size(); i++) {
            byte[] wire = Vecs.unhex(lastIndexWire((String) nodes.get(i).get("path")));
            assertEquals(
                    Const.CHECK_OK,
                    derivation.child(wire, (short) 0, Derivation.CURVE_ED, n, (short) -1));
            assertArrayEquals(hex(nodes.get(i), "privateKey"), Arrays.copyOf(n, 32));
            assertArrayEquals(hex(nodes.get(i), "chainCode"), Arrays.copyOfRange(n, 32, 64));
        }
    }

    // SLIP-10 vector 2 and the ed25519 templates through PUBLIC_KEY P1 = 1.
    @Test
    void slip10Commands() throws Exception {
        Map<String, Object> doc = Vecs.load("derivation.json");
        Map<String, Object> v2 = Vecs.list(doc, "slip10").get(1);
        loadedWith(Vecs.accessHash(), hex(v2, "seed"));
        for (Map<String, Object> node : Vecs.list(v2, "nodes")) {
            String path = (String) node.get("path");
            if (path.equals("m")) {
                continue;
            }
            Response r = publicKey(1, Vecs.unhex(wireOf(path)));
            assertEquals(0x9000, r.sw(), path);
            assertArrayEquals(hex(node, "wei"), r.data(), path);
        }
        byte[] seed = hex(Vecs.obj(doc, "templates"), "seed");
        loadedWith(Vecs.accessHash(), seed);
        for (Map<String, Object> t : Vecs.list(Vecs.obj(doc, "templates"), "ed25519")) {
            Response r = publicKey(1, hex(t, "wire"));
            assertEquals(0x9000, r.sw(), (String) t.get("name"));
            assertArrayEquals(hex(t, "wei"), r.data(), (String) t.get("name"));
            // the host map agrees on the public key
            byte[] pub = Slip10.wei(hex(t, "privateKey"));
            assertArrayEquals(pub, r.data());
        }
    }

    // invalidChild / invalidMaster: the same coded predicates the Derivation steps apply,
    // with the vector's IL injected.
    @Test
    void invalidNodes() {
        card = Vecs.blankSelf();
        ModArith m = Internals.modArith(applet());
        Map<String, Object> doc = Vecs.load("derivation.json");
        byte[] out = new byte[32];
        for (Map<String, Object> c : Vecs.list(doc, "invalidMaster")) {
            byte[] il = hex(c, "il");
            boolean valid =
                    ModArith.isZero(il, (short) 0) != Const.CHECK_OK
                            && m.below(ModArith.MOD_N, il, (short) 0) == Const.CHECK_OK;
            assertEquals(c.get("valid"), valid, (String) c.get("name"));
        }
        for (Map<String, Object> c : Vecs.list(doc, "invalidChild")) {
            byte[] il = hex(c, "il");
            byte[] parent = hex(c, "parentKey");
            boolean valid = m.below(ModArith.MOD_N, il, (short) 0) == Const.CHECK_OK;
            if (valid) {
                m.addMod(ModArith.MOD_N, il, (short) 0, parent, (short) 0, out, (short) 0);
                valid = ModArith.isZero(out, (short) 0) != Const.CHECK_OK;
            }
            assertEquals(c.get("valid"), valid, (String) c.get("name"));
            if (valid) {
                assertArrayEquals(hex(c, "childKey"), out);
            }
        }
    }

    /** The wire form of a full path ({@code depth ‖ indices}). */
    private static String wireOf(String path) {
        byte[] wire = org.qntx.card.host.Paths.wire(path);
        StringBuilder sb = new StringBuilder(wire.length * 2);
        for (byte b : wire) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /** The wire form of the last index of a path ({@code index & 0x80000000} hardened). */
    private static String lastIndexWire(String path) {
        byte[] wire = org.qntx.card.host.Paths.wire(path);
        StringBuilder sb = new StringBuilder(8);
        for (int i = wire.length - 4; i < wire.length; i++) {
            sb.append(String.format("%02x", wire[i]));
        }
        return sb.toString();
    }
}
