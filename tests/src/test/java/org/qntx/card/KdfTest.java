// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.Arrays;
import java.util.Map;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Vecs;

/**
 * kdf.json replayed through the applet's {@link Kdf} and {@link Mem} engines — same vectors as the
 * host oracle, so agreement is an independent check of the card-side implementation.
 */
final class KdfTest {

    private static Mem memOf(Card card) {
        return Internals.mem(card.applet(org.qntx.card.tests.Spec.WALLET_AID));
    }

    private static Mem mem() {
        Card card = Vecs.factory();
        return memOf(card);
    }

    @Test
    void oneStepKdfMatchesVectors() {
        Map<String, Object> doc = Vecs.load("kdf.json");
        Mem mem = mem();
        byte[] out = new byte[64];
        for (Map<String, Object> c : Vecs.list(doc, "kdf")) {
            byte[] z = Vecs.hex(c, "z");
            byte[] label = Vecs.hex(c, "label");
            byte[] ctx = Vecs.hex(c, "ctx");
            int len = ((Number) c.get("len")).intValue();
            if (len != 32 && len != 64) {
                // the applet's kdf derives full blocks only (len ∈ {32, 64}); the 16/33
                // vectors stay host/vector-generator checks
                continue;
            }
            Arrays.fill(out, (byte) 0xAA);
            Kdf.kdf(
                    mem,
                    z,
                    (short) 0,
                    (short) z.length,
                    label,
                    ctx,
                    (short) 0,
                    (short) ctx.length,
                    out,
                    (short) 0,
                    (short) len);
            assertArrayEquals(Vecs.hex(c, "out"), Arrays.copyOf(out, len), "kdf len " + len);
        }
    }

    @Test
    void kdf108MatchesVectors() {
        Map<String, Object> doc = Vecs.load("kdf.json");
        Mem mem = mem();
        AESKey key =
                (AESKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                                KeyBuilder.LENGTH_AES_128,
                                false);
        byte[] out = new byte[32];
        for (Map<String, Object> c : Vecs.list(doc, "kdf108")) {
            key.setKey(Vecs.hex(c, "key"), (short) 0);
            byte[] label = Vecs.hex(c, "label");
            byte[] ctx = Vecs.hex(c, "ctx");
            Arrays.fill(out, (byte) 0xAA);
            Kdf.kdf108(mem, key, label, ctx, (short) 0, (short) ctx.length, out, (short) 0);
            assertArrayEquals(Vecs.hex(c, "out"), out);
        }
    }

    @Test
    void cmacMatchesVectors() {
        Map<String, Object> doc = Vecs.load("kdf.json");
        Mem mem = mem();
        AESKey key =
                (AESKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                                KeyBuilder.LENGTH_AES_128,
                                false);
        byte[] tag = new byte[16];
        for (Map<String, Object> c : Vecs.list(doc, "cmac")) {
            key.setKey(Vecs.hex(c, "key"), (short) 0);
            byte[] msg = Vecs.hex(c, "message");
            mem.cmac.init(key, Signature.MODE_SIGN);
            mem.cmac.update(msg, (short) 0, (short) msg.length);
            short got = mem.cmac.sign(msg, (short) 0, (short) 0, tag, (short) 0);
            assertArrayEquals(
                    Vecs.hex(c, "tag"), Arrays.copyOf(tag, got), (String) c.get("message"));
        }
    }

    @Test
    void sessionHandshakeKdfMatchesSessionVector() {
        // §8.1: keys = KDF(Z, "qntx-card/v1/kdf-session", TH, 64) = kce‖kcm‖kre‖krm
        Map<String, Object> doc = Vecs.load("session.json");
        Mem mem = mem();
        byte[] out = new byte[64];
        byte[] z = Vecs.hex(doc, "z");
        byte[] th = Vecs.hex(doc, "th");
        byte[] label = Vecs.unhex((String) doc.get("kdfLabel"));
        Kdf.kdf(
                mem,
                z,
                (short) 0,
                (short) z.length,
                label,
                th,
                (short) 0,
                (short) th.length,
                out,
                (short) 0,
                (short) 64);
        byte[] expect = new byte[64];
        int off = 0;
        for (String k : new String[] {"kce", "kcm", "kre", "krm"}) {
            byte[] v = Vecs.hex(doc, k);
            System.arraycopy(v, 0, expect, off, 16);
            off += 16;
        }
        assertArrayEquals(expect, out);
    }
}
