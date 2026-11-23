// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The private {@link Derivation#hmac} against BouncyCastle HMAC-SHA512: the 12- and 32-byte keys
 * the call sites actually pass ({@code "Bitcoin seed"}, {@code "ed25519 seed"}, a chain code) plus
 * boundary lengths; non-zero key, message and output offsets so the padding cannot hide a shifted
 * pad block. The wire-visible derivation vectors cover the callers end to end.
 */
final class DerivationTest {

    private static final Class<?>[] HMAC_SIG = {
        byte[].class,
        short.class,
        short.class,
        byte[].class,
        short.class,
        short.class,
        byte[].class,
        short.class
    };

    @Test
    void hmacMatchesBouncyCastle() throws Exception {
        Card card = Vecs.factory();
        Derivation derivation = Internals.derivation(card.applet(Spec.WALLET_AID));
        for (int kLen : new int[] {12, 32, 64, 1, 128}) {
            for (int mLen : new int[] {0, 37, 97, 250}) {
                byte[] keys = new byte[kLen + 3];
                byte[] msgs = new byte[mLen + 5];
                byte[] out = new byte[64 + 7];
                Vecs.RND.nextBytes(keys);
                Vecs.RND.nextBytes(msgs);
                Internals.invoke(
                        derivation,
                        "hmac",
                        HMAC_SIG,
                        keys,
                        (short) 3,
                        (short) kLen,
                        msgs,
                        (short) 5,
                        (short) mLen,
                        out,
                        (short) 7);
                byte[] key = new byte[kLen];
                System.arraycopy(keys, 3, key, 0, kLen);
                HMac mac = new HMac(new SHA512Digest());
                mac.init(new KeyParameter(key));
                mac.update(msgs, 5, mLen);
                byte[] want = new byte[64];
                mac.doFinal(want, 0);
                byte[] got = new byte[64];
                System.arraycopy(out, 7, got, 0, 64);
                assertArrayEquals(want, got, "kLen=" + kLen + " mLen=" + mLen);
            }
        }
    }
}
