// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review;

import static org.qntx.card.review.ReviewHost.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.qntx.card.sim.Fault;

/**
 * Checked-and-correct probe (not a PoC): for each woven ModArith.mulMasked call position inside
 * SIGN_BIP340, skip the call once and check whether the card self-verifies (6F00) or outputs a
 * signature — and if it outputs one, whether that signature actually verifies under the independent
 * verifier. Gated on QNTX_REVIEW=full.
 */
@EnabledIfEnvironmentVariable(named = "QNTX_REVIEW", matches = "full")
final class Bip340SelfVerifyTest {

    private static final byte[] H0 = sha256("bip340-sv".getBytes());
    private static final long[] PATH = {0x80000000L};

    private static byte[] pathBytes(long... idx) {
        byte[] out = new byte[1 + 4 * idx.length];
        out[0] = (byte) idx.length;
        for (int i = 0; i < idx.length; i++) {
            byte[] b = u32(idx[i]);
            System.arraycopy(b, 0, out, 1 + 4 * i, 4);
        }
        return out;
    }

    @Test
    void sweep() {
        byte[] seed = sha512("bip340-sv seed".getBytes());
        byte[] msg = sha256("bip340-sv msg".getBytes());
        byte[] tweak = new byte[32];
        StringBuilder log = new StringBuilder("n | sw | verifies?\n");
        int bad = 0;
        for (int n = 1; n <= 64; n++) {
            ReviewCard c = ReviewCard.uninitialised();
            c.blank();
            ReviewSession s = c.create(seed, H0);
            s.cmd((byte) 0x22, (byte) 0, (byte) 0, H0);
            Fault.armSkip("ModArith.mulMasked", n);
            ReviewSession.Inner r;
            try {
                r = s.cmd((byte) 0x32, (byte) 0, (byte) 0, concat(msg, tweak, pathBytes(PATH)));
            } catch (Throwable t) {
                Fault.reset();
                log.append(n).append(" | threw ").append(t.getClass().getSimpleName()).append('\n');
                continue;
            }
            Fault.reset();
            String v;
            if (r.sw == 0x9000) {
                byte[][] node = bip32Node(seed, PATH);
                byte[] qx =
                        i2b(
                                taprootQ(b2i(node[0]), b2i(tweak)).getAffineXCoord().toBigInteger(),
                                32);
                boolean ok = bip340Verify(qx, msg, r.data);
                v = ok ? "valid" : "INVALID — released";
                if (!ok) {
                    bad++;
                }
            } else {
                v = "-";
            }
            log.append(n)
                    .append(" | ")
                    .append(String.format("%04X", r.sw))
                    .append(" | ")
                    .append(v)
                    .append('\n');
        }
        System.out.println("BIP340_SELFVERIFY_SWEEP\n" + log);
        org.junit.jupiter.api.Assertions.assertEquals(
                0, bad, bad + " fault positions produced 9000 with an invalid signature:\n" + log);
    }
}
