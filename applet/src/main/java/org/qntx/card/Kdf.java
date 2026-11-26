// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.security.AESKey;
import javacard.security.MessageDigest;
import javacard.security.Signature;

/**
 * The two key-derivation functions of spec/protocol.md §1. Static helpers over the shared engines;
 * {@link Kdf#kdf108} uses the {@link Mem#W_KDF} region of {@link Mem#W} as scratch — inputs and
 * {@code out} must not overlap it — while {@link Kdf#kdf} keeps no scratch at all: its counters
 * come from {@link Const#KDF_COUNTER} and every block is written straight to {@code out}, so two
 * derivations sharing one command share no temporary (§16.2 item 4).
 */
final class Kdf {
    private Kdf() {}

    /**
     * One-step KDF of NIST SP 800-56C Rev. 2 §4.1 option 1 (§1): the first {@code len} bytes of
     * {@code SHA-256(u32(1) ‖ Z ‖ label ‖ ctx) ‖ SHA-256(u32(2) ‖ …)}, {@code len ∈ {32, 64}}.
     */
    static void kdf(
            Mem mem,
            byte[] z,
            short zOff,
            short zLen,
            byte[] label,
            byte[] ctx,
            short ctxOff,
            short ctxLen,
            byte[] out,
            short outOff,
            short len) {
        MessageDigest sha = mem.sha256;
        for (short i = 1; (short) (i * 32) <= len; i++) {
            sha.reset();
            sha.update(Const.KDF_COUNTER, (short) ((i - 1) * 4), (short) 4);
            sha.update(z, zOff, zLen);
            sha.update(label, (short) 0, (short) label.length);
            sha.update(ctx, ctxOff, ctxLen);
            sha.doFinal(z, (short) 0, (short) 0, out, (short) (outOff + (short) ((i - 1) * 32)));
        }
    }

    /**
     * Counter-mode KDF of NIST SP 800-108r1 §4.1 with PRF = CMAC, r = 8, 256-bit output (§1):
     * {@code CMAC(K, i ‖ label ‖ 0x00 ‖ ctx ‖ 0x0100)} for {@code i = 1, 2}. Writes 32 bytes.
     */
    static void kdf108(
            Mem mem,
            AESKey k,
            byte[] label,
            byte[] ctx,
            short ctxOff,
            short ctxLen,
            byte[] out,
            short outOff) {
        Signature cmac = mem.cmac;
        byte[] w = mem.W;
        for (short i = 1; i <= 2; i++) {
            cmac.init(k, Signature.MODE_SIGN);
            w[(short) (Mem.W_KDF + 36)] = (byte) i;
            cmac.update(w, (short) (Mem.W_KDF + 36), (short) 1);
            cmac.update(label, (short) 0, (short) label.length);
            w[(short) (Mem.W_KDF + 36)] = 0;
            cmac.update(w, (short) (Mem.W_KDF + 36), (short) 1);
            cmac.update(ctx, ctxOff, ctxLen);
            w[(short) (Mem.W_KDF + 36)] = 1;
            w[(short) (Mem.W_KDF + 37)] = 0;
            cmac.update(w, (short) (Mem.W_KDF + 36), (short) 2);
            cmac.sign(w, (short) 0, (short) 0, out, (short) (outOff + (short) ((i - 1) * 16)));
        }
    }
}
