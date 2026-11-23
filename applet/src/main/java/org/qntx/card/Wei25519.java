// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;

/**
 * The Wei25519 domain of protocol.md §10.4 — the short-Weierstrass curve {@code Y² = X³ + a_W·X +
 * b_W} over {@code q = 2²⁵⁵ − 19} isomorphic to edwards25519 — and the base-point scalar
 * multiplication behind {@code W(A)}. Scalar multiples go through the shared {@link Mem#plainXy}
 * engine; the scalar is loaded into a dedicated transient key and the slot is overwritten before
 * every return (never {@code clearKey}; architecture.md §4).
 */
final class Wei25519 {
    /** Field prime {@code q = 2²⁵⁵ − 19}. */
    private static final byte[] Q = {
        (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xED,
    };

    /** Curve coefficient {@code a_W} (§10.4). */
    private static final byte[] A = {
        (byte) 0x2A, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
        (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
        (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
        (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
        (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0x98, (byte) 0x49, (byte) 0x14,
        (byte) 0xA1, (byte) 0x44,
    };

    /** Curve coefficient {@code b_W} (§10.4). */
    private static final byte[] B = {
        (byte) 0x7B, (byte) 0x42, (byte) 0x5E, (byte) 0xD0, (byte) 0x97, (byte) 0xB4,
        (byte) 0x25, (byte) 0xED, (byte) 0x09, (byte) 0x7B, (byte) 0x42, (byte) 0x5E,
        (byte) 0xD0, (byte) 0x97, (byte) 0xB4, (byte) 0x25, (byte) 0xED, (byte) 0x09,
        (byte) 0x7B, (byte) 0x42, (byte) 0x5E, (byte) 0xD0, (byte) 0x97, (byte) 0xB4,
        (byte) 0x26, (byte) 0x0B, (byte) 0x5E, (byte) 0x9C, (byte) 0x77, (byte) 0x10,
        (byte) 0xC8, (byte) 0x64,
    };

    /** Generator {@code G_W}, uncompressed {@code 04 ‖ X ‖ Y} (§10.4). */
    static final byte[] G = {
        (byte) 0x04, (byte) 0x2A, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
        (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
        (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
        (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
        (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
        (byte) 0xAD, (byte) 0x24, (byte) 0x5A, (byte) 0x20, (byte) 0xAE, (byte) 0x19,
        (byte) 0xA1, (byte) 0xB8, (byte) 0xA0, (byte) 0x86, (byte) 0xB4, (byte) 0xE0,
        (byte) 0x1E, (byte) 0xDD, (byte) 0x2C, (byte) 0x77, (byte) 0x48, (byte) 0xD1,
        (byte) 0x4C, (byte) 0x92, (byte) 0x3D, (byte) 0x4D, (byte) 0x7E, (byte) 0x6D,
        (byte) 0x7C, (byte) 0x61, (byte) 0xB2, (byte) 0x29, (byte) 0xE9, (byte) 0xC5,
        (byte) 0xA2, (byte) 0x7E, (byte) 0xCE, (byte) 0xD3, (byte) 0xD9,
    };

    /** Group order {@code ℓ}. */
    private static final byte[] L = {
        (byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x14, (byte) 0xDE,
        (byte) 0xF9, (byte) 0xDE, (byte) 0xA2, (byte) 0xF7, (byte) 0x9C, (byte) 0xD6,
        (byte) 0x58, (byte) 0x12, (byte) 0x63, (byte) 0x1A, (byte) 0x5C, (byte) 0xF5,
        (byte) 0xD3, (byte) 0xED,
    };

    private final Mem mem;

    /** The scalar slot of {@link #mulBase}; overwritten before every return. */
    private final ECPrivateKey scalarKey;

    Wei25519(Mem mem) {
        this.mem = mem;
        scalarKey =
                (ECPrivateKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                                KeyBuilder.LENGTH_EC_FP_256,
                                false);
    }

    /**
     * Loads the Wei25519 domain and {@code K = 1} into the transient scalar key. A {@code
     * CLEAR_ON_DESELECT} EC key's domain parameters die with the selection epoch (§8.5), so {@link
     * WalletApplet#select()} calls this on every selection before any Ed25519 path can run; the
     * writes land on the transient object only, nothing persistent.
     */
    void loadDomain() {
        scalarKey.setFieldFP(Q, (short) 0, (short) Q.length);
        scalarKey.setA(A, (short) 0, (short) A.length);
        scalarKey.setB(B, (short) 0, (short) B.length);
        scalarKey.setG(G, (short) 0, (short) G.length);
        scalarKey.setR(L, (short) 0, (short) L.length);
        scalarKey.setK((short) 1);
    }

    /**
     * {@code out = 04 ‖ X ‖ Y} of {@code scalar·G_W} (§10.4), the affine point behind {@code W(A) =
     * X ‖ Y}; {@code scalar} is a 32-byte big-endian value already reduced below {@code ℓ}. The
     * scalar slot is overwritten before every return, including exceptions.
     */
    short mulBase(byte[] scalar, short sOff, byte[] out, short oOff) {
        try {
            scalarKey.setS(scalar, sOff, (short) 32);
            mem.plainXy.init(scalarKey);
            return mem.plainXy.generateSecret(G, (short) 0, Const.POINT_LEN, out, oOff);
        } finally {
            scalarKey.setS(Const.ZEROS, (short) 0, (short) 32);
        }
    }

    /**
     * {@code out = scalar·point} (65-byte uncompressed) via PLAIN_XY, the {@link #mulBase} sibling
     * for the Ed25519 self-verification's {@code c·A} (§16.2 item 5); {@code scalar} is already
     * reduced below {@code ℓ} and the scalar slot is overwritten in a {@code finally}.
     */
    short mul(byte[] scalar, short sOff, byte[] point, short pOff, byte[] out, short oOff) {
        try {
            scalarKey.setS(scalar, sOff, (short) 32);
            mem.plainXy.init(scalarKey);
            return mem.plainXy.generateSecret(point, pOff, Const.POINT_LEN, out, oOff);
        } finally {
            scalarKey.setS(Const.ZEROS, (short) 0, (short) 32);
        }
    }

    /**
     * {@code out = s·G_W + H} (65-byte uncompressed) via the shared {@link Mem#paceGm} engine — the
     * {@code S·G_W + T} of the Ed25519 self-verification (§16.2 item 5). The output must not
     * overlap {@code h}; the scalar slot is overwritten in a {@code finally}.
     */
    short mulAdd(byte[] s, short sOff, byte[] h, short hOff, byte[] out, short oOff) {
        try {
            scalarKey.setS(s, sOff, (short) 32);
            mem.paceGm.init(scalarKey);
            return mem.paceGm.generateSecret(h, hOff, Const.POINT_LEN, out, oOff);
        } finally {
            scalarKey.setS(Const.ZEROS, (short) 0, (short) 32);
        }
    }
}
