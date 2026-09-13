/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import java.util.List;

/**
 * Host-side mirror of the applet capability bitmask reported by {@code GET_INFO} (tag {@code 0x04},
 * see {@code social.meowl.wallet.Constants} and {@code notes/specs/protocol.md} §5).
 *
 * <p>Each constant carries its single-bit mask; {@link #decode(int)} expands a raw bitmask into the
 * ordered list of capabilities it advertises. Declaration order is ascending by mask so rendered
 * output is deterministic.
 *
 * <p><strong>Maintenance:</strong> any new applet capability bit must be mirrored here.
 */
public enum MeowlCapability {
    ECDSA_K1(0x0001),
    SCHNORR_K1(0x0002),
    ED25519(0x0004),
    SC_GCM(0x0008),
    SC_CBC_HMAC(0x0010),
    PKI(0x0020),
    RESET_TO_FACTORY(0x0040),
    BIP32(0x0080),
    SLIP10(0x0100);

    private final int mask;

    MeowlCapability(int mask) {
        this.mask = mask;
    }

    /** The single-bit mask this capability occupies in the {@code GET_INFO} bitmask. */
    public int mask() {
        return mask;
    }

    /**
     * Expands a raw capability bitmask into the ordered list of capabilities it sets. Unknown bits
     * (those not mapped to a constant) are ignored for forward compatibility; use {@link
     * #unknownBits(int)} to recover them.
     */
    public static List<MeowlCapability> decode(int bits) {
        List<MeowlCapability> out = new java.util.ArrayList<>();
        for (MeowlCapability cap : values()) {
            if ((bits & cap.mask) != 0) {
                out.add(cap);
            }
        }
        return List.copyOf(out);
    }

    /** Returns any bits set in {@code bits} that this enum does not recognise (forward-compat). */
    public static int unknownBits(int bits) {
        int known = 0;
        for (MeowlCapability cap : values()) {
            known |= cap.mask;
        }
        return bits & ~known;
    }
}
