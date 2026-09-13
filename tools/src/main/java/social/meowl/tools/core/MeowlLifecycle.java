/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import java.util.Optional;

/**
 * Host-side mirror of the applet lifecycle state reported by {@code GET_INFO} (tag {@code 0x03},
 * see {@code social.meowl.wallet.LifecycleState} and {@code notes/specs/protocol.md} §4).
 *
 * <p><strong>Maintenance:</strong> any new applet lifecycle state must be mirrored here.
 */
public enum MeowlLifecycle {
    UNINITIALIZED(0),
    PERSONALIZED(1),
    SETUP_DONE(2),
    SEEDED(3);

    private final int code;

    MeowlLifecycle(int code) {
        this.code = code;
    }

    /** The on-wire single-byte lifecycle code. */
    public int code() {
        return code;
    }

    /** Resolves a wire code to its lifecycle, or {@link Optional#empty()} for an unknown code. */
    public static Optional<MeowlLifecycle> ofCode(int code) {
        for (MeowlLifecycle state : values()) {
            if (state.code == code) {
                return Optional.of(state);
            }
        }
        return Optional.empty();
    }
}
