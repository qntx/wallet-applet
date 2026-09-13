/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.shared;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;

/**
 * Multi-step {@code RESET_TO_FACTORY} trigger per {@code notes/specs/protocol.md} §4.
 *
 * <p>Each {@code RESET_TO_FACTORY} APDU decrements an internal counter via {@link
 * #recordInvocation}; any other APDU re-arms it via {@link #rearm()}. The status word returned to
 * the host is always {@code SW_RESET_COUNTDOWN_BASE + remaining}, communicating the countdown
 * verbatim. When {@code remaining} reaches zero the {@link WipeTrigger} is invoked, the counter is
 * re-armed, and {@code SW_RESET_COUNTDOWN_BASE + 0} is thrown.
 *
 * <p>The counter lives in {@link JCSystem#CLEAR_ON_RESET} transient memory: a power loss
 * mid-sequence resets the count, so an attacker must hold the card across {@code N} uninterrupted
 * APDU round trips with no interleaved traffic — the explicit design goal.
 */
public final class ResetToFactory {

    private final byte[] remaining;

    /** Constructs a fresh trigger with the counter armed to the configured threshold. */
    public ResetToFactory() {
        this.remaining = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        this.remaining[0] = Constants.RESET_REQUIRED_INVOCATIONS;
    }

    /** Rearms the counter. Invoked whenever a non-{@code RESET_TO_FACTORY} APDU arrives. */
    public void rearm() {
        remaining[0] = Constants.RESET_REQUIRED_INVOCATIONS;
    }

    /**
     * Records one {@code RESET_TO_FACTORY} invocation. Always throws {@link ISOException}; never
     * returns normally. Treat as a tail call.
     */
    public void recordInvocation(WipeTrigger trigger) {
        byte step = (byte) (remaining[0] - 1);
        remaining[0] = step;
        if (step == 0) {
            // Re-arm BEFORE wipe() so a wipe() throw doesn't leave remaining[0] = 0; otherwise
            // the next invocation would compute step = -1 = 0xFF and emit 0x6FFF.
            remaining[0] = Constants.RESET_REQUIRED_INVOCATIONS;
            trigger.wipe();
            ISOException.throwIt(Constants.SW_RESET_COUNTDOWN_BASE);
        }
        ISOException.throwIt((short) (Constants.SW_RESET_COUNTDOWN_BASE + (step & 0xFF)));
    }

    /** Returns the current countdown value; primarily for unit-test assertions. */
    public byte remaining() {
        return remaining[0];
    }
}
