/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.wallet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;

/**
 * User PIN + PUK manager per {@code notes/specs/protocol.md} §7.
 *
 * <p>Holds one user PIN and one unblock PUK, each backed by {@link OwnerPIN} for JC-native
 * bounded-retry counters and storage protection. Status-word semantics:
 *
 * <ul>
 *   <li>Correct PIN/PUK → {@code 9000}; wrong value → {@code 0x63Cn} with the 4-bit retry count in
 *       the low nibble (ISO 7816-4); exhausted counter → {@link Constants#SW_AUTH_BLOCKED}.
 *   <li>Length-policy violations return {@link Constants#SW_WRONG_LENGTH} and do <em>not</em>
 *       consume a retry — they are host-side protocol errors, not guesses.
 *   <li>{@link #unblockPin} validates the new-PIN length before it touches the PUK, so a malformed
 *       new PIN is a host-side protocol error that does NOT consume a PUK attempt — same ordering
 *       as {@link #changePin}.
 * </ul>
 *
 * <p>Every entry point validates length bounds before invoking {@link OwnerPIN#check}, which would
 * otherwise raise {@link ArrayIndexOutOfBoundsException} on an over-long input.
 */
public final class PinManager {

    private final OwnerPIN pin;
    private final OwnerPIN puk;
    private final byte[] provisioned; // [0] != 0 → setup() has been called

    /** Constructs an unprovisioned manager. */
    public PinManager() {
        this.pin = new OwnerPIN(Constants.PIN_RETRY_LIMIT, Constants.PIN_MAX_LEN);
        this.puk = new OwnerPIN(Constants.PUK_RETRY_LIMIT, Constants.PUK_MAX_LEN);
        this.provisioned = new byte[1];
    }

    /** Returns {@code true} once {@link #setupInTx} has been called successfully. */
    private boolean isProvisioned() {
        return provisioned[0] != 0;
    }

    /** Returns {@code true} once {@link #verifyPin} has succeeded in this session. */
    public boolean isPinVerified() {
        return pin.isValidated();
    }

    /** Clears the in-session PIN-verified flag. Called from {@code select} and on session end. */
    public void clearSession() {
        // OwnerPIN.reset() is a no-op when not validated; that's the behaviour we want here.
        pin.reset();
    }

    /**
     * Initial provisioning: installs the user PIN and unblock PUK. <strong>Caller MUST hold a
     * {@link JCSystem#beginTransaction()} block</strong> so the two installs and the companion
     * lifecycle transition commit atomically. May only run when {@link #isProvisioned()} is {@code
     * false}.
     */
    public void setupInTx(
            byte[] pinBuf,
            short pinOffset,
            short pinLen,
            byte[] pukBuf,
            short pukOffset,
            short pukLen) {
        if (provisioned[0] != 0) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        requireLengthPolicy(pinLen, Constants.PIN_MIN_LEN, Constants.PIN_MAX_LEN);
        requireLengthPolicy(pukLen, Constants.PUK_MIN_LEN, Constants.PUK_MAX_LEN);
        pin.update(pinBuf, pinOffset, (byte) pinLen);
        puk.update(pukBuf, pukOffset, (byte) pukLen);
        provisioned[0] = 1;
    }

    /**
     * Verifies a candidate PIN. On success {@link OwnerPIN#isValidated} returns {@code true}.
     *
     * @throws ISOException with status word {@link Constants#SW_PIN_RETRIES_BASE} {@code | n} where
     *     {@code n} is the number of attempts remaining after the failed verification, or {@link
     *     Constants#SW_AUTH_BLOCKED} if the counter was already zero.
     */
    public void verifyPin(byte[] buf, short offset, short length) {
        requireProvisioned();
        verifyOwnerPin(pin, buf, offset, length, Constants.PIN_MIN_LEN, Constants.PIN_MAX_LEN);
    }

    /**
     * Atomically rotates the PIN. Requires the old PIN to verify against the stored value; consumes
     * a PIN attempt if the old PIN is wrong, exactly like {@link #verifyPin}.
     */
    public void changePin(
            byte[] oldBuf,
            short oldOffset,
            short oldLen,
            byte[] newBuf,
            short newOffset,
            short newLen) {
        requireProvisioned();
        requireLengthPolicy(newLen, Constants.PIN_MIN_LEN, Constants.PIN_MAX_LEN);
        verifyPin(oldBuf, oldOffset, oldLen);
        JCSystem.beginTransaction();
        pin.update(newBuf, newOffset, (byte) newLen);
        JCSystem.commitTransaction();
    }

    /** Atomically rotates the PUK. Requires the current PUK to verify; consumes a PUK attempt. */
    public void changePuk(
            byte[] oldBuf,
            short oldOffset,
            short oldLen,
            byte[] newBuf,
            short newOffset,
            short newLen) {
        requireProvisioned();
        requireLengthPolicy(newLen, Constants.PUK_MIN_LEN, Constants.PUK_MAX_LEN);
        verifyOwnerPin(
                puk, oldBuf, oldOffset, oldLen, Constants.PUK_MIN_LEN, Constants.PUK_MAX_LEN);
        JCSystem.beginTransaction();
        puk.update(newBuf, newOffset, (byte) newLen);
        JCSystem.commitTransaction();
    }

    /**
     * Unblocks the PIN after exhausted retries. The new-PIN length policy is checked BEFORE the PUK
     * so a malformed new PIN — a host-side protocol error — does not burn one of the scarce PUK
     * attempts; a wrong PUK still consumes one. This mirrors {@link #changePin}, which validates
     * the new-PIN length before verifying the old PIN. Ordering the length gate first leaks nothing
     * about the PUK: the {@code SW_WRONG_LENGTH} path never reaches {@link OwnerPIN#check}, so a
     * malformed new PIN cannot be used to probe the PUK without spending an attempt.
     */
    public void unblockPin(
            byte[] pukBuf,
            short pukOffset,
            short pukLen,
            byte[] newPinBuf,
            short newPinOffset,
            short newPinLen) {
        requireProvisioned();
        if (pin.getTriesRemaining() != 0) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        requireLengthPolicy(newPinLen, Constants.PIN_MIN_LEN, Constants.PIN_MAX_LEN);
        verifyOwnerPin(
                puk, pukBuf, pukOffset, pukLen, Constants.PUK_MIN_LEN, Constants.PUK_MAX_LEN);
        JCSystem.beginTransaction();
        pin.update(newPinBuf, newPinOffset, (byte) newPinLen);
        pin.resetAndUnblock();
        JCSystem.commitTransaction();
    }

    /**
     * Logically invalidates PIN/PUK by clearing the {@link #provisioned} flag. Every PIN/PUK entry
     * point gates on {@link #requireProvisioned}, so a {@code provisioned == 0} card cannot reach
     * {@link OwnerPIN#check} no matter what bytes the host sends. The subsequent {@code SETUP} call
     * drives {@link OwnerPIN#update} with fresh PIN/PUK values, which per the JC 3.0.5 spec
     * overwrites the stored value, clears the validated flag, and resets the retry counter — so the
     * prior credentials cannot survive into the next personalisation cycle.
     *
     * <p>The earlier two-update scrub via {@code OwnerPIN.update(scrub, 0, PIN_MAX_LEN)} was
     * removed because it tripped a J3R180 quirk: when the wipe length differed from the next {@code
     * SETUP} length (32-byte PUK scrub → 8-byte PUK setup), {@link OwnerPIN#check} on the
     * freshly-installed PUK returned false even though the bytes matched, breaking {@code
     * UNBLOCK_PIN} and {@code CHANGE_PUK} immediately after reset-to-factory. Dropping the scrub
     * also shrinks the wipe transaction enough that it commits within the BWT of a contactless
     * link.
     *
     * <p>Caller MUST hold a {@link JCSystem#beginTransaction()} block; bundled with PKI, master
     * seed and lifecycle wipes into the single atomic reset-to-factory commit driven by {@link
     * WalletApplet#wipe()}.
     */
    public void wipeInTx() {
        provisioned[0] = 0;
    }

    /**
     * Shared verify backbone: tries-remaining probe → length-policy gate → {@link OwnerPIN#check}.
     * On a wrong candidate, raises {@code SW_PIN_RETRIES_BASE | n} (or {@code SW_AUTH_BLOCKED} on
     * exhaustion). Length-policy violations return {@code SW_WRONG_LENGTH} <em>without</em>
     * consuming a retry — the same SW is returned for every length-violating input regardless of
     * candidate bytes, so this path leaks no information to a brute-force attacker.
     */
    private static void verifyOwnerPin(
            OwnerPIN owner, byte[] buf, short offset, short length, byte minLen, byte maxLen) {
        byte triesRemaining = owner.getTriesRemaining();
        if (triesRemaining == 0) {
            ISOException.throwIt(Constants.SW_AUTH_BLOCKED);
        }
        if (length < minLen || length > maxLen) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        if (!owner.check(buf, offset, (byte) length)) {
            byte remaining = owner.getTriesRemaining();
            if (remaining == 0) {
                ISOException.throwIt(Constants.SW_AUTH_BLOCKED);
            }
            ISOException.throwIt((short) (Constants.SW_PIN_RETRIES_BASE | (remaining & 0x0F)));
        }
    }

    private static void requireLengthPolicy(short length, byte minLen, byte maxLen) {
        if (length < minLen || length > maxLen) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
    }

    private void requireProvisioned() {
        if (!isProvisioned()) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
}
