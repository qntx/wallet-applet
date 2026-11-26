// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import javacard.security.Key;
import javacard.security.Signature;

/**
 * The {@link Fault#armEcdsaFlip} delegate {@link Memory#signature} wraps around every {@code
 * ALG_ECDSA_SHA_256} engine it hands to instrumented code: unarmed it is a pure pass-through; on
 * the armed {@code nth} {@code sign}/{@code signPreComputedHash} call it flips the last byte of the
 * DER signature written ({@code s}'s trailing byte XOR {@code 0x01}). Wrapping unconditionally is
 * what lets arming act on the engines an applet created at install — the corrupted output is what a
 * faulted crypto chip could emit, so the applet's self-verify before output (spec/protocol.md §9.9)
 * is what the injected fault exercises. The same wrapper lets {@link Fault#armVerifyTrue} force a
 * {@code verify} call to succeed regardless of the signature, a data fault on the coded result's
 * engine boolean.
 */
final class FlippingSignature extends Signature {

    private final Signature inner;

    FlippingSignature(Signature inner) {
        this.inner = inner;
    }

    private static short maybeFlip(short len, byte[] sigBuff, short sigOffset) {
        if (Fault.ecdsaFlip() && len > 0) {
            sigBuff[sigOffset + len - 1] ^= 0x01;
        }
        return len;
    }

    public void init(Key theKey, byte theMode) {
        inner.init(theKey, theMode);
    }

    public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen) {
        inner.init(theKey, theMode, bArray, bOff, bLen);
    }

    public void setInitialDigest(
            byte[] initialState,
            short initialStateOffset,
            short initialStateLength,
            byte[] initMsg,
            short initMsgOffset,
            short initMsgLength) {
        inner.setInitialDigest(
                initialState,
                initialStateOffset,
                initialStateLength,
                initMsg,
                initMsgOffset,
                initMsgLength);
    }

    public byte getAlgorithm() {
        return inner.getAlgorithm();
    }

    public byte getMessageDigestAlgorithm() {
        return inner.getMessageDigestAlgorithm();
    }

    public byte getCipherAlgorithm() {
        return inner.getCipherAlgorithm();
    }

    public byte getPaddingAlgorithm() {
        return inner.getPaddingAlgorithm();
    }

    public short getLength() {
        return inner.getLength();
    }

    public void update(byte[] inBuff, short inOffset, short inLength) {
        inner.update(inBuff, inOffset, inLength);
    }

    public short sign(
            byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset) {
        return maybeFlip(
                inner.sign(inBuff, inOffset, inLength, sigBuff, sigOffset), sigBuff, sigOffset);
    }

    public short signPreComputedHash(
            byte[] hashBuff, short hashOffset, short hashLength, byte[] sigBuff, short sigOffset) {
        return maybeFlip(
                inner.signPreComputedHash(hashBuff, hashOffset, hashLength, sigBuff, sigOffset),
                sigBuff,
                sigOffset);
    }

    public boolean verify(
            byte[] inBuff,
            short inOffset,
            short inLength,
            byte[] sigBuff,
            short sigOffset,
            short sigLength) {
        return Fault.verifyTrue()
                || inner.verify(inBuff, inOffset, inLength, sigBuff, sigOffset, sigLength);
    }

    public boolean verifyPreComputedHash(
            byte[] hashBuff,
            short hashOffset,
            short hashLength,
            byte[] sigBuff,
            short sigOffset,
            short sigLength) {
        return Fault.verifyTrue()
                || inner.verifyPreComputedHash(
                        hashBuff, hashOffset, hashLength, sigBuff, sigOffset, sigLength);
    }
}
