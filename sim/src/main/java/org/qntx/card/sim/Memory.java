// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import javacard.framework.JCSystem;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Transient-memory hooks the {@link Agent} weaves into applet bytecode (architecture spec section
 * 8, patch 6): only calls from instrumented applet packages pass through here, so these entry
 * points charge card A's measured transient pool (audit-impl memory.out). While a card command or
 * install is bound they charge {@link CardRuntime}; with no card bound they are a plain pass
 * through so applet classes also run in plain unit tests.
 */
public final class Memory {

    private Memory() {}

    public static byte[] makeTransientByteArray(short length, byte event) {
        charge(length, "transient byte[" + (length & 0xFFFF) + "]");
        return JCSystem.makeTransientByteArray(length, event);
    }

    public static short[] makeTransientShortArray(short length, byte event) {
        charge(2 * (length & 0xFFFF), "transient short[" + (length & 0xFFFF) + "]");
        return JCSystem.makeTransientShortArray(length, event);
    }

    public static boolean[] makeTransientBooleanArray(short length, byte event) {
        charge(length, "transient boolean[" + (length & 0xFFFF) + "]");
        return JCSystem.makeTransientBooleanArray(length, event);
    }

    public static Object[] makeTransientObjectArray(short length, byte event) {
        charge(2 * (length & 0xFFFF), "transient Object[" + (length & 0xFFFF) + "]");
        return JCSystem.makeTransientObjectArray(length, event);
    }

    public static Key buildKey(byte keyType, short keyLength, boolean keyEncryption) {
        CardRuntime rt = CardRuntime.current();
        if (rt != null) {
            rt.chargeTransientKey(keyType, keyLength);
        }
        Key key = KeyBuilder.buildKey(keyType, keyLength, keyEncryption);
        if (rt != null) {
            rt.trackTransientEc(keyType, key);
        }
        return key;
    }

    public static Key buildKey(
            byte keyType, byte keyAlgorithmType, short keyLength, boolean keyEncryption) {
        CardRuntime rt = CardRuntime.current();
        if (rt != null) {
            rt.chargeTransientKey(keyType, keyLength);
        }
        Key key = KeyBuilder.buildKey(keyType, keyAlgorithmType, keyLength, keyEncryption);
        if (rt != null) {
            rt.trackTransientEc(keyType, key);
        }
        return key;
    }

    public static Key buildKeyWithSharedDomain(
            byte keyType, byte keyAlgorithmType, Key domainKey, boolean keyEncryption) {
        CardRuntime rt = CardRuntime.current();
        if (rt != null && Nvm.isTransientKeyType(keyType)) {
            rt.rejectUnmeasured("shared-domain transient key type " + keyType);
        }
        return KeyBuilder.buildKeyWithSharedDomain(
                keyType, keyAlgorithmType, domainKey, keyEncryption);
    }

    public static Cipher cipher(byte algorithm, boolean externalAccess) {
        CardRuntime rt = CardRuntime.current();
        if (rt != null) {
            rt.chargeEngine("cipher", algorithm);
        }
        return Cipher.getInstance(algorithm, externalAccess);
    }

    public static Cipher cipher(byte algorithm, byte paddingAlgorithm, boolean externalAccess) {
        CardRuntime rt = CardRuntime.current();
        if (rt != null) {
            rt.rejectUnmeasured("Cipher overload with padding " + paddingAlgorithm);
        }
        return Cipher.getInstance(algorithm, paddingAlgorithm, externalAccess);
    }

    /**
     * The signature engine instrumented code receives; {@code ALG_ECDSA_SHA_256} is always wrapped
     * in the {@link Fault#armEcdsaFlip} delegate so arming acts on engines created at install — the
     * delegate is a pure pass-through while nothing is armed. Engine charging is unchanged — the
     * wrap happens after the same charge a bare engine gets.
     */
    public static Signature signature(byte algorithm, boolean externalAccess) {
        CardRuntime rt = CardRuntime.current();
        if (rt != null) {
            rt.chargeEngine("signature", algorithm);
        }
        Signature engine = Signature.getInstance(algorithm, externalAccess);
        return algorithm == Signature.ALG_ECDSA_SHA_256 ? new FlippingSignature(engine) : engine;
    }

    public static Signature signature(
            byte signatureAlgorithm,
            byte cipherAlgorithm,
            byte messageDigestAlgorithm,
            boolean externalAccess) {
        CardRuntime rt = CardRuntime.current();
        if (rt != null) {
            rt.rejectUnmeasured("Signature overload with parts " + signatureAlgorithm);
        }
        return Signature.getInstance(
                signatureAlgorithm, cipherAlgorithm, messageDigestAlgorithm, externalAccess);
    }

    /**
     * The wrapped digest instrumented code receives: {@code update}/{@code doFinal} calls are
     * counted per algorithm and per command ({@link Card#digests}, {@link Card#digestBytes}).
     */
    public static MessageDigest messageDigest(byte algorithm, boolean externalAccess) {
        CardRuntime rt = CardRuntime.current();
        if (rt != null) {
            rt.chargeEngine("digest", algorithm);
        }
        return new CountingDigest(algorithm, MessageDigest.getInstance(algorithm, externalAccess));
    }

    public static KeyAgreement keyAgreement(byte algorithm, boolean externalAccess) {
        CardRuntime rt = CardRuntime.current();
        if (rt != null) {
            rt.chargeEngine("agreement", algorithm);
        }
        return KeyAgreement.getInstance(algorithm, externalAccess);
    }

    /**
     * The random engine instrumented code receives, always wrapped in the {@link Rng#fix} delegate
     * so arming acts on engines created at install; the delegate is a pure pass-through while
     * nothing is fixed. Engine charging is unchanged — the wrap happens after the same charge a
     * bare engine gets.
     */
    public static RandomData randomData(byte algorithm) {
        CardRuntime rt = CardRuntime.current();
        if (rt != null) {
            rt.chargeEngine("random", algorithm);
        }
        return new FixedRandom(RandomData.getInstance(algorithm));
    }

    private static void charge(int bytes, String description) {
        CardRuntime rt = CardRuntime.current();
        if (rt != null) {
            rt.chargeTransient(bytes, description);
        }
    }
}
