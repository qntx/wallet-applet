// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KDFCounterParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Card side of one SCP03 secure channel (GP 2.3.1 Amendment D §6, {@code i = 0x00}: random card
 * challenge, no sequence counter, no R-MAC/R-ENC, S8 MACs). The host-side mirror is
 * GlobalPlatformPro {@code GPSession.openSecureChannel} and {@code SCP03Wrapper}.
 *
 * <p>Lifecycle: {@link #initUpdate} stores the pending session keys and answers with the card
 * cryptogram; {@link #extAuth} checks the host cryptogram and C-MAC and opens the channel; {@link
 * #unwrap} verifies the C-MAC, updates the chaining value and decrypts C-DEC payloads. Any failure
 * closes the channel, matching Amendment D §6.2.3.3.
 */
final class Scp03 {

    /** The GP test key of {@link Isd}'s factory key set (KVN {@value #KVN}). */
    static final int KVN = 0x30;

    static final byte[] TEST_KEY = HexFormat.of().parseHex("404142434445464748494A4B4C4D4E4F");

    // Amendment D §6.2.4 Table 6-2 derivation constants; GPSession's host mirror is
    // PlaintextKeys.SCP03_CONSTANTS
    // (library/src/main/java/pro/javacard/gp/keys/PlaintextKeys.java:44)
    private static final int C_CARD_CRYPTO = 0x00;
    private static final int C_HOST_CRYPTO = 0x01;
    private static final int C_ENC = 0x04;
    private static final int C_MAC = 0x06;

    private byte[] enc = TEST_KEY.clone();
    private byte[] mac = TEST_KEY.clone();
    private byte[] dek = TEST_KEY.clone();
    private int kvn = KVN;

    private byte[] senc;
    private byte[] smac;
    private byte[] context;
    private final byte[] chaining = new byte[16];
    private final byte[] counter = new byte[16];
    private boolean open;
    private boolean cdec;

    int kvn() {
        return kvn;
    }

    boolean isOpen() {
        return open;
    }

    void close() {
        open = false;
        cdec = false;
        senc = null;
        smac = null;
        context = null;
    }

    /**
     * INITIALIZE UPDATE: accepts key version {@code 0x00} (any) or the current KVN. Stores the
     * pending session keys and returns the 29-byte response data {@code kdd(10) ‖ kvn ‖ 03 ‖ 00 ‖
     * cardChallenge(8) ‖ cardCryptogram(8)} of Amendment D §6.2.3.2, or {@code null} on a key
     * version mismatch (caller answers {@code 6A88}).
     */
    byte[] initUpdate(byte[] diversification, int requestKvn, byte[] hostChallenge) {
        close();
        if (requestKvn != 0 && requestKvn != kvn) {
            return null;
        }
        byte[] cardChallenge = new byte[8];
        new SecureRandom().nextBytes(cardChallenge);
        context = concat(hostChallenge, cardChallenge);
        senc = kdf(enc, C_ENC, context, 16);
        smac = kdf(mac, C_MAC, context, 16);
        byte[] cardCryptogram = kdf(smac, C_CARD_CRYPTO, context, 8);
        byte[] out = new byte[29];
        System.arraycopy(diversification, 0, out, 0, 10);
        out[10] = (byte) kvn;
        out[11] = 0x03;
        out[12] = 0x00;
        System.arraycopy(cardChallenge, 0, out, 13, 8);
        System.arraycopy(cardCryptogram, 0, out, 21, 8);
        return out;
    }

    /**
     * EXTERNAL AUTHENTICATE: {@code hostCryptogram(8) ‖ C-MAC(8)}; returns {@code true} once the
     * channel is open. The C-MAC is verified against a zero chaining value before the cryptogram,
     * the ordering of Amendment D §6.2.3.3.
     */
    boolean extAuth(byte[] commandData, int securityLevel) {
        if (senc == null || (securityLevel != 0x01 && securityLevel != 0x03)) {
            close();
            return false;
        }
        if (commandData.length != 16) {
            close();
            return false;
        }
        byte[] hostCryptogram = Arrays.copyOfRange(commandData, 0, 8);
        byte[] cmac = Arrays.copyOfRange(commandData, 8, 16);
        // chaining starts at zero for the first MAC after INIT UPDATE (Amendment D §6.2.5)
        byte[] full =
                cmac(
                        smac,
                        concat(
                                new byte[16],
                                cmacInput(0x84, 0x82, securityLevel, 0, 16, hostCryptogram)));
        if (!Arrays.equals(Arrays.copyOf(full, 8), cmac)
                || !Arrays.equals(kdf(smac, C_HOST_CRYPTO, context, 8), hostCryptogram)) {
            close();
            return false;
        }
        System.arraycopy(full, 0, chaining, 0, 16);
        Arrays.fill(counter, (byte) 0);
        context = null;
        cdec = securityLevel == 0x03;
        open = true;
        return true;
    }

    /**
     * C-MAC verification and C-DECryption of one wrapped command. {@code wire} is the full received
     * APDU (header ‖ Lc ‖ data ‖ MAC ‖ optional Le); returns the unwrapped {@code ins ‖ p1 ‖ p2 ‖
     * plain data} or {@code null} when the MAC is wrong — the caller closes the channel.
     * GlobalPlatformPro builds the MAC input as {@code chaining ‖ cla ‖ ins ‖ p1 ‖ p2 ‖ Lc ‖ data}
     * (SCP03Wrapper.wrap), which equals the wire bytes minus the trailing Le and last 8 MAC bytes.
     */
    byte[] unwrap(byte[] wire, int macLen) {
        // data boundaries: header 4 + Lc encoding (1 or 3 bytes) + lc bytes + Le
        int lcOff = 4;
        int lcLen;
        int lc;
        if (wire[4] == 0 && wire.length > 6) {
            lcLen = 3;
            lc = ((wire[5] & 0xFF) << 8) | (wire[6] & 0xFF);
        } else {
            lcLen = 1;
            lc = wire[4] & 0xFF;
        }
        int dataOff = lcOff + lcLen;
        if (lc < macLen || dataOff + lc > wire.length) {
            return null;
        }
        int macOff = dataOff + lc - macLen;
        byte[] input = new byte[16 + macOff];
        System.arraycopy(chaining, 0, input, 0, 16);
        System.arraycopy(wire, 0, input, 16, macOff);
        byte[] full = cmac(smac, input);
        if (!Arrays.equals(
                Arrays.copyOf(full, macLen), Arrays.copyOfRange(wire, macOff, macOff + macLen))) {
            return null;
        }
        System.arraycopy(full, 0, chaining, 0, 16);
        byte[] data = Arrays.copyOfRange(wire, dataOff, macOff);
        if (cdec) {
            // Amendment D §6.2.6: the counter increments for every secured command
            increment(counter);
            if (data.length > 0) {
                if (data.length % 16 != 0) {
                    return null;
                }
                byte[] iv = cbc(true, counter, senc, new byte[16]);
                data = unpad80(cbc(false, data, senc, iv));
            }
        }
        byte[] inner = new byte[3 + data.length];
        inner[0] = wire[1];
        inner[1] = wire[2];
        inner[2] = wire[3];
        System.arraycopy(data, 0, inner, 3, data.length);
        return inner;
    }

    /**
     * PUT KEY: replaces the static ENC/MAC/DEK with the keys GPPro's {@code putKeys(keys, true)}
     * encodes (GPSession.encodeKey, GPSession.java:860-905): AES entries {@code 0x88 ‖ cgramLen+1 ‖
     * keyLen ‖ cgram ‖ kcvLen ‖ kcv} and DES3 entries {@code 0x80 ‖ cgramLen ‖ cgram ‖ kcvLen ‖
     * kcv} — GPPro labels 16-byte replacement keys DES3 unless they are >16 B or the key set
     * already knows the channel is SCP03 (PlaintextKeys.getKeyInfo). Both cryptograms are AES-CBC
     * under the static DEK. Each KCV is checked before the set is committed; returns the new key
     * bytes for the response KCVs or {@code null} on a format/KCV failure ({@code 6A80}).
     */
    byte[][] putKeys(byte[] data) {
        try {
            ByteArrayInputStream in = new ByteArrayInputStream(data);
            int newKvn = in.read();
            byte[][] keys = new byte[3][];
            for (int i = 0; i < 3; i++) {
                int type = in.read();
                int cgramLen;
                int keyLen;
                if (type == 0x88) {
                    cgramLen = in.read() - 1;
                    keyLen = in.read();
                } else if (type == 0x80) {
                    cgramLen = in.read();
                    keyLen = cgramLen;
                } else {
                    return null;
                }
                if (keyLen != 16 && keyLen != 24 && keyLen != 32) {
                    return null;
                }
                byte[] cgram = in.readNBytes(cgramLen);
                int kcvLen = in.read();
                byte[] kcv = in.readNBytes(kcvLen);
                if (cgram.length != cgramLen
                        || kcv.length != kcvLen
                        || cgramLen % 16 != 0
                        || cgramLen < keyLen) {
                    return null;
                }
                byte[] plain = cbc(false, cgram, dek, new byte[16]);
                byte[] key = Arrays.copyOf(plain, keyLen);
                // the KCV follows the declared key type: 3DES-ECB of 0x01s for
                // DES3-typed entries, AES-CBC for AES-typed (GPCrypto.kcv_3des/kcv_aes)
                byte[] expectedKcv = type == 0x80 ? kcv3des(key) : kcv(key);
                if (kcvLen != 0 && !Arrays.equals(Arrays.copyOf(expectedKcv, kcvLen), kcv)) {
                    return null;
                }
                keys[i] = key;
            }
            if (in.available() != 0) {
                return null;
            }
            enc = keys[0];
            mac = keys[1];
            dek = keys[2];
            kvn = newKvn;
            close();
            return keys;
        } catch (IOException | IndexOutOfBoundsException | IllegalArgumentException e) {
            return null;
        }
    }

    /** The response payload of PUT KEY: {@code newKvn ‖ KCV ‖ KCV ‖ KCV} (Amendment D §6.3). */
    byte[] kcvs(byte[][] keys) {
        byte[] out = new byte[1 + 9];
        out[0] = (byte) kvn;
        for (int i = 0; i < 3; i++) {
            System.arraycopy(kcv(keys[i]), 0, out, 1 + i * 3, 3);
        }
        return out;
    }

    private static byte[] kcv(byte[] key) {
        // Amendment D §6.2.4: AES-CBC of sixteen 0x01 bytes, first 3 bytes (GPCrypto.kcv_aes)
        return Arrays.copyOf(cbc(true, oneBytes(), key, new byte[16]), 3);
    }

    private static byte[] kcv3des(byte[] key) {
        // GP KCV for DES-typed keys: 3DES-ECB of eight zero bytes, first 3 bytes
        // (GPCrypto.kcv_3des — unlike the AES KCV it is not over 0x01s)
        try {
            byte[] k24 = new byte[24];
            System.arraycopy(key, 0, k24, 0, key.length);
            if (key.length == 16) {
                System.arraycopy(key, 0, k24, 16, 8);
            }
            Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k24, "DESede"));
            return Arrays.copyOf(cipher.doFinal(new byte[8]), 3);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] oneBytes() {
        byte[] b = new byte[16];
        Arrays.fill(b, (byte) 0x01);
        return b;
    }

    /**
     * Amendment D §6.2.4 KDF: CMAC counter-mode with an 8-bit counter, block A = 11 zero bytes ‖
     * constant ‖ 00 ‖ u16(bits) (GPCrypto.scp03_kdf, GPCrypto.java:211-240).
     */
    static byte[] kdf(byte[] key, int constant, byte[] context, int len) {
        byte[] a = new byte[15];
        a[11] = (byte) constant;
        a[13] = (byte) ((len * 8) >> 8);
        a[14] = (byte) (len * 8);
        CMac cmac = new CMac(AESEngine.newInstance());
        KDFCounterBytesGenerator generator = new KDFCounterBytesGenerator(cmac);
        generator.init(new KDFCounterParameters(key, a, context, 8));
        byte[] out = new byte[len];
        generator.generateBytes(out, 0, out.length);
        return out;
    }

    static byte[] cmac(byte[] key, byte[] data) {
        CMac cmac = new CMac(AESEngine.newInstance());
        cmac.init(new KeyParameter(key));
        cmac.update(data, 0, data.length);
        byte[] out = new byte[16];
        cmac.doFinal(out, 0);
        return out;
    }

    static byte[] cbc(boolean encrypt, byte[] data, byte[] key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(
                    encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new IvParameterSpec(iv));
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] cmacInput(int cla, int ins, int p1, int p2, int lc, byte[] data) {
        byte[] out = new byte[5 + data.length];
        out[0] = (byte) cla;
        out[1] = (byte) ins;
        out[2] = (byte) p1;
        out[3] = (byte) p2;
        out[4] = (byte) lc;
        System.arraycopy(data, 0, out, 5, data.length);
        return out;
    }

    private static byte[] unpad80(byte[] data) {
        for (int i = data.length - 1; i >= 0; i--) {
            if (data[i] == (byte) 0x80) {
                return Arrays.copyOf(data, i);
            }
            if (data[i] != 0) {
                throw new IllegalArgumentException("bad 0x80 padding");
            }
        }
        return new byte[0];
    }

    private static void increment(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            if (++counter[i] != 0) {
                return;
            }
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
