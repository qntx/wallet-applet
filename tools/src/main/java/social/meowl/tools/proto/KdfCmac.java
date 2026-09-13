/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.proto;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Host-side mirror of the applet {@code Kdf} class: AES-CMAC-128–based KDF used by the meowl Secure
 * Channel.
 *
 * <p>Two-stage extract-then-expand construction:
 *
 * <ul>
 *   <li><b>Extract</b>: {@code K_extract = sha256(salt)[0..16]} when the salt exceeds 16 bytes,
 *       else the salt zero-padded to 16 bytes. Then {@code PRK = AES-CMAC(K_extract, IKM)} (16
 *       bytes).
 *   <li><b>Expand</b>: NIST SP 800-108 KBKDF feedback-mode iteration over AES-CMAC; {@code T(i) =
 *       AES-CMAC(PRK, T(i-1) ‖ info ‖ counter_byte_i)}, {@code OKM = T(1) ‖ T(2) ‖ … ‖ T(N)}.
 * </ul>
 *
 * <p>Implementation: BouncyCastle's {@code AESCMAC} via {@link Mac#getInstance(String,
 * java.security.Provider)}; the JDK does not ship a CMAC primitive directly. The provider is
 * registered statically by {@link HostCrypto}, so callers do not need to bootstrap it.
 *
 * <p>See {@code applet/.../Kdf.java} for the on-card counterpart and {@code notes/specs/protocol.md}
 * §6.2 for the wire-protocol context.
 */
public final class KdfCmac {

    /** AES-CMAC-128 output (and PRK) length, in bytes. */
    public static final int BLOCK_LEN = 16;

    /** Hard ceiling on a single {@link #expand} call: {@code 255 × 16 = 4080} bytes. */
    public static final int MAX_LEN = 255 * BLOCK_LEN;

    private KdfCmac() {}

    /**
     * Derives the 16-byte PRK from {@code salt ‖ ikm}.
     *
     * @param salt may be {@code null} or empty (treated as the 16-byte zero buffer)
     * @param ikm input keying material
     * @return 16-byte pseudorandom key
     */
    public static byte[] extract(byte[] salt, byte[] ikm) {
        Objects.requireNonNull(ikm, "ikm");
        byte[] extractKey = compressSaltToKey(salt);
        try {
            Mac mac = Mac.getInstance("AESCMAC", BouncyCastleProvider.PROVIDER_NAME);
            mac.init(new SecretKeySpec(extractKey, "AES"));
            return mac.doFinal(ikm);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-CMAC-128 unavailable", e);
        } finally {
            Arrays.fill(extractKey, (byte) 0);
        }
    }

    /**
     * Compresses an arbitrary-length salt to a 16-byte AES-CMAC-128 key.
     *
     * <ul>
     *   <li>{@code null} or empty: 16-byte zero buffer
     *   <li>1..16 bytes: zero-padded to 16 bytes (low bytes hold the salt)
     *   <li>{@code > 16} bytes: {@code SHA-256(salt)[0..16]}
     * </ul>
     */
    private static byte[] compressSaltToKey(byte[] salt) {
        byte[] key = new byte[BLOCK_LEN];
        if (salt == null || salt.length == 0) {
            return key;
        }
        if (salt.length <= BLOCK_LEN) {
            System.arraycopy(salt, 0, key, 0, salt.length);
            return key;
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(salt);
            System.arraycopy(digest, 0, key, 0, BLOCK_LEN);
            Arrays.fill(digest, (byte) 0);
            return key;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * Derives {@code length} bytes of OKM from {@code prk}. Matches the on-card {@code Kdf#expand}:
     * {@code T(i) = AES-CMAC(PRK, T(i-1) ‖ info ‖ counter_byte_i)}.
     *
     * @param prk 16-byte PRK from {@link #extract}
     * @param info optional context-and-application label; may be {@code null}
     * @param length desired output length in bytes; {@code 0 ≤ length ≤ 255 × 16}
     */
    public static byte[] expand(byte[] prk, byte[] info, int length) {
        Objects.requireNonNull(prk, "prk");
        if (prk.length != BLOCK_LEN) {
            throw new IllegalArgumentException(
                    "PRK must be %d bytes, got %d".formatted(BLOCK_LEN, prk.length));
        }
        if (length < 0 || length > MAX_LEN) {
            throw new IllegalArgumentException(
                    "Kdf-Expand length out of range: %d (max %d)".formatted(length, MAX_LEN));
        }
        byte[] effectiveInfo = info == null ? new byte[0] : info;

        Mac mac;
        try {
            mac = Mac.getInstance("AESCMAC", BouncyCastleProvider.PROVIDER_NAME);
            mac.init(new SecretKeySpec(prk, "AES"));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-CMAC-128 unavailable", e);
        }

        byte[] out = new byte[length];
        byte[] previous = new byte[0];
        int blocks = (length + BLOCK_LEN - 1) / BLOCK_LEN;
        int written = 0;
        for (int i = 1; i <= blocks; i++) {
            mac.update(previous);
            mac.update(effectiveInfo);
            mac.update((byte) i);
            byte[] next = mac.doFinal();
            // Scrub each intermediate T(i-1); the last block is scrubbed by the post-loop fill.
            Arrays.fill(previous, (byte) 0);
            previous = next;
            int copyLen = Math.min(BLOCK_LEN, length - written);
            System.arraycopy(previous, 0, out, written, copyLen);
            written += copyLen;
        }
        Arrays.fill(previous, (byte) 0);
        return out;
    }
}
