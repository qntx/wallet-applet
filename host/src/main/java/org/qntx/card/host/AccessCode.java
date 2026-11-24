// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * The access-code rules of spec/protocol.md §7.1: a code is 6–64 characters of printable ASCII
 * ({@code 0x20}–{@code 0x7E}), hashed with Argon2id (m = 65536 KiB, t = 3, p = 4, T = 32, version
 * 0x13, no secret, no associated data) over the per-card salt {@code "qntx-card/v1/access" ‖
 * ID(A)}.
 *
 * <p>Hosts: before sending a {@code VERIFY} when {@code STATUS} (§9.3) reports {@code tries = 1},
 * tell the user to keep the card in the field until the response arrives. T-FAIL is committed
 * before the comparison (§9.5), so a power loss during that {@code VERIFY} leaves {@code f = L} and
 * the next {@code VERIFY} erases the wallet although the code was right.
 */
public final class AccessCode {
    private static final byte[] LABEL = "qntx-card/v1/access".getBytes(StandardCharsets.US_ASCII);

    private AccessCode() {}

    /**
     * {@code accessHash = Argon2id(P = code, S = "qntx-card/v1/access" ‖ cardId, m = 65536, t = 3,
     * p = 4, T = 32)}.
     *
     * @throws IllegalArgumentException when the code is not 6–64 characters of {@code 0x20}–{@code
     *     0x7E} or {@code cardId} is not 16 bytes
     */
    public static byte[] hash(String code, byte[] cardId) {
        if (code == null || code.length() < 6 || code.length() > 64) {
            throw new IllegalArgumentException("access code must be 6–64 characters");
        }
        for (int i = 0; i < code.length(); i++) {
            char c = code.charAt(i);
            if (c < 0x20 || c > 0x7E) {
                throw new IllegalArgumentException("access code must be printable ASCII");
            }
        }
        if (cardId == null || cardId.length != 16) {
            throw new IllegalArgumentException("cardId must be 16 bytes");
        }
        byte[] salt = new byte[LABEL.length + cardId.length];
        System.arraycopy(LABEL, 0, salt, 0, LABEL.length);
        System.arraycopy(cardId, 0, salt, LABEL.length, cardId.length);
        Argon2BytesGenerator g = new Argon2BytesGenerator();
        g.init(
                new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                        .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                        .withMemoryAsKB(65536)
                        .withIterations(3)
                        .withParallelism(4)
                        .withSalt(salt)
                        .build());
        byte[] out = new byte[32];
        g.generateBytes(code.getBytes(StandardCharsets.UTF_8), out);
        return out;
    }
}
