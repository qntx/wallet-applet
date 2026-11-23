// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The host side of the §9.12–9.14 transfer commands (§11.2): encoders for the inner command data
 * and decoders that check a response before it is relayed. {@link #decodeOffer} and {@link
 * #decodeExportHead} verify the card signatures a relay would otherwise forward unchecked — a
 * failure is a {@link CardNotGenuineException}, like the certificate checks of {@link Open}.
 */
public final class Transfer {
    /** The §9.12 offer signature label, ASCII without terminator. */
    public static final byte[] LABEL_OFFER =
            "qntx-card/v1/offer".getBytes(StandardCharsets.US_ASCII);

    /** The §9.13 export transcript label, ASCII without terminator. */
    public static final byte[] LABEL_EXPORT =
            "qntx-card/v1/export".getBytes(StandardCharsets.US_ASCII);

    private Transfer() {}

    /** A decoded {@code OFFER} response: the link public key and its identity signature. */
    public record Offer(byte[] lk, byte[] sig) {}

    /** A decoded {@code EXPORT P1 = 0x00} response: the ephemeral point and its signature. */
    public record ExportHead(byte[] e, byte[] sig) {}

    /** A decoded {@code EXPORT P1 = 0x01} response: the encrypted payload and its tag. */
    public record ExportPayload(byte[] ct, byte[] tag) {}

    /** {@code OFFER} command data: empty (§9.12). */
    public static byte[] offer() {
        return new byte[0];
    }

    /** {@code EXPORT P1 = 0x00} command data: {@code cert_T(97) ‖ offer(129)} (§9.13). */
    public static byte[] export0(byte[] certT, byte[] offer) {
        check(certT, 97, "certT");
        check(offer, 129, "offer");
        byte[] data = new byte[226];
        System.arraycopy(certT, 0, data, 0, 97);
        System.arraycopy(offer, 0, data, 97, 129);
        return data;
    }

    /** {@code EXPORT P1 = 0x01} command data: {@code accessHash_T(32)} (§9.13). */
    public static byte[] export1(byte[] accessHashT) {
        check(accessHashT, 32, "accessHashT");
        return accessHashT.clone();
    }

    /** {@code IMPORT P1 = 0x00} command data: {@code cert_S(97) ‖ exportHead(129)} (§9.14). */
    public static byte[] import0(byte[] certS, byte[] exportHead) {
        check(certS, 97, "certS");
        check(exportHead, 129, "exportHead");
        byte[] data = new byte[226];
        System.arraycopy(certS, 0, data, 0, 97);
        System.arraycopy(exportHead, 0, data, 97, 129);
        return data;
    }

    /** {@code IMPORT P1 = 0x01} command data: {@code ct ‖ tag} of 160 or 176 bytes (§9.14). */
    public static byte[] import1(byte[] payload) {
        if (payload == null || (payload.length != 160 && payload.length != 176)) {
            throw new IllegalArgumentException("payload must be 160 or 176 bytes");
        }
        return payload.clone();
    }

    /**
     * Decodes an {@code OFFER} response (§9.12): {@code LK(65) ‖ sig_T(64)}. Verifies the signature
     * under the identity {@code A_T} of the target's certificate — the host check before the offer
     * is relayed to the source ({@code host.md} §1). Throws {@link CardNotGenuineException} on a
     * malformed response or a bad signature.
     */
    public static Offer decodeOffer(byte[] resp, byte[] certT) throws CardNotGenuineException {
        check(certT, 97, "certT");
        if (resp == null || resp.length != 129 || resp[0] != 0x04) {
            throw new CardNotGenuineException("malformed OFFER response");
        }
        byte[] lk = Arrays.copyOf(resp, 65);
        byte[] sig = Arrays.copyOfRange(resp, 65, 129);
        byte[] m = concat(LABEL_OFFER, lk);
        if (!Crypto.verify(Crypto.decompress(Arrays.copyOf(certT, 33)), Crypto.sha256(m), sig)) {
            throw new CardNotGenuineException("OFFER signature does not verify");
        }
        return new Offer(lk, sig);
    }

    /**
     * Decodes an {@code EXPORT P1 = 0x00} response (§9.13): {@code E(65) ‖ sig_S(64)}. Verifies
     * {@code sig_S} under the source's identity {@code A_S} over the transcript {@code M =
     * "qntx-card/v1/export" ‖ A_S ‖ A_T ‖ LK_T ‖ E}. Throws {@link CardNotGenuineException} on a
     * malformed response or a bad signature.
     */
    public static ExportHead decodeExportHead(byte[] resp, byte[] certS, byte[] certT, byte[] lkT)
            throws CardNotGenuineException {
        check(certS, 97, "certS");
        check(certT, 97, "certT");
        check(lkT, 65, "lkT");
        if (resp == null || resp.length != 129 || resp[0] != 0x04) {
            throw new CardNotGenuineException("malformed EXPORT response");
        }
        byte[] e = Arrays.copyOf(resp, 65);
        byte[] sig = Arrays.copyOfRange(resp, 65, 129);
        byte[] m = concat(LABEL_EXPORT, Arrays.copyOf(certS, 33), Arrays.copyOf(certT, 33), lkT, e);
        if (!Crypto.verify(Crypto.decompress(Arrays.copyOf(certS, 33)), Crypto.sha256(m), sig)) {
            throw new CardNotGenuineException("EXPORT signature does not verify");
        }
        return new ExportHead(e, sig);
    }

    /**
     * Decodes an {@code EXPORT P1 = 0x01} response (§9.13): {@code ct(144 ‖ 160) ‖ tag(16)}. Length
     * is the only host check — the target's CMAC check authenticates the content.
     */
    public static ExportPayload decodeExportPayload(byte[] resp) throws CardNotGenuineException {
        if (resp == null || (resp.length != 160 && resp.length != 176)) {
            throw new CardNotGenuineException("malformed export payload");
        }
        return new ExportPayload(
                Arrays.copyOf(resp, resp.length - 16),
                Arrays.copyOfRange(resp, resp.length - 16, resp.length));
    }

    private static void check(byte[] v, int len, String what) {
        if (v == null || v.length != len) {
            throw new IllegalArgumentException(what + " must be " + len + " bytes");
        }
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }
}
