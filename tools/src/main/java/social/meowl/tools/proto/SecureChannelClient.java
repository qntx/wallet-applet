/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.proto;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBOException;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * Host-side client for the meowl Secure Channel. One instance corresponds to one open session,
 * identified by the ephemeral keypair generated at {@link #handshake} time.
 *
 * <p>Wire layout (see {@code notes/specs/protocol.md} §6):
 *
 * <ul>
 *   <li>handshake: {@code [client_eph_pub(65)]} → {@code [card_eph_pub(65) | sigLen(2 BE) | sig]}
 *   <li>KDF salt = {@code client_eph_x ‖ card_eph_x} (64 bytes)
 *   <li>KDF info = ASCII {@code "meowl-sc-v1"} (11 bytes)
 *   <li>KDF L = 64 bytes → {@code K_enc(32) ‖ K_mac(16) ‖ IV_base(16)}
 *   <li>inbound MAC = AES-CMAC-128(K_mac, [CLA INS P1 P2 LC] ‖ IV ‖ CT)
 *   <li>outbound MAC = AES-CMAC-128(K_mac, 0xFF ‖ IV ‖ CT)
 * </ul>
 *
 * <p>Keys live in plain Java fields; the JDK offers no reliable {@code byte[]} scrubbing, so we do
 * not attempt cryptographic memory hygiene on the host.
 */
public final class SecureChannelClient {

    /** {@code CLA = 0x80} for every meowl-applet APDU per protocol.md §1. */
    public static final int CLA_MEOWL = 0x80;

    /** {@code INS = 0x10} — INIT_SECURE_CHANNEL, protocol.md §6.1. */
    public static final int INS_INIT_SC = 0x10;

    /** {@code INS = 0x11} — OPEN_SECURE_CHANNEL, protocol.md §6.3. */
    public static final int INS_OPEN_SC = 0x11;

    /** KDF info label, protocol.md §6.2. */
    public static final byte[] KDF_INFO = "meowl-sc-v1".getBytes(StandardCharsets.UTF_8);

    /** KDF output length: K_enc(32) + K_mac(16) + IV_base(16) = 64 bytes. */
    private static final int KDF_OKM_LEN =
            HostCrypto.AES_KEY_LEN + HostCrypto.MAC_KEY_LEN + HostCrypto.AES_BLOCK_LEN;

    /** Outbound MAC's direction-tag, fixed at 0xFF (protocol.md §6.3, outbound). */
    private static final byte OUTBOUND_DIRECTION_TAG = (byte) 0xFF;

    private final APDUBIBO bibo;
    private final byte[] authentikeyCompressed;

    private byte[] kEnc;
    private byte[] kMac;
    private byte[] ivBase;
    private byte[] clientEphPub;
    private byte[] cardEphPub;
    private byte[] handshakeSignature;
    private long inboundCounter;
    private long lastOutboundCounter;
    private boolean invalidated;
    private Handshake lastHandshake;

    /**
     * @param bibo the underlying APDU transport (typically a decorated PC/SC channel)
     * @param authentikeyCompressed the card's 33-byte compressed authentikey, used to verify the
     *     handshake signature
     */
    public SecureChannelClient(APDUBIBO bibo, byte[] authentikeyCompressed) {
        this.bibo = Objects.requireNonNull(bibo, "bibo");
        if (authentikeyCompressed.length != HostCrypto.EC_POINT_COMPRESSED_LEN) {
            throw new IllegalArgumentException(
                    "authentikey must be %d compressed bytes"
                            .formatted(HostCrypto.EC_POINT_COMPRESSED_LEN));
        }
        this.authentikeyCompressed = authentikeyCompressed.clone();
    }

    /**
     * Convenience factory that constructs a client and immediately drives the handshake, returning
     * the connected client ready for {@link #sendInner}. Equivalent to {@code new
     * SecureChannelClient(bibo, authentikey)} followed by {@link #handshake()}.
     *
     * @throws SecureChannelException on any wire or cryptographic failure during the handshake
     */
    public static SecureChannelClient open(APDUBIBO bibo, byte[] authentikeyCompressed)
            throws BIBOException {
        SecureChannelClient client = new SecureChannelClient(bibo, authentikeyCompressed);
        client.handshake();
        return client;
    }

    /**
     * Drives the {@code INIT_SECURE_CHANNEL} handshake, verifies the card's ECDSA signature with
     * the supplied authentikey, and derives the session keys.
     *
     * @return a snapshot of the session state (also accessible via {@link #cardEphPub} / {@link
     *     #handshakeSignature})
     * @throws SecureChannelException on any wire or cryptographic failure
     */
    public Handshake handshake() throws BIBOException {
        var keys = HostCrypto.generateEphKeyPair();
        clientEphPub = keys.publicEncoded();

        ResponseAPDU resp =
                bibo.transmit(new CommandAPDU(CLA_MEOWL, INS_INIT_SC, 0x00, 0x00, clientEphPub));
        if (resp.getSW() != 0x9000) {
            throw new SecureChannelException(
                    resp.getSW(), "INIT_SECURE_CHANNEL failed (SW=0x%04X)".formatted(resp.getSW()));
        }

        byte[] body = resp.getData();
        if (body.length < HostCrypto.EC_POINT_UNCOMPRESSED_LEN + 2) {
            throw new SecureChannelException(
                    0,
                    "Handshake response too short: %d bytes (need at least %d)"
                            .formatted(body.length, HostCrypto.EC_POINT_UNCOMPRESSED_LEN + 2));
        }

        cardEphPub = Arrays.copyOfRange(body, 0, HostCrypto.EC_POINT_UNCOMPRESSED_LEN);
        // Validate the SEC1 0x04 prefix here so a wire-format mismatch surfaces with a clear
        // diagnostic instead of an ECDH-side IllegalArgumentException further downstream.
        if ((cardEphPub[0] & 0xFF) != 0x04) {
            throw new SecureChannelException(
                    0,
                    "card ephemeral pubkey lacks the SEC1-uncompressed 0x04 prefix (got 0x%02X)"
                            .formatted(cardEphPub[0] & 0xFF));
        }
        int sigLen =
                ((body[HostCrypto.EC_POINT_UNCOMPRESSED_LEN] & 0xFF) << 8)
                        | (body[HostCrypto.EC_POINT_UNCOMPRESSED_LEN + 1] & 0xFF);
        if (body.length != HostCrypto.EC_POINT_UNCOMPRESSED_LEN + 2 + sigLen) {
            throw new SecureChannelException(
                    0,
                    "Handshake response length mismatch: declared sigLen %d but body has %d trailing bytes"
                            .formatted(
                                    sigLen,
                                    body.length - HostCrypto.EC_POINT_UNCOMPRESSED_LEN - 2));
        }
        handshakeSignature =
                Arrays.copyOfRange(
                        body,
                        HostCrypto.EC_POINT_UNCOMPRESSED_LEN + 2,
                        HostCrypto.EC_POINT_UNCOMPRESSED_LEN + 2 + sigLen);

        // The signature must verify against [card_eph_pub || client_eph_pub] under authentikey.
        byte[] signedMessage = HostCrypto.concat(cardEphPub, clientEphPub);
        if (!HostCrypto.verifyEcdsaSecp256k1(
                authentikeyCompressed, signedMessage, handshakeSignature)) {
            throw new SecureChannelException(
                    0, "authentikey ECDSA signature verification failed during handshake");
        }

        // ECDH on the host side and AES-CMAC-based KDF schedule.
        byte[] sharedX = HostCrypto.ecdhSharedX(keys.privateScalar(), cardEphPub);
        byte[] clientX = keys.xCoordinate();
        byte[] cardX = Arrays.copyOfRange(cardEphPub, 1, 1 + HostCrypto.EC_SCALAR_LEN);
        byte[] salt = HostCrypto.concat(clientX, cardX);
        byte[] prk = KdfCmac.extract(salt, sharedX);
        byte[] okm = KdfCmac.expand(prk, KDF_INFO, KDF_OKM_LEN);
        kEnc = Arrays.copyOfRange(okm, 0, HostCrypto.AES_KEY_LEN);
        kMac =
                Arrays.copyOfRange(
                        okm,
                        HostCrypto.AES_KEY_LEN,
                        HostCrypto.AES_KEY_LEN + HostCrypto.MAC_KEY_LEN);
        ivBase =
                Arrays.copyOfRange(
                        okm, HostCrypto.AES_KEY_LEN + HostCrypto.MAC_KEY_LEN, KDF_OKM_LEN);
        inboundCounter = 0L;
        // Card increments outboundCounter to 1 before the first wrap; lastOutboundCounter
        // starts at 0 so the strict-greater check accepts the first IV.
        lastOutboundCounter = 0L;
        invalidated = false;

        lastHandshake =
                new Handshake(cardEphPub.clone(), handshakeSignature.clone(), ivBase.clone());
        return lastHandshake;
    }

    /**
     * Encrypts {@code innerApdu}, sends it inside an {@code OPEN_SECURE_CHANNEL} envelope, and
     * returns the decrypted inner response. The outer SW must be {@code 0x9000} — any other value
     * triggers {@link SecureChannelException}.
     */
    public byte[] sendInner(byte[] innerApdu) throws BIBOException {
        requireSession();
        Objects.requireNonNull(innerApdu, "innerApdu");

        inboundCounter++;
        byte[] iv = ivFromCounter(inboundCounter);
        byte[] ciphertext = HostCrypto.aesCbcEncrypt(kEnc, iv, innerApdu);

        int lc = iv.length + ciphertext.length + HostCrypto.MAC_LEN;
        // Secure Channel envelopes ride short-form APDUs; if lc exceeds the single-byte LC field,
        // the
        // host's MAC input (which packs lc into one byte) would diverge from what the card sees
        // and the envelope would be silently rejected with an obscure MAC mismatch.
        if (lc > 0xFF) {
            throw new SecureChannelException(
                    0,
                    "Envelope too large for short-form APDU: LC = "
                            + lc
                            + " bytes (max 255). Reduce the inner APDU size.");
        }
        byte[] header = {(byte) CLA_MEOWL, (byte) INS_OPEN_SC, 0x00, 0x00, (byte) lc};
        byte[] mac = HostCrypto.aesCmac128(kMac, header, iv, ciphertext);

        byte[] envelope = HostCrypto.concat(iv, ciphertext, mac);
        ResponseAPDU resp =
                bibo.transmit(new CommandAPDU(CLA_MEOWL, INS_OPEN_SC, 0x00, 0x00, envelope));
        if (resp.getSW() != 0x9000) {
            // The card has already torn down its session; mirror that on the host so a
            // subsequent sendInner() fails fast rather than encrypting under stale keys.
            invalidate();
            throw new SecureChannelException(
                    resp.getSW(),
                    "OPEN_SECURE_CHANNEL rejected by card (SW=0x%04X)".formatted(resp.getSW()));
        }
        return decryptOutbound(resp.getData());
    }

    /**
     * Frames {@code [CLA_MEOWL | ins | p1 | p2 | lc | data]} into an inner APDU and sends it
     * through the Secure Channel. Convenience over {@link #sendInner(byte[])} for the common case
     * of a single inner-band command with a known INS, removing per-caller APDU-framing
     * boilerplate.
     */
    public byte[] sendInner(int ins, int p1, int p2, byte[] data) throws BIBOException {
        Objects.requireNonNull(data, "data");
        if (data.length > 0xFF) {
            throw new IllegalArgumentException(
                    "inner APDU data exceeds the single-byte LC field: " + data.length + " bytes");
        }
        byte[] inner = new byte[5 + data.length];
        inner[0] = (byte) CLA_MEOWL;
        inner[1] = (byte) ins;
        inner[2] = (byte) p1;
        inner[3] = (byte) p2;
        inner[4] = (byte) data.length;
        System.arraycopy(data, 0, inner, 5, data.length);
        return sendInner(inner);
    }

    /** Returns the card's ephemeral public key (SEC1 uncompressed, 65 bytes). */
    public byte[] cardEphPub() {
        requireSession();
        return cardEphPub.clone();
    }

    /** Returns the DER-encoded handshake signature surfaced by the card. */
    public byte[] handshakeSignature() {
        requireSession();
        return handshakeSignature.clone();
    }

    /** Returns the IV base derived during handshake (16 bytes). */
    public byte[] ivBase() {
        requireSession();
        return ivBase.clone();
    }

    /** The handshake snapshot from the most recent {@link #handshake()} / {@link #open}. */
    public Handshake lastHandshake() {
        requireSession();
        return lastHandshake;
    }

    /** Snapshot of the per-handshake state, returned by {@link #handshake}. */
    public record Handshake(byte[] cardEphPub, byte[] signatureDer, byte[] ivBase) {

        public Handshake {
            Objects.requireNonNull(cardEphPub, "cardEphPub");
            Objects.requireNonNull(signatureDer, "signatureDer");
            Objects.requireNonNull(ivBase, "ivBase");
        }
    }

    private void requireSession() {
        if (invalidated) {
            throw new IllegalStateException(
                    "Secure Channel session has been invalidated by a prior cryptographic"
                            + " failure — call handshake() again to open a fresh session");
        }
        if (kEnc == null) {
            throw new IllegalStateException("no Secure Channel session — call handshake() first");
        }
    }

    /**
     * Wipes the host-side session keys and marks the session invalidated; subsequent {@link
     * #sendInner} calls fail fast with {@link IllegalStateException}. Called on any cryptographic
     * failure so further sends do not produce a confusing chain of MAC mismatches.
     */
    private void invalidate() {
        if (kEnc != null) Arrays.fill(kEnc, (byte) 0);
        if (kMac != null) Arrays.fill(kMac, (byte) 0);
        if (ivBase != null) Arrays.fill(ivBase, (byte) 0);
        kEnc = null;
        kMac = null;
        ivBase = null;
        invalidated = true;
    }

    /**
     * Builds the inbound IV from a 64-bit counter: counter occupies the low 8 bytes of a 16-byte
     * big-endian buffer, high 8 bytes zero. This makes the IV monotonic for the card's strict
     * {@code IV > last_inbound_IV} check.
     */
    private static byte[] ivFromCounter(long counter) {
        byte[] iv = new byte[HostCrypto.AES_BLOCK_LEN];
        for (int i = 0; i < 8; i++) {
            iv[HostCrypto.AES_BLOCK_LEN - 1 - i] = (byte) ((counter >>> (8 * i)) & 0xFF);
        }
        return iv;
    }

    private byte[] decryptOutbound(byte[] envelope) {
        if (envelope.length < HostCrypto.AES_BLOCK_LEN + HostCrypto.MAC_LEN
                || (envelope.length - HostCrypto.AES_BLOCK_LEN - HostCrypto.MAC_LEN)
                                % HostCrypto.AES_BLOCK_LEN
                        != 0) {
            throw new SecureChannelException(
                    0, "Outbound envelope length is malformed: " + envelope.length);
        }
        byte[] iv = Arrays.copyOfRange(envelope, 0, HostCrypto.AES_BLOCK_LEN);
        byte[] ciphertext =
                Arrays.copyOfRange(
                        envelope, HostCrypto.AES_BLOCK_LEN, envelope.length - HostCrypto.MAC_LEN);
        byte[] mac =
                Arrays.copyOfRange(envelope, envelope.length - HostCrypto.MAC_LEN, envelope.length);

        // MAC = AES-CMAC-128(K_mac, 0xFF || IV || ciphertext).
        byte[] expected =
                HostCrypto.aesCmac128(kMac, new byte[] {OUTBOUND_DIRECTION_TAG}, iv, ciphertext);
        if (!constantTimeEquals(mac, expected)) {
            invalidate();
            throw new SecureChannelException(0, "outbound envelope MAC mismatch");
        }

        // Defence in depth: the outbound counter packed into IV ⊕ IV_base must be strictly
        // greater than the previously observed one. The MAC check already gates on integrity,
        // but a compromised silicon could replay; mirror the card's strict-greater rule here.
        long observed = extractOutboundCounter(iv, ivBase);
        if (Long.compareUnsigned(observed, lastOutboundCounter) <= 0) {
            invalidate();
            throw new SecureChannelException(
                    0,
                    "outbound IV counter regressed: observed "
                            + Long.toUnsignedString(observed)
                            + " <= last "
                            + Long.toUnsignedString(lastOutboundCounter));
        }
        lastOutboundCounter = observed;

        return HostCrypto.aesCbcDecrypt(kEnc, iv, ciphertext);
    }

    /**
     * Recovers the 64-bit outbound counter from the IV. The card encodes {@code IV = IV_base XOR
     * counter} with the counter in the low 8 bytes (high 8 zero); XOR-ing with {@code IV_base}
     * reverses the mask.
     */
    private static long extractOutboundCounter(byte[] iv, byte[] ivBase) {
        long counter = 0L;
        for (int i = 0; i < 8; i++) {
            int byteIndex = HostCrypto.AES_BLOCK_LEN - 8 + i;
            int unmasked = (iv[byteIndex] & 0xFF) ^ (ivBase[byteIndex] & 0xFF);
            counter = (counter << 8) | unmasked;
        }
        return counter;
    }

    /** Constant-time equality; mirrors the applet-side {@code ConstantTime.equals}. */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= (a[i] ^ b[i]) & 0xFF;
        }
        return diff == 0;
    }
}
