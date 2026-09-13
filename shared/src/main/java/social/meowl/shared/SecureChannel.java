/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.shared;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Implements the meowl Secure Channel as specified in {@code notes/specs/protocol.md} §6.
 *
 * <h2>Handshake (INS 0x10)</h2>
 *
 * <pre>
 *   Host  → Card : client_eph_pub_uncompressed (65 bytes, secp256k1)
 *   Card        : 1. eph_card = genKeyPair(secp256k1)      (transient)
 *                 2. shared    = ECDH_xy(eph_card_priv, client_eph_pub)
 *                 3. PRK       = Kdf-Extract(salt=client_x ‖ card_x, ikm=shared_x)  (CMAC)
 *                 4. okm       = Kdf-Expand(PRK, info="meowl-sc-v1", L=64)         (CMAC)
 *                                K_enc(32) ‖ K_mac(16) ‖ IV_base(16)
 *                 5. sig       = ECDSA-SHA256(authentikey_priv,
 *                                             eph_card_pub ‖ client_eph_pub)
 *   Card  → Host : eph_card_pub_uncompressed (65) ‖ sigLen (2 BE) ‖ sig (DER, variable)
 * </pre>
 *
 * <h2>Inbound envelope (INS 0x11)</h2>
 *
 * <pre>
 *   APDU = [CLA INS P1 P2 LC]  IV(16)  ciphertext(N×16)  MAC(16)
 *     MAC = AES-CMAC-128(K_mac, [CLA INS P1 P2 LC] ‖ IV ‖ ciphertext)
 *   The IV must strictly exceed the previously accepted IV (replay defense).
 *   plaintext = AES-256-CBC-decrypt(K_enc, IV, ciphertext) with PKCS#5 padding.
 * </pre>
 *
 * <h2>Outbound envelope</h2>
 *
 * <pre>
 *   response = IV(16) ‖ ciphertext(N×16) ‖ MAC(16)
 *     MAC = AES-CMAC-128(K_mac, 0xFF ‖ IV ‖ ciphertext)
 *     IV  = IV_base XOR monotonic_counter (16 bytes)
 * </pre>
 *
 * <p>The handshake stages its inputs in a dedicated transient scratch buffer ({@link #hsScratch})
 * rather than in the APDU buffer, because the working set during ECDH + KDF + ECDSA-sign exceeds
 * the 261-byte short APDU buffer typical of contemporary silicon.
 *
 * <p>All session keys, IVs, replay counters and the open-flag live in {@link
 * JCSystem#CLEAR_ON_DESELECT} transient memory — a deselect tears the session down automatically.
 * The explicit {@link #reset()} called from {@link WalletApplet#select} acts as a belt-and-braces.
 */
public final class SecureChannel {

    /** Required size of the client ephemeral public key (uncompressed SEC1). */
    private static final short CLIENT_EPH_PUB_LEN = Constants.EC_POINT_UNCOMPRESSED_LEN;

    /** {@code K_enc(32) ‖ K_mac(16) ‖ IV_base(16)} layout produced by {@link Kdf#expand}. */
    private static final short OKM_LEN =
            (short) (Constants.SC_ENC_KEY_LEN + Constants.SC_MAC_KEY_LEN + Constants.SC_BLOCK_LEN);

    /** Offset of {@code K_mac} inside {@link #okm}. */
    private static final short OKM_MAC_OFFSET = Constants.SC_ENC_KEY_LEN;

    /** Offset of {@code IV_base} inside {@link #okm}. */
    private static final short OKM_IV_OFFSET =
            (short) (Constants.SC_ENC_KEY_LEN + Constants.SC_MAC_KEY_LEN);

    /** Handshake scratch layout (all sizes in bytes). */
    private static final short HS_CLIENT_PUB = (short) 0; // 65

    private static final short HS_CARD_PUB =
            (short) (HS_CLIENT_PUB + CLIENT_EPH_PUB_LEN); // 65 → ends 130
    private static final short HS_SHARED =
            (short) (HS_CARD_PUB + CLIENT_EPH_PUB_LEN); // 65 → ends 195
    private static final short HS_SALT = (short) (HS_SHARED + CLIENT_EPH_PUB_LEN); // 64 → ends 259
    private static final short HS_SCRATCH_LEN = (short) (HS_SALT + (Constants.EC_SCALAR_LEN * 2));

    /**
     * Minimum length of the shared handshake scratch buffer a caller must supply to the
     * constructor. Exposed so applets can size their shared transient buffer without hard-coding
     * the internal handshake layout.
     */
    public static final short MIN_SCRATCH_LEN = HS_SCRATCH_LEN;

    /** Application-binding label for {@link Kdf#expand}. */
    private static final byte[] KDF_INFO = {
        (byte) 'm',
        (byte) 'e',
        (byte) 'o',
        (byte) 'w',
        (byte) 'l',
        (byte) '-',
        (byte) 's',
        (byte) 'c',
        (byte) '-',
        (byte) 'v',
        (byte) '1',
    };

    /** Single-byte response-direction header fed to the outbound MAC. */
    private static final byte[] RESP_HEADER = {(byte) 0xFF};

    private final Authentikey authentikey;
    private final Kdf kdf;

    private final KeyPair ephKeypair;
    private final KeyAgreement ecdh;
    private final AESKey encKey;

    /** Session MAC key {@code K_mac} (CLEAR_ON_DESELECT, 128-bit AES key for CMAC-128). */
    private final AESKey macKey;

    /** AES-CMAC-128 engine driving every envelope MAC. J3R180-native, ~76 µs/call. */
    private final Signature macSig;

    private final Cipher aesCbc;
    private final Signature ecdsa;

    /** {@code K_enc ‖ K_mac ‖ IV_base} scratch produced by {@link Kdf#expand}. */
    private final byte[] okm;

    /** Last accepted inbound IV. Strictly-increasing IVs defeat replay. */
    private final byte[] lastInboundIv;

    /** Monotonic counter feeding the next outbound IV. */
    private final byte[] outboundCounter;

    /** Scratch buffer for the AES-CMAC-128 tag (16 bytes). */
    private final byte[] macScratch;

    /** Handshake working scratch (sized for KDF salt + shared + both pubkeys). */
    private final byte[] hsScratch;

    /** Single-byte open flag (transient). */
    private final byte[] openFlag;

    /**
     * @param sharedScratch singleton transient buffer of at least {@link #HS_SCRATCH_LEN} bytes,
     *     repurposed as handshake scratch; reused by {@link EcdsaK1}, {@link Schnorr} and {@link
     *     Ed25519} since APDU dispatch is single-threaded
     */
    public SecureChannel(Authentikey authentikey, byte[] sharedScratch) {
        if ((short) sharedScratch.length < HS_SCRATCH_LEN) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        this.authentikey = authentikey;
        this.kdf = new Kdf();

        this.ephKeypair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        Secp256k1Curve.setCurveParameters((ECPrivateKey) ephKeypair.getPrivate());
        Secp256k1Curve.setCurveParameters((ECPublicKey) ephKeypair.getPublic());

        this.ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        this.aesCbc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        this.ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        this.macSig = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);

        // CLEAR_ON_DESELECT for every session-scoped buffer — standard SCP lifecycle, and a hard
        // requirement on cards (J3R180) whose CLEAR_ON_RESET pool is too small.
        this.encKey =
                (AESKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                                KeyBuilder.LENGTH_AES_256,
                                false);
        this.macKey =
                (AESKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                                KeyBuilder.LENGTH_AES_128,
                                false);

        this.okm = JCSystem.makeTransientByteArray(OKM_LEN, JCSystem.CLEAR_ON_DESELECT);
        this.lastInboundIv =
                JCSystem.makeTransientByteArray(Constants.SC_BLOCK_LEN, JCSystem.CLEAR_ON_DESELECT);
        this.outboundCounter =
                JCSystem.makeTransientByteArray(Constants.SC_BLOCK_LEN, JCSystem.CLEAR_ON_DESELECT);
        this.macScratch =
                JCSystem.makeTransientByteArray(Constants.SC_MAC_LEN, JCSystem.CLEAR_ON_DESELECT);
        this.hsScratch = sharedScratch;
        this.openFlag = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    }

    /** Whether a Secure Channel session is currently open. */
    private boolean isOpen() {
        return openFlag[0] != 0;
    }

    /** Tears down the session, clearing all derived keys and counters. */
    public void reset() {
        encKey.clearKey();
        macKey.clearKey();
        kdf.reset();
        Util.arrayFillNonAtomic(okm, (short) 0, OKM_LEN, (byte) 0);
        Util.arrayFillNonAtomic(lastInboundIv, (short) 0, Constants.SC_BLOCK_LEN, (byte) 0);
        Util.arrayFillNonAtomic(outboundCounter, (short) 0, Constants.SC_BLOCK_LEN, (byte) 0);
        Util.arrayFillNonAtomic(macScratch, (short) 0, Constants.SC_MAC_LEN, (byte) 0);
        Util.arrayFillNonAtomic(hsScratch, (short) 0, HS_SCRATCH_LEN, (byte) 0);
        openFlag[0] = 0;
    }

    /**
     * Handles {@code INS_INIT_SECURE_CHANNEL}. Reads the client ephemeral pubkey from the APDU data
     * field, generates a fresh card ephemeral keypair, derives session keys, signs the
     * concatenation of both ephemeral pubkeys with the long-lived {@code authentikey}, and writes
     * the response back into the APDU buffer starting at offset 0.
     *
     * @return the number of bytes written into {@code apduBuffer} starting at offset 0
     */
    public short initHandshake(byte[] apduBuffer, short inDataOffset, short inDataLen) {
        reset();
        if (inDataLen != CLIENT_EPH_PUB_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        // Per protocol.md §6.1: a non-0x04 prefix is a crypto failure (6FB2), not a length error.
        if (apduBuffer[inDataOffset] != (byte) 0x04) {
            ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
        }

        try {
            // Stage every handshake field in hsScratch; the APDU buffer is reserved for the
            // response.
            Util.arrayCopyNonAtomic(
                    apduBuffer, inDataOffset, hsScratch, HS_CLIENT_PUB, CLIENT_EPH_PUB_LEN);

            ephKeypair.genKeyPair();
            ECPublicKey cardEphPub = (ECPublicKey) ephKeypair.getPublic();
            short cardPubLen = cardEphPub.getW(hsScratch, HS_CARD_PUB);
            if (cardPubLen != CLIENT_EPH_PUB_LEN || hsScratch[HS_CARD_PUB] != (byte) 0x04) {
                ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
            }

            ecdh.init((ECPrivateKey) ephKeypair.getPrivate());
            short sharedLen =
                    ecdh.generateSecret(
                            hsScratch, HS_CLIENT_PUB, CLIENT_EPH_PUB_LEN, hsScratch, HS_SHARED);
            if (sharedLen != Constants.EC_POINT_UNCOMPRESSED_LEN
                    || hsScratch[HS_SHARED] != (byte) 0x04) {
                ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
            }

            // Compose KDF salt = client_x ‖ card_x.
            Util.arrayCopyNonAtomic(
                    hsScratch,
                    (short) (HS_CLIENT_PUB + 1),
                    hsScratch,
                    HS_SALT,
                    Constants.EC_SCALAR_LEN);
            Util.arrayCopyNonAtomic(
                    hsScratch,
                    (short) (HS_CARD_PUB + 1),
                    hsScratch,
                    (short) (HS_SALT + Constants.EC_SCALAR_LEN),
                    Constants.EC_SCALAR_LEN);

            kdf.extract(
                    hsScratch,
                    HS_SALT,
                    (short) (Constants.EC_SCALAR_LEN * 2),
                    hsScratch,
                    (short) (HS_SHARED + 1),
                    Constants.EC_SCALAR_LEN);
            kdf.expand(KDF_INFO, (short) 0, (short) KDF_INFO.length, okm, (short) 0, OKM_LEN);
            encKey.setKey(okm, (short) 0);
            macKey.setKey(okm, OKM_MAC_OFFSET);

            Util.arrayFillNonAtomic(lastInboundIv, (short) 0, Constants.SC_BLOCK_LEN, (byte) 0);
            Util.arrayFillNonAtomic(outboundCounter, (short) 0, Constants.SC_BLOCK_LEN, (byte) 0);
            openFlag[0] = (byte) 1;

            // Sign (card_eph_pub ‖ client_eph_pub) with the authentikey via update + sign so the
            // two
            // non-adjacent regions of hsScratch are concatenated without an intermediate copy.
            ecdsa.init(authentikey.privateKey(), Signature.MODE_SIGN);
            ecdsa.update(hsScratch, HS_CARD_PUB, CLIENT_EPH_PUB_LEN);
            // sign() output goes directly into the APDU buffer at the final response offset.
            short sigOffset = (short) (CLIENT_EPH_PUB_LEN + 2);
            short sigLen =
                    ecdsa.sign(hsScratch, HS_CLIENT_PUB, CLIENT_EPH_PUB_LEN, apduBuffer, sigOffset);

            // Final outbound layout: card_pub(65) ‖ sigLen(2) ‖ sig(DER).
            Util.arrayCopyNonAtomic(
                    hsScratch, HS_CARD_PUB, apduBuffer, (short) 0, CLIENT_EPH_PUB_LEN);
            Util.setShort(apduBuffer, CLIENT_EPH_PUB_LEN, sigLen);

            // Wipe the handshake scratch, then reset the KDF so its transient PRK does not outlive
            // the handshake: PRK alone re-derives K_enc/K_mac, and the KDF's SHA-256 scratch tail
            // still holds the last OKM block (IV_base). The live session keys persist in their own
            // AESKey slots and SC.okm keeps IV_base for the outbound IV, so this only drops the
            // redundant KDF-internal copies (NEWAUDIT-009).
            Util.arrayFillNonAtomic(hsScratch, (short) 0, HS_SCRATCH_LEN, (byte) 0);
            kdf.reset();

            return (short) (sigOffset + sigLen);
        } catch (ISOException e) {
            reset();
            throw Constants.fail(e.getReason());
        } catch (Exception e) {
            reset();
            throw Constants.fail(Constants.SW_SECURE_CHANNEL_FAILED);
        }
    }

    /**
     * Decrypts and authenticates an envelope encoded as {@code IV ‖ ciphertext ‖ MAC} carried in
     * the outer APDU data field. On success, the plaintext is written into {@code apduBuffer}
     * starting at {@link ISO7816#OFFSET_CDATA} and the method returns its length.
     *
     * <p>Any cryptographic failure invalidates the session — the host must re-handshake.
     */
    public short unwrap(byte[] apduBuffer, short outerDataOffset, short outerDataLen) {
        if (!isOpen()) {
            ISOException.throwIt(Constants.SW_SECURE_CHANNEL_REQUIRED);
        }
        short minLen =
                (short) (Constants.SC_BLOCK_LEN + Constants.SC_BLOCK_LEN + Constants.SC_MAC_LEN);
        if (outerDataLen < minLen) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short ctLen = (short) (outerDataLen - Constants.SC_BLOCK_LEN - Constants.SC_MAC_LEN);
        if ((short) (ctLen % Constants.SC_BLOCK_LEN) != 0) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short ivOffset = outerDataOffset;
        short ctOffset = (short) (ivOffset + Constants.SC_BLOCK_LEN);
        short macOffset = (short) (ctOffset + ctLen);

        // Replay defence before MAC verification: reject non-monotonic IVs cheaply. The IV
        // bytes themselves are public, so the comparison's data-dependent timing is not a
        // secret-leak channel; we still use constant-time compare16 because the rest of this
        // class speaks one defence-in-depth dialect (CtUtil.ctEquals, stripPkcs5) and a stray
        // ternary here would be the first non-constant-time branch on a security-sensitive
        // path. Critically, this branch does NOT reset() the session: an attacker without
        // K_mac could otherwise replay any captured envelope to wipe the session keys, a free
        // DoS lever. The MAC-verification failure path below is still a session-killer because
        // at that point the attacker either holds K_mac or is corrupting in flight — a genuine
        // integrity event, not just replay.
        if (compare16(apduBuffer, ivOffset, lastInboundIv, (short) 0) <= 0) {
            ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
        }

        // MAC = AES-CMAC-128(K_mac, outer_header ‖ IV ‖ ciphertext). CtUtil.ctEquals is mandatory:
        // Util.arrayCompare is left-to-right ternary and leaks mismatch position.
        macSig.init(macKey, Signature.MODE_SIGN);
        macSig.update(apduBuffer, (short) 0, (short) 5);
        macSig.sign(
                apduBuffer,
                ivOffset,
                (short) (Constants.SC_BLOCK_LEN + ctLen),
                macScratch,
                (short) 0);
        if (!CtUtil.ctEquals(macScratch, (short) 0, apduBuffer, macOffset, Constants.SC_MAC_LEN)) {
            reset();
            ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
        }
        Util.arrayCopyNonAtomic(
                apduBuffer, ivOffset, lastInboundIv, (short) 0, Constants.SC_BLOCK_LEN);

        // AES-CBC NOPAD; PKCS#5 padding is stripped manually below.
        aesCbc.init(encKey, Cipher.MODE_DECRYPT, apduBuffer, ivOffset, Constants.SC_BLOCK_LEN);
        short paddedLen =
                aesCbc.doFinal(apduBuffer, ctOffset, ctLen, apduBuffer, ISO7816.OFFSET_CDATA);
        return stripPkcs5(apduBuffer, ISO7816.OFFSET_CDATA, paddedLen);
    }

    /**
     * Wraps {@code plaintextLen} bytes of response data placed at {@code apduBuffer[plainOffset ..
     * plainOffset+plaintextLen]} into an outbound envelope {@code IV ‖ ciphertext ‖ MAC} written to
     * offset 0. Returns the total envelope length.
     */
    public short wrap(byte[] apduBuffer, short plainOffset, short plaintextLen) {
        if (!isOpen()) {
            ISOException.throwIt(Constants.SW_SECURE_CHANNEL_REQUIRED);
        }
        short padded = pkcs5PaddedLength(plaintextLen);
        short total = (short) (Constants.SC_BLOCK_LEN + padded + Constants.SC_MAC_LEN);
        if (total > (short) apduBuffer.length) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }

        // Move plaintext to its final pre-encryption position (after the IV slot) and pad.
        Util.arrayCopyNonAtomic(
                apduBuffer, plainOffset, apduBuffer, Constants.SC_BLOCK_LEN, plaintextLen);
        applyPkcs5(apduBuffer, Constants.SC_BLOCK_LEN, plaintextLen, padded);

        // IV = IV_base XOR (counter++).
        incrementCounter();
        for (short i = 0; i < Constants.SC_BLOCK_LEN; i++) {
            apduBuffer[i] = (byte) (okm[(short) (OKM_IV_OFFSET + i)] ^ outboundCounter[i]);
        }

        aesCbc.init(encKey, Cipher.MODE_ENCRYPT, apduBuffer, (short) 0, Constants.SC_BLOCK_LEN);
        short ctLen =
                aesCbc.doFinal(
                        apduBuffer,
                        Constants.SC_BLOCK_LEN,
                        padded,
                        apduBuffer,
                        Constants.SC_BLOCK_LEN);

        short macOffset = (short) (Constants.SC_BLOCK_LEN + ctLen);
        macSig.init(macKey, Signature.MODE_SIGN);
        macSig.update(RESP_HEADER, (short) 0, (short) RESP_HEADER.length);
        macSig.sign(
                apduBuffer,
                (short) 0,
                (short) (Constants.SC_BLOCK_LEN + ctLen),
                macScratch,
                (short) 0);
        Util.arrayCopyNonAtomic(macScratch, (short) 0, apduBuffer, macOffset, Constants.SC_MAC_LEN);

        return (short) (Constants.SC_BLOCK_LEN + ctLen + Constants.SC_MAC_LEN);
    }

    /**
     * Increments the 16-byte outbound counter; on overflow the channel is torn down and {@link
     * Constants#SW_SECURE_CHANNEL_FAILED} is raised. Without this guard a wrapped counter would
     * reuse {@code IV_base XOR 0} on a fresh ciphertext — AES-CBC with the same (key, IV) leaks
     * plaintext XOR. Practically unreachable after 2¹²⁸ - 1 wraps; defence-in-depth against fault
     * injection.
     */
    private void incrementCounter() {
        for (short i = (short) (Constants.SC_BLOCK_LEN - 1); i >= 0; i--) {
            short next = (short) ((outboundCounter[i] & 0xFF) + 1);
            outboundCounter[i] = (byte) next;
            if (next <= 0xFF) {
                return;
            }
        }
        // All 16 bytes carried out — counter wrapped to all-zero. Tear down so the host must
        // re-handshake with a fresh IV_base before any further outbound ciphertext is emitted.
        reset();
        ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
    }

    /**
     * Constant-time 16-byte big-endian three-way comparison: returns {@code > 0} iff {@code a > b},
     * {@code 0} on equality, {@code < 0} otherwise. Used solely for the inbound IV monotonicity
     * check; mask-based so the channel speaks one defence-in-depth dialect with {@link
     * CtUtil#ctEquals} and {@link CtUtil#ctLessThan}.
     */
    static short compare16(byte[] a, short aOff, byte[] b, short bOff) {
        // gtMask / ltMask track "have we already proven a > b / a < b at a more significant
        // byte?". Once set, a downstream byte must not overwrite the verdict — masks are sticky.
        // Sign-bit extraction stays in the short domain so the JC 3.0.5 CAP converter accepts
        // it without an int-support directive.
        short gtMask = 0;
        short ltMask = 0;
        for (short i = 0; i < Constants.SC_BLOCK_LEN; i++) {
            short av = (short) (a[(short) (aOff + i)] & 0xFF);
            short bv = (short) (b[(short) (bOff + i)] & 0xFF);
            short diffAB = (short) (av - bv);
            short diffBA = (short) (bv - av);
            short ltHere = (short) -((diffAB >>> 15) & 1);
            short gtHere = (short) -((diffBA >>> 15) & 1);
            // Promote ltHere/gtHere only while still tied at every more significant byte.
            short stillTied = (short) ~(gtMask | ltMask);
            ltMask |= (short) (ltHere & stillTied);
            gtMask |= (short) (gtHere & stillTied);
        }
        // Branch-free three-way result: +1 / -1 / 0.
        return (short) ((gtMask & 1) - (ltMask & 1));
    }

    /**
     * Validates and strips PKCS#5/#7 padding from an AES-CBC plaintext block in place; returns the
     * unpadded length. Any malformed pad raises {@link Constants#SW_SECURE_CHANNEL_FAILED}.
     *
     * <p>Every padding-error branch folds into a single accumulator {@code failMask} checked once
     * at the end, so the time taken here is independent of which pad invariant failed.
     * Encrypt-then-MAC above already gates externally-observable signals; the constant-time walk is
     * defence-in-depth aligned with the rest of the secret-touching code.
     */
    static short stripPkcs5(byte[] buf, short offset, short paddedLen) {
        // Block-alignment is structural metadata (ciphertext length the AES engine accepted),
        // not a secret-derived byte, so an early return is safe here.
        if (paddedLen <= 0 || (short) (paddedLen % Constants.SC_BLOCK_LEN) != 0) {
            ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
        }
        short padVal = (short) (buf[(short) (offset + paddedLen - 1)] & 0xFF);
        // failMask: 0 = OK, non-zero = at least one invariant failed. All sign-bit extractions
        // stay inside the short domain so the JC 3.0.5 CAP converter accepts them; for any short
        // {@code s}, {@code (s >>> 15) & 1} is 1 iff {@code s < 0}.
        short failMask = 0;
        // padVal == 0 → reject. (padVal | -padVal) has sign bit set iff padVal != 0.
        short padNonZeroBit = (short) (((short) (padVal | -padVal) >>> 15) & 1);
        failMask |= (short) (1 - padNonZeroBit);
        // padVal > BLOCK_LEN → reject. (BLOCK_LEN - padVal) is negative iff padVal > BLOCK_LEN.
        failMask |= (short) (((short) (Constants.SC_BLOCK_LEN - padVal) >>> 15) & 1);
        // Walk the full trailing block at constant cost; per-byte contribution is gated by the
        // "this position must equal padVal" mask.
        for (short i = 0; i < Constants.SC_BLOCK_LEN; i++) {
            short distFromEnd = (short) (i + 1); // 1..BLOCK_LEN
            short outsidePad = (short) (((short) (padVal - distFromEnd) >>> 15) & 1);
            short mustMatch = (short) (outsidePad - 1);
            short bv = (short) (buf[(short) (offset + paddedLen - distFromEnd)] & 0xFF);
            short mismatchHere = (short) ((bv ^ padVal) & mustMatch);
            failMask |= (short) (((short) (mismatchHere | -mismatchHere) >>> 15) & 1);
        }
        if (failMask != 0) {
            ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
        }
        return (short) (paddedLen - padVal);
    }

    private static short pkcs5PaddedLength(short plaintextLen) {
        short rem = (short) (plaintextLen % Constants.SC_BLOCK_LEN);
        return (short) (plaintextLen + Constants.SC_BLOCK_LEN - rem);
    }

    private static void applyPkcs5(byte[] buf, short offset, short plaintextLen, short padded) {
        byte pad = (byte) (padded - plaintextLen);
        for (short i = plaintextLen; i < padded; i++) {
            buf[(short) (offset + i)] = pad;
        }
    }
}
