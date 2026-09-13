/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.wallet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Entry point of the meowl multi-chain hardware-wallet applet — a thin router that delegates every
 * cryptographic and business primitive to a single-purpose companion class in this package.
 *
 * <p>Outer INS surface (reachable on a freshly-installed card, no Secure Channel required): {@code
 * GET_INFO}, {@code GET_AUTHENTIKEY}, {@code RESET_TO_FACTORY}, {@code INIT_SECURE_CHANNEL}, {@code
 * OPEN_SECURE_CHANNEL}. Every other INS — PIN, PKI, seed, signing — is reachable only through
 * {@code OPEN_SECURE_CHANNEL} and is dispatched by {@link #dispatchInner}.
 */
public final class WalletApplet extends Applet implements WipeTrigger {

    /**
     * Size of the shared transient scratch buffer, sized to the largest of its four
     * mutually-exclusive consumers (single-threaded APDU dispatch keeps them from overlapping):
     * Ed25519 {@value Ed25519#SCRATCH_LEN}, Schnorr 354, SecureChannel handshake 259, EcdsaK1 168.
     * Sharing one buffer saves ~970 bytes of transient RAM — the difference between fitting or not
     * on cards with a ~3 KB user-RAM budget (notably J3R180).
     */
    private static final short SHARED_SCRATCH_LEN = Ed25519.SCRATCH_LEN;

    /**
     * Per-session scratch used by inner handlers that need to stage their input before producing a
     * response that would overlap with the input region in the APDU buffer.
     */
    private static final short INNER_SCRATCH_LEN = (short) 128;

    /** Selector for {@link #signWithDigest}: secp256k1 ECDSA signer. */
    private static final byte SIGNER_ECDSA_K1 = (byte) 0;

    /** Selector for {@link #signWithDigest}: BIP-340 Schnorr signer. */
    private static final byte SIGNER_SCHNORR_K1 = (byte) 1;

    /**
     * Capability bitmask reported by {@code GET_INFO}. Compile-time constant so the {@code
     * GET_INFO} hot path emits a single {@code sipush} rather than recomputing the OR every call.
     */
    private static final short ADVERTISED_CAPABILITIES =
            (short)
                    (Constants.CAP_RESET_TO_FACTORY
                            | Constants.CAP_SC_CBC_HMAC
                            | Constants.CAP_PKI
                            | Constants.CAP_BIP32
                            | Constants.CAP_SLIP10
                            | Constants.CAP_K1_ECDSA
                            | Constants.CAP_K1_SCHNORR
                            | Constants.CAP_ED25519);

    private final LifecycleState state;
    private final Authentikey authentikey;
    private final ResetToFactory resetTrigger;
    private final SecureChannel secureChannel;
    private final PinManager pinManager;
    private final PkiManager pkiManager;
    private final MasterSeed masterSeed;
    private final Bip32 bip32;
    private final Slip10 slip10;
    private final EcdsaK1 ecdsaK1;
    private final Schnorr schnorr;
    private final Ed25519 ed25519;
    private final byte[] innerScratch;

    /**
     * Transient {@code [off1, len1, off2, len2]} workspace populated by {@link
     * #parseTwoLengthPrefixedFields}. Four {@code short} entries shared across PIN/PUK setup,
     * change-pin, change-puk, unblock-pin — single-threaded APDU dispatch keeps the reads ordered.
     */
    private final short[] twoFieldDesc;

    private WalletApplet() {
        // SC moved off HMAC-SHA-256 onto AES-CMAC-128 (Kdf class) — only HMAC-SHA-512 remains
        // necessary, for BIP-32 / SLIP-10 derivation. The dedicated HmacSha512 class collapses
        // the previously algorithm-agnostic HmacSha into a single-target SHA-512 engine.
        HmacSha512 sharedHmac512 = new HmacSha512();
        Fp25519Inv sharedInv = new Fp25519Inv();
        // CLEAR_ON_DESELECT scratch: nothing outlives a session, and the install-time
        // CLEAR_ON_RESET pool on NFC SECID cards (J3R180) is too small for a 600-byte allocation.
        byte[] sharedScratch =
                JCSystem.makeTransientByteArray(SHARED_SCRATCH_LEN, JCSystem.CLEAR_ON_DESELECT);
        this.state = new LifecycleState();
        this.authentikey = new Authentikey();
        this.resetTrigger = new ResetToFactory();
        this.secureChannel = new SecureChannel(this.authentikey, sharedScratch);
        this.pinManager = new PinManager();
        this.pkiManager = new PkiManager(this.authentikey);
        this.masterSeed = new MasterSeed(sharedHmac512);
        this.bip32 = new Bip32(this.masterSeed, sharedHmac512);
        this.slip10 = new Slip10(this.masterSeed, sharedHmac512);
        this.ecdsaK1 = new EcdsaK1(this.bip32, sharedScratch);
        this.schnorr = new Schnorr(this.bip32, sharedScratch);
        this.ed25519 = new Ed25519(sharedScratch, sharedInv);
        this.innerScratch =
                JCSystem.makeTransientByteArray(INNER_SCRATCH_LEN, JCSystem.CLEAR_ON_DESELECT);
        this.twoFieldDesc = JCSystem.makeTransientShortArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
        register();
    }

    /** GlobalPlatform install entry point. */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new WalletApplet();
    }

    @Override
    public boolean select() {
        resetTrigger.rearm();
        secureChannel.reset();
        pinManager.clearSession();
        return true;
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];

        if (cla != Constants.CLA_MEOWL) {
            ISOException.throwIt(Constants.SW_CLA_NOT_SUPPORTED);
        }

        if (ins != Constants.INS_RESET_TO_FACTORY) {
            resetTrigger.rearm();
        }

        short responseLen;
        switch (ins) {
            case Constants.INS_GET_INFO:
                responseLen = handleGetInfo(buffer);
                break;
            case Constants.INS_GET_AUTHENTIKEY:
                responseLen = handleGetAuthentikey(buffer);
                break;
            case Constants.INS_RESET_TO_FACTORY:
                resetTrigger.recordInvocation(this);
                return;
            case Constants.INS_INIT_SECURE_CHANNEL:
                responseLen = handleInitSecureChannel(apdu, buffer);
                break;
            case Constants.INS_OPEN_SECURE_CHANNEL:
                responseLen = handleOpenSecureChannel(apdu, buffer);
                break;
            default:
                throw Constants.fail(Constants.SW_INS_NOT_SUPPORTED);
        }
        apdu.setOutgoingAndSend((short) 0, responseLen);
    }

    /**
     * Opens a fresh Secure Channel session. Tearing down the previous SC keys and the PIN-verified
     * flag first preserves the "PIN binds to the SC session" property (protocol.md §6.4) — a
     * re-handshake MUST NOT inherit the prior session's authentication state.
     */
    private short handleInitSecureChannel(APDU apdu, byte[] buffer) {
        short lc = apdu.setIncomingAndReceive();
        secureChannel.reset();
        pinManager.clearSession();
        return secureChannel.initHandshake(buffer, ISO7816.OFFSET_CDATA, lc);
    }

    /**
     * Unwraps an encrypted inner APDU, dispatches it via {@link #dispatchInner}, and re-wraps the
     * inner response. Inner-APDU layout matches the outer frame: {@code [CLA INS P1 P2 LC data]}.
     * Handlers whose response overlaps the input must stage the input via {@link #innerScratch}.
     *
     * <p>The unwrapped plaintext (PIN bytes for {@code SETUP} / {@code VERIFY_PIN}, the seed for
     * {@code IMPORT_SEED}, the BIP-32 path + digest for {@code SIGN_*}, …) is wiped from the APDU
     * buffer in this method's {@code finally} regardless of whether {@link #dispatchInner} returns
     * normally or throws. Centralising the wipe here is the single source of truth that closes
     * NEWAUDIT-005 (per-handler PIN/PUK wipe gaps) and NEWAUDIT-007 (residual plaintext after a
     * torn handler) at the same point.
     */
    private short handleOpenSecureChannel(APDU apdu, byte[] buffer) {
        short lc = apdu.setIncomingAndReceive();
        short plainLen = secureChannel.unwrap(buffer, ISO7816.OFFSET_CDATA, lc);
        short envelopeLen = 0;
        try {
            if (plainLen < 5) {
                ISOException.throwIt(Constants.SW_WRONG_LENGTH);
            }
            short innerOff = ISO7816.OFFSET_CDATA;
            byte innerCla = buffer[innerOff];
            byte innerIns = buffer[(short) (innerOff + 1)];
            byte innerP1 = buffer[(short) (innerOff + 2)];
            byte innerP2 = buffer[(short) (innerOff + 3)];
            short innerLc = (short) (buffer[(short) (innerOff + 4)] & 0xFF);
            if ((short) (5 + innerLc) != plainLen) {
                ISOException.throwIt(Constants.SW_WRONG_LENGTH);
            }
            if (innerCla != Constants.CLA_MEOWL) {
                ISOException.throwIt(Constants.SW_CLA_NOT_SUPPORTED);
            }
            short innerDataOff = (short) (innerOff + 5);
            short respLen =
                    dispatchInner(buffer, innerIns, innerP1, innerP2, innerDataOff, innerLc);
            envelopeLen = secureChannel.wrap(buffer, ISO7816.OFFSET_CDATA, respLen);
            return envelopeLen;
        } finally {
            // Wipe the unwrapped inner-APDU plaintext that SC.unwrap staged into the buffer —
            // PIN/PUK on SETUP / VERIFY_PIN / CHANGE_PIN / CHANGE_PUK / UNBLOCK_PIN, the BIP-39
            // seed on IMPORT_SEED, the BIP-32 path + digest on the SIGN_* opcodes, PKI cert
            // chunks on IMPORT_PKI_CERT — covering both NEWAUDIT-005 (per-handler wipe gaps) and
            // NEWAUDIT-007 (residual plaintext after a torn handler) at one point.
            //
            // SC.wrap has already overwritten buffer[0..envelopeLen) with the outbound
            // IV‖ciphertext‖MAC, so those bytes hold ciphertext, not plaintext: wiping them would
            // corrupt the response (zeroing the outbound IV breaks the host MAC check on every
            // reply). Wipe only the request-plaintext tail that lies BEYOND the envelope. On an
            // exception path envelopeLen stays 0, so the whole inner-plaintext window is wiped.
            wipeSecureChannelRequestTail(buffer, plainLen, envelopeLen);
        }
    }

    static void wipeSecureChannelRequestTail(byte[] buffer, short plainLen, short envelopeLen) {
        short reqEnd = (short) (ISO7816.OFFSET_CDATA + plainLen);
        short wipeFrom = envelopeLen > ISO7816.OFFSET_CDATA ? envelopeLen : ISO7816.OFFSET_CDATA;
        if (reqEnd > wipeFrom) {
            Util.arrayFillNonAtomic(buffer, wipeFrom, (short) (reqEnd - wipeFrom), (byte) 0);
        }
    }

    private short dispatchInner(
            byte[] buffer, byte ins, byte p1, byte p2, short dataOff, short dataLen) {
        switch (ins) {
            case Constants.INS_SETUP:
                return handleSetup(buffer, dataOff, dataLen);
            case Constants.INS_VERIFY_PIN:
                return handleVerifyPin(buffer, dataOff, dataLen);
            case Constants.INS_CHANGE_PIN:
                return handleChangePin(buffer, dataOff, dataLen);
            case Constants.INS_CHANGE_PUK:
                return handleChangePuk(buffer, dataOff, dataLen);
            case Constants.INS_UNBLOCK_PIN:
                return handleUnblockPin(buffer, dataOff, dataLen);
            case Constants.INS_EXPORT_PKI_PUBKEY:
                return handleExportPkiPubkey(buffer);
            case Constants.INS_SIGN_PKI_CSR:
                return handleSignPkiCsr(buffer, dataOff, dataLen);
            case Constants.INS_IMPORT_PKI_CERT:
                return handleImportPkiCert(buffer, p1, dataOff, dataLen);
            case Constants.INS_EXPORT_PKI_CERT:
                return handleExportPkiCert(buffer, dataOff, dataLen);
            case Constants.INS_LOCK_PKI:
                return handleLockPki();
            case Constants.INS_IMPORT_SEED:
                return handleImportSeed(buffer, dataOff, dataLen);
            case Constants.INS_GENERATE_SEED:
                return handleGenerateSeed(buffer, dataLen);
            case Constants.INS_EXPORT_XPUB:
                return handleExportXpub(buffer, dataOff, dataLen);
            case Constants.INS_SIGN_ECDSA_K1:
                return handleSignEcdsaK1(buffer, dataOff, dataLen);
            case Constants.INS_SIGN_SCHNORR_K1:
                return handleSignSchnorrK1(buffer, dataOff, dataLen);
            case Constants.INS_SIGN_ED25519:
                return handleSignEd25519(buffer, dataOff, dataLen);
            default:
                throw Constants.fail(Constants.SW_INS_NOT_SUPPORTED);
        }
    }

    private short handleGetInfo(byte[] buffer) {
        short offset = 0;
        offset =
                ApduTlv.putShort(
                        buffer, offset, Constants.TAG_PROTOCOL_VERSION, Constants.PROTOCOL_VERSION);
        offset =
                ApduTlv.putShort(
                        buffer, offset, Constants.TAG_APPLET_VERSION, Constants.APPLET_VERSION);
        offset = ApduTlv.putByte(buffer, offset, Constants.TAG_LIFECYCLE_STATE, state.current());
        offset =
                ApduTlv.putShort(
                        buffer, offset, Constants.TAG_CAPABILITIES, ADVERTISED_CAPABILITIES);

        short headerOffset = offset;
        short valueStart = ApduTlv.reserve(buffer, headerOffset, Constants.TAG_AUTHENTIKEY_PUBKEY);
        short pkLen = authentikey.writeCompressedPubkeyTo(buffer, valueStart);
        ApduTlv.finishReserved(buffer, headerOffset, pkLen);
        return (short) (valueStart + pkLen);
    }

    private short handleGetAuthentikey(byte[] buffer) {
        return authentikey.writeCompressedPubkeyTo(buffer, (short) 0);
    }

    /**
     * Common gate for any handler that requires the user PIN to be verified in this Secure Channel
     * session. Throws {@link Constants#SW_SECURITY_STATUS_NOT_SATISFIED} otherwise.
     */
    private void requirePinVerified() {
        if (!pinManager.isPinVerified()) {
            ISOException.throwIt(Constants.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    /*  PIN / PUK + PKI personalisation handlers — reachable only via OPEN_SECURE_CHANNEL.  */

    /** {@code SETUP} inner data layout: {@code [pinLen(1), PIN, pukLen(1), PUK]}. */
    private short handleSetup(byte[] buffer, short dataOff, short dataLen) {
        state.require(LifecycleState.PERSONALIZED);
        if (dataLen < (short) (1 + Constants.PIN_MIN_LEN + 1 + Constants.PUK_MIN_LEN)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        parseTwoLengthPrefixedFields(buffer, dataOff, dataLen);
        // PIN, PUK, provisioned flag and lifecycle advance commit atomically: a power loss between
        // them would brick the card (VERIFY_PIN gated out by the FSM, SETUP rejected by the
        // already-provisioned guard).
        JCSystem.beginTransaction();
        pinManager.setupInTx(
                buffer, twoFieldDesc[0], twoFieldDesc[1], buffer, twoFieldDesc[2], twoFieldDesc[3]);
        state.transitionToInTx(LifecycleState.SETUP_DONE);
        JCSystem.commitTransaction();
        return 0;
    }

    private short handleVerifyPin(byte[] buffer, short dataOff, short dataLen) {
        state.requireAtLeast(LifecycleState.SETUP_DONE);
        pinManager.verifyPin(buffer, dataOff, dataLen);
        return 0;
    }

    /** {@code CHANGE_PIN} inner data layout: {@code [oldLen(1), old, newLen(1), new]}. */
    private short handleChangePin(byte[] buffer, short dataOff, short dataLen) {
        state.requireAtLeast(LifecycleState.SETUP_DONE);
        parseTwoLengthPrefixedFields(buffer, dataOff, dataLen);
        pinManager.changePin(
                buffer, twoFieldDesc[0], twoFieldDesc[1], buffer, twoFieldDesc[2], twoFieldDesc[3]);
        return 0;
    }

    /**
     * {@code CHANGE_PUK} inner data layout: {@code [oldLen(1), oldPUK, newLen(1), newPUK]}.
     * Requires PIN to be currently verified so a stolen card whose PIN is unknown cannot be
     * hijacked by rotating its PUK.
     */
    private short handleChangePuk(byte[] buffer, short dataOff, short dataLen) {
        state.requireAtLeast(LifecycleState.SETUP_DONE);
        requirePinVerified();
        parseTwoLengthPrefixedFields(buffer, dataOff, dataLen);
        pinManager.changePuk(
                buffer, twoFieldDesc[0], twoFieldDesc[1], buffer, twoFieldDesc[2], twoFieldDesc[3]);
        return 0;
    }

    /** {@code UNBLOCK_PIN} inner data layout: {@code [pukLen(1), PUK, newPinLen(1), newPIN]}. */
    private short handleUnblockPin(byte[] buffer, short dataOff, short dataLen) {
        state.requireAtLeast(LifecycleState.SETUP_DONE);
        parseTwoLengthPrefixedFields(buffer, dataOff, dataLen);
        pinManager.unblockPin(
                buffer, twoFieldDesc[0], twoFieldDesc[1], buffer, twoFieldDesc[2], twoFieldDesc[3]);
        return 0;
    }

    /**
     * Parses two length-prefixed byte fields {@code [len1(1), field1, len2(1), field2]} from {@code
     * buffer[dataOff .. dataOff + dataLen]} and stages the result into {@link #twoFieldDesc} as
     * {@code [off1, len1, off2, len2]}. Raises {@link Constants#SW_WRONG_LENGTH} if either length
     * prefix overruns the available data.
     */
    private void parseTwoLengthPrefixedFields(byte[] buffer, short dataOff, short dataLen) {
        short cursor = dataOff;
        short len1 = (short) (buffer[cursor++] & 0xFF);
        short off1 = cursor;
        cursor += len1;
        if ((short) (cursor + 1) > (short) (dataOff + dataLen)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short len2 = (short) (buffer[cursor++] & 0xFF);
        short off2 = cursor;
        if ((short) (cursor + len2) != (short) (dataOff + dataLen)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        twoFieldDesc[0] = off1;
        twoFieldDesc[1] = len1;
        twoFieldDesc[2] = off2;
        twoFieldDesc[3] = len2;
    }

    private short handleExportPkiPubkey(byte[] buffer) {
        state.require(LifecycleState.UNINITIALIZED);
        return pkiManager.exportPubkey(buffer, ISO7816.OFFSET_CDATA);
    }

    /** {@code SIGN_PKI_CSR} inner data layout: {@code [hash(32)]}. */
    private short handleSignPkiCsr(byte[] buffer, short dataOff, short dataLen) {
        state.require(LifecycleState.UNINITIALIZED);
        if (dataLen != Constants.EC_SCALAR_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        // Stage the digest in innerScratch: the signature output overlaps the input region. The
        // try-finally wipe clears the staged digest even on ISOException out of signCsr.
        Util.arrayCopyNonAtomic(buffer, dataOff, innerScratch, (short) 0, Constants.EC_SCALAR_LEN);
        try {
            return pkiManager.signCsr(innerScratch, (short) 0, buffer, ISO7816.OFFSET_CDATA);
        } finally {
            Util.arrayFillNonAtomic(innerScratch, (short) 0, Constants.EC_SCALAR_LEN, (byte) 0);
        }
    }

    /**
     * {@code IMPORT_PKI_CERT}: three-step protocol selected by {@code P1}.
     *
     * <ul>
     *   <li>{@code P1 = INIT}: data = {@code [totalSize (2 BE)]}.
     *   <li>{@code P1 = WRITE}: data = {@code [offset (2 BE), chunk...]}.
     *   <li>{@code P1 = FINALIZE}: data is empty.
     * </ul>
     */
    private short handleImportPkiCert(byte[] buffer, byte p1, short dataOff, short dataLen) {
        state.require(LifecycleState.UNINITIALIZED);
        switch (p1) {
            case Constants.PKI_IMPORT_P1_INIT:
                if (dataLen != 2) {
                    ISOException.throwIt(Constants.SW_WRONG_LENGTH);
                }
                pkiManager.importInit(Util.getShort(buffer, dataOff));
                return 0;
            case Constants.PKI_IMPORT_P1_WRITE:
                if (dataLen < 3) {
                    ISOException.throwIt(Constants.SW_WRONG_LENGTH);
                }
                short writeOff = Util.getShort(buffer, dataOff);
                short chunkLen = (short) (dataLen - 2);
                pkiManager.importWrite(writeOff, buffer, (short) (dataOff + 2), chunkLen);
                return 0;
            case Constants.PKI_IMPORT_P1_FINALIZE:
                if (dataLen != 0) {
                    ISOException.throwIt(Constants.SW_WRONG_LENGTH);
                }
                pkiManager.importFinalize();
                return 0;
            default:
                throw Constants.fail(Constants.SW_INCORRECT_P1P2);
        }
    }

    /**
     * {@code EXPORT_PKI_CERT} inner data layout: {@code [offset (2 BE), requestedLen (2 BE)]}. The
     * response starts with the certificate total length (2 BE) so the host knows when to stop
     * paging, followed by the requested window.
     */
    private short handleExportPkiCert(byte[] buffer, short dataOff, short dataLen) {
        // Allow export at any post-personalisation state — host needs the cert to verify the
        // card before unlocking the user PIN flow.
        if (dataLen != 4) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short offset = Util.getShort(buffer, dataOff);
        short requested = Util.getShort(buffer, (short) (dataOff + 2));
        short certLen = pkiManager.certLen();
        Util.setShort(buffer, ISO7816.OFFSET_CDATA, certLen);
        short written =
                certLen > 0
                        ? pkiManager.exportCert(
                                offset, requested, buffer, (short) (ISO7816.OFFSET_CDATA + 2))
                        : (short) 0;
        return (short) (2 + written);
    }

    private short handleLockPki() {
        state.require(LifecycleState.UNINITIALIZED);
        if (!pkiManager.hasCert()) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        JCSystem.beginTransaction();
        state.transitionToInTx(LifecycleState.PERSONALIZED);
        JCSystem.commitTransaction();
        return 0;
    }

    /*  HD wallet handlers — seed import / generation and BIP-32 / SLIP-10 child export.  */

    /**
     * {@code IMPORT_SEED} inner data layout: {@code [seedLen(1), seed(seedLen)]}. Requires the
     * lifecycle to be {@code SETUP_DONE} and the PIN to be currently verified.
     */
    private short handleImportSeed(byte[] buffer, short dataOff, short dataLen) {
        state.require(LifecycleState.SETUP_DONE);
        requirePinVerified();
        if (dataLen < 1) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short seedLen = (short) (buffer[dataOff] & 0xFF);
        if ((short) (1 + seedLen) != dataLen) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        JCSystem.beginTransaction();
        masterSeed.importSeed(buffer, (short) (dataOff + 1), seedLen);
        state.transitionToInTx(LifecycleState.SEEDED);
        JCSystem.commitTransaction();
        // Seed bytes get wiped centrally by handleOpenSecureChannel's finally; no per-handler
        // wipe needed here.
        return 0;
    }

    /**
     * {@code GENERATE_SEED} — card-internal CSPRNG seed; the raw seed is returned <em>once</em> as
     * the response so the host can render it (e.g. as a BIP-39 mnemonic) for backup. Subsequent
     * derivation only ever exposes the chain code and the public key.
     */
    private short handleGenerateSeed(byte[] buffer, short dataLen) {
        state.require(LifecycleState.SETUP_DONE);
        requirePinVerified();
        if (dataLen != 0) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        // Generate into ISO7816.OFFSET_CDATA so the response is in place when wrap() runs.
        JCSystem.beginTransaction();
        short writtenLen = masterSeed.generateSeed(buffer, ISO7816.OFFSET_CDATA);
        state.transitionToInTx(LifecycleState.SEEDED);
        JCSystem.commitTransaction();
        return writtenLen;
    }

    /**
     * {@code EXPORT_XPUB} inner data layout: {@code [curve(1), depth(1), path(4*depth)]}. Returns
     * {@code [compressed_pubkey(33), chain_code(32)]} for secp256k1 and {@code
     * [compressed_pubkey(32), chain_code(32)]} for Ed25519 (RFC 8032 §5.1.2 LE encoded pubkey,
     * derived on-card via {@link Ed25519#publicKey} from the SLIP-10 leaf private key).
     */
    private short handleExportXpub(byte[] buffer, short dataOff, short dataLen) {
        state.require(LifecycleState.SEEDED);
        requirePinVerified();
        if (dataLen < 2) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        byte curve = buffer[dataOff];
        short depth = (short) (buffer[(short) (dataOff + 1)] & 0xFF);
        if (depth > Constants.HD_MAX_DEPTH || (short) (2 + depth * Bip32.INDEX_LEN) != dataLen) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short pathOff = (short) (dataOff + 2);
        switch (curve) {
            case Constants.CURVE_SECP256K1:
                return bip32.derivePath(buffer, pathOff, depth, buffer, ISO7816.OFFSET_CDATA);
            case Constants.CURVE_ED25519:
                return handleExportXpubEd25519(buffer, pathOff, depth);
            default:
                throw Constants.fail(Constants.SW_INCORRECT_P1P2);
        }
    }

    /**
     * Ed25519 branch of {@link #handleExportXpub}. Returns {@code [pubkey_LE(32), chain_code(32)]}
     * with the pubkey derived on-card from the SLIP-10 leaf private key. A single {@link
     * Slip10#deriveLeafKeyAndChainCode} walk yields both the leaf key (consumed by {@link
     * Ed25519#publicKey}) and the chain code; staging the path in {@link #innerScratch} keeps it
     * clear of the APDU-buffer region the response overwrites.
     */
    private short handleExportXpubEd25519(byte[] buffer, short pathOff, short depth) {
        short pathLen = (short) (depth * Bip32.INDEX_LEN);
        // Stage the path at innerScratch[64..] so the [leaf_key(32) ‖ chain_code(32)] output of the
        // single SLIP-10 walk lands in innerScratch[0..64] without trampling the input.
        Util.arrayCopyNonAtomic(buffer, pathOff, innerScratch, (short) 64, pathLen);
        try {
            slip10.deriveLeafKeyAndChainCode(
                    innerScratch, (short) 64, depth, innerScratch, (short) 0);
            short pkLen = ed25519.publicKey(innerScratch, (short) 0, buffer, ISO7816.OFFSET_CDATA);
            Util.arrayCopyNonAtomic(
                    innerScratch,
                    (short) 32,
                    buffer,
                    (short) (ISO7816.OFFSET_CDATA + pkLen),
                    Constants.CHAIN_CODE_LEN);
            return (short) (pkLen + Constants.CHAIN_CODE_LEN);
        } finally {
            Util.arrayFillNonAtomic(innerScratch, (short) 0, (short) (64 + pathLen), (byte) 0);
        }
    }

    /*  Signing handlers — secp256k1 ECDSA, BIP-340 Schnorr and Ed25519 EdDSA.  */

    /**
     * {@code SIGN_ECDSA_K1} inner data layout: {@code [depth(1), path(4*depth), digest(32)]}.
     * Returns {@code [r(32), s(32)]} with {@code s} low-{@code s} normalised per BIP-62 / EIP-2.
     */
    private short handleSignEcdsaK1(byte[] buffer, short dataOff, short dataLen) {
        return signWithDigest(buffer, dataOff, dataLen, SIGNER_ECDSA_K1);
    }

    /**
     * {@code SIGN_SCHNORR_K1} inner data layout: {@code [depth(1), path(4*depth), digest(32)]}.
     * Returns the 64-byte BIP-340 signature {@code bytes(R) ‖ s}. Software-implemented on top of
     * {@link Schnorr}; aux randomness from the on-card RNG makes the signature non-deterministic.
     */
    private short handleSignSchnorrK1(byte[] buffer, short dataOff, short dataLen) {
        return signWithDigest(buffer, dataOff, dataLen, SIGNER_SCHNORR_K1);
    }

    /**
     * Common backbone of {@code SIGN_ECDSA_K1} and {@code SIGN_SCHNORR_K1}: enforce lifecycle + PIN
     * gating, validate the {@code [depth(1), path(4*depth), digest(32)]} envelope, stage the digest
     * into {@link #innerScratch} (so the signature output anchored at {@code OFFSET_CDATA} cannot
     * trample it mid-flight), dispatch to the selected primitive, and wipe the staged digest on
     * every code path.
     */
    private short signWithDigest(byte[] buffer, short dataOff, short dataLen, byte signerKind) {
        state.require(LifecycleState.SEEDED);
        requirePinVerified();
        if (dataLen < (short) (1 + Constants.DIGEST_LEN)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short depth = (short) (buffer[dataOff] & 0xFF);
        if (depth > Constants.HD_MAX_DEPTH
                || (short) (1 + depth * Bip32.INDEX_LEN + Constants.DIGEST_LEN) != dataLen) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short pathOff = (short) (dataOff + 1);
        short digestOff = (short) (pathOff + depth * Bip32.INDEX_LEN);
        Util.arrayCopyNonAtomic(buffer, digestOff, innerScratch, (short) 0, Constants.DIGEST_LEN);
        try {
            if (signerKind == SIGNER_ECDSA_K1) {
                return ecdsaK1.signDigest(
                        buffer,
                        pathOff,
                        depth,
                        innerScratch,
                        (short) 0,
                        buffer,
                        ISO7816.OFFSET_CDATA);
            }
            return schnorr.signDigest(
                    buffer, pathOff, depth, innerScratch, (short) 0, buffer, ISO7816.OFFSET_CDATA);
        } finally {
            Util.arrayFillNonAtomic(innerScratch, (short) 0, Constants.DIGEST_LEN, (byte) 0);
        }
    }

    /**
     * {@code SIGN_ED25519} inner data layout: {@code [depth(1), path(4*depth), message(*)]}. The
     * message is the raw payload the host wants signed (not a pre-hash) because RFC 8032 hashes the
     * message internally. Returns the 64-byte {@code R ‖ S} signature in RFC 8032 §5.1.2 LE
     * compressed form, computed entirely in software via {@link Ed25519#sign}. The signature is
     * deterministic by construction (the nonce {@code r} is derived from {@code SHA-512(prefix ‖
     * M)}); no on-card RNG is consumed.
     */
    private short handleSignEd25519(byte[] buffer, short dataOff, short dataLen) {
        state.require(LifecycleState.SEEDED);
        requirePinVerified();
        if (dataLen < (short) 1) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short depth = (short) (buffer[dataOff] & 0xFF);
        if (depth > Constants.HD_MAX_DEPTH) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short pathLen = (short) (depth * Bip32.INDEX_LEN);
        if ((short) (1 + pathLen) > dataLen) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short pathOff = (short) (dataOff + 1);
        short msgOff = (short) (pathOff + pathLen);
        short msgLen = (short) (dataLen - 1 - pathLen);
        // Stage the path inside innerScratch[32..32+pathLen] so subsequent buffer writes (the
        // 64-byte signature anchored at OFFSET_CDATA) cannot trample the SLIP-10 inputs. The leaf
        // private key is materialised into innerScratch[0..32]. The try-finally wipe covers any
        // exception out of slip10.deriveLeafKey or ed25519.sign.
        Util.arrayCopyNonAtomic(buffer, pathOff, innerScratch, (short) 32, pathLen);
        try {
            slip10.deriveLeafKey(innerScratch, (short) 32, depth, innerScratch, (short) 0);
            // Ed25519.sign reads `msg` twice (r-hash and k-hash); both reads complete before the
            // output is written, so the in-buffer message slice survives until OFFSET_CDATA
            // overwrites it.
            return ed25519.sign(
                    innerScratch, (short) 0, buffer, msgOff, msgLen, buffer, ISO7816.OFFSET_CDATA);
        } finally {
            Util.arrayFillNonAtomic(innerScratch, (short) 0, (short) (32 + pathLen), (byte) 0);
        }
    }

    /**
     * Reset-to-factory wipe. Per {@code notes/specs/protocol.md} §4 the authentikey is preserved;
     * Secure Channel state, PIN/PUK gates, PKI cert state, master-seed gates and lifecycle state
     * are reset.
     *
     * <p>The persistent gates commit inside a single {@link JCSystem#beginTransaction()} block so a
     * torn power-off cannot leave host-visible state half-reset. Master key material is physically
     * cleared after that commit to avoid enlarging the EEPROM transaction.
     */
    @Override
    public void wipe() {
        secureChannel.reset();
        pinManager.clearSession();
        JCSystem.beginTransaction();
        pinManager.wipeInTx();
        pkiManager.wipeInTx();
        masterSeed.wipeInTx();
        state.resetInTx();
        JCSystem.commitTransaction();
        masterSeed.wipeKeyMaterialNonAtomic();
    }
}
