/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.wallet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.Signature;

/**
 * PKI personalisation manager per {@code notes/specs/protocol.md} §8.
 *
 * <h2>Flow</h2>
 *
 * <ol>
 *   <li><b>EXPORT_PKI_PUBKEY</b> — host reads the long-lived {@code authentikey} public key
 *       (delegated to {@link Authentikey#writeCompressedPubkeyTo}); used as the CSR subject public
 *       key.
 *   <li><b>SIGN_PKI_CSR</b> — host constructs an ASN.1 {@code CertificationRequestInfo} (RFC 2986)
 *       off-card, hashes it to a 32-byte digest, sends the digest, and the card returns an
 *       ECDSA-SHA-256-equivalent signature produced from the digest with the authentikey private
 *       key.
 *   <li><b>IMPORT_PKI_CERT</b> — manufacturer-issued certificate is uploaded in {@link
 *       Constants#PKI_CERT_CHUNK_MAX_LEN}-byte chunks. Three-step protocol:
 *       <ul>
 *         <li>{@code P1 = 0x00 (INIT)} — data = {@code totalSize (2 BE)}. Allocates EEPROM.
 *         <li>{@code P1 = 0x01 (WRITE)} — data = {@code offset (2 BE) ‖ chunk}.
 *         <li>{@code P1 = 0x02 (FINALIZE)} — no data. Commits the stored size.
 *       </ul>
 *   <li><b>EXPORT_PKI_CERT</b> — host pages through the cert with {@code [offset (2 BE) | requested
 *       length (2 BE)]} requests; card returns the requested window. Allowed in any lifecycle state
 *       ≥ {@link LifecycleState#PERSONALIZED}.
 *   <li><b>LOCK_PKI</b> — transitions the lifecycle from {@link LifecycleState#UNINITIALIZED} to
 *       {@link LifecycleState#PERSONALIZED} and freezes the certificate. Subsequent {@code
 *       IMPORT_PKI_CERT} or {@code SIGN_PKI_CSR} commands fail.
 * </ol>
 *
 * <p>Storage: the certificate lives in EEPROM-backed {@link #cert}, sized at {@link
 * Constants#PKI_CERT_MAX_LEN}. Two book-keeping fields ({@link #importedLen}, {@link
 * #stagedTotalLen}) follow the chunked import protocol.
 */
public final class PkiManager {

    /** ECDSA signing engine that re-uses the authentikey private key for CSR self-signing. */
    private final Signature ecdsa;

    private final Authentikey authentikey;

    /** Persistent certificate storage. */
    private final byte[] cert;

    /** Number of bytes currently committed to {@link #cert} (after finalize). */
    private short importedLen;

    /** Total cert length declared by INIT, used to bound WRITE chunks. */
    private short stagedTotalLen;

    /**
     * Import protocol state machine — one of {@code IMPORT_STATE_*}. Held in a one-byte persistent
     * field because the import may span multiple APDU exchanges.
     */
    private byte importState;

    private static final byte IMPORT_STATE_IDLE = (byte) 0x00;
    private static final byte IMPORT_STATE_STAGED = (byte) 0x01;

    public PkiManager(Authentikey authentikey) {
        this.authentikey = authentikey;
        this.ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        this.cert = new byte[Constants.PKI_CERT_MAX_LEN];
        this.importedLen = 0;
        this.stagedTotalLen = 0;
        this.importState = IMPORT_STATE_IDLE;
    }

    /** Whether a certificate is currently committed and exportable. */
    public boolean hasCert() {
        return importedLen > 0;
    }

    /**
     * Writes the compressed authentikey public key into {@code dst} starting at {@code offset};
     * delegates to {@link Authentikey#writeCompressedPubkeyTo}. The CSR flow requires the host to
     * know the subject public key.
     */
    public short exportPubkey(byte[] dst, short offset) {
        return authentikey.writeCompressedPubkeyTo(dst, offset);
    }

    /**
     * Signs a host-provided 32-byte digest with the authentikey private key, producing a
     * DER-encoded ECDSA signature.
     *
     * @return number of bytes written to {@code out[outOffset..]}
     */
    public short signCsr(byte[] digest, short digestOffset, byte[] out, short outOffset) {
        if (digestOffset < 0
                || (short) ((short) digest.length - digestOffset) < Constants.EC_SCALAR_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        // signPreComputedHash() lets us sign an already-computed digest without re-hashing.
        ecdsa.init(authentikey.privateKey(), Signature.MODE_SIGN);
        return ecdsa.signPreComputedHash(
                digest, digestOffset, Constants.EC_SCALAR_LEN, out, outOffset);
    }

    /**
     * Step 1 of chunked import: declares the total certificate size and resets the working area.
     * The cert buffer is zeroed in full so the invariant "anything past {@code importedLen} is
     * zero" holds at the buffer level, irrespective of how the buffer is later read.
     */
    public void importInit(short totalLen) {
        if (totalLen <= 0 || totalLen > Constants.PKI_CERT_MAX_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        JCSystem.beginTransaction();
        importState = IMPORT_STATE_STAGED;
        stagedTotalLen = totalLen;
        // Importing a new cert invalidates the previously committed one.
        importedLen = 0;
        Util.arrayFillNonAtomic(cert, (short) 0, Constants.PKI_CERT_MAX_LEN, (byte) 0);
        JCSystem.commitTransaction();
    }

    /**
     * Step 2 of chunked import: writes {@code chunk[0..chunkLen]} at {@code offset} of the staged
     * certificate. Bounds-checked against {@link #stagedTotalLen}.
     */
    public void importWrite(short offset, byte[] chunk, short chunkOffset, short chunkLen) {
        if (importState != IMPORT_STATE_STAGED) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (offset < 0
                || offset > stagedTotalLen
                || chunkLen <= 0
                || chunkLen > (short) (stagedTotalLen - offset)
                || chunkLen > Constants.PKI_CERT_CHUNK_MAX_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        Bounds.requireCapacity(chunk, chunkOffset, chunkLen);
        // Util.arrayCopy is the transactional variant.
        JCSystem.beginTransaction();
        Util.arrayCopy(chunk, chunkOffset, cert, offset, chunkLen);
        JCSystem.commitTransaction();
    }

    /**
     * Step 3 of chunked import: finalises the staged size into the committed size. Subsequent
     * {@link #exportCert} calls will read from offset 0 up to {@link #importedLen}.
     */
    public void importFinalize() {
        if (importState != IMPORT_STATE_STAGED || stagedTotalLen == 0) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        JCSystem.beginTransaction();
        importedLen = stagedTotalLen;
        importState = IMPORT_STATE_IDLE;
        stagedTotalLen = 0;
        JCSystem.commitTransaction();
    }

    /**
     * Pages a window of the committed certificate.
     *
     * @return the number of bytes written to {@code dst[dstOffset..]}, which is {@code
     *     min(requestedLen, importedLen - offset)}; zero if {@code offset == importedLen}.
     */
    public short exportCert(short offset, short requestedLen, byte[] dst, short dstOffset) {
        if (!hasCert()) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (offset < 0 || offset > importedLen || requestedLen < 0) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short available = (short) (importedLen - offset);
        short take = requestedLen < available ? requestedLen : available;
        Util.arrayCopyNonAtomic(cert, offset, dst, dstOffset, take);
        return take;
    }

    /** Committed certificate size; used by host pagination to know when to stop. */
    public short certLen() {
        return importedLen;
    }

    /**
     * Reset-to-factory hook. Per {@code notes/specs/protocol.md} §8 the authentikey is preserved;
     * the manufacturer-issued certificate is logically wiped so a re-personalised card can install
     * a fresh one.
     *
     * <p>We zero only the bookkeeping fields, not the 1 KiB cert buffer: with {@code importedLen =
     * 0} the buffer is unreadable through {@link #exportCert} (which gates on {@code importedLen})
     * and {@link #importInit} repaints the staged region with zeros before any future WRITE
     * arrives, so residual bytes can never surface to the host. Skipping the bulk fill keeps the
     * wipe transaction small enough to commit within the BWT of a contactless link.
     *
     * <p>Caller MUST hold a {@link JCSystem#beginTransaction()} block; bundled with PIN, master
     * seed and lifecycle wipes into the single atomic reset-to-factory commit driven by {@link
     * WalletApplet#wipe()}.
     */
    public void wipeInTx() {
        importedLen = 0;
        stagedTotalLen = 0;
        importState = IMPORT_STATE_IDLE;
    }
}
