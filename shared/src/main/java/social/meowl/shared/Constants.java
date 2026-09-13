/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.shared;

import javacard.framework.ISOException;

/**
 * Wire-level and policy constants for the meowl-applet.
 *
 * <p>Every magic number that appears on the APDU wire or in a policy threshold is declared here so
 * the rest of the codebase stays free of literal hex constants and the protocol spec under {@code
 * notes/specs/} can be diffed against a single file.
 *
 * <p>JavaCard 3.0.5 has no {@code enum}, so {@code byte} / {@code short} literals are the idiomatic
 * representation.
 */
public final class Constants {

    private Constants() {}

    /*  Versioning — packed as 16-bit big-endian (major << 8 | minor).  */

    /** Wire-protocol version reported by {@code GET_INFO}. */
    public static final short PROTOCOL_VERSION = (short) 0x0100;

    /** Applet implementation version reported by {@code GET_INFO}. */
    public static final short APPLET_VERSION = (short) 0x0001;

    /*  CLA  */

    /**
     * Class byte for every command the meowl applet processes. ISO 7816-4 private-class range; see
     * {@code notes/specs/protocol.md} §1.
     */
    public static final byte CLA_MEOWL = (byte) 0x80;

    /*  INS table — see notes/specs/protocol.md §2 for the wire contract.
     *
     *  Banding convention (so reviewers can read intent from the opcode alone):
     *    0x00–0x0F  lifecycle / identity / capability discovery
     *    0x10–0x1F  secure channel
     *    0x20–0x2F  PIN / PUK
     *    0x30–0x3F  PKI personalisation
     *    0x40–0x4F  seed management
     *    0x50–0x5F  signing primitives
     *    0x60–0x6F  derivation utilities
     *    0xFF       reset to factory (per ISO 7816-4 reserved range hint)
     *
     *  Reserved INS values left unimplemented at the current revision are declared as comments
     *  rather than as constants so that the implemented surface and the planned surface are
     *  visually distinct.
     */

    /** {@code GET_INFO} — returns a TLV-encoded capability + identity profile. */
    public static final byte INS_GET_INFO = (byte) 0x01;

    /** {@code GET_AUTHENTIKEY} — returns the compressed authentikey public key. */
    public static final byte INS_GET_AUTHENTIKEY = (byte) 0x02;

    /** {@code RESET_TO_FACTORY} — wipes secrets after N consecutive invocations. */
    public static final byte INS_RESET_TO_FACTORY = (byte) 0x03;

    /** {@code INIT_SECURE_CHANNEL} — ECDH handshake; establishes session keys. */
    public static final byte INS_INIT_SECURE_CHANNEL = (byte) 0x10;

    /** {@code OPEN_SECURE_CHANNEL} — envelopes an inner APDU under the session keys. */
    public static final byte INS_OPEN_SECURE_CHANNEL = (byte) 0x11;

    /** {@code SETUP} — initial PIN/PUK provisioning. */
    public static final byte INS_SETUP = (byte) 0x20;

    /** {@code VERIFY_PIN} — unlock session-scoped PIN authorisation. */
    public static final byte INS_VERIFY_PIN = (byte) 0x21;

    /** {@code CHANGE_PIN} — rotate user PIN. */
    public static final byte INS_CHANGE_PIN = (byte) 0x22;

    /** {@code CHANGE_PUK} — rotate unblock PUK. */
    public static final byte INS_CHANGE_PUK = (byte) 0x23;

    /** {@code UNBLOCK_PIN} — PUK-based PIN unblock. */
    public static final byte INS_UNBLOCK_PIN = (byte) 0x24;

    /** {@code EXPORT_PKI_PUBKEY} — export authentikey pubkey for CSR construction. */
    public static final byte INS_EXPORT_PKI_PUBKEY = (byte) 0x30;

    /** {@code SIGN_PKI_CSR} — sign a host-provided CSR digest with the authentikey. */
    public static final byte INS_SIGN_PKI_CSR = (byte) 0x31;

    /** {@code IMPORT_PKI_CERT} — chunked manufacturer certificate import. */
    public static final byte INS_IMPORT_PKI_CERT = (byte) 0x32;

    /** {@code EXPORT_PKI_CERT} — paged certificate export. */
    public static final byte INS_EXPORT_PKI_CERT = (byte) 0x33;

    /** {@code LOCK_PKI} — finalise PKI personalisation; transitions to PERSONALIZED. */
    public static final byte INS_LOCK_PKI = (byte) 0x34;

    /** {@code IMPORT_SEED} — install a user-supplied master seed and advance to SEEDED. */
    public static final byte INS_IMPORT_SEED = (byte) 0x40;

    /** {@code GENERATE_SEED} — card-internal CSPRNG seed; raw seed returned once. */
    public static final byte INS_GENERATE_SEED = (byte) 0x41;

    /** {@code EXPORT_XPUB} — derive a BIP-32 / SLIP-10 child and return its public material. */
    public static final byte INS_EXPORT_XPUB = (byte) 0x42;

    /**
     * {@code SIGN_ECDSA_K1} — sign a host-supplied 32-byte digest with the secp256k1 private key
     * derived at the given BIP-32 path. The response is a fixed-length {@code r(32) ‖ s(32)} pair
     * with {@code s} normalised to the low half of {@code n} (per BIP-62 / EIP-2).
     */
    public static final byte INS_SIGN_ECDSA_K1 = (byte) 0x50;

    /**
     * {@code SIGN_SCHNORR_K1} — sign a 32-byte digest with the BIP-340 Schnorr scheme on secp256k1
     * under the BIP-32-derived leaf scalar. Inner data: {@code [depth(1), path(4*depth),
     * digest(32)]}. Returns {@code [r(32), s(32)]} per BIP-340 §3 (R is x-only, encoded as the
     * affine x-coordinate of the nonce point with implicit even-y).
     */
    public static final byte INS_SIGN_SCHNORR_K1 = (byte) 0x51;

    /**
     * {@code SIGN_ED25519} — sign an arbitrary-length host-supplied message with the Ed25519
     * private key derived at the given SLIP-10 path. Inner data: {@code [depth(1), path(4*depth),
     * msg(...)]}; the message is whatever bytes the host wants to authenticate (per RFC 8032 the
     * card hashes them itself — the only signing primitive in the applet that does not take a
     * pre-computed digest, since the algorithm definition itself absorbs the message into the nonce
     * and challenge hashes). Returns {@code [R(32), S(32)]} per RFC 8032 §5.1.6 — {@code R}
     * compressed Edwards form, {@code S} little-endian scalar.
     */
    public static final byte INS_SIGN_ED25519 = (byte) 0x52;

    /*  Status words — ISO 7816-4 standard codes plus applet-private extensions in the 6Fxx
     *  range. Keep the comments authoritative: every host SDK decodes against this table.
     */

    /** ISO 7816-4 {@code 6700} — wrong length. */
    public static final short SW_WRONG_LENGTH = (short) 0x6700;

    /** ISO 7816-4 {@code 6982} — security status not satisfied (PIN / Secure Channel). */
    public static final short SW_SECURITY_STATUS_NOT_SATISFIED = (short) 0x6982;

    /** ISO 7816-4 {@code 6985} — condition of use not satisfied (e.g. wrong lifecycle state). */
    public static final short SW_CONDITIONS_NOT_SATISFIED = (short) 0x6985;

    /** ISO 7816-4 {@code 6A86} — incorrect P1 or P2. */
    public static final short SW_INCORRECT_P1P2 = (short) 0x6A86;

    /** ISO 7816-4 {@code 6D00} — INS not supported. */
    public static final short SW_INS_NOT_SUPPORTED = (short) 0x6D00;

    /** ISO 7816-4 {@code 6E00} — CLA not supported. */
    public static final short SW_CLA_NOT_SUPPORTED = (short) 0x6E00;

    /**
     * Reset-to-factory countdown base. The card returns {@code SW_RESET_COUNTDOWN_BASE + n}, where
     * {@code n} is the number of additional {@code RESET_TO_FACTORY} invocations still required to
     * trigger the wipe. {@code n == 0} signals that the wipe has been performed.
     *
     * <p>Range used: {@code 0x6FA0}–{@code 0x6FAF}. See {@code notes/specs/protocol.md} §4.
     */
    public static final short SW_RESET_COUNTDOWN_BASE = (short) 0x6FA0;

    /** Applet-private {@code 6FB0} — lifecycle state forbids this command. */
    public static final short SW_LIFECYCLE_INVALID = (short) 0x6FB0;

    /** Applet-private {@code 6FB1} — command requires an open Secure Channel. */
    public static final short SW_SECURE_CHANNEL_REQUIRED = (short) 0x6FB1;

    /** Applet-private {@code 6FB2} — Secure Channel cryptographic check failed. */
    public static final short SW_SECURE_CHANNEL_FAILED = (short) 0x6FB2;

    /**
     * ISO 7816-4 {@code 63Cn} base — PIN verification failed, {@code n} attempts remain. The caller
     * ORs in the (4-bit) remaining-tries count.
     */
    public static final short SW_PIN_RETRIES_BASE = (short) 0x63C0;

    /**
     * ISO 7816-4 {@code 6983} — Authentication method blocked. Used both for an exhausted PIN retry
     * counter and an exhausted PUK retry counter; the JC platform treats both as the same
     * cryptographic class.
     */
    public static final short SW_AUTH_BLOCKED = (short) 0x6983;

    /** Applet-private {@code 6FE0} — a required JavaCard feature is not available on this card. */
    public static final short SW_UNSUPPORTED_FEATURE = (short) 0x6FE0;

    /**
     * Applet-private {@code 6FE1} — a should-never-happen sentinel value was produced internally
     * (e.g. a tagged-hash output that reduced to zero mod {@code n} during Schnorr signing — the
     * BIP-340 spec mandates failing the signature in that case; the probability is ≈ 2⁻²⁵⁶). Hosts
     * should treat this as a transient error and retry; subsequent calls draw fresh aux randomness
     * and will not collide with overwhelming probability.
     */
    public static final short SW_INTERNAL_ERROR = (short) 0x6FE1;

    /*  Capability bitmask advertised in GET_INFO under TAG_CAPABILITIES.
     *  16-bit so feature flags can be added incrementally without re-encoding the field.
     */

    /** Bit 0 — card supports secp256k1 ECDSA signing. */
    public static final short CAP_K1_ECDSA = (short) 0x0001;

    /** Bit 1 — card supports BIP-340 Schnorr signing on secp256k1. */
    public static final short CAP_K1_SCHNORR = (short) 0x0002;

    /** Bit 2 — card supports Ed25519 EdDSA signing. */
    public static final short CAP_ED25519 = (short) 0x0004;

    // Bit 3 reserved for future AES-GCM Secure Channel.

    /**
     * Bit 4 — card exposes a Secure Channel using AES-256-CBC + AES-CMAC-128 (protocol.md §6). The
     * constant name is retained for backwards-compatible capability parsing on hosts; the
     * underlying primitive uses AES-CMAC-128, not HMAC, to match the J3R180 native algorithm
     * matrix.
     */
    public static final short CAP_SC_CBC_HMAC = (short) 0x0010;

    /** Bit 5 — card exposes the PKI personalisation flow. */
    public static final short CAP_PKI = (short) 0x0020;

    /** Bit 6 — card supports {@code RESET_TO_FACTORY}. */
    public static final short CAP_RESET_TO_FACTORY = (short) 0x0040;

    /** Bit 7 — card supports BIP-32 secp256k1 derivation. */
    public static final short CAP_BIP32 = (short) 0x0080;

    /** Bit 8 — card supports SLIP-10 Ed25519 derivation. */
    public static final short CAP_SLIP10 = (short) 0x0100;

    /*  TLV tags used inside GET_INFO. Single-byte tags in the application-private range so they
     *  never collide with ISO 7816-4 reserved primitive tags.
     */

    /** Tag 0x01 — protocol version (2 bytes, big-endian). */
    public static final byte TAG_PROTOCOL_VERSION = (byte) 0x01;

    /** Tag 0x02 — applet implementation version (2 bytes, big-endian). */
    public static final byte TAG_APPLET_VERSION = (byte) 0x02;

    /** Tag 0x03 — lifecycle state (1 byte). */
    public static final byte TAG_LIFECYCLE_STATE = (byte) 0x03;

    /** Tag 0x04 — capability bitmask (2 bytes, big-endian). */
    public static final byte TAG_CAPABILITIES = (byte) 0x04;

    /** Tag 0x05 — compressed authentikey public key (33 bytes). */
    public static final byte TAG_AUTHENTIKEY_PUBKEY = (byte) 0x05;

    /*  Sizes  */

    /** Length of an EC scalar (secp256k1 private key / hash / x-coordinate). */
    public static final short EC_SCALAR_LEN = (short) 32;

    /** Length of an uncompressed EC point ({@code 0x04 || x || y}). */
    public static final short EC_POINT_UNCOMPRESSED_LEN = (short) 65;

    /** Length of a compressed EC point ({@code 0x02|0x03 || x}). */
    public static final short EC_POINT_COMPRESSED_LEN = (short) 33;

    /*  Secure Channel sizes  */

    /** AES-256 key length (bytes) used for the Secure Channel encryption key {@code K_enc}. */
    public static final short SC_ENC_KEY_LEN = (short) 32;

    /** AES-128 key length (bytes) used for the Secure Channel MAC key {@code K_mac} (CMAC-128). */
    public static final short SC_MAC_KEY_LEN = (short) 16;

    /** AES-CBC block size and IV length (bytes). */
    public static final short SC_BLOCK_LEN = (short) 16;

    /** AES-CMAC-128 tag length (bytes) used as the Secure Channel MAC. */
    public static final short SC_MAC_LEN = (short) 16;

    /*  PIN / PUK policy  */

    /** Minimum PIN length in bytes. */
    public static final byte PIN_MIN_LEN = (byte) 4;

    /** Maximum PIN length in bytes. */
    public static final byte PIN_MAX_LEN = (byte) 16;

    /** Default PIN try-counter limit. */
    public static final byte PIN_RETRY_LIMIT = (byte) 3;

    /** Minimum PUK length in bytes. */
    public static final byte PUK_MIN_LEN = (byte) 8;

    /** Maximum PUK length in bytes. */
    public static final byte PUK_MAX_LEN = (byte) 32;

    /** Default PUK try-counter limit. */
    public static final byte PUK_RETRY_LIMIT = (byte) 5;

    /*  HD derivation  */

    /** Minimum acceptable BIP-32 seed length in bytes (16 bytes = 128 bits). */
    public static final short SEED_MIN_LEN = (short) 16;

    /** Maximum acceptable BIP-32 seed length in bytes (64 bytes = 512 bits, BIP-39 standard). */
    public static final short SEED_MAX_LEN = (short) 64;

    /** Fixed length of card-generated seeds (64 bytes / 512 bits, BIP-39 PBKDF2 output). */
    public static final short SEED_GENERATED_LEN = (short) 64;

    /** BIP-32 chain code length (always 32 bytes). */
    public static final short CHAIN_CODE_LEN = (short) 32;

    /** Maximum HD path depth accepted by {@code EXPORT_XPUB}. */
    public static final short HD_MAX_DEPTH = (short) 8;

    /** Curve identifier (P1 of {@code EXPORT_XPUB}) selecting secp256k1 BIP-32. */
    public static final byte CURVE_SECP256K1 = (byte) 0x00;

    /** Curve identifier selecting Ed25519 SLIP-10. */
    public static final byte CURVE_ED25519 = (byte) 0x01;

    /*  Signing primitives  */

    /**
     * Length of the digest accepted by the {@code SIGN_ECDSA_K1} and {@code SIGN_SCHNORR_K1}
     * primitives. Always 32 bytes — the card signs hashes only, never raw transactions.
     */
    public static final short DIGEST_LEN = (short) 32;

    /**
     * Length of the ECDSA / Schnorr signature returned to the host: {@code r(32) ‖ s(32)}.
     * Recovery-byte computation, when needed (e.g. for Ethereum), is host-side.
     */
    public static final short SIG_LEN_R_S = (short) 64;

    /**
     * Maximum length of a DER-encoded ECDSA signature returned by {@code
     * Signature.ALG_ECDSA_SHA_256}: {@code 0x30 ‖ len(1) ‖ 0x02 ‖ rLen(1) ‖ r(≤33) ‖ 0x02 ‖ sLen(1)
     * ‖ s(≤33)} → {@code 2 + 2 + 33 + 2 + 33 = 72 bytes}.
     */
    public static final short ECDSA_DER_MAX_LEN = (short) 72;

    /*  PKI personalisation  */

    /** Maximum committed certificate size in EEPROM. Sized for a typical X.509v3 EE cert. */
    public static final short PKI_CERT_MAX_LEN = (short) 1024;

    /** Maximum payload length per IMPORT_PKI_CERT WRITE chunk. */
    public static final short PKI_CERT_CHUNK_MAX_LEN = (short) 200;

    /** {@code IMPORT_PKI_CERT} sub-command: stage the import with the declared total size. */
    public static final byte PKI_IMPORT_P1_INIT = (byte) 0x00;

    /** {@code IMPORT_PKI_CERT} sub-command: write a chunk at the given offset. */
    public static final byte PKI_IMPORT_P1_WRITE = (byte) 0x01;

    /** {@code IMPORT_PKI_CERT} sub-command: commit the staged size as the new cert length. */
    public static final byte PKI_IMPORT_P1_FINALIZE = (byte) 0x02;

    /*  Reset-to-factory policy  */

    /**
     * Number of consecutive un-interleaved {@code RESET_TO_FACTORY} invocations required to trigger
     * the wipe. See {@code notes/specs/protocol.md} §4.
     */
    public static final byte RESET_REQUIRED_INVOCATIONS = (byte) 4;

    /*  Backup applet — BIP-39 seed-backup card (social.meowl.backup). Reuses the common surface
     *  above (CLA, the SW table, EC/SC sizes, the SC + lifecycle + PIN INS 0x01/0x02/0x03/0x10/
     *  0x11/0x20/0x21/0x22) and adds the seed-backup opcodes plus its own policy. The backup PIN
     *  has no PUK and wipes the seed on exhaustion (see BackupPin), so PUK_* above is wallet-only.
     *  INS values sit in the free upper half of the seed band so they never collide with the
     *  wallet seed opcodes 0x40–0x42.
     */

    /**
     * {@code BACKUP_SEED} — store BIP-39 entropy into the single seed slot (PIN-gated, SC-only).
     */
    public static final byte INS_BACKUP_SEED = (byte) 0x43;

    /** {@code RESTORE_SEED} — return the stored entropy under the Secure Channel (PIN-gated). */
    public static final byte INS_RESTORE_SEED = (byte) 0x44;

    /** {@code VERIFY_SEED} — recompute the seed integrity CMAC and report a match (PIN-gated). */
    public static final byte INS_VERIFY_SEED = (byte) 0x45;

    /** {@code SET_NAME} — set the user-facing backup card label (PIN-gated). */
    public static final byte INS_SET_NAME = (byte) 0x46;

    /** Minimum BIP-39 entropy length: 16 bytes = 128 bits = 12 words. */
    public static final short ENTROPY_MIN_LEN = (short) 16;

    /** Maximum BIP-39 entropy length: 32 bytes = 256 bits = 24 words. */
    public static final short ENTROPY_MAX_LEN = (short) 32;

    /** Maximum backup card label length in bytes. */
    public static final short BACKUP_NAME_MAX_LEN = (short) 32;

    /** Backup PIN maximum length in bytes; aligned with the Ledger Recovery Key 4–8 policy. */
    public static final byte BACKUP_PIN_MAX_LEN = (byte) 8;

    /** Backup PIN try limit; on exhaustion the seed is wiped (no PUK recovery). */
    public static final byte BACKUP_PIN_RETRY_LIMIT = (byte) 3;

    /** Status tag 0x06 — backup seed presence (1 byte: {@code 0x01} stored, {@code 0x00} empty). */
    public static final byte TAG_SEED_PRESENT = (byte) 0x06;

    /** Status tag 0x07 — remaining backup PIN tries (1 byte). */
    public static final byte TAG_PIN_TRIES = (byte) 0x07;

    /** Status tag 0x08 — backup card label (variable length, ≤ {@link #BACKUP_NAME_MAX_LEN}). */
    public static final byte TAG_CARD_NAME = (byte) 0x08;

    /** Status tag 0x09 — stored entropy length in bytes (1 byte: 16/24/32, or 0 when empty). */
    public static final byte TAG_SEED_LEN = (byte) 0x09;

    /** Applet-private {@code 6FD0} — stored-seed integrity (AES-CMAC-128) check failed. */
    public static final short SW_SEED_INTEGRITY_FAIL = (short) 0x6FD0;

    /** Applet-private {@code 6FD1} — a seed is already stored; the single slot is occupied. */
    public static final short SW_SEED_ALREADY_PRESENT = (short) 0x6FD1;

    /**
     * Throws {@link ISOException} with the given status word and returns a {@link RuntimeException}
     * that callers MUST {@code throw}. The trailing throw is unreachable at runtime — {@code
     * ISOException.throwIt} never returns — but it tells the JC 3.0.5 verifier (which does not
     * model {@code throwIt} as terminal) that control leaves the caller.
     *
     * <p>Usage at a callsite that would otherwise need a dummy {@code throw new RuntimeException()}
     * or {@code return 0} after {@code ISOException.throwIt}:
     *
     * <pre>{@code throw Constants.fail(Constants.SW_UNSUPPORTED_FEATURE); }</pre>
     */
    public static RuntimeException fail(short sw) {
        ISOException.throwIt(sw);
        throw new RuntimeException();
    }
}
