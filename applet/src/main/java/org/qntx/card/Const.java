// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

/**
 * Wire constants of spec/protocol.md: INS codes, labels, coded values (architecture.md §6, the
 * RM(1,4) code set of design/evidence/coded.py), the inner dispatch rule table (§9.2) and field
 * sizes. Static tables only; no state.
 */
final class Const {
    private Const() {}

    /** Proprietary class byte of every command after SELECT (§2). */
    static final byte CLA = (byte) 0x80;

    /** §13: internal error or detected fault (ISO7816 has no constant for it). */
    static final short SW_FAULT = (short) 0x6F00;

    /** §13.2: the failure limit was reached and the wallet was erased (ISO7816 6983). */
    static final short SW_ERASED = (short) 0x6983;

    /** §13.2: wrong access code base; OR-ed with the attempts remaining (§9.5 step 10). */
    static final short SW_WRONG_CODE = (short) 0x63C0;

    /**
     * §13.1: the instance exists but initialisation (§4.3) has not finished — ISO 7816-4 "selected
     * file deactivated". The card answers every command but GET_IDENTITY with it.
     */
    static final short SW_NOT_INITIALISED = (short) 0x6283;

    /**
     * Forces this class's initializer at install: the static arrays below must be written at
     * install, never lazily during a command.
     */
    static void init() {}

    static final byte INS_GET_IDENTITY = (byte) 0xE0;
    static final byte INS_PERSONALIZE = (byte) 0xE2;
    static final byte INS_OPEN = (byte) 0x10;
    static final byte INS_SESSION = (byte) 0x12;

    static final byte INS_STATUS = (byte) 0x20;
    static final byte INS_CREATE = (byte) 0x21;
    static final byte INS_VERIFY = (byte) 0x22;
    static final byte INS_CHANGE = (byte) 0x23;
    static final byte INS_ERASE = (byte) 0x24;
    static final byte INS_WAIT = (byte) 0x25;
    static final byte INS_PUBLIC_KEY = (byte) 0x30;
    static final byte INS_SIGN_ECDSA = (byte) 0x31;
    static final byte INS_SIGN_BIP340 = (byte) 0x32;

    /** §9.2: only these (INS, P1) pairs continue a pending state. */
    static final byte INS_SIGN_ED25519 = (byte) 0x33;

    static final byte INS_OFFER = (byte) 0x40;
    static final byte INS_EXPORT = (byte) 0x41;
    static final byte INS_IMPORT = (byte) 0x42;

    /** §1, ASCII without terminator: the certificate message label (§5.2). */
    static final byte[] LABEL_CERT = {
        (byte) 0x71, (byte) 0x6E, (byte) 0x74, (byte) 0x78, (byte) 0x2D, (byte) 0x63, (byte) 0x61,
        (byte) 0x72, (byte) 0x64, (byte) 0x2F, (byte) 0x76, (byte) 0x31, (byte) 0x2F, (byte) 0x63,
        (byte) 0x65, (byte) 0x72, (byte) 0x74,
    };

    /** §1: the session signature label (§8.1). */
    static final byte[] LABEL_SESSION = {
        (byte) 0x71, (byte) 0x6E, (byte) 0x74, (byte) 0x78, (byte) 0x2D, (byte) 0x63, (byte) 0x61,
        (byte) 0x72, (byte) 0x64, (byte) 0x2F, (byte) 0x76, (byte) 0x31, (byte) 0x2F, (byte) 0x73,
        (byte) 0x65, (byte) 0x73, (byte) 0x73, (byte) 0x69, (byte) 0x6F, (byte) 0x6E,
    };

    /** §1: the session key-derivation label (§8.1). */
    static final byte[] LABEL_KDF_SESSION = {
        (byte) 0x71, (byte) 0x6E, (byte) 0x74, (byte) 0x78, (byte) 0x2D, (byte) 0x63, (byte) 0x61,
        (byte) 0x72, (byte) 0x64, (byte) 0x2F, (byte) 0x76, (byte) 0x31, (byte) 0x2F, (byte) 0x6B,
        (byte) 0x64, (byte) 0x66, (byte) 0x2D, (byte) 0x73, (byte) 0x65, (byte) 0x73, (byte) 0x73,
        (byte) 0x69, (byte) 0x6F, (byte) 0x6E,
    };

    /** §1: the wrap key-derivation label "qntx-card/v1/wrap" (§10.1). */
    static final byte[] LABEL_WRAP = {
        (byte) 0x71, (byte) 0x6E, (byte) 0x74, (byte) 0x78, (byte) 0x2D, (byte) 0x63, (byte) 0x61,
        (byte) 0x72, (byte) 0x64, (byte) 0x2F, (byte) 0x76, (byte) 0x31, (byte) 0x2F, (byte) 0x77,
        (byte) 0x72, (byte) 0x61, (byte) 0x70,
    };

    /** §1: the seed fingerprint label "qntx-card/v1/fingerprint" (§10.1). */
    static final byte[] LABEL_FINGERPRINT = {
        (byte) 0x71, (byte) 0x6E, (byte) 0x74, (byte) 0x78, (byte) 0x2D, (byte) 0x63, (byte) 0x61,
        (byte) 0x72, (byte) 0x64, (byte) 0x2F, (byte) 0x76, (byte) 0x31, (byte) 0x2F, (byte) 0x66,
        (byte) 0x69, (byte) 0x6E, (byte) 0x67, (byte) 0x65, (byte) 0x72, (byte) 0x70, (byte) 0x72,
        (byte) 0x69, (byte) 0x6E, (byte) 0x74,
    };

    /** §1: the offer signature label "qntx-card/v1/offer" (§9.12). */
    static final byte[] LABEL_OFFER = {
        (byte) 0x71, (byte) 0x6E, (byte) 0x74, (byte) 0x78, (byte) 0x2D, (byte) 0x63, (byte) 0x61,
        (byte) 0x72, (byte) 0x64, (byte) 0x2F, (byte) 0x76, (byte) 0x31, (byte) 0x2F, (byte) 0x6F,
        (byte) 0x66, (byte) 0x66, (byte) 0x65, (byte) 0x72,
    };

    /** §1: the export signature label "qntx-card/v1/export" (§9.13). */
    static final byte[] LABEL_EXPORT = {
        (byte) 0x71, (byte) 0x6E, (byte) 0x74, (byte) 0x78, (byte) 0x2D, (byte) 0x63, (byte) 0x61,
        (byte) 0x72, (byte) 0x64, (byte) 0x2F, (byte) 0x76, (byte) 0x31, (byte) 0x2F, (byte) 0x65,
        (byte) 0x78, (byte) 0x70, (byte) 0x6F, (byte) 0x72, (byte) 0x74,
    };

    /** §1: the transfer key-derivation label "qntx-card/v1/kdf-transfer" (§9.13). */
    static final byte[] LABEL_KDF_TRANSFER = {
        (byte) 0x71, (byte) 0x6E, (byte) 0x74, (byte) 0x78, (byte) 0x2D, (byte) 0x63, (byte) 0x61,
        (byte) 0x72, (byte) 0x64, (byte) 0x2F, (byte) 0x76, (byte) 0x31, (byte) 0x2F, (byte) 0x6B,
        (byte) 0x64, (byte) 0x66, (byte) 0x2D, (byte) 0x74, (byte) 0x72, (byte) 0x61, (byte) 0x6E,
        (byte) 0x73, (byte) 0x66, (byte) 0x65, (byte) 0x72,
    };

    /** §1: the generated-seed label "qntx-card/v1/seed" (§9.4). */
    static final byte[] LABEL_SEED = {
        (byte) 0x71, (byte) 0x6E, (byte) 0x74, (byte) 0x78, (byte) 0x2D, (byte) 0x63, (byte) 0x61,
        (byte) 0x72, (byte) 0x64, (byte) 0x2F, (byte) 0x76, (byte) 0x31, (byte) 0x2F, (byte) 0x73,
        (byte) 0x65, (byte) 0x65, (byte) 0x64,
    };

    /** §10.2: the BIP-32 HMAC key "Bitcoin seed". */
    static final byte[] HMAC_BITCOIN = {
        (byte) 0x42,
        (byte) 0x69,
        (byte) 0x74,
        (byte) 0x63,
        (byte) 0x6F,
        (byte) 0x69,
        (byte) 0x6E,
        (byte) 0x20,
        (byte) 0x73,
        (byte) 0x65,
        (byte) 0x65,
        (byte) 0x64,
    };

    /** §1: the Ed25519 nonce label "qntx-card/v1/ed25519-nonce" (§12.3), 26 bytes. */
    static final byte[] LABEL_ED25519_NONCE = {
        (byte) 0x71, (byte) 0x6E, (byte) 0x74, (byte) 0x78, (byte) 0x2D, (byte) 0x63, (byte) 0x61,
                (byte) 0x72,
        (byte) 0x64, (byte) 0x2F, (byte) 0x76, (byte) 0x31, (byte) 0x2F, (byte) 0x65, (byte) 0x64,
                (byte) 0x32,
        (byte) 0x35, (byte) 0x35, (byte) 0x31, (byte) 0x39, (byte) 0x2D, (byte) 0x6E, (byte) 0x6F,
                (byte) 0x6E,
        (byte) 0x63, (byte) 0x65,
    };

    /**
     * BIP-340 tagged-hash tags (BIP-340 "Tagged Hashes", §12.2): each constant is {@code
     * SHA-256(tag)}; the tagged hash of {@code data} is {@code SHA-256(tag ‖ tag ‖ data)}.
     */
    static final byte[] TAG_AUX = {
        (byte) 0xF1, (byte) 0xEF, (byte) 0x4E, (byte) 0x5E, (byte) 0xC0, (byte) 0x63, (byte) 0xCA,
                (byte) 0xDA,
        (byte) 0x6D, (byte) 0x94, (byte) 0xCA, (byte) 0xFA, (byte) 0x9D, (byte) 0x98, (byte) 0x7E,
                (byte) 0xA0,
        (byte) 0x69, (byte) 0x26, (byte) 0x58, (byte) 0x39, (byte) 0xEC, (byte) 0xC1, (byte) 0x1F,
                (byte) 0x97,
        (byte) 0x2D, (byte) 0x77, (byte) 0xA5, (byte) 0x2E, (byte) 0xD8, (byte) 0xC1, (byte) 0xCC,
                (byte) 0x90,
    };

    /** SHA-256("BIP0340/nonce"), the {@link #TAG_AUX} sibling for the nonce tag. */
    static final byte[] TAG_NONCE = {
        (byte) 0x07, (byte) 0x49, (byte) 0x77, (byte) 0x34, (byte) 0xA7, (byte) 0x9B, (byte) 0xCB,
                (byte) 0x35,
        (byte) 0x5B, (byte) 0x9B, (byte) 0x8C, (byte) 0x7D, (byte) 0x03, (byte) 0x4F, (byte) 0x12,
                (byte) 0x1C,
        (byte) 0xF4, (byte) 0x34, (byte) 0xD7, (byte) 0x3E, (byte) 0xF7, (byte) 0x2D, (byte) 0xDA,
                (byte) 0x19,
        (byte) 0x87, (byte) 0x00, (byte) 0x61, (byte) 0xFB, (byte) 0x52, (byte) 0xBF, (byte) 0xEB,
                (byte) 0x2F,
    };

    /** SHA-256("BIP0340/challenge"), the {@link #TAG_AUX} sibling for the challenge tag. */
    static final byte[] TAG_CHALLENGE = {
        (byte) 0x7B, (byte) 0xB5, (byte) 0x2D, (byte) 0x7A, (byte) 0x9F, (byte) 0xEF, (byte) 0x58,
                (byte) 0x32,
        (byte) 0x3E, (byte) 0xB1, (byte) 0xBF, (byte) 0x7A, (byte) 0x40, (byte) 0x7D, (byte) 0xB3,
                (byte) 0x82,
        (byte) 0xD2, (byte) 0xF3, (byte) 0xF2, (byte) 0xD8, (byte) 0x1B, (byte) 0xB1, (byte) 0x22,
                (byte) 0x4F,
        (byte) 0x49, (byte) 0xFE, (byte) 0x51, (byte) 0x8F, (byte) 0x6D, (byte) 0x48, (byte) 0xD3,
                (byte) 0x7C,
    };

    /** §10.2: the SLIP-10 HMAC key "ed25519 seed". */
    static final byte[] HMAC_ED25519 = {
        (byte) 0x65,
        (byte) 0x64,
        (byte) 0x32,
        (byte) 0x35,
        (byte) 0x35,
        (byte) 0x31,
        (byte) 0x39,
        (byte) 0x20,
        (byte) 0x73,
        (byte) 0x65,
        (byte) 0x65,
        (byte) 0x64,
    };

    // Coded 16-bit constants (architecture.md §6): pairwise Hamming distance >= 8,
    // none equal to 0x0000 or 0xFFFF (§16.2 item 1).
    static final short LIFE_FACTORY = (short) 0x0F0F;
    static final short LIFE_BLANK = (short) 0x0FF0;
    static final short LIFE_LOADED = (short) 0x3333;
    static final short ORIGIN_GENERATED = (short) 0x33CC;
    static final short ORIGIN_IMPORTED = (short) 0x3C3C;
    static final short OFFER_NONE = (short) 0x3CC3;
    static final short OFFER_VALID = (short) 0x5555;
    static final short VERIFIED_NO = (short) 0x55AA;
    static final short VERIFIED_YES = (short) 0x5A5A;
    static final short CHECK_FAIL = (short) 0x5AA5;
    static final short CHECK_OK = (short) 0x6666;
    static final short CHECK_MALFORMED = (short) 0x8888;

    /**
     * The two derivation steps {@link Secp256k1#verifyHash} applies to {@link #CHECK_FAIL}: {@code
     * CHECK_FAIL ^ CHECK_STEP_1 ^ CHECK_STEP_2 = CHECK_OK}. A single skipped branch leaves {@code
     * 0x66A5} or {@code 0x5A66}, not a code-set member, which every caller rejects as {@code !=
     * CHECK_OK} (§16.2 items 1, 4). The steps themselves are not code-set members.
     */
    static final short CHECK_STEP_1 = (short) 0x3C00;

    static final short CHECK_STEP_2 = (short) 0x00C3;

    /**
     * §4.3: the coded value the {@code init} field holds once every initialisation step ran — an
     * RM(1,4) codeword, pairwise Hamming distance ≥ 8 to the other coded constants and ≥ 5 to every
     * step index 0 … {@link #INIT_STEPS} − 1, which occupy the field until then.
     */
    static final short INIT_DONE = (short) 0x9966;

    /** §4.3: the number of initialisation steps (indexes 0 … INIT_STEPS − 1 of {@code init}). */
    static final short INIT_STEPS = 7;

    /**
     * The two big-endian block counters of {@link Kdf#kdf} (§1): {@code u32(1) ‖ u32(2)} — a
     * constant so the counter is a load, never a store a fault can drop (§16.2 item 4).
     */
    static final byte[] KDF_COUNTER = {0, 0, 0, 1, 0, 0, 0, 2};

    static final short SESSION_OPEN = (short) 0x6699;
    static final short PENDING_STREAM = (short) 0x6969;
    static final short PENDING_EXPORT = (short) 0x6996;
    static final short PENDING_IMPORT = (short) 0x9669;

    /**
     * The shadow-word members of the RM(1,4) set (§16.2 item 1): unused codewords, Hamming distance
     * 8 from every member above, from {@code 0x0000}/{@code 0xFFFF} and from each other. A guarded
     * check's second evaluation reads the shadow word so the two evaluations never share one
     * transient flag.
     */
    static final short VERIFIED_SHADOW = (short) 0xA55A;

    static final short PENDING_EXPORT_SHADOW = (short) 0xC33C;

    /** Bit in {@link #INNER_LIFE} rows for each coded life value (dispatch table of §9.2). */
    static final short LIFE_BIT_BLANK = 2;

    static final short LIFE_BIT_LOADED = 4;

    /**
     * Inner dispatch rule table (§9.2), one row per implemented inner command: INS, the {@code
     * LIFE_BIT_*} mask of allowed life states, the largest allowed P1 (P2 must be 0), and whether
     * the session must be verified. Constant tables, not runtime flags.
     */
    static final byte[] INNER_INS = {
        INS_STATUS,
        INS_CREATE,
        INS_VERIFY,
        INS_CHANGE,
        INS_ERASE,
        INS_WAIT,
        INS_PUBLIC_KEY,
        INS_SIGN_ECDSA,
        INS_SIGN_BIP340,
        INS_SIGN_ED25519,
        INS_OFFER,
        INS_EXPORT,
        INS_IMPORT,
    };

    static final byte[] INNER_LIFE = {
        (byte) (LIFE_BIT_BLANK | LIFE_BIT_LOADED), // STATUS
        (byte) LIFE_BIT_BLANK, // CREATE
        (byte) LIFE_BIT_LOADED, // VERIFY
        (byte) LIFE_BIT_LOADED, // CHANGE
        (byte) LIFE_BIT_LOADED, // ERASE
        (byte) LIFE_BIT_LOADED, // WAIT
        (byte) LIFE_BIT_LOADED, // PUBLIC_KEY
        (byte) LIFE_BIT_LOADED, // SIGN_ECDSA
        (byte) LIFE_BIT_LOADED, // SIGN_BIP340
        (byte) LIFE_BIT_LOADED, // SIGN_ED25519
        (byte) (LIFE_BIT_BLANK | LIFE_BIT_LOADED), // OFFER
        (byte) LIFE_BIT_LOADED, // EXPORT
        (byte) (LIFE_BIT_BLANK | LIFE_BIT_LOADED), // IMPORT
    };
    static final byte[] INNER_P1_MAX = {0, 1, 0, 0, 0, 0, 1, 0, 0, 2, 0, 1, 1};
    static final byte[] INNER_VERIFIED = {0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0};

    /** §7.3: failure limit L, free attempts F, wait units per attempt W. */
    static final short FAIL_LIMIT = 10;

    static final short FREE_ATTEMPTS = 3;
    static final short WAIT_UNITS = 15;

    /** §9.15: the SHA-256 iterations of one WAIT unit. */
    static final short WAIT_ITERATIONS = 400;

    static final short POINT_LEN = 65;
    static final short COMPRESSED_LEN = 33;
    static final short CERT_LEN = 97;
    static final short STATE_LEN = 274;
    static final short AES_KEY_LEN = 16;
    static final short HASH_LEN = 32;

    /**
     * Read-only zero block for overwriting key material ({@code setKey}/{@code setS}); the platform
     * has no {@code clearKey} (architecture.md §4). Never written.
     */
    static final byte[] ZEROS = new byte[32];
}
