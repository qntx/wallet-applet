// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * The §8 secure session: OPEN (§8.1), the command/response records (§8.3–8.4), teardown (§8.5) and
 * the coded session flags (§16.2 item 1). All state is transient: four AES keys in {@code
 * CLEAR_ON_DESELECT} objects, the five record engines re-armed per session and one {@code byte[10]}
 * holding the five 16-bit words {@code open}, {@code verified}, {@code ctr}, {@code pending} and
 * {@code waited} (the plain WAIT counter of §9.15, the only uncoded word).
 */
final class Session {
    /** Offsets of the 16-bit words inside {@link #words}. */
    private static final short O_OPEN = 0;

    private static final short O_VERIFIED = 2;
    private static final short O_CTR = 4;
    private static final short O_PENDING = 6;
    private static final short O_WAITED = 8;

    /** {@link Mem#W} layout used by {@link #unwrap} and {@link #wrap} (below {@link Mem#W_DER}). */
    private static final short W_CTR = 0;

    private static final short W_TAG = 16;
    private static final short W_IVSEED = 32;
    private static final short W_IV = 48;

    /** {@link Mem#W} layout of {@link #open} (all below {@link Mem#W_DER} = 184). */
    private static final short W_X = 0;

    private static final short W_ZPT = 32;
    private static final short W_Z = 33;

    /** {@link #open} reuses the wiped scalar slot for the transcript hash. */
    private static final short W_TH = 0;

    private static final short W_A = 162;
    private static final short W_KEYS = 97;

    /** {@link Mem#P} slot of {@link #open}: the host ephemeral. */
    private static final short P_HOST = 0;

    private final Mem mem;
    private final State state;
    private final Secp256k1 secp;
    private final Identity identity;
    private final AESKey kce;
    private final AESKey kcm;
    private final AESKey kre;
    private final AESKey krm;

    /**
     * The record layer's own engines (§8.3–8.4): {@code ceEnc}/{@code ceDec} on {@code kce}, {@code
     * reEnc} on {@code kre} and the CMACs {@code cm}/{@code rm}. {@link #initEngines} sets them up
     * once per session in {@link #open} and once per teardown with the zeroed keys — {@code
     * Cipher.doFinal}/{@code Signature.sign} reset an engine to its initialised state, so a record
     * costs no {@code init} at all (architecture §5.1).
     */
    private final Cipher ceEnc;

    private final Cipher ceDec;
    private final Cipher reEnc;
    private final Signature cm;
    private final Signature rm;
    private final byte[] words;

    Session(Mem mem, State state, Secp256k1 secp, Identity identity) {
        this.mem = mem;
        this.state = state;
        this.secp = secp;
        this.identity = identity;
        kce = aesKey();
        kcm = aesKey();
        kre = aesKey();
        krm = aesKey();
        ceEnc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        ceDec = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        reEnc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cm = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
        rm = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
        words = JCSystem.makeTransientByteArray((short) 10, JCSystem.CLEAR_ON_DESELECT);
    }

    private static AESKey aesKey() {
        return (AESKey)
                KeyBuilder.buildKey(
                        KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
    }

    /** Initialises the five record engines on whatever the four session keys currently hold. */
    private void initEngines() {
        ceEnc.init(kce, Cipher.MODE_ENCRYPT);
        ceDec.init(kce, Cipher.MODE_DECRYPT);
        reEnc.init(kre, Cipher.MODE_ENCRYPT);
        cm.init(kcm, Signature.MODE_SIGN);
        rm.init(krm, Signature.MODE_SIGN);
    }

    /**
     * OPEN (§8.1). The four checks run before teardown, so a rejected OPEN leaves a previous
     * session alive; no persistent write happens. Writes the response at buffer offset 0 and
     * returns its length.
     */
    short open(APDU apdu, short lc) {
        byte[] buf = apdu.getBuffer();
        short life = state.life();
        if (life != Const.LIFE_BLANK && life != Const.LIFE_LOADED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (lc != Const.POINT_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (buf[ISO7816.OFFSET_CDATA] != 0x04) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        teardown();
        byte[] p = mem.P;
        byte[] w = mem.W;
        Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, p, P_HOST, Const.POINT_LEN);
        secp.randomScalar(w, W_X);
        // cardEph = x·G straight into the response area; Z point into scratch
        secp.mul(w, W_X, Secp256k1.G, (short) 0, buf, (short) 0);
        try {
            secp.mul(w, W_X, p, P_HOST, w, W_ZPT);
        } catch (CryptoException e) {
            // §8.1: a multiplication failure on hostEph means an invalid point
            secp.wipeScalar();
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        secp.wipeScalar();
        identity.identity(w, W_A);
        mem.sha256.reset();
        mem.sha256.update(Const.LABEL_SESSION, (short) 0, (short) Const.LABEL_SESSION.length);
        mem.sha256.update(p, P_HOST, Const.POINT_LEN);
        mem.sha256.update(buf, (short) 0, Const.POINT_LEN);
        mem.sha256.doFinal(w, W_A, Const.COMPRESSED_LEN, w, W_TH);
        identity.signHash(w, W_TH, buf, Const.POINT_LEN);
        Kdf.kdf(
                mem,
                w,
                W_Z,
                (short) 32,
                Const.LABEL_KDF_SESSION,
                w,
                W_TH,
                Const.HASH_LEN,
                w,
                W_KEYS,
                (short) 64);
        kce.setKey(w, (short) (W_KEYS + 0));
        kcm.setKey(w, (short) (W_KEYS + 16));
        kre.setKey(w, (short) (W_KEYS + 32));
        krm.setKey(w, (short) (W_KEYS + 48));
        initEngines();
        setWord(O_OPEN, Const.SESSION_OPEN);
        state.cert(buf, (short) (Const.POINT_LEN + 64));
        // §8.1: x, Z and the KDF output in Mem.W are wiped by process() before the response
        return 226;
    }

    /**
     * §8.3 steps 1–5: validates and decrypts a command record in place at {@code OFFSET_CDATA};
     * returns the inner plaintext length. Steps 2–5 tear the session down and throw the outer
     * status.
     */
    short unwrap(APDU apdu, short lc) {
        byte[] buf = apdu.getBuffer();
        if (openWord() != Const.SESSION_OPEN) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0) {
            tearThrow(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (lc < 24 || (short) (lc & 0x0F) != 8) {
            tearThrow(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        byte[] w = mem.W;
        short ctLen = (short) (lc - 8);
        // tag = CMAC(K_cm, u16(ctr) ‖ ct)[0..8), compared in constant time
        Util.setShort(w, W_CTR, getWord(O_CTR));
        cm.update(w, W_CTR, (short) 2);
        cm.update(buf, ISO7816.OFFSET_CDATA, ctLen);
        cm.sign(w, (short) 0, (short) 0, w, W_TAG);
        // the guarded check, evaluated twice, immediately before decryption (§16.2 item 4)
        short t1 = Bytes.equal(w, W_TAG, buf, (short) (ISO7816.OFFSET_CDATA + ctLen), (short) 8);
        if (t1 != Const.CHECK_OK) {
            tearThrow(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        short t2 = Bytes.equal(w, W_TAG, buf, (short) (ISO7816.OFFSET_CDATA + ctLen), (short) 8);
        if (t2 != Const.CHECK_OK) {
            tearThrow(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        // IV = AES(K_ce, 0x01 ‖ 0¹³ ‖ u16(ctr)): one CBC block with a zero IV; ceDec
        // runs zero-IV too, so the first plaintext block is corrected by xoring the IV
        initIv(w, (byte) 0x01);
        ceEnc.doFinal(w, W_IVSEED, (short) 16, w, W_IV);
        ceDec.doFinal(buf, ISO7816.OFFSET_CDATA, ctLen, buf, ISO7816.OFFSET_CDATA);
        for (short i = 15; i >= 0; i--) {
            buf[(short) (ISO7816.OFFSET_CDATA + i)] ^= w[(short) (W_IV + i)];
        }
        short plen = Bytes.unpad(buf, ISO7816.OFFSET_CDATA, ctLen);
        if (plen < 0) {
            Bytes.wipe(buf, ISO7816.OFFSET_CDATA, ctLen);
            tearThrow(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        return plen;
    }

    /**
     * §8.4: wraps {@code data ‖ SW} (already at buffer offset 0) into a response record and wipes
     * every buffer byte past the R-APDU — the decrypted record's plaintext and M2 padding at {@code
     * OFFSET_CDATA} must not survive the command (§16.3 item 3). Returns the R-APDU length.
     */
    short wrap(APDU apdu, short dataLen, short sw) {
        byte[] buf = apdu.getBuffer();
        byte[] w = mem.W;
        Util.setShort(buf, dataLen, sw);
        short plen = Bytes.pad(buf, (short) 0, (short) (dataLen + 2));
        // zero-IV CBC over the first-block-xored plaintext is CBC with the IV of §8.4
        initIv(w, (byte) 0x02);
        reEnc.doFinal(w, W_IVSEED, (short) 16, w, W_IV);
        for (short i = 15; i >= 0; i--) {
            buf[i] ^= w[(short) (W_IV + i)];
        }
        reEnc.doFinal(buf, (short) 0, plen, buf, (short) 0);
        Util.setShort(w, W_CTR, getWord(O_CTR));
        rm.update(w, W_CTR, (short) 2);
        rm.update(buf, (short) 0, plen);
        rm.sign(w, (short) 0, (short) 0, w, W_TAG);
        Util.arrayCopyNonAtomic(w, W_TAG, buf, plen, (short) 8);
        short used = (short) (plen + 8);
        Bytes.wipe(buf, used, (short) (buf.length - used));
        return used;
    }

    /**
     * §8.4: advances {@code ctr} after the response was sent; the response carrying {@code ctr =
     * 0xFFFF} and any inner {@code 6F00} tear the session down (§8.5).
     */
    void afterResponse(short sw) {
        if (sw == Const.SW_FAULT || getWord(O_CTR) == (short) 0xFFFF) {
            teardown();
        } else {
            setWord(O_CTR, (short) (getWord(O_CTR) + 1));
        }
    }

    /**
     * §8.5: wipes, in spec order, the {@code verified} flag, the session seed, the derivation
     * caches, the pending state (its transfer keys overwritten with fresh random values, §16.2 item
     * 4), {@code waited}, the four session keys (overwritten, never {@code clearKey}; architecture
     * §4), {@code ctr} and the open flag. If a session was open, {@link #initEngines} then re-arms
     * the record engines on the zeroed keys so no engine keeps a session-key schedule past the
     * session (§16.3); a teardown with nothing to tear down (e.g. a bare SELECT) skips it.
     * Idempotent; also runs in {@code select()} and OPEN without relying on deselection.
     */
    void teardown() {
        short wasOpen = getWord(O_OPEN);
        setWord(O_VERIFIED, (short) 0);
        Bytes.wipe(mem.seed, (short) 0, (short) mem.seed.length);
        Bytes.wipe(mem.secpCache, (short) 0, (short) mem.secpCache.length);
        Bytes.wipe(mem.edCache, (short) 0, (short) mem.edCache.length);
        // the Ed25519 stream, the pending export and import states (§8.5)
        endPending();
        setWord(O_WAITED, (short) 0);
        kce.setKey(Const.ZEROS, (short) 0);
        kcm.setKey(Const.ZEROS, (short) 0);
        kre.setKey(Const.ZEROS, (short) 0);
        krm.setKey(Const.ZEROS, (short) 0);
        setWord(O_CTR, (short) 0);
        setWord(O_OPEN, (short) 0);
        if (wasOpen == Const.SESSION_OPEN) {
            initEngines();
        }
    }

    /** Coded read of {@code verified}: {@code 0x0000} is the safe cleared state (§16.2 item 1). */
    short verified() {
        short v = getWord(O_VERIFIED);
        if (v != Const.VERIFIED_YES && v != Const.VERIFIED_NO && v != 0) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        return v == Const.VERIFIED_YES ? Const.VERIFIED_YES : Const.VERIFIED_NO;
    }

    /** VERIFY (§9.5 step 1) and ERASE clear {@code verified} to the coded NO member. */
    void clearVerified() {
        setWord(O_VERIFIED, Const.VERIFIED_NO);
    }

    /** VERIFY and CREATE set {@code verified} on success (§9.2). */
    void setVerified() {
        setWord(O_VERIFIED, Const.VERIFIED_YES);
    }

    /**
     * The plain WAIT count, 0..{@code W} (§9.15): uncoded session state, read by VERIFY step 3 — a
     * faulted read buys at most one unwaited attempt (§16.2 item 4 note).
     */
    short waited() {
        return getWord(O_WAITED);
    }

    /** {@code waited ← min(waited + 1, W)} (§9.15). */
    void addWait() {
        short w = getWord(O_WAITED);
        setWord(O_WAITED, w == Const.WAIT_UNITS ? w : (short) (w + 1));
    }

    /** VERIFY step 4 consumes the completed wait units. */
    void clearWaited() {
        setWord(O_WAITED, (short) 0);
    }

    /**
     * §9.2 pending states, before dispatch: returns the pending code this command continues and
     * ends (word {@code <- 0x0000}) every pending state it does not continue. A corrupt word is a
     * detected fault.
     */
    short beginDispatch(byte ins, byte p1) {
        short p = getWord(O_PENDING);
        if (p == 0) {
            return 0;
        }
        short cont;
        if (p == Const.PENDING_STREAM) {
            cont =
                    ins == Const.INS_SIGN_ED25519 && (p1 == 1 || p1 == 2)
                            ? Const.PENDING_STREAM
                            : (short) 0;
        } else if (p == Const.PENDING_EXPORT) {
            cont = ins == Const.INS_EXPORT && p1 == 1 ? Const.PENDING_EXPORT : (short) 0;
        } else if (p == Const.PENDING_IMPORT) {
            cont = ins == Const.INS_IMPORT && p1 == 1 ? Const.PENDING_IMPORT : (short) 0;
        } else {
            ISOException.throwIt(Const.SW_FAULT);
            return 0;
        }
        if (cont == 0) {
            endPending();
        }
        return cont;
    }

    /**
     * §9.2 pending states, after dispatch: a continuation command ends its own pending state on
     * every outcome except a successful {@code SIGN_ED25519} {@code P1 = 0x01}.
     */
    void endDispatch(short pending, byte ins, byte p1, short sw) {
        if (pending == 0) {
            return;
        }
        if (ins != Const.INS_SIGN_ED25519 || p1 != 1 || sw != ISO7816.SW_NO_ERROR) {
            endPending();
        }
    }

    /**
     * Coded read of the pending word (§16.2 item 1): {@code 0x0000} is the platform-cleared no
     * pending state; any other non-member is a detected fault.
     */
    short pending() {
        short p = getWord(O_PENDING);
        if (p != 0
                && p != Const.PENDING_STREAM
                && p != Const.PENDING_EXPORT
                && p != Const.PENDING_IMPORT) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        return p;
    }

    /** A successful {@code SIGN_ED25519} {@code P1 = 0x00} arms the stream pending state (§9.2). */
    void setPending(short code) {
        setWord(O_PENDING, code);
    }

    /**
     * The open-transaction depth, read through a woven short call so a fault test can arm it; a raw
     * {@code JCSystem.getTransactionDepth} is outside the weave (§16.1 item 3 needs the gate).
     */
    short txDepth() {
        return JCSystem.getTransactionDepth();
    }

    /**
     * Ends the active pending state (§9.2): wipes the Ed25519 stream {@link Mem#edStream}, resets
     * the shared SHA-512 engine the stream hashes with, overwrites the pending export/import keys
     * {@link Mem#kTe}/{@link Mem#kTm} with fresh random values and wipes the pending sender {@link
     * Mem#sender} (§8.5, every run — the keys hold a completed or aborted transfer's shared
     * secret), and clears the word. Idempotent — also runs when the word is already {@code 0x0000}.
     * The digest reset is the only stream-state cleanup: {@code begin} relies on it rather than
     * resetting again.
     */
    private void endPending() {
        Bytes.wipe(mem.edStream, (short) 0, (short) mem.edStream.length);
        mem.resetSha512();
        // outside a pending transfer K_te/K_tm must be keys nobody holds: fresh
        // random values, never a constant, so a pending check bypassed by a fault
        // encrypts/MACs under unknown keys (§16.2 item 4); sender stages them and
        // is wiped right after
        mem.random.nextBytes(mem.sender, (short) 0, (short) 16);
        mem.kTe.setKey(mem.sender, (short) 0);
        mem.random.nextBytes(mem.sender, (short) 0, (short) 16);
        mem.kTm.setKey(mem.sender, (short) 0);
        Bytes.wipe(mem.sender, (short) 0, (short) mem.sender.length);
        setWord(O_PENDING, (short) 0);
    }

    /** Coded read of the open word; a corrupt word is a fault, torn down by {@code process}. */
    private short openWord() {
        short o = getWord(O_OPEN);
        if (o == 0 || o == Const.SESSION_OPEN) {
            return o;
        }
        ISOException.throwIt(Const.SW_FAULT);
        return 0;
    }

    /** §8.3 steps 2–5 and corrupt coded words: teardown, then the outer status. */
    private void tearThrow(short sw) {
        teardown();
        ISOException.throwIt(sw);
    }

    private short getWord(short off) {
        return Util.getShort(words, off);
    }

    private void setWord(short off, short value) {
        Util.setShort(words, off, value);
    }

    /** {@code W[W_IVSEED]} = {@code first ‖ 0¹³ ‖ u16(ctr)} (§8.3–8.4 IV construction). */
    private void initIv(byte[] w, byte first) {
        w[W_IVSEED] = first;
        Util.arrayFillNonAtomic(w, (short) (W_IVSEED + 1), (short) 13, (byte) 0);
        Util.setShort(w, (short) (W_IVSEED + 14), getWord(O_CTR));
    }
}
