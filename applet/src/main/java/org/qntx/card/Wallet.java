// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * The wallet commands STATUS, CREATE, VERIFY, CHANGE, ERASE and WAIT (protocol.md §7.2, §9.3–9.7,
 * §9.15), the seed wrap of §10.1 and the persistent {@code wrapKey}. Everything a transaction
 * writes is computed into scratch first; the {@code t*()} methods only begin, write and commit — no
 * computation and no APDU-buffer writes inside (§16.1 item 2). Every guarded check is written
 * {@code if (x != CHECK_OK) { failure }} so a skipped conditional branch falls into the failure
 * path (§16.2 item 3).
 */
final class Wallet {
    /**
     * {@link Mem#W} layout of the wrap computation (all below {@link Mem#W_KDF} = 216): {@code
     * h(32) ‖ t(32) ‖ newWrapKey(16) ‖ kdfOut(32) ‖ ct(64) ‖ tag(16) ‖ fp(32)}. The KDF engines
     * write only {@code W[252..256)} internally, so the layout never collides with them.
     */
    private static final short W_H = 0;

    private static final short W_T = 32;
    private static final short W_NEWKEY = 64;
    private static final short W_KEYS = 80;
    private static final short W_CT = 112;
    private static final short W_TAG = 176;
    private static final short W_FP = 192;

    /** {@link Mem#P} layout: stored tag/fingerprint staging and {@code ID(A)} for CREATE. */
    private static final short P_STAG = 0;

    private static final short P_SFP = 16;
    private static final short P_IDA = 113;

    /** {@link Mem#H} slot of the 49-byte {@code members} staging block of CREATE and T-INSTALL. */
    private static final short H_MEMBERS = 0;

    private final Mem mem;
    private final State state;
    private final Session session;
    private final Identity identity;
    private final Derivation derivation;
    private final Secp256k1 secp;

    /**
     * The persistent AES-128 wrap key of §10.1: overwritten inside T-CREATE, T-CHANGE, T-INSTALL
     * and T-ERASE; a random key unrelated to any ciphertext in BLANK (§4.2).
     */
    private final AESKey wrapKey;

    /**
     * The private half of the link key pair §4.2 assigns to T-OFFER; T-CREATE, T-INSTALL and
     * T-ERASE overwrite it with a fresh random scalar so no published {@code LK} keeps a working
     * private key (§4.2, §16.1). Owned by {@link Transfer}; only the transaction bodies write it.
     */
    private final ECPrivateKey linkPrivate;

    Wallet(
            Mem mem,
            State state,
            Session session,
            Identity identity,
            Derivation derivation,
            Secp256k1 secp,
            ECPrivateKey linkPrivate) {
        this.mem = mem;
        this.state = state;
        this.session = session;
        this.identity = identity;
        this.derivation = derivation;
        this.secp = secp;
        this.linkPrivate = linkPrivate;
        wrapKey =
                (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
    }

    /**
     * Initialisation step 6 (§4.3): a fresh random {@code wrapKey} and the coded FACTORY state —
     * {@code fails ← 0} (value and complement), {@code offer ← NONE}, {@code life ← FACTORY};
     * {@code init ← INIT_DONE} is written by the dispatch, last.
     */
    void initState() {
        mem.random.nextBytes(mem.W, (short) 0, Const.AES_KEY_LEN);
        wrapKey.setKey(mem.W, (short) 0);
        state.writeFails((short) 0);
        state.setCoded(State.OFF_OFFER, Const.OFFER_NONE);
        state.setLife(Const.LIFE_FACTORY);
    }

    /**
     * STATUS (§9.3): {@code life(1) ‖ tries(1)} — {@code 0x01} BLANK, {@code 0x02} LOADED; {@code
     * tries = 0} in BLANK, {@code max(L − f, 0)} in LOADED with {@code f} an unsigned count
     * (consistent out-of-range values such as {@code 0x8000} give 0). The {@code fails} complement
     * is checked in both states and a disagreement is a fault (§16.2 item 2).
     */
    short status(byte[] out, short off) {
        short life = state.life();
        short f = state.fails();
        if (life == Const.LIFE_BLANK) {
            out[off] = 0x01;
            out[(short) (off + 1)] = 0;
            return 2;
        }
        if (life == Const.LIFE_LOADED) {
            out[off] = 0x02;
            // tries = max(L − f, 0) read unsigned: f < 0 or f ≥ L shows 0
            short t = (short) (Const.FAIL_LIMIT - f);
            out[(short) (off + 1)] = (byte) (t < 1 || t > Const.FAIL_LIMIT ? 0 : t);
            return 2;
        }
        // a life the §9.2 table would have denied is a detected fault: the gate
        // re-check must have been skipped (§16.2 item 4)
        ISOException.throwIt(Const.SW_FAULT);
        return 0;
    }

    /**
     * CREATE (§9.4). Data checks: {@code others} pairwise distinct and none {@code == ID(A)}, then
     * the seed/master validity (each {@code 6A80}). {@code P1 = 0} draws {@code t} and hashes
     * {@code seed = SHA-512(label ‖ t ‖ hostEntropy)}, redrawing while the master is invalid;
     * {@code P1 = 1} takes the given seed. On success: T-CREATE, {@code verified ← YES}, the seed
     * stays in {@link Mem#seed}, response {@code WalletInfo} (§9.2).
     */
    short create(byte[] buf, byte p1, short dataOff, short dataLen) {
        byte[] w = mem.W;
        byte[] p = mem.P;
        short base = (short) (p1 == 0 ? 64 : 96);
        short m = (short) ((short) (dataLen - base) / 16);
        identity.id(p, P_IDA);
        short others = (short) (dataOff + base);
        short last = (short) (others + m * 16);
        for (short i = others; i != last; i += 16) {
            // an other rejected unless proven different from ID(A): equal and faulted
            // reads alike take the rejection path (§9.4, §16.2 item 3)
            if (Bytes.equal(buf, i, p, P_IDA, (short) 16) != Const.CHECK_FAIL) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            for (short j = (short) (i + 16); j != last; j += 16) {
                if (Bytes.equal(buf, i, buf, j, (short) 16) != Const.CHECK_FAIL) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
            }
        }
        short origin;
        if (p1 == 0) {
            // a command that died between update and doFinal leaves pending bytes
            mem.sha512.reset();
            for (; ; ) {
                mem.random.nextBytes(w, W_T, Const.HASH_LEN);
                mem.sha512.update(Const.LABEL_SEED, (short) 0, (short) Const.LABEL_SEED.length);
                mem.sha512.update(w, W_T, Const.HASH_LEN);
                mem.sha512.doFinal(
                        buf,
                        (short) (dataOff + Const.HASH_LEN),
                        Const.HASH_LEN,
                        mem.seed,
                        (short) 0);
                if (derivation.master(
                                mem.seed, (short) 0, (short) mem.seed.length, mem.N, (short) 0)
                        == Const.CHECK_OK) {
                    break;
                }
            }
            origin = Const.ORIGIN_GENERATED;
        } else {
            Util.arrayCopy(
                    buf,
                    (short) (dataOff + Const.HASH_LEN),
                    mem.seed,
                    (short) 0,
                    (short) mem.seed.length);
            if (derivation.master(mem.seed, (short) 0, (short) mem.seed.length, mem.N, (short) 0)
                    != Const.CHECK_OK) {
                Bytes.wipe(mem.seed, (short) 0, (short) mem.seed.length);
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            origin = Const.ORIGIN_IMPORTED;
        }
        derivation.wipeCaches();
        // the members block c ‖ ID(A) ‖ others ‖ 0* and the wrap are prepared before the
        // transaction opens (§16.1 item 2)
        byte[] h = mem.H;
        h[H_MEMBERS] = (byte) (m + 1);
        Util.arrayCopy(p, P_IDA, h, (short) (H_MEMBERS + 1), (short) 16);
        Util.arrayFillNonAtomic(h, (short) (H_MEMBERS + 17), (short) 32, (byte) 0);
        Util.arrayCopy(buf, others, h, (short) (H_MEMBERS + 17), (short) (m * 16));
        mem.random.nextBytes(w, W_NEWKEY, Const.AES_KEY_LEN);
        // the access hash is staged only now: ModArith owns W[0..96) and W[128..256),
        // so the master check above would have clobbered an earlier copy (§5.1)
        Util.arrayCopy(buf, dataOff, w, W_H, Const.HASH_LEN);
        wrap(w, mem.seed, (short) 0);
        // W_T is dead past the draw loop: the link-scalar overwrite of §4.3
        secp.randomScalar(w, W_T);
        // the guarded life check, evaluated twice, immediately before T-CREATE (§16.2 item 4)
        if (state.life() != Const.LIFE_BLANK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (state.life() != Const.LIFE_BLANK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        tInstall(h, origin);
        session.setVerified();
        return walletInfo(buf);
    }

    /**
     * VERIFY (§9.5): the exact step order of the spec; every guarded comparison is {@code if (x !=
     * CHECK_OK) { failure }}. The candidate hash is first used in step 7, after T-FAIL has been
     * committed and read back (§16.1 item 2).
     */
    short verify(byte[] buf, short dataOff) {
        byte[] w = mem.W;
        // step 1
        session.clearVerified();
        Bytes.wipe(mem.seed, (short) 0, (short) mem.seed.length);
        derivation.wipeCaches();
        // the candidate is only copied — not used — before the gate of step 6 passes
        Util.arrayCopy(buf, dataOff, w, W_H, Const.HASH_LEN);
        // step 2: two independent reads, each test evaluated on each read (§16.2 item 4)
        short fa = state.readFails();
        short fb = state.readFails();
        if (fa == -1) {
            tErase();
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (fb == -1) {
            tErase();
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (belowLimit(fa) != Const.CHECK_OK) {
            tErase();
            ISOException.throwIt(Const.SW_ERASED);
        }
        if (belowLimit(fb) != Const.CHECK_OK) {
            tErase();
            ISOException.throwIt(Const.SW_ERASED);
        }
        // step 3: evaluated once — a skip buys one unwaited attempt, never more (§16.2 item 4)
        if (fa >= Const.FREE_ATTEMPTS && session.waited() < Const.WAIT_UNITS) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        // step 4
        session.clearWaited();
        // step 5: T-FAIL
        tFail((short) (fa + 1));
        // step 6: the read-back gate, twice independently (§16.2 item 4)
        if (gate(fb) != Const.CHECK_OK) {
            gateFail();
        }
        if (gate(fb) != Const.CHECK_OK) {
            gateFail();
        }
        // step 7: two independent KDF108+CMAC computations (§16.2 item 3)
        if (match(w) != Const.CHECK_OK) {
            mismatch(fb);
        }
        if (match(w) != Const.CHECK_OK) {
            mismatch(fb);
        }
        // step 8: match() has just read the stored ct into W_CT for the CMAC — the
        // freshest read is already in place, a second read could only be stale
        mem.aesCbc.init(mem.kEnc, Cipher.MODE_DECRYPT, Const.ZEROS, (short) 0, (short) 16);
        mem.aesCbc.doFinal(w, W_CT, (short) 64, mem.seed, (short) 0);
        if (fingerprint() != Const.CHECK_OK) {
            Bytes.wipe(mem.seed, (short) 0, (short) mem.seed.length);
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (fingerprint() != Const.CHECK_OK) {
            Bytes.wipe(mem.seed, (short) 0, (short) mem.seed.length);
            ISOException.throwIt(Const.SW_FAULT);
        }
        tOk();
        session.setVerified();
        return walletInfo(buf);
    }

    /**
     * CHANGE (§9.6): {@code verified} evaluated twice immediately before T-CHANGE; new random
     * {@code wrapKey}, {@code ct} and {@code tag} from the session seed and the new hash; the
     * session stays verified. Empty response.
     */
    void change(byte[] buf, short dataOff) {
        byte[] w = mem.W;
        Util.arrayCopy(buf, dataOff, w, W_H, Const.HASH_LEN);
        mem.random.nextBytes(w, W_NEWKEY, Const.AES_KEY_LEN);
        wrap(w, mem.seed, (short) 0);
        // the guarded check, evaluated twice, immediately before T-CHANGE (§16.2 item 4)
        if (session.verified() != Const.VERIFIED_YES) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (session.verified() != Const.VERIFIED_YES) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        tChange();
    }

    /**
     * ERASE (§9.7): {@code life} and {@code verified} evaluated twice immediately before T-ERASE;
     * then {@code verified} cleared, session seed and caches wiped; the session stays open. Empty
     * response.
     */
    void erase() {
        // the guarded checks, each evaluated twice, immediately before T-ERASE (§16.2 item 4)
        if (state.life() != Const.LIFE_LOADED) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (state.life() != Const.LIFE_LOADED) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (session.verified() != Const.VERIFIED_YES) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (session.verified() != Const.VERIFIED_YES) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        tErase();
        session.clearVerified();
        Bytes.wipe(mem.seed, (short) 0, (short) mem.seed.length);
        derivation.wipeCaches();
    }

    /** WAIT (§9.15): {@code I = 400} iterated SHA-256 of a zero block; {@code waited += 1}. */
    void waitUnit() {
        byte[] w = mem.W;
        Bytes.wipe(w, (short) 0, Const.HASH_LEN);
        for (short i = 0; i < Const.WAIT_ITERATIONS; i++) {
            mem.sha256.doFinal(w, (short) 0, Const.HASH_LEN, w, (short) 0);
        }
        Bytes.wipe(w, (short) 0, Const.HASH_LEN);
        session.addWait();
    }

    /**
     * T-CREATE and T-INSTALL of §4.3 — the same field set with different sources: everything
     * prepared in scratch (the fresh {@code wrapKey} at {@code W_NEWKEY}, {@code ct}/{@code
     * tag}/{@code fp} at their slots, {@code members} in {@code mem.H}, the fresh link scalar at
     * {@code W_T}) is written inside one transaction.
     */
    private void tInstall(byte[] members, short origin) {
        byte[] w = mem.W;
        JCSystem.beginTransaction();
        wrapKey.setKey(w, W_NEWKEY);
        state.write(State.OFF_CT, w, W_CT, (short) 64);
        state.write(State.OFF_TAG, w, W_TAG, (short) 16);
        state.write(State.OFF_FP, w, W_FP, Const.HASH_LEN);
        state.setCoded(State.OFF_ORIGIN, origin);
        state.write(State.OFF_MEMBERS, members, (short) 0, (short) 49);
        state.writeFails((short) 0);
        linkPrivate.setS(w, W_T, Const.HASH_LEN);
        state.setCoded(State.OFF_OFFER, Const.OFFER_NONE);
        state.setLife(Const.LIFE_LOADED);
        JCSystem.commitTransaction();
    }

    /** T-FAIL (§4.3): {@code fails ← f} with its complement. */
    private void tFail(short f) {
        JCSystem.beginTransaction();
        state.writeFails(f);
        JCSystem.commitTransaction();
    }

    /** T-OK (§4.3): {@code fails ← 0}. */
    private void tOk() {
        JCSystem.beginTransaction();
        state.writeFails((short) 0);
        JCSystem.commitTransaction();
    }

    /** T-CHANGE (§4.3): fresh {@code wrapKey}, {@code ct} and {@code tag}. */
    private void tChange() {
        byte[] w = mem.W;
        JCSystem.beginTransaction();
        wrapKey.setKey(w, W_NEWKEY);
        state.write(State.OFF_CT, w, W_CT, (short) 64);
        state.write(State.OFF_TAG, w, W_TAG, (short) 16);
        JCSystem.commitTransaction();
    }

    /**
     * T-ERASE (§4.3): {@code life ← BLANK}; {@code wrapKey} overwritten with fresh random drawn
     * before the transaction opens; {@code ct}, {@code tag}, {@code fp}, {@code origin} and {@code
     * members} cleared (offsets 6–8 and 14–175; {@code edCounter} and {@code cert} survive); {@code
     * fails ← 0}; {@code offer ← NONE}.
     */
    private void tErase() {
        byte[] w = mem.W;
        mem.random.nextBytes(w, W_NEWKEY, Const.AES_KEY_LEN);
        secp.randomScalar(w, W_T);
        JCSystem.beginTransaction();
        state.setLife(Const.LIFE_BLANK);
        wrapKey.setKey(w, W_NEWKEY);
        state.clear(State.OFF_ORIGIN, (short) 2);
        state.clear(State.OFF_MEMBERS, (short) (State.OFF_TAG + 16 - State.OFF_MEMBERS));
        state.writeFails((short) 0);
        linkPrivate.setS(w, W_T, Const.HASH_LEN);
        state.setCoded(State.OFF_OFFER, Const.OFFER_NONE);
        JCSystem.commitTransaction();
    }

    /**
     * {@code 0 ≤ f < L} as a coded result: {@code f} is an unsigned 16-bit count, so in {@code
     * short} arithmetic the out-of-range values are {@code f < 0 || f >= L} (§7.3).
     */
    private short belowLimit(short f) {
        return f >= 0 && f < Const.FAIL_LIMIT ? Const.CHECK_OK : Const.CHECK_FAIL;
    }

    /**
     * VERIFY step 6 read-back gate, on a fresh {@code fails} read: the transaction is closed, the
     * read is consistent, equals {@code fb + 1} and {@code 0 < f₁ ≤ L} (§9.5).
     */
    private short gate(short fb) {
        short r = Const.CHECK_FAIL;
        if (JCSystem.getTransactionDepth() == 0) {
            short f1 = state.readFails();
            // f1 must be exactly the committed fb + 1, which also fixes 1 ≤ f1 ≤ L;
            // belowLimit(f1 − 1) keeps that range check explicit (§9.5 step 6)
            if (f1 == (short) (fb + 1) && belowLimit((short) (f1 - 1)) == Const.CHECK_OK) {
                r = Const.CHECK_OK;
            }
        }
        return r;
    }

    /** VERIFY step 6 failure: abort a still-open transaction, then T-ERASE and {@code 6F00}. */
    private void gateFail() {
        if (JCSystem.getTransactionDepth() != 0) {
            JCSystem.abortTransaction();
        }
        tErase();
        ISOException.throwIt(Const.SW_FAULT);
    }

    /**
     * One independent §7.2 MAC recomputation (VERIFY step 7): KDF108 from the stored {@code
     * wrapKey} over the candidate at {@code W_H}, then {@code CMAC(kMac, ct)} against the stored
     * {@code tag}, constant time. Loads both {@code K_enc} and {@code K_mac} so a match leaves
     * {@code K_enc} ready for the decryption of step 8.
     */
    private short match(byte[] w) {
        Kdf.kdf108(mem, wrapKey, Const.LABEL_WRAP, w, W_H, Const.HASH_LEN, w, W_KEYS);
        mem.kEnc.setKey(w, W_KEYS);
        mem.kMac.setKey(w, (short) (W_KEYS + 16));
        state.read(State.OFF_CT, w, W_CT, (short) 64);
        mem.cmac.init(mem.kMac, Signature.MODE_SIGN);
        mem.cmac.sign(w, W_CT, (short) 64, w, W_TAG);
        state.read(State.OFF_TAG, mem.P, P_STAG, (short) 16);
        return Bytes.equal(w, W_TAG, mem.P, P_STAG, (short) 16);
    }

    /** VERIFY step 9–10: {@code f₁ = fb + 1} — {@code f₁ = L} erases, else {@code 63Cx}. */
    private void mismatch(short fb) {
        short f1 = (short) (fb + 1);
        if (f1 == Const.FAIL_LIMIT) {
            tErase();
            ISOException.throwIt(Const.SW_ERASED);
        }
        ISOException.throwIt((short) (Const.SW_WRONG_CODE | (Const.FAIL_LIMIT - f1)));
    }

    /**
     * One independent fingerprint check of VERIFY step 8: recomputes {@code SHA-256(label ‖ seed)}
     * into {@code W_FP} and compares with the stored {@code fp}, constant time.
     */
    private short fingerprint() {
        byte[] w = mem.W;
        fpHash(mem.seed, (short) 0, w, W_FP);
        state.read(State.OFF_FP, mem.P, P_SFP, Const.HASH_LEN);
        return Bytes.equal(w, W_FP, mem.P, P_SFP, Const.HASH_LEN);
    }

    /** {@code out = SHA-256("qntx-card/v1/fingerprint" ‖ seed)} (§10.1). */
    void fpHash(byte[] seed, short sOff, byte[] out, short oOff) {
        // a command that died between update and doFinal leaves pending bytes
        mem.sha256.reset();
        mem.sha256.update(
                Const.LABEL_FINGERPRINT, (short) 0, (short) Const.LABEL_FINGERPRINT.length);
        mem.sha256.doFinal(seed, sOff, (short) 64, out, oOff);
    }

    /**
     * The wrap of §10.1 for a NEW {@code wrapKey} (CREATE, CHANGE, T-INSTALL): the fresh key at
     * {@code W_NEWKEY} is loaded into {@code mem.kMac} temporarily to run KDF108 (the persistent
     * {@code wrapKey.setKey} happens only inside the transaction); then {@code kEnc ‖ kMac} derive
     * from the hash at {@code W_H} and {@code W_CT}, {@code W_TAG}, {@code W_FP} are filled from
     * the seed at {@code seed[sOff]}.
     */
    private void wrap(byte[] w, byte[] seed, short sOff) {
        mem.kMac.setKey(w, W_NEWKEY);
        Kdf.kdf108(mem, mem.kMac, Const.LABEL_WRAP, w, W_H, Const.HASH_LEN, w, W_KEYS);
        mem.kEnc.setKey(w, W_KEYS);
        mem.kMac.setKey(w, (short) (W_KEYS + 16));
        mem.aesCbc.init(mem.kEnc, Cipher.MODE_ENCRYPT, Const.ZEROS, (short) 0, (short) 16);
        mem.aesCbc.doFinal(seed, sOff, (short) 64, w, W_CT);
        mem.cmac.init(mem.kMac, Signature.MODE_SIGN);
        mem.cmac.sign(w, W_CT, (short) 64, w, W_TAG);
        fpHash(seed, sOff, w, W_FP);
    }

    /**
     * The install half of IMPORT {@code P1 = 0x01} (§9.14), called by {@link Transfer} after every
     * payload check passed: the decrypted payload at {@code buf[dataOff]} is {@code origin ‖
     * seed(64) ‖ accessHash_T(32) ‖ c ‖ IDs}; {@code dataLen} is the payload region to wipe ({@code
     * ct ‖ tag}). The seed is staged in {@link Mem#seed} for the wrap and the WalletInfo {@code
     * masterPublicKey}, then wiped; the payload is wiped before the response is written. {@code
     * verified} is cleared on success (§9.14). Staging the seed early is safe only because every
     * failure past this point is {@code 6F00}, which tears the session down and wipes {@code
     * Mem#seed} — every {@code 6A80} check runs before {@code install} is called. {@code life} is
     * the value {@link Transfer#import1} read at the start of the command; the guarded evaluations
     * below compare the live state against it, not merely against the BLANK/LOADED set.
     */
    short install(byte[] buf, short dataOff, short dataLen, short origin, short c, short life) {
        byte[] w = mem.W;
        byte[] h = mem.H;
        Util.arrayCopy(buf, (short) (dataOff + 1), mem.seed, (short) 0, (short) 64);
        Util.arrayCopy(buf, (short) (dataOff + 65), w, W_H, Const.HASH_LEN);
        h[H_MEMBERS] = (byte) c;
        Util.arrayCopy(buf, (short) (dataOff + 98), h, (short) (H_MEMBERS + 1), (short) (c * 16));
        for (short i = (short) (H_MEMBERS + 1 + c * 16); i != (short) (H_MEMBERS + 49); i++) {
            h[i] = 0;
        }
        mem.random.nextBytes(w, W_NEWKEY, Const.AES_KEY_LEN);
        wrap(w, mem.seed, (short) 0);
        secp.randomScalar(w, W_T);
        // the guarded life check, evaluated twice, immediately before T-INSTALL (§16.2 item 4)
        if (state.life() != life || state.life() != life) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        tInstall(h, origin);
        // every needed byte is out of buf now: the payload goes before the response lands (§9.14)
        Bytes.wipe(buf, dataOff, dataLen);
        session.clearVerified();
        short len = walletInfo(buf);
        Bytes.wipe(mem.seed, (short) 0, (short) mem.seed.length);
        derivation.wipeCaches();
        return len;
    }

    /**
     * WalletInfo of §9.2 — {@code masterPublicKey(33) ‖ origin(1) ‖ c(1) ‖ IDs} — read back from
     * the stored coded state, at buffer offset 0. A stored count outside {@code [1, 3]} is a
     * detected fault.
     */
    private short walletInfo(byte[] buf) {
        byte[] p = mem.P;
        derivation.masterPublicKey(buf, (short) 0);
        short o = state.origin();
        buf[Const.COMPRESSED_LEN] = o == Const.ORIGIN_GENERATED ? (byte) 0x01 : (byte) 0x02;
        state.read(State.OFF_MEMBERS, p, (short) 0, (short) 49);
        short c = (short) (p[0] & 0xFF);
        if (c < 1 || c > 3) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        buf[(short) (Const.COMPRESSED_LEN + 1)] = (byte) c;
        Util.arrayCopy(p, (short) 1, buf, (short) (Const.COMPRESSED_LEN + 2), (short) (c * 16));
        return (short) (Const.COMPRESSED_LEN + 2 + c * 16);
    }
}
