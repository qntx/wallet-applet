// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * The card-to-card transfer commands OFFER, EXPORT and IMPORT (protocol.md §9.12–9.14, §11), the
 * persistent {@code linkKey} pair and the two peer-key slots of §16.1 item 1, initialised to the
 * nothing-up-my-sleeve {@link Secp256k1#PEER_INIT} point so no slot ever holds a key whose discrete
 * logarithm is known. Peer certificates authenticate under the batch CA; membership decides which
 * slot a peer key takes (in {@code BLANK} always slot 0, in {@code LOADED} the position among the
 * other members). Decompressed peer points are staged in {@link Mem#W}[0..65) only until the {@code
 * setW} comparison — {@link ModArith} owns all of {@code W} during its operations. Pending export
 * and import keep {@code K_te ‖ K_tm} in {@link Mem#kTe}/{@link Mem#kTm} and the sender ID in
 * {@link Mem#sender}; {@link Session} overwrites the keys with fresh random values and wipes the
 * sender when the pending state ends (§16.2 item 4). Every check that gates a seed transfer or the
 * peer slot write is evaluated twice by independent recomputation — the second evaluation repeats
 * the verification, MAC computation, membership lookup or state read immediately before the effect
 * it guards; it never re-tests a stored result: the peer key is decompressed again and compared
 * with the slot before the slot is used again, the transcript is recomputed into its own buffer,
 * and the pending-export state is read from a separate shadow word. The transfer keys themselves
 * are derived twice — two ECDH products in separate buffers (the export's second {@code mul}
 * reloading {@code e} with its own load), two KDFs whose outputs are compared in constant time
 * before {@code setKey} and read back with {@code getKey} after — and the seed and access hash an
 * {@code EXPORT P1 = 0x01} or an install stages are compared with their sources before the effect
 * (§16.2 item 4).
 */
final class Transfer {
    /** {@link Mem#W} offset where a decompressed peer point is staged for {@code setW}. */
    private static final short W_PEER = 0;

    /**
     * {@link Mem#P} layout: {@code getW} read-back, own member ID, members block, candidate ID, the
     * first ECDH product and the {@code getKey} read-back (all dead between uses).
     */
    private static final short P_GETW = 0;

    private static final short P_SELF = 0;
    private static final short P_MEM = 16;
    private static final short P_CAND = 81;

    /** {@link Mem#P} offset of the first ECDH product and the {@code getKey} read-back. */
    private static final short P_PROD = 0;

    /** {@link Mem#H} layout shared by the four handlers (all regions dead between them). */
    private static final short H_TH = 0;

    private static final short H_A = 32;
    private static final short H_SCALAR = 65;
    private static final short H_K1 = 97;
    private static final short H_K2 = 129;

    /**
     * A second fp slot for the recomputed re-seal guard of IMPORT P1=01 — the {@link #H_K2} region
     * under its own name: the two derivations of {@code P1 = 0x00} are dead before {@code P1 =
     * 0x01} runs.
     */
    private static final short H_FP = 129;

    /** {@link Mem#N} layout: the generated {@code E} or recomputed {@code LK}. */
    private static final short N_POINT = 0;

    /** {@link Mem#W} offset of the second ECDH product ({@link #hashM} staging is dead then). */
    private static final short W_PROD = 0;

    private final Mem mem;
    private final State state;
    private final Session session;
    private final Identity identity;
    private final Secp256k1 secp;
    private final Derivation derivation;
    private final Wallet wallet;
    private final KeyPair linkKey;
    private final ECPrivateKey linkPrivate;
    private final ECPublicKey linkPublic;
    private final ECPublicKey[] peer;

    Transfer(
            Mem mem,
            State state,
            Session session,
            Identity identity,
            Secp256k1 secp,
            Derivation derivation,
            Wallet wallet,
            KeyPair linkKey) {
        this.mem = mem;
        this.state = state;
        this.session = session;
        this.identity = identity;
        this.secp = secp;
        this.derivation = derivation;
        this.wallet = wallet;
        this.linkKey = linkKey;
        linkPrivate = (ECPrivateKey) linkKey.getPrivate();
        linkPublic = (ECPublicKey) linkKey.getPublic();
        peer = new ECPublicKey[2];
        for (short i = 0; i < 2; i++) {
            peer[i] =
                    (ECPublicKey)
                            KeyBuilder.buildKey(
                                    KeyBuilder.TYPE_EC_FP_PUBLIC,
                                    KeyBuilder.LENGTH_EC_FP_256,
                                    false);
        }
    }

    /**
     * Initialisation step 1 (§4.3): the secp256k1 domain into the link pair and both peer slots,
     * and the nothing-up-my-sleeve {@link Secp256k1#PEER_INIT} point into the peer slots — never
     * {@code G}, so a slot a skipped {@code setPeer} leaves behind holds no key whose discrete
     * logarithm is known; an initialised slot lets {@code setPeer} skip the {@code CryptoException}
     * path (§16.1 item 1). Idempotent.
     */
    void initDomains() {
        Secp256k1.setDomain((ECKey) linkKey.getPublic());
        Secp256k1.setDomain((ECKey) linkKey.getPrivate());
        for (short i = 0; i < 2; i++) {
            Secp256k1.setDomain(peer[i]);
            peer[i].setW(Secp256k1.PEER_INIT, (short) 0, Const.POINT_LEN);
        }
    }

    /** Initialisation step 5 (§4.3): the initial {@code linkKey} pair of §11. */
    void initLink() {
        linkKey.genKeyPair();
    }

    /**
     * The persistent link key pair of §4.2/§11 — allocated at install, generated by initialisation
     * step 5 and regenerated by T-OFFER; its private half is overwritten inside Wallet's T-CREATE,
     * T-INSTALL and T-ERASE.
     */
    static KeyPair newLinkKey() {
        return new KeyPair(
                (ECPublicKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                (ECPrivateKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false));
    }

    /**
     * OFFER (§9.12): with {@code offer != VALID} a fresh link pair is committed by T-OFFER before
     * the output; with {@code offer = VALID} the stored {@code LK} is returned again and nothing is
     * written. Response {@code LK(65) ‖ sig(64)} — the signature is fresh each time.
     */
    short offer(byte[] buf) {
        short o = state.offer();
        if (o != Const.OFFER_VALID) {
            // the life guard, evaluated twice, immediately before T-OFFER (§16.2 item 4)
            short l1 = state.life();
            if (l1 != Const.LIFE_BLANK && l1 != Const.LIFE_LOADED) {
                ISOException.throwIt(Const.SW_FAULT);
            }
            short l2 = state.life();
            if (l2 != Const.LIFE_BLANK && l2 != Const.LIFE_LOADED) {
                ISOException.throwIt(Const.SW_FAULT);
            }
            tOffer();
            // the committed read-back, before anything is written to the buffer
            if (session.txDepth() != 0 || session.txDepth() != 0) {
                ISOException.throwIt(Const.SW_FAULT);
            }
            if (state.offer() != Const.OFFER_VALID || state.offer() != Const.OFFER_VALID) {
                ISOException.throwIt(Const.SW_FAULT);
            }
        }
        linkPublic.getW(buf, (short) 0);
        hash(Const.LABEL_OFFER, buf, (short) 0, Const.POINT_LEN, mem.H, H_TH);
        identity.signHash(mem.H, H_TH, buf, Const.POINT_LEN);
        return (short) (Const.POINT_LEN + 64);
    }

    /**
     * EXPORT {@code P1 = 0x00} (§9.13): authenticates the target's offer — the §9.13 data checks in
     * order, each {@code 6A80} — derives {@code E}, {@code Z}, the pending export keys and answers
     * {@code E ‖ sig_S}. The certificate, membership and {@code sig_T} checks are recomputed after
     * {@code hashM} (§16.2 item 4): {@link Identity#signHash} writes {@code sig_S} over the
     * certificate's signature and {@code LK_T} in {@code buf}, so every re-verification must run
     * before it.
     */
    short export0(byte[] buf, short dataOff) {
        byte[] h = mem.H;
        byte[] n = mem.N;
        if (identity.verifyCert(buf, dataOff) != Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        identity.identity(h, H_A);
        if (Bytes.equal(buf, dataOff, h, H_A, Const.COMPRESSED_LEN) != Const.CHECK_FAIL) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short slot = memberSlot(buf, dataOff);
        if (secp.decompress(buf, dataOff, mem.W, W_PEER) != Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        setPeer(slot, mem.W, W_PEER);
        short lkOff = (short) (dataOff + Const.CERT_LEN);
        if (buf[lkOff] != 0x04) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (offerSignature(buf, lkOff, slot, H_TH) != Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        secp.randomScalar(h, H_SCALAR);
        // the drawn scalar is checked in range a second time, independently of the
        // draw loop's own check, immediately before it is used (§16.2 item 4)
        if (Secp256k1.inRange(h, H_SCALAR) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        try {
            // the single-use e stays in the transient ephKey slot: PLAIN_XY rejects an
            // invalid LK_T itself (§16.5), mapped to the last data check's 6A80
            secp.mul(h, H_SCALAR, Secp256k1.G, (short) 0, n, N_POINT);
            hashM(h, H_A, buf, dataOff, buf, lkOff, n, N_POINT, H_TH);
            // the transfer keys are derived twice (§16.2 item 4): two ECDH products in
            // separate buffers, the second reloading e with its own load — the first
            // agrees from the scalar still in the ephKey slot
            if (secp.agree(secp.ephKey(), buf, lkOff, mem.P, P_PROD) != Const.CHECK_OK) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            transferKey(mem.P, P_PROD, H_TH, H_K1);
            secp.mul(h, H_SCALAR, buf, lkOff, mem.W, W_PROD);
            transferKey(mem.W, W_PROD, H_TH, H_K2);
        } finally {
            secp.wipeScalar();
        }
        // the checks guarding the pending export keys and the E output, recomputed
        // (§16.2 item 4); the offer hash goes to H_SCALAR — H_TH holds TH — which
        // also overwrites the dead e. recheckPeer decompresses A_T again and compares
        // it with the slot before the second verification uses it (§16.2 item 4)
        if (identity.verifyCert(buf, dataOff) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (memberSlot(buf, dataOff) != slot) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        recheckPeer(buf, dataOff, slot);
        if (offerSignature(buf, lkOff, slot, H_SCALAR) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        identity.signHash(h, H_TH, buf, Const.POINT_LEN);
        loadKeys();
        Util.arrayCopy(n, N_POINT, buf, (short) 0, Const.POINT_LEN);
        session.setPendingExport();
        return (short) (Const.POINT_LEN + 64);
    }

    /**
     * EXPORT {@code P1 = 0x01} (§9.13): {@code payload = origin ‖ seed ‖ accessHash_T ‖ c ‖ IDs}
     * under M2, {@code ct ‖ tag} with the pending export keys. An absent pending export is {@code
     * 6985}.
     */
    short export1(byte[] buf, short dataOff) {
        if (session.pending() != Const.PENDING_EXPORT) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] h = mem.H;
        h[0] = state.origin() == Const.ORIGIN_GENERATED ? (byte) 0x01 : (byte) 0x02;
        Util.arrayCopy(mem.seed, (short) 0, h, (short) 1, (short) 64);
        Util.arrayCopy(buf, dataOff, h, (short) 65, Const.HASH_LEN);
        state.read(State.OFF_MEMBERS, h, (short) 97, (short) 49);
        short c = (short) (h[97] & 0xFF);
        // a pending export implies a member target was found — c ≥ 2 (§9.13 check 3)
        if (c < 2 || c > 3) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        short ctLen = Bytes.pad(h, (short) 0, (short) (98 + c * 16));
        // the staged seed and access hash are compared with their sources (§16.2 item 4):
        // a skipped copy leaves zeros, not the value the output claims to carry
        if (Bytes.equal(h, (short) 1, mem.seed, (short) 0, (short) 64) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (Bytes.equal(h, (short) 65, buf, dataOff, Const.HASH_LEN) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        // the guarded check, evaluated twice, immediately before the output (architecture §6);
        // the second evaluation reads the shadow word (§16.2 item 1)
        if (session.verified() != Const.VERIFIED_YES) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (session.verifiedShadow() != Const.VERIFIED_YES) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        // the pending-export check's second evaluation, immediately before the
        // pending keys are used (§16.2 item 4), on the shadow word
        if (session.pendingExportShadow() != Const.PENDING_EXPORT) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        mem.aesCbc.init(mem.kTe, Cipher.MODE_ENCRYPT, Const.ZEROS, (short) 0, (short) 16);
        mem.aesCbc.doFinal(h, (short) 0, ctLen, buf, (short) 0);
        mem.cmac.init(mem.kTm, Signature.MODE_SIGN);
        mem.cmac.sign(buf, (short) 0, ctLen, buf, ctLen);
        return (short) (ctLen + 16);
    }

    /**
     * IMPORT {@code P1 = 0x00} (§9.14): authenticates the sender's export head — the §9.14 data
     * checks in order, each {@code 6A80} — derives the pending import keys and remembers {@code
     * ID(A_S)}. Requires {@code offer = VALID} ({@code 6985}).
     */
    short import0(byte[] buf, short dataOff) {
        if (state.offer() != Const.OFFER_VALID) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short life = state.life();
        byte[] h = mem.H;
        byte[] n = mem.N;
        if (identity.verifyCert(buf, dataOff) != Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        identity.identity(h, H_A);
        if (Bytes.equal(buf, dataOff, h, H_A, Const.COMPRESSED_LEN) != Const.CHECK_FAIL) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short slot = 0;
        // BLANK is the only life that skips the member check: a skipped branch must enter
        // it (§16.2 item 4), and in BLANK members are cleared so it fails anyway
        if (life != Const.LIFE_BLANK) {
            slot = memberSlot(buf, dataOff);
        }
        // the point is staged in N, not W: the memberSlot recompute below touches W
        // through Identity (W_TH/W_DER), and LK replaces it right after setPeer
        if (secp.decompress(buf, dataOff, n, N_POINT) != Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // the guards of the peer-slot write, recomputed immediately before the
        // effect (§16.2 item 4): the certificate again, and a fresh life read so
        // a faulted first read of `life` cannot decide the member gate twice
        if (identity.verifyCert(buf, dataOff) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (state.life() != Const.LIFE_BLANK && memberSlot(buf, dataOff) != slot) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        setPeer(slot, n, N_POINT);
        short eOff = (short) (dataOff + Const.CERT_LEN);
        linkPublic.getW(n, N_POINT);
        hashM(buf, dataOff, h, H_A, n, N_POINT, buf, eOff, H_TH);
        short sigOff = (short) (eOff + Const.POINT_LEN);
        if (secp.verifyHash(peer[slot], h, H_TH, buf, sigOff) != Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (secp.onCurve(buf, eOff) != Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // sig_S guards the pending import keys, recomputed in full on live data: A_S
        // decompressed again and compared with the slot, A and LK read again, TH
        // recomputed into its own slot and verified again; the pending keys come from
        // the recomputed TH (§16.2 item 4)
        recheckPeer(buf, dataOff, slot);
        identity.identity(h, H_A);
        linkPublic.getW(n, N_POINT);
        hashM(buf, dataOff, h, H_A, n, N_POINT, buf, eOff, H_SCALAR);
        if (secp.verifyHash(peer[slot], h, H_SCALAR, buf, sigOff) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        // the transfer keys are derived twice (§16.2 item 4): two ECDH products in
        // separate buffers — each KDF feeds the TH its own evaluation computed, never
        // the other's (K1 the recomputed TH′ at H_SCALAR, K2 the first at H_TH)
        if (secp.agree(linkPrivate, buf, eOff, mem.P, P_PROD) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        transferKey(mem.P, P_PROD, H_SCALAR, H_K1);
        if (secp.agree(linkPrivate, buf, eOff, mem.W, W_PROD) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        transferKey(mem.W, W_PROD, H_TH, H_K2);
        loadKeys();
        identity.cardId(buf, dataOff, mem.sender, (short) 0);
        session.setPending(Const.PENDING_IMPORT);
        return 0;
    }

    /**
     * IMPORT {@code P1 = 0x01} (§9.14): tag, decryption and the payload checks of §9.14 in order —
     * each {@code 6A80} — then the atomic install; response WalletInfo. Requires {@code offer =
     * VALID} and a pending import ({@code 6985}).
     */
    short import1(byte[] buf, short dataOff, short dataLen) {
        if (state.offer() != Const.OFFER_VALID) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (session.pending() != Const.PENDING_IMPORT) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short life = state.life();
        byte[] h = mem.H;
        short ctLen = (short) (dataLen - 16);
        if (mac(buf, dataOff, ctLen) != Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // the MAC recomputed immediately before decryption: decryption is in
        // place, so ct is gone afterwards (§16.2 item 4)
        if (mac(buf, dataOff, ctLen) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        mem.aesCbc.init(mem.kTe, Cipher.MODE_DECRYPT, Const.ZEROS, (short) 0, (short) 16);
        mem.aesCbc.doFinal(buf, dataOff, ctLen, buf, dataOff);
        short payloadLen = Bytes.unpad(buf, dataOff, ctLen);
        // check 2: c is the payload's own count byte, not a length derivation (§9.14)
        short c = (short) (buf[(short) (dataOff + 97)] & 0xFF);
        if ((short) (98 + c * 16) != payloadLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        byte o = buf[dataOff];
        if (o != 0x01 && o != 0x02) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        c = countRange(c);
        short ids = (short) (dataOff + 98);
        short idsEnd = (short) (ids + c * 16);
        for (short i = ids; i != idsEnd; i += 16) {
            for (short j = (short) (i + 16); j != idsEnd; j += 16) {
                if (Bytes.equal(buf, i, buf, j, (short) 16) != Const.CHECK_FAIL) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
            }
        }
        identity.id(mem.P, P_SELF);
        if (memberOf(buf, ids, idsEnd, mem.P, P_SELF) != Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (memberOf(buf, ids, idsEnd, mem.sender, (short) 0) != Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (derivation.master(buf, seedOff(dataOff), (short) 64, mem.N, (short) 0)
                != Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short origin = o == 0x01 ? Const.ORIGIN_GENERATED : Const.ORIGIN_IMPORTED;
        // BLANK is the only life that skips the re-seal checks: a skipped branch enters
        // them (§16.2 item 4), where cleared members and fp fail anyway
        if (life != Const.LIFE_BLANK) {
            reseal(buf, dataOff, c, origin);
        }
        // the guards of T-INSTALL, immediately before the effect (§16.2 item 4):
        // not BLANK — a fresh life read so a faulted first read cannot decide
        // the whole block twice — then every equality check, each twice
        if (state.life() != Const.LIFE_BLANK) {
            if (state.origin() != origin || state.origin() != origin) {
                ISOException.throwIt(Const.SW_FAULT);
            }
            short memLen = (short) (1 + c * 16);
            if (state.equal(State.OFF_MEMBERS, buf, (short) (dataOff + 97), memLen)
                            != Const.CHECK_OK
                    || state.equal(State.OFF_MEMBERS, buf, (short) (dataOff + 97), memLen)
                            != Const.CHECK_OK) {
                ISOException.throwIt(Const.SW_FAULT);
            }
            // a second slot: the recomputed fp must differ from the one reseal left in
            // H_TH, so a dropped recompute cannot reuse the stale value
            wallet.fpHash(buf, seedOff(dataOff), h, H_FP);
            if (state.equal(State.OFF_FP, h, H_FP, Const.HASH_LEN) != Const.CHECK_OK
                    || state.equal(State.OFF_FP, h, H_FP, Const.HASH_LEN) != Const.CHECK_OK) {
                ISOException.throwIt(Const.SW_FAULT);
            }
        }
        return wallet.install(buf, dataOff, dataLen, origin, c, life);
    }

    /**
     * T-OFFER (§4.3): a fresh link pair and {@code offer ← VALID}; committed before {@code LK} is
     * read back for the response (§16.1 item 4).
     */
    private void tOffer() {
        JCSystem.beginTransaction();
        linkKey.genKeyPair();
        state.setCoded(State.OFF_OFFER, Const.OFFER_VALID);
        JCSystem.commitTransaction();
    }

    /**
     * The peer slot write of §16.1 item 1: {@code getW} first, {@code setW} when the slot does not
     * already hold the point. The comparison's fall-through path is the write: skipping the branch
     * writes, and a skipped write leaves {@link Secp256k1#PEER_INIT} or another member's key, under
     * which the first evaluation's verification fails and the second evaluation's read-back differs
     * (§16.2 item 4).
     */
    private void setPeer(short slot, byte[] point, short pOff) {
        peer[slot].getW(mem.P, P_GETW);
        if (Bytes.equal(mem.P, P_GETW, point, pOff, Const.POINT_LEN) != Const.CHECK_OK) {
            peer[slot].setW(point, pOff, Const.POINT_LEN);
        }
    }

    /**
     * The peer-slot re-read of a second evaluation (§16.2 item 4): the certificate point is
     * decompressed again and compared with the slot's still-current content. A skipped {@link
     * #setPeer} or a clobbered slot makes the second evaluation see a different key than the first,
     * and every disagreement is a fault — the second evaluation never trusts the key the first
     * evaluation used.
     */
    private void recheckPeer(byte[] buf, short aOff, short slot) {
        if (secp.decompress(buf, aOff, mem.W, W_PEER) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        peer[slot].getW(mem.P, P_GETW);
        if (Bytes.equal(mem.P, P_GETW, mem.W, W_PEER, Const.POINT_LEN) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
    }

    /**
     * The member-index check of §9.13 step 3 / §9.14 step 3, folded into the peer-slot lookup of
     * §16.1 item 1: {@code ID(A)} must sit in {@code members} (else {@code 6A80}); the slot is the
     * position among the members other than this card. A {@code members} block without the card's
     * own ID is inconsistent persistent state ({@code 6F00}).
     */
    private short memberSlot(byte[] cert, short aOff) {
        byte[] p = mem.P;
        identity.id(p, P_SELF);
        identity.cardId(cert, aOff, p, P_CAND);
        state.read(State.OFF_MEMBERS, p, P_MEM, (short) 49);
        short c = (short) (p[P_MEM] & 0xFF);
        if (c < 1 || c > 3) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        short self = -1;
        short found = -1;
        // the index of found among the members other than self (§16.1 item 1): i minus the
        // selves seen before it — computed inside the loop so no boundary on self's
        // position is needed
        short slot = -1;
        short selvesBefore = 0;
        for (short i = 0; i != c; i++) {
            short o = (short) (P_MEM + 1 + i * 16);
            short isSelf = Bytes.equal(p, o, p, P_SELF, (short) 16);
            if (isSelf == Const.CHECK_OK) {
                self = i;
            }
            if (Bytes.equal(p, o, p, P_CAND, (short) 16) == Const.CHECK_OK) {
                found = i;
                slot = (short) (i - selvesBefore);
            }
            selvesBefore += isSelf == Const.CHECK_OK ? (short) 1 : (short) 0;
        }
        if (found < 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (self < 0 || self == found) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        return slot;
    }

    /**
     * §9.14 check 3's {@code c ∈ {2, 3}}: kept beside the length consistency it complements, though
     * the {@code {160, 176}} dispatch bound already forces {@code 98 + 16c} there.
     */
    private static short countRange(short c) {
        if (c < 2 || c > 3) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        return c;
    }

    /** The payload's seed offset — {@code origin(1) ‖ seed(64)} (§9.14 check 4). */
    private static short seedOff(short dataOff) {
        return (short) (dataOff + 1);
    }

    /**
     * §9.14 check 1: {@code CMAC(K_tm, ct)} into {@link Mem#H}[0..16), compared with the tag in
     * constant time.
     */
    private short mac(byte[] buf, short ctOff, short ctLen) {
        mem.cmac.init(mem.kTm, Signature.MODE_SIGN);
        mem.cmac.sign(buf, ctOff, ctLen, mem.H, (short) 0);
        return Bytes.equal(mem.H, (short) 0, buf, (short) (ctOff + ctLen), (short) 16);
    }

    /**
     * The {@code sig_T} check of §9.13 step 5: {@code SHA-256("qntx-card/v1/offer" ‖ LK_T)} into
     * {@link Mem#H}[hOff..hOff+32), verified under the peer slot.
     */
    private short offerSignature(byte[] buf, short lkOff, short slot, short hOff) {
        hash(Const.LABEL_OFFER, buf, lkOff, Const.POINT_LEN, mem.H, hOff);
        return secp.verifyHash(peer[slot], mem.H, hOff, buf, (short) (lkOff + Const.POINT_LEN));
    }

    /** Constant-time membership test of the 16-byte ID at {@code id[iOff]} in {@code ids}. */
    private static short memberOf(byte[] ids, short idsOff, short idsEnd, byte[] id, short iOff) {
        short r = Const.CHECK_FAIL;
        for (short i = idsOff; i != idsEnd; i += 16) {
            if (Bytes.equal(ids, i, id, iOff, (short) 16) == Const.CHECK_OK) {
                r = Const.CHECK_OK;
            }
        }
        return r;
    }

    /**
     * The re-seal equality checks of §9.14 check 5 (LOADED only): stored {@code origin}, {@code
     * members} and {@code fp} against the payload — each evaluated twice (architecture §6).
     */
    private void reseal(byte[] buf, short dataOff, short c, short origin) {
        if (state.origin() != origin) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short memLen = (short) (1 + c * 16);
        if (state.equal(State.OFF_MEMBERS, buf, (short) (dataOff + 97), memLen) != Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        wallet.fpHash(buf, (short) (dataOff + 1), mem.H, H_TH);
        if (state.equal(State.OFF_FP, mem.H, H_TH, Const.HASH_LEN) != Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    /**
     * {@code TH = SHA-256("qntx-card/v1/export" ‖ A_S ‖ A_T ‖ LK ‖ E)} into {@link
     * Mem#H}[thOff..thOff+32): the message the export signature covers (§9.13–9.14). The sender's
     * compressed identity is {@code aS} (the card's own in {@link #export0}, the certificate's in
     * {@link #import0}), the target's is {@code aT}, {@code lk} the target's 65-byte offer point,
     * {@code e} the 65-byte export point and {@code thOff} the caller's TH slot — a second
     * evaluation hashes into its own slot so a dropped recompute cannot leave the first
     * evaluation's TH behind (§16.2 item 4).
     */
    private void hashM(
            byte[] aS,
            short aSOff,
            byte[] aT,
            short aTOff,
            byte[] lk,
            short lkOff,
            byte[] e,
            short eOff,
            short thOff) {
        // the four message parts are staged contiguously in W: W_PEER is consumed
        // by setPeer before export0's call, and no Wallet offset is live here
        byte[] w = mem.W;
        Util.arrayCopy(aS, aSOff, w, (short) 0, Const.COMPRESSED_LEN);
        Util.arrayCopy(aT, aTOff, w, Const.COMPRESSED_LEN, Const.COMPRESSED_LEN);
        Util.arrayCopy(lk, lkOff, w, (short) (2 * Const.COMPRESSED_LEN), Const.POINT_LEN);
        Util.arrayCopy(
                e, eOff, w, (short) (2 * Const.COMPRESSED_LEN + Const.POINT_LEN), Const.POINT_LEN);
        hash(Const.LABEL_EXPORT, w, (short) 0, (short) 196, mem.H, thOff);
    }

    /** {@code out = SHA-256(label ‖ msg)} — the single-block message hash of §9.12. */
    private void hash(byte[] label, byte[] msg, short mOff, short mLen, byte[] out, short oOff) {
        mem.sha256.reset();
        mem.sha256.update(label, (short) 0, (short) label.length);
        mem.sha256.doFinal(msg, mOff, mLen, out, oOff);
    }

    /**
     * {@code KDF(Z, "qntx-card/v1/kdf-transfer", TH, 32)} (§9.13–9.14) of one derivation: the
     * 65-byte product point at {@code prod[pOff]} ({@code Z = prod[pOff + 1 .. pOff + 33)}) and the
     * transcript hash at {@code h[thOff]} derive 32 key bytes into {@code h[outOff]}. The caller
     * picks {@code thOff} so each derivation feeds {@link Kdf} the TH its own evaluation computed
     * (§16.2 item 4).
     */
    private void transferKey(byte[] prod, short pOff, short thOff, short outOff) {
        Kdf.kdf(
                mem,
                prod,
                (short) (pOff + 1),
                Const.HASH_LEN,
                Const.LABEL_KDF_TRANSFER,
                mem.H,
                thOff,
                Const.HASH_LEN,
                mem.H,
                outOff,
                Const.HASH_LEN);
    }

    /**
     * The pending transfer keys of §9.13–9.14, from the two independent derivations of §16.2 item
     * 4: {@code K1} and {@code K2} are compared in constant time before {@code setKey} — a single
     * fault in either product or KDF makes them differ — and each key object is read back with
     * {@code getKey} and compared with {@code K2}, so a skipped or faulted {@code setKey} leaves no
     * pending keys at all.
     */
    private void loadKeys() {
        byte[] h = mem.H;
        byte[] p = mem.P;
        if (Bytes.equal(h, H_K1, h, H_K2, Const.HASH_LEN) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        mem.kTe.setKey(h, H_K1);
        mem.kTm.setKey(h, (short) (H_K1 + Const.AES_KEY_LEN));
        mem.kTe.getKey(p, P_PROD);
        mem.kTm.getKey(p, (short) (P_PROD + Const.AES_KEY_LEN));
        if (Bytes.equal(p, P_PROD, h, H_K2, Const.HASH_LEN) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
    }
}
