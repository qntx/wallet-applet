// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * SIGN_ED25519 (§9.11, §12.3): the hedged, single-pass Ed25519 signature — begin derives the key,
 * commits T-EDCTR and produces the nonce {@code r} and {@code R}, update streams the message into
 * the shared SHA-512 engine and finish computes {@code S = (r + k·a) mod ℓ} with the masked
 * recombination of §16.2 item 7 and the {@code S·G_W = R + k·A} self-verification of §16.2 item 6.
 *
 * <p>Stream state in {@link Mem#edStream} {@code a(32) ‖ r(32) ‖ R(65) ‖ A(65)} — {@code a}, {@code
 * r} big-endian scalars, {@code R}, {@code A} uncompressed Wei25519 points.
 *
 * <p>Scratch layout of {@link #begin}: {@code H[0..64)} the nonce digest, {@code H[96..128)} {@code
 * prefix}, {@code H[128..144)} {@code ID(A_card)}, {@code H[160..192)} {@code a} (copied to {@code
 * edStream[0..32)}); {@code N[0..64)} the reversed digest for {@code reduce512}, {@code N[64..72)}
 * the counter {@code u32(N)} and its read-back — read there also for the pre-derive exhaustion
 * precondition. {@link #finish}: {@code N[0..64)} the challenge digest, {@code H[0..64)} the
 * reversed digest then the shares {@code a₁ ‖ a₂}, {@code H[64..96)} {@code r}, {@code H[96..128)}
 * {@code S}, {@code H[128..160)} the {@code mulMasked} temporary, {@code H[160..192)} {@code k}
 * then {@code c = ℓ − k}; {@code P[0..65)} {@code T = c·A}, {@code P[65..130)} {@code V}. {@link
 * Mem#W} belongs to {@link ModArith} throughout.
 */
final class Ed25519 {
    /** {@link Mem#edStream} layout: {@code a ‖ r ‖ R ‖ A}. */
    private static final short ED_A = 0;

    private static final short ED_R = 32;
    private static final short ED_PT_R = 64;
    private static final short ED_PT_A = 129;

    /** {@link Mem#N} slot of the counter u32 and its read-back — free before and post-derive. */
    private static final short N_CTR = 64;

    /** {@link Mem#H} layout of {@link #begin}. */
    private static final short H_PREFIX = 96;

    private static final short H_ID = 128;
    private static final short H_SCALAR = 160;

    /** {@link Mem#H} layout of {@link #finish}. */
    private static final short F_R = 64;

    private static final short F_S = 96;
    private static final short F_TMP = 128;
    private static final short F_K = 160;

    private final Mem mem;
    private final State state;
    private final Session session;
    private final Derivation derivation;
    private final Wei25519 wei;
    private final ModArith modArith;
    private final Identity identity;

    Ed25519(
            Mem mem,
            State state,
            Session session,
            Derivation derivation,
            Wei25519 wei,
            ModArith modArith,
            Identity identity) {
        this.mem = mem;
        this.state = state;
        this.session = session;
        this.derivation = derivation;
        this.wei = wei;
        this.modArith = modArith;
        this.identity = identity;
    }

    /**
     * {@code P1 = 0x00} begin (§9.11): data {@code path}, response {@code W(R)} (64 B) at {@code
     * buf[0]}. The {@code edCounter} precondition comes before the data checks (§9.2): {@code
     * 0xFFFFFFFF} returns {@code 6985} and writes nothing.
     */
    short begin(byte[] buf, short dataOff) {
        byte[] h = mem.H;
        byte[] n = mem.N;
        byte[] ed = mem.edStream;
        // the exhaustion precondition precedes derive (§9.11); the bytes in N are dead —
        // derive overwrites the array, and the counter is re-read below for the increment
        state.read(State.OFF_EDCOUNTER, n, N_CTR, (short) 4);
        if (n[N_CTR] == (byte) 0xFF
                && n[(short) (N_CTR + 1)] == (byte) 0xFF
                && n[(short) (N_CTR + 2)] == (byte) 0xFF
                && n[(short) (N_CTR + 3)] == (byte) 0xFF) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        derivation.derive(buf, Derivation.CURVE_ED, dataOff);
        derivation.edKey(h, H_SCALAR, H_PREFIX); // a → H[160..192), prefix → H[96..128)
        Util.arrayCopy(h, H_SCALAR, ed, ED_A, (short) 32);
        wei.mulBase(ed, ED_A, ed, ED_PT_A); // A = a·G_W
        // identity.id clobbers P[65..130) and parts of W — called before r is computed
        identity.id(h, H_ID);
        // the guarded check, evaluated twice, immediately before T-EDCTR (§16.2 item 4);
        // the second evaluation reads the shadow word
        if (session.verified() != Const.VERIFIED_YES) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (session.verifiedShadow() != Const.VERIFIED_YES) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        // the counter is re-read: derive's HMACs own H and overwrote the N copy above
        state.read(State.OFF_EDCOUNTER, n, N_CTR, (short) 4);
        for (short i = (short) (N_CTR + 3); ; i--) {
            n[i]++;
            if (n[i] != 0) {
                break; // N = edCounter + 1, big-endian; the FF gate above bounds the carry
            }
        }
        tEdctr(n, N_CTR);
        // §16.1 item 3 read-back gate: committed before r is computed
        if (session.txDepth() != 0) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        state.read(State.OFF_EDCOUNTER, n, (short) (N_CTR + 4), (short) 4);
        if (Bytes.equal(n, (short) (N_CTR + 4), n, N_CTR, (short) 4) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        // r = int_le(SHA-512(label ‖ Zr ‖ prefix ‖ ID ‖ u32(N))) mod ℓ, one 110-byte block —
        // the engine is clean: doFinal resets it and endPending clears abandoned streams
        mem.random.nextBytes(h, (short) 0, (short) 32); // Zr
        mem.sha512.update(
                Const.LABEL_ED25519_NONCE, (short) 0, (short) Const.LABEL_ED25519_NONCE.length);
        mem.sha512.update(h, (short) 0, (short) 32);
        mem.sha512.update(h, H_PREFIX, (short) 32);
        mem.sha512.update(h, H_ID, (short) 16);
        mem.sha512.doFinal(n, N_CTR, (short) 4, h, (short) 0);
        Bytes.reverse(h, (short) 0, n, (short) 0, (short) 64);
        modArith.reduce512(n, (short) 0, ed, ED_R);
        wei.mulBase(ed, ED_R, ed, ED_PT_R); // R = r·G_W — the doFinal reset left
        // the empty stream context H of §12.3 that update/finish extend
        session.setPending(Const.PENDING_STREAM); // armed last (§9.2)
        Util.arrayCopy(ed, (short) (ED_PT_R + 1), buf, (short) 0, (short) 64);
        return (short) 64;
    }

    /**
     * {@code P1 = 0x01} update (§9.11): streams {@code chunk} into the RFC 8032 challenge hash. An
     * absent stream is {@code 6985}.
     */
    short update(byte[] buf, short dataOff, short dataLen) {
        if (session.pending() != Const.PENDING_STREAM) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        mem.sha512.update(buf, dataOff, dataLen);
        return 0;
    }

    /**
     * {@code P1 = 0x02} finish (§9.11): {@code chunk} completes the stream; response {@code
     * le32(S)} (32 B) at {@code buf[0]} with {@code S = (r + k·a) mod ℓ} per §16.2 item 7 and the
     * {@code S·G_W = R + k·A} self-check of §16.2 item 6, twice.
     */
    short finish(byte[] buf, short dataOff, short dataLen) {
        if (session.pending() != Const.PENDING_STREAM) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] h = mem.H;
        byte[] n = mem.N;
        byte[] p = mem.P;
        byte[] ed = mem.edStream;
        // k = int_le(H.final()) mod ℓ
        mem.sha512.doFinal(buf, dataOff, dataLen, n, (short) 0);
        Bytes.reverse(n, (short) 0, h, (short) 0, (short) 64);
        modArith.reduce512(h, (short) 0, h, F_K);
        Util.arrayCopy(ed, ED_R, h, F_R, (short) 32);
        // S = ((r + k·a₁) + k·a₂) mod ℓ, shares re-drawn per signature (§16.2 item 7)
        modArith.share(ModArith.MOD_L, ed, ED_A, h, (short) 0, h, (short) 32);
        modArith.mulMasked(ModArith.MOD_L, h, F_R, F_K, (short) 0, (short) 32, F_S, F_TMP);
        // self-verify (§16.2 item 6): c = ℓ − k, V = S·G_W + c·A must equal R — twice
        modArith.negateIf(ModArith.MOD_L, h, F_K, (short) 1);
        wei.mul(h, F_K, ed, ED_PT_A, p, (short) 0);
        wei.mulAdd(h, F_S, p, (short) 0, p, (short) 65);
        if (Bytes.equal(p, (short) 65, ed, ED_PT_R, Const.POINT_LEN) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (Bytes.equal(p, (short) 65, ed, ED_PT_R, Const.POINT_LEN) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        // the guarded check, evaluated twice, immediately before the output (§16.2 item 4);
        // the second evaluation reads the shadow word
        if (session.verified() != Const.VERIFIED_YES) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (session.verifiedShadow() != Const.VERIFIED_YES) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        Bytes.reverse(h, F_S, buf, (short) 0, (short) 32); // le32(S)
        // §12.3: wipe the stream here as well — endDispatch ends it again on any outcome
        Bytes.wipe(ed, (short) 0, (short) ed.length);
        Bytes.wipe(h, (short) 0, (short) h.length);
        return (short) 32;
    }

    /**
     * T-EDCTR (§4.3, §12.3): {@code edCounter ← N}, a single 4-byte write committed before {@code
     * r} exists. Kept narrow so the commit's work is exactly what the spec names.
     */
    private void tEdctr(byte[] n32, short off) {
        JCSystem.beginTransaction();
        state.write(State.OFF_EDCOUNTER, n32, off, (short) 4);
        JCSystem.commitTransaction();
    }
}
