// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * SIGN_BIP340 (§9.10, §12.2): BIP-340 "Default Signing" with the BIP-341 tweak — {@code d₀} from
 * {@link Derivation}, parity-normalized, tweaked, the nonce hedged with 32 random bytes, the secret
 * product {@code e·d} recombined masked per §16.2 item 6, and the signature self-verified ({@code
 * s·G − e·Q = R}, §16.2 item 5) before output.
 *
 * <p>Scratch layout: {@code P[0..65)} {@code P}/{@code P_even}, then {@code R}; {@code P[65..130)}
 * {@code Q}, then the self-verify point {@code V}; {@code N[0..65)} the self-verify's {@code T =
 * c·Q}; {@code H[0..32)} {@code d}, then {@code mulMasked}'s {@code tmp}; {@code H[32..64)} {@code
 * k'}; {@code H[64..96)} {@code t_aux}, then {@code e}/{@code c}; {@code H[96..128)} {@code aux},
 * then share {@code s₁}; {@code H[128..160)} share {@code s₂}; {@code H[160..192)} {@code s}.
 * {@link Mem#W} belongs to {@link ModArith} throughout; every secret slot is wiped by {@link
 * Mem#wipeScratch} on every path.
 */
final class Bip340 {
    private final Mem mem;
    private final Session session;
    private final Derivation derivation;
    private final Secp256k1 secp;
    private final ModArith modArith;

    Bip340(Mem mem, Session session, Derivation derivation, Secp256k1 secp, ModArith modArith) {
        this.mem = mem;
        this.session = session;
        this.derivation = derivation;
        this.secp = secp;
        this.modArith = modArith;
    }

    /**
     * Data {@code message(32) ‖ tweak(32) ‖ path}, response {@code R_x(32) ‖ s(32)} at {@code
     * buf[0]} (§9.10). {@code int(tweak) ≥ n} or a zero tweaked key is {@code 6A80}; a failed
     * self-verification or degraded flag is {@code 6F00}.
     */
    short sign(byte[] buf, short dataOff) {
        byte[] h = mem.H;
        byte[] p = mem.P;
        byte[] n = mem.N;
        short tweakOff = (short) (dataOff + 32);
        derivation.derive(buf, Derivation.CURVE_SECP, (short) (dataOff + 64));
        Util.arrayCopy(n, (short) 0, h, (short) 0, (short) 32); // d₀
        secp.mul(n, (short) 0, Secp256k1.G, (short) 0, p, (short) 0);
        secp.wipeScalar();
        // §9.10 data checks after the path checks: t < n, then the tweaked key ≠ 0
        if (modArith.below(ModArith.MOD_N, buf, tweakOff) != Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // §12.2: odd y(P) negates both d₀ (mod n) and y (mod p) — the BIP-341 internal key
        short bit = (short) (p[64] & 1);
        modArith.negateIf(ModArith.MOD_N, h, (short) 0, bit);
        modArith.negateIf(ModArith.MOD_P, p, (short) 33, bit);
        modArith.addMod(ModArith.MOD_N, h, (short) 0, buf, tweakOff, h, (short) 0);
        if (ModArith.isZero(h, (short) 0) == Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (ModArith.isZero(buf, tweakOff) == Const.CHECK_OK) {
            // t = 0 signs with the even internal key; PACE_GM never gets a zero scalar
            Util.arrayCopy(p, (short) 0, p, (short) 65, Const.POINT_LEN);
        } else {
            secp.mulAdd(buf, tweakOff, p, (short) 0, p, (short) 65);
        }
        // BIP-340 Sign's own negation: parity of the tweaked Q = d·G, not of P. The
        // self-verify's T = c·Q' needs the even point too, so y flips with the scalar
        bit = (short) (p[129] & 1);
        modArith.negateIf(ModArith.MOD_N, h, (short) 0, bit);
        modArith.negateIf(ModArith.MOD_P, p, (short) 98, bit);
        // aux and t_aux = d ⊕ TaggedHash_aux(aux)
        mem.random.nextBytes(h, (short) 96, (short) 32);
        tagged(Const.TAG_AUX);
        mem.sha256.doFinal(h, (short) 96, (short) 32, h, (short) 64);
        for (short i = 0; i != 32; i++) {
            h[(short) (64 + i)] ^= h[i];
        }
        // k' = int(TaggedHash_nonce(t_aux ‖ x(Q) ‖ m)) mod n
        tagged(Const.TAG_NONCE);
        mem.sha256.update(h, (short) 64, (short) 32);
        mem.sha256.update(p, (short) 66, (short) 32);
        mem.sha256.doFinal(buf, dataOff, (short) 32, h, (short) 32);
        if (modArith.reduce(ModArith.MOD_N, h, (short) 32) != Const.CHECK_OK
                || ModArith.isZero(h, (short) 32) == Const.CHECK_OK) {
            // probability 2^-256; a fault is the plausible explanation
            ISOException.throwIt(Const.SW_FAULT);
        }
        secp.mul(h, (short) 32, Secp256k1.G, (short) 0, p, (short) 0);
        secp.wipeScalar();
        modArith.negateIf(ModArith.MOD_N, h, (short) 32, (short) (p[64] & 1));
        // e = int(TaggedHash_challenge(x(R) ‖ x(Q) ‖ m)) mod n
        tagged(Const.TAG_CHALLENGE);
        mem.sha256.update(p, (short) 1, (short) 32);
        mem.sha256.update(p, (short) 66, (short) 32);
        mem.sha256.doFinal(buf, dataOff, (short) 32, h, (short) 64);
        if (modArith.reduce(ModArith.MOD_N, h, (short) 64) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        // s = ((k + e·d₁) + e·d₂) mod n, shares re-drawn per signature (§16.2 item 6)
        modArith.share(ModArith.MOD_N, h, (short) 0, h, (short) 96, h, (short) 128);
        modArith.mulMasked(
                ModArith.MOD_N,
                h,
                (short) 32,
                (short) 64,
                (short) 96,
                (short) 128,
                (short) 160,
                (short) 0);
        // self-verify (§16.2 item 5): V = s·G − e·Q must equal R, even y — checked twice
        modArith.negateIf(ModArith.MOD_N, h, (short) 64, (short) 1); // c = (n − e) mod n
        secp.mul(h, (short) 64, p, (short) 65, n, (short) 0);
        secp.wipeScalar();
        secp.mulAdd(h, (short) 160, n, (short) 0, p, (short) 65);
        if (verifyPoint(p) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (verifyPoint(p) != Const.CHECK_OK) {
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
        Util.arrayCopy(p, (short) 1, buf, (short) 0, (short) 32);
        Util.arrayCopy(h, (short) 160, buf, (short) 32, (short) 32);
        return (short) 64;
    }

    /** Starts a BIP-340 tagged hash: {@code SHA-256(tag ‖ tag ‖ …)}. */
    private void tagged(byte[] tag) {
        // every sha256 use on the card ends in doFinal, which resets the engine
        MessageDigest sha = mem.sha256;
        sha.update(tag, (short) 0, (short) 32);
        sha.update(tag, (short) 0, (short) 32);
    }

    /**
     * The self-verify check {@code x(V) = x(R)} (constant time) and {@code y(V)} even; {@code V} at
     * {@code p[65..130)}, {@code R} at {@code p[0..65)}. Coded result.
     */
    private short verifyPoint(byte[] p) {
        short r = Const.CHECK_FAIL;
        if (Bytes.equal(p, (short) 66, p, (short) 1, (short) 32) == Const.CHECK_OK
                && (p[129] & 1) == 0) {
            r = Const.CHECK_OK;
        }
        return r;
    }
}
