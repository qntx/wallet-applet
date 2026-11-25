// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;

/**
 * BIP-32 secp256k1 and SLIP-10 ed25519 derivation from the session seed (protocol.md §10.2–10.4)
 * behind PUBLIC_KEY (§9.8), plus the node caches of architecture.md §5.3. HMAC-SHA512 is computed
 * in software over the shared SHA-512 engine (RFC 2104, block 128; every key used here is at most
 * 64 bytes) with {@link Mem#H} as the pad/digest area and {@link Mem#N} as the working node.
 *
 * <p>Caches never change outputs: a hit only skips recomputation of a node the same derivation
 * would produce. Both caches are session state — wiped by VERIFY step 1, ERASE, IMPORT and teardown
 * — never by {@link Mem#wipeScratch}.
 */
final class Derivation {
    /** Curve selector: the command's {@code P1} (§9.8). */
    static final byte CURVE_SECP = 0;

    static final byte CURVE_ED = 1;

    /** {@link Mem#N} layout: {@code key(32) ‖ chain(32) ‖ ckdInput(37)}. */
    private static final short N_KEY = 0;

    private static final short N_CHAIN = 32;
    private static final short N_CKD = 64;
    private static final short N_CKD_LEN = 37;

    /**
     * Cache layout inside {@link Mem#secpCache} and {@link Mem#edCache}: {@code depth(1) ‖
     * indices(40) ‖ key(32) ‖ chain(32) ‖ pub(65, secp256k1 only)}. {@code pub[0] = 0} marks a
     * parent whose uncompressed public key was never computed; {@code 0x04} marks a present one.
     */
    private static final short C_DEPTH = 0;

    private static final short C_PATH = 1;
    private static final short C_KEY = 41;
    private static final short C_CHAIN = 73;
    private static final short C_PUB = 105;

    /** {@link Mem#P} slot: uncompressed point / CKD {@code I} (64 B), below the identity slot. */
    private static final short P_TMP = 0;

    /**
     * {@link Mem#P} slot of a child's parent public point {@code K_par} (65 B): the point the
     * non-hardened CKD input compresses from and, after {@link #derive} of a non-hardened leaf, the
     * key {@link Ecdsa} needs for the §16.2 item 5 public-derivation check.
     */
    static final short P_PAR = 65;

    private final Mem mem;
    private final Session session;
    private final Secp256k1 secp;
    private final Wei25519 wei;
    private final ModArith modArith;

    Derivation(Mem mem, Session session, Secp256k1 secp, Wei25519 wei, ModArith modArith) {
        this.mem = mem;
        this.session = session;
        this.secp = secp;
        this.wei = wei;
        this.modArith = modArith;
    }

    /**
     * RFC 2104 HMAC-SHA512 with the shared engine and {@link Mem#H}: {@code H[0..128)} is filled
     * with the pad byte and the key xored into its first {@code kLen} bytes (inner digest at {@code
     * H[128..192)}); the opad block is rebuilt the same way, so {@code key} must still be intact
     * after the inner {@code doFinal} — every call site passes a {@link Const} key or {@code
     * N[32..64)}, neither touched by that digest nor by the output write. Keys are at most 128
     * bytes; {@code msg} is one contiguous segment.
     */
    private void hmac(
            byte[] key,
            short kOff,
            short kLen,
            byte[] msg,
            short mOff,
            short mLen,
            byte[] out,
            short oOff) {
        byte[] h = mem.H;
        MessageDigest sha = mem.sha512;
        // a command that died between update and doFinal leaves pending bytes
        sha.reset();
        Util.arrayFillNonAtomic(h, (short) 0, (short) 128, (byte) 0x36);
        for (short i = 0; i < kLen; i++) {
            h[i] ^= key[(short) (kOff + i)];
        }
        sha.update(h, (short) 0, (short) 128);
        sha.doFinal(msg, mOff, mLen, h, (short) 128);
        Util.arrayFillNonAtomic(h, (short) 0, (short) 128, (byte) 0x5C);
        for (short i = 0; i < kLen; i++) {
            h[i] ^= key[(short) (kOff + i)];
        }
        sha.update(h, (short) 0, (short) 128);
        sha.doFinal(h, (short) 128, (short) 64, out, oOff);
    }

    /**
     * §10.2: {@code out = kM(32) ‖ cM(32)}, the BIP-32 master node {@code HMAC-SHA512("Bitcoin
     * seed", seed)}; coded {@code CHECK_OK} iff {@code 1 ≤ int(kM) ≤ n − 1} (constant time via
     * {@link ModArith#isZero}/{@link ModArith#below}).
     */
    short master(byte[] seed, short sOff, short sLen, byte[] out, short oOff) {
        hmac(
                Const.HMAC_BITCOIN,
                (short) 0,
                (short) Const.HMAC_BITCOIN.length,
                seed,
                sOff,
                sLen,
                out,
                oOff);
        short r = Const.CHECK_FAIL;
        if (ModArith.isZero(out, oOff) != Const.CHECK_OK
                && modArith.below(ModArith.MOD_N, out, oOff) == Const.CHECK_OK) {
            r = Const.CHECK_OK;
        }
        return r;
    }

    /**
     * One {@code CKDpriv} step of §10.3 / the hardened-only SLIP-10 step of §10.4: reads the node
     * in {@link Mem#N}, applies index {@code data[iOff..iOff+4)} (big-endian), leaves the child
     * node in {@link Mem#N} and, for a non-hardened step, this parent's uncompressed public point
     * at {@code Mem#P[65..130)}. {@code pub[pOff]} is THIS parent's cached point: {@code pOff < 0}
     * means none (the point is computed), a marker {@code 0x04} reuses the slot, any other marker
     * computes the point and fills the slot. A {@code CryptoException} from the point
     * multiplication is an invalid child (§16.2 item 8), not an error. Coded result: {@code IL < n}
     * and {@code k ≠ 0} for secp256k1; always {@code CHECK_OK} for ed25519.
     */
    short child(byte[] data, short iOff, byte curve, byte[] pub, short pOff) {
        byte[] n = mem.N;
        byte[] p = mem.P;
        boolean hardened = (data[iOff] & 0x80) != 0 || curve == CURVE_ED;
        short c = Const.CHECK_OK;
        if (hardened) {
            n[N_CKD] = 0;
            Util.arrayCopy(n, N_KEY, n, (short) (N_CKD + 1), (short) 32);
        } else if (pOff > -1 && pub[pOff] == 0x04) {
            // the slot belongs to this parent: reuse its uncompressed point for the CKD input
            // and for the leaf's K_par at Mem.P[65..130)
            secp.compress(pub, pOff, n, N_CKD);
            Util.arrayCopy(pub, pOff, p, P_PAR, Const.POINT_LEN);
        } else {
            try {
                // the point is computed into P[65..130): the HMAC output overwrites P[0..65)
                secp.mul(n, N_KEY, Secp256k1.G, (short) 0, p, P_PAR);
                secp.wipeScalar();
                secp.compress(p, P_PAR, n, N_CKD);
                if (pOff > -1) {
                    // the slot belongs to this parent: fill it for later warm derivations
                    Util.arrayCopy(p, P_PAR, pub, pOff, Const.POINT_LEN);
                }
            } catch (CryptoException e) {
                secp.wipeScalar();
                c = Const.CHECK_FAIL;
            }
        }
        if (c == Const.CHECK_OK) {
            Util.arrayCopy(data, iOff, n, (short) (N_CKD + 33), (short) 4);
            hmac(n, N_CHAIN, Const.HASH_LEN, n, N_CKD, N_CKD_LEN, p, P_TMP);
            if (curve == CURVE_ED) {
                Util.arrayCopy(p, P_TMP, n, N_KEY, (short) 64);
            } else {
                c = stepSecp(n, p);
            }
        }
        return c;
    }

    // the secp256k1 tail of a child step: IL < n, k = (int(IL) + k_par) mod n, k != 0
    private short stepSecp(byte[] n, byte[] p) {
        short r = Const.CHECK_FAIL;
        if (modArith.below(ModArith.MOD_N, p, P_TMP) == Const.CHECK_OK) {
            // k = (int(IL) + k_par) mod n, in place in the node slot
            modArith.addMod(ModArith.MOD_N, p, P_TMP, n, N_KEY, n, N_KEY);
            if (ModArith.isZero(n, N_KEY) != Const.CHECK_OK) {
                Util.arrayCopy(p, (short) (P_TMP + 32), n, N_CHAIN, Const.HASH_LEN);
                r = Const.CHECK_OK;
            }
        }
        return r;
    }

    /**
     * {@code out = compressed(kM·G)} (33 B) of the session seed (§10.2). The stored seed's master
     * was valid when written, so a failure here is a detected fault ({@code 6F00}).
     */
    void masterPublicKey(byte[] out, short oOff) {
        byte[] n = mem.N;
        if (master(mem.seed, (short) 0, (short) mem.seed.length, n, N_KEY) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        secp.mul(n, N_KEY, Secp256k1.G, (short) 0, mem.P, P_TMP);
        secp.wipeScalar();
        secp.compress(mem.P, P_TMP, out, oOff);
    }

    /** §8.5 / §9.5 step 1: wipes both node caches (session state, not scratch). */
    void wipeCaches() {
        Bytes.wipe(mem.secpCache, (short) 0, (short) mem.secpCache.length);
        Bytes.wipe(mem.edCache, (short) 0, (short) mem.edCache.length);
    }

    /**
     * PUBLIC_KEY (§9.8): {@link #derive} runs the data checks and leaves the leaf node in {@link
     * Mem#N}; then, immediately before the output, {@code verified} evaluated twice (a failure is a
     * detected fault, §16.2 item 4). Response: secp256k1 {@code compressed(k·G) ‖ c} (65 B),
     * ed25519 {@code W(A) = X ‖ Y} (64 B). Writes at {@code buf[0]}.
     */
    short publicKey(byte[] buf, byte p1, short dataOff, short dataLen) {
        derive(buf, p1, dataOff);
        byte[] n = mem.N;
        byte[] p = mem.P;
        // the guarded check, evaluated twice, immediately before the output (§16.2 item 4);
        // the second evaluation reads the shadow word
        if (session.verified() != Const.VERIFIED_YES) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (session.verifiedShadow() != Const.VERIFIED_YES) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (p1 == CURVE_SECP) {
            secp.mul(n, N_KEY, Secp256k1.G, (short) 0, p, P_TMP);
            secp.wipeScalar();
            secp.compress(p, P_TMP, buf, (short) 0);
            Util.arrayCopy(n, N_CHAIN, buf, Const.COMPRESSED_LEN, Const.HASH_LEN);
            Bytes.wipe(p, (short) 0, (short) p.length);
            return (short) (Const.COMPRESSED_LEN + Const.HASH_LEN);
        }
        // §10.4: a = clamped scalar of the leaf, reduced mod ℓ; A = a·G_W → W(A) = X ‖ Y
        byte[] h = mem.H;
        edKey(h, (short) 64, (short) 96);
        wei.mulBase(h, (short) 64, p, P_TMP);
        Util.arrayCopy(p, (short) (P_TMP + 1), buf, (short) 0, (short) 64);
        Bytes.wipe(h, (short) 0, (short) 128);
        Bytes.wipe(p, (short) 0, (short) p.length);
        return (short) 64;
    }

    /**
     * Derives the leaf node of {@code buf[dataOff..]} ({@code path = depth(1) ‖ indices}): data
     * checks in order — {@code depth ∈ [1, 10]}, every ed25519 index hardened, every BIP-32 child
     * valid (each {@code 6A80}) — the node caches and the wipe-and-{@code 6A80} on an invalid
     * child. Post-condition: {@code N[0..64)} = leaf {@code key ‖ chain}; for secp256k1
     * additionally {@code P[0..32)} = {@code IL} of the leaf step and, when the leaf index is
     * non-hardened, {@code P[65..130)} = the uncompressed parent public key {@code K_par} (also for
     * {@code depth = 1}, whose parent is the master).
     */
    void derive(byte[] buf, byte curve, short dataOff) {
        byte[] n = mem.N;
        byte[] cache = curve == CURVE_SECP ? mem.secpCache : mem.edCache;
        short depth = (short) (buf[dataOff] & 0xFF);
        if (depth < 1 || depth > 10) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (curve == CURVE_ED) {
            // §10.4: every ed25519 index is hardened (§9.8)
            for (short i = 0; i != depth; i++) {
                if ((buf[(short) (dataOff + 1 + i * 4)] & 0x80) == 0) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
            }
        }
        short start = 0;
        boolean cached =
                depth >= 2
                        && cache[C_DEPTH] == (byte) (depth - 1)
                        && Bytes.equal(
                                        cache,
                                        C_PATH,
                                        buf,
                                        (short) (dataOff + 1),
                                        (short) ((depth - 1) * 4))
                                == Const.CHECK_OK;
        if (cached) {
            // §5.3: the cached parent at depth d−1; the leaf costs one HMAC-SHA512
            Util.arrayCopy(cache, C_KEY, n, N_KEY, (short) 64);
            start = (short) (depth - 1);
        } else if (curve == CURVE_SECP) {
            if (master(mem.seed, (short) 0, (short) mem.seed.length, n, N_KEY) != Const.CHECK_OK) {
                // the stored seed's master was valid when written: a fault
                ISOException.throwIt(Const.SW_FAULT);
            }
        } else {
            hmac(
                    Const.HMAC_ED25519,
                    (short) 0,
                    (short) Const.HMAC_ED25519.length,
                    mem.seed,
                    (short) 0,
                    (short) mem.seed.length,
                    n,
                    N_KEY);
        }
        for (short i = start; i != depth; i++) {
            // the cache slot names THIS parent only while cached is set — on a hit from the
            // start, on a cold path right after the leaf's parent was stored below
            short c =
                    child(
                            buf,
                            (short) (dataOff + 1 + i * 4),
                            curve,
                            cache,
                            cached ? C_PUB : (short) -1);
            if (c != Const.CHECK_OK) {
                Bytes.wipe(n, (short) 0, (short) 64);
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            if (i == (short) (depth - 2)) {
                // N holds the leaf's parent: cache it before the leaf step overwrites N. Its
                // compressed key is not at hand — marker 0; a non-hardened leaf step fills the
                // slot inside child() (harmless on ed25519: a hardened leaf never reads it)
                cache[C_DEPTH] = (byte) (depth - 1);
                Util.arrayCopy(
                        buf, (short) (dataOff + 1), cache, C_PATH, (short) ((depth - 1) * 4));
                Util.arrayCopy(n, N_KEY, cache, C_KEY, (short) 64);
                if (curve == CURVE_SECP) {
                    cache[C_PUB] = 0;
                }
                cached = true;
            }
        }
    }

    /**
     * §10.4: reads the leaf {@code sk} at {@code N[0..32)} and writes {@code a} — the clamped first
     * half of {@code SHA-512(sk)} read little-endian, big-endian and reduced mod {@code ℓ}
     * (architecture §5.5) — at {@code out[aOff..aOff+32)} and {@code prefix = h[32..64)} at {@code
     * out[prefixOff..prefixOff+32)}; wipes {@code h}. Used by PUBLIC_KEY P1 = 1 and {@link Ed25519}
     * begin.
     */
    void edKey(byte[] out, short aOff, short prefixOff) {
        byte[] h = mem.H;
        mem.sha512.reset();
        mem.sha512.doFinal(mem.N, N_KEY, Const.HASH_LEN, h, (short) 0);
        h[0] &= (byte) 0xF8;
        h[31] &= (byte) 0x7F;
        h[31] |= (byte) 0x40;
        Bytes.reverse(h, (short) 0, out, aOff, (short) 32);
        if (modArith.reduce(ModArith.MOD_L, out, aOff) != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        Util.arrayCopy(h, (short) 32, out, prefixOff, (short) 32);
        Bytes.wipe(h, (short) 0, (short) 64);
    }
}
