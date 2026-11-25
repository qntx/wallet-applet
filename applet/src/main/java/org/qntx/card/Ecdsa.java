// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;

/**
 * SIGN_ECDSA (§9.9, §12.1): RFC 6979-independent ECDSA over the secp256k1 leaf key with the
 * platform nonce, self-verified before output (§16.2 item 5) under one of four rotating verify keys
 * (§16.1 item 1, architecture §5.4) — persistent public-key objects that hold no secret and no
 * state; the {@code setW} is the command's only persistent write and runs outside any transaction.
 *
 * <p>Scratch layout: {@code H[0..32)} the digest copy; {@code Mem#N} the leaf node, {@code
 * P[0..32)} {@code IL} and {@code P[65..130)} {@code K_par} left by {@link Derivation#derive};
 * {@code buf[0..65)} the independently computed leaf public key, then the {@code r ‖ s} output;
 * {@link Mem#W_DER} the sign/verify DER area. The leaf key, {@code IL} and the digest copy are
 * wiped by {@link Mem#wipeScratch} on every path.
 */
final class Ecdsa {
    private final Mem mem;
    private final Session session;
    private final Derivation derivation;
    private final Secp256k1 secp;

    /** The rotating verify keys of §16.1 item 1: persistent, public, stateless. */
    private final ECPublicKey[] verifyKeys;

    Ecdsa(Mem mem, Session session, Derivation derivation, Secp256k1 secp) {
        this.mem = mem;
        this.session = session;
        this.derivation = derivation;
        this.secp = secp;
        verifyKeys = new ECPublicKey[4];
        for (short i = 0; i < 4; i++) {
            verifyKeys[i] =
                    (ECPublicKey)
                            KeyBuilder.buildKey(
                                    KeyBuilder.TYPE_EC_FP_PUBLIC,
                                    KeyBuilder.LENGTH_EC_FP_256,
                                    false);
        }
    }

    /**
     * Initialisation step 2 (§4.3): the secp256k1 domain into the four self-verification keys.
     * Idempotent — a torn step simply reloads the parameters.
     */
    void initDomains() {
        for (short i = 0; i < 4; i++) {
            Secp256k1.setDomain(verifyKeys[i]);
        }
    }

    /**
     * Data {@code digest(32) ‖ path}, response {@code r(32) ‖ s(32)} at {@code buf[0]} (§9.9). The
     * verification key is computed independently of the signature (§16.2 item 5): public derivation
     * {@code Q = IL·G + K_par} via {@code PACE_GM} for a non-hardened leaf, {@code k_leaf·G} for a
     * hardened one — always before the signature exists. A failed self-verification or a degraded
     * {@code verified} flag is a detected fault ({@code 6F00}).
     */
    short sign(byte[] buf, short dataOff) {
        byte[] h = mem.H;
        byte[] n = mem.N;
        byte[] p = mem.P;
        derivation.derive(buf, Derivation.CURVE_SECP, (short) (dataOff + 32));
        // after derive — its HMACs own all of H; the plaintext digest survives in buf
        Util.arrayCopy(buf, dataOff, h, (short) 0, Const.HASH_LEN);
        short depth = (short) (buf[(short) (dataOff + 32)] & 0xFF);
        boolean hardened = (buf[(short) (dataOff + 33 + depth * 4 - 4)] & 0x80) != 0;
        // the independent leaf public key, before signing (§16.2 item 5)
        if (hardened) {
            secp.mul(n, (short) 0, Secp256k1.G, (short) 0, buf, (short) 0);
            secp.wipeScalar();
        } else {
            // Q = IL·G + K_par, the §10.3 public derivation of the leaf
            secp.mulAdd(p, (short) 0, p, Derivation.P_PAR, buf, (short) 0);
        }
        // §5.4: one random byte picks the verify key; the setW is the only persistent
        // write of the command and runs outside any transaction (§16.1 item 1)
        mem.random.nextBytes(h, (short) 32, (short) 1);
        ECPublicKey key = verifyKeys[(short) (h[32] & 3)];
        key.setW(buf, (short) 0, Const.POINT_LEN);
        secp.sign(n, (short) 0, h, (short) 0, buf, (short) 0);
        short v1 = secp.verifyHash(key, h, (short) 0, buf, (short) 0);
        if (v1 != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        short v2 = secp.verifyHash(key, h, (short) 0, buf, (short) 0);
        if (v2 != Const.CHECK_OK) {
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
        return (short) 64;
    }
}
