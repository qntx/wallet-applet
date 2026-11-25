// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The peer-slot initial point of §16.1 item 1 (A1): {@link Secp256k1#PEER_INIT} is the
 * nothing-up-my-sleeve point derived as the first {@code i = 0, 1, …} with {@code x =
 * int(SHA-256("qntx-card/v1/peer-slot" ‖ u8(i))) < p} and {@code x³ + 7} a quadratic residue,
 * {@code y} the even root. This test re-derives it with BouncyCastle/BigInteger and checks both
 * peer slots hold it — and never the base point {@code G} — after initialisation.
 */
final class PeerSlotInitTest {
    private static final X9ECParameters SECP = SECNamedCurves.getByName("secp256k1");
    private static final BigInteger P = SECP.getCurve().getField().getCharacteristic();

    /** The independent derivation of §16.1 item 1; returns {@code {i, uncompressed point}}. */
    private static Object[] derive() throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        for (int i = 0; i < 256; i++) {
            sha.update("qntx-card/v1/peer-slot".getBytes("US-ASCII"));
            byte[] digest = sha.digest(new byte[] {(byte) i});
            BigInteger x = new BigInteger(1, digest);
            if (x.compareTo(P) >= 0) {
                continue;
            }
            BigInteger rhs = x.modPow(BigInteger.valueOf(3), P).add(BigInteger.valueOf(7)).mod(P);
            // p mod 4 = 3: a residue's root is rhs^((p+1)/4); the Legendre symbol picks residues
            if (!rhs.modPow(P.subtract(BigInteger.ONE).shiftRight(1), P).equals(BigInteger.ONE)) {
                continue;
            }
            BigInteger y = rhs.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
            if (y.testBit(0)) {
                y = P.subtract(y); // the even root
            }
            ECPoint point = SECP.getCurve().createPoint(x, y);
            return new Object[] {i, point.getEncoded(false)};
        }
        throw new IllegalStateException("no candidate below 256");
    }

    @Test
    void peerInitMatchesIndependentDerivation() throws Exception {
        Object[] derived = derive();
        assertEquals(0, derived[0], "the first candidate is not i = 0");
        assertArrayEquals(
                Secp256k1.PEER_INIT,
                (byte[]) derived[1],
                "PEER_INIT does not match the independent derivation");
        assertFalse(
                Arrays.equals(Secp256k1.G, Secp256k1.PEER_INIT), "PEER_INIT is the base point G");
    }

    @Test
    void bothSlotsHoldPeerInitAfterInitialisation() {
        Card card = Vecs.blankSelf();
        byte[] w0 = Internals.peerW(card.applet(Spec.WALLET_AID), 0);
        byte[] w1 = Internals.peerW(card.applet(Spec.WALLET_AID), 1);
        assertArrayEquals(Secp256k1.PEER_INIT, w0, "slot 0 does not hold PEER_INIT");
        assertArrayEquals(Secp256k1.PEER_INIT, w1, "slot 1 does not hold PEER_INIT");
        assertFalse(Arrays.equals(Secp256k1.G, w0), "slot 0 holds G");
        assertFalse(Arrays.equals(Secp256k1.G, w1), "slot 1 holds G");
    }
}
