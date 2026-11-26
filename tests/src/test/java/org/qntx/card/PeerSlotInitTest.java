// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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

    /**
     * The {@code P_init} hex block of spec/protocol.md §16.1 item 1 must be {@link
     * Secp256k1#PEER_INIT}: the spec is normative, so a drift between the documented point and the
     * coded point is a bug in both.
     */
    @Test
    void peerInitMatchesSpecBlock() throws Exception {
        Path spec =
                Path.of(System.getProperty("qntx.vectors", "spec/vectors"))
                        .getParent()
                        .resolve("protocol.md");
        String text = Files.readString(spec);
        int item1 = text.indexOf("`P_init = (x, y)`");
        assertFalse(item1 < 0, "spec/protocol.md §16.1 item 1 does not define P_init");
        Matcher m =
                Pattern.compile("```\\s*([0-9a-f]+)\\s*([0-9a-f]+)\\s*([0-9a-f]+)\\s*```")
                        .matcher(text);
        assertFalse(!m.find(item1), "no hex block after the P_init definition");
        String hex = m.group(1) + m.group(2) + m.group(3);
        byte[] parsed = new byte[hex.length() / 2];
        for (int i = 0; i < parsed.length; i++) {
            parsed[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        assertEquals(65, parsed.length, "the spec block is not a 65-byte uncompressed point");
        assertArrayEquals(
                Secp256k1.PEER_INIT,
                parsed,
                "the P_init hex block of §16.1 item 1 differs from Secp256k1.PEER_INIT");
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
