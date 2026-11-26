// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * Self-check of the independent review2 host against published vectors (NIST SP 800-38B, BIP-32,
 * RFC 8032 through the spec section 10.4 mapping) and a full simulator flow.
 */
final class HostSelfTest {

    // NIST SP 800-38B appendix D.1 example 2 (AES-CMAC, 16-byte message).
    @Test
    void cmacMatchesNistExample2() {
        byte[] tag =
                H2.cmac(
                        H2.hex("2b7e151628aed2a6abf7158809cf4f3c"),
                        H2.hex("6bc1bee22e409f96e93d7e117393172a"));
        assertArrayEquals(H2.hex("070a16b46b4d4144f79bdd9dd04a287c"), tag);
        // KDF108 built on the same CMAC: 32 deterministic bytes.
        byte[] k =
                H2.kdf108(
                        H2.hex("2b7e151628aed2a6abf7158809cf4f3c"),
                        "qntx-card/v1/wrap",
                        new byte[0]);
        assertEquals(32, k.length);
        assertArrayEquals(
                k,
                H2.kdf108(
                        H2.hex("2b7e151628aed2a6abf7158809cf4f3c"),
                        "qntx-card/v1/wrap",
                        new byte[0]));
    }

    // BIP-32 test vector 2, chain m: the master public key of the 64-byte seed.
    @Test
    void bip32MasterOfTestVector2() {
        byte[] seed =
                H2.hex(
                        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeab"
                                + "a8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a575"
                                + "4514e4b484542");
        assertTrue(H2.bip32MasterValid(seed));
        assertArrayEquals(
                H2.hex("03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7"),
                H2.bip32MasterPub(seed));
    }

    // Spec section 10.4 worked example: RFC 8032 TEST 1 key mapped through Wei25519.
    @Test
    void wei25519MapsRfc8032Test1() {
        byte[] sk = H2.hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        byte[] w = H2.weiPoint(H2.edSecretScalar(sk));
        assertEquals("5961a13b", H2.hex(Arrays.copyOf(w, 4)));
        assertArrayEquals(
                H2.hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
                H2.weiToEdwards(w));
    }

    // Full simulator flow: the card's masterPublicKey of an imported seed matches ours.
    @Test
    void createImportedSeedMatchesHostBip32() {
        byte[] seed =
                H2.hex(
                        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeab"
                                + "a8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a575"
                                + "4514e4b484542");
        byte[] accessHash = H2.sha256(H2.ascii("review2 self-test code"));
        Card2 card = new Card2();
        card.blank(Ca2.INSTANCE);
        Session2 session = card.open(Ca2.INSTANCE);
        Session2.Res res = session.cmd(0x21, 0x01, 0x00, H2.cat(accessHash, seed));
        assertEquals(0x9000, res.sw, () -> "CREATE sw " + Integer.toHexString(res.sw));
        // WalletInfo = masterPublicKey(33) || origin(1) || c(1) || IDs
        assertEquals(51, res.data.length);
        assertArrayEquals(H2.bip32MasterPub(seed), Arrays.copyOf(res.data, 33));
        assertEquals(0x02, res.data[33] & 0xFF); // origin: imported
        assertEquals(1, res.data[34] & 0xFF); // c: this card only
        assertArrayEquals(H2.cardId(session.identity()), Arrays.copyOfRange(res.data, 35, 51));
    }
}
