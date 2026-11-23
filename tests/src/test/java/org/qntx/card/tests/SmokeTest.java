// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Certificates;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Open;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;

/** Temporary end-to-end smoke: personalize, open, STATUS inside a session. */
final class SmokeTest {
    private static final SecureRandom RND = new SecureRandom();
    private static final BigInteger CA_PRIVATE =
            new BigInteger("2", 16).pow(254).add(BigInteger.ONE); // throwaway test CA
    private static final byte[] CA_PUBLIC = Crypto.publicKey(CA_PRIVATE);

    private Card card;

    @BeforeEach
    void install() {
        card = Vecs.factory();
    }

    @Test
    void personalizeOpenStatus() throws Exception {
        byte[] rapdu = card.transmit(Spec.hex("80E0000000"));
        assertEquals(0x9000, sw(rapdu));
        byte[] a = Arrays.copyOf(rapdu, 33);
        byte[] cert = Certificates.issue(CA_PRIVATE, a);
        byte[] personalize = new byte[5 + 162 + 1];
        personalize[0] = (byte) 0x80;
        personalize[1] = (byte) 0xE2;
        personalize[4] = (byte) 162;
        System.arraycopy(cert, 0, personalize, 5, 97);
        System.arraycopy(CA_PUBLIC, 0, personalize, 102, 65);
        rapdu = card.transmit(personalize);
        assertEquals(0x9000, sw(rapdu));

        Open.Request req = Open.request(RND);
        rapdu = card.transmit(req.apdu());
        Session session = Open.response(req.secret(), req.apdu(), rapdu, List.of(CA_PUBLIC));

        rapdu = card.transmit(session.wrap(0x20, 0, 0, new byte[0]));
        Response r = session.unwrap(rapdu);
        assertEquals(0x9000, r.sw());
        assertArrayEquals(new byte[] {0x01, 0x00}, r.data());
    }

    private static int sw(byte[] rapdu) {
        return (rapdu[rapdu.length - 2] & 0xFF) << 8 | rapdu[rapdu.length - 1] & 0xFF;
    }
}
