// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Ed25519;
import org.qntx.card.host.Paths;
import org.qntx.card.host.Wei25519Map;

/**
 * The APDU {@code Lc = 248} row (architecture §10): a {@code SIGN_ED25519} update record carries a
 * 236-byte chunk, so the record APDU reaches the applet with {@code Lc = 248} — the maximum the
 * {@code setIncomingAndReceive} + {@code receiveBytes} loop of §3 must assemble. The signature over
 * the streamed message verifies against the BouncyCastle Ed25519 oracle, so a dropped or
 * mis-chained byte would fail the check.
 */
final class ApduLc248 extends Suite {
    private static final String CODE = "realCard-h3";
    private static final String ED_PATH = "m/44'/501'/0'/0'/0'";

    @Test
    void innerRecordWithLc248() throws Exception {
        WalletSession card = WalletSession.open(reader, new SecureRandom());
        try {
            byte[] accessHash = card.accessHash(CODE);
            byte[] create = new byte[64];
            System.arraycopy(accessHash, 0, create, 0, 32);
            byte[] entropy = new byte[32];
            new SecureRandom().nextBytes(entropy);
            System.arraycopy(entropy, 0, create, 32, 32);
            card.innerOk(WalletSession.INS_CREATE, 0, 0, create);

            // §9.2: any command other than a stream continuation ends the pending stream, so the
            // verifying key is read before begin
            byte[] path = Paths.wire(ED_PATH);
            byte[] wA = card.innerOk(WalletSession.INS_PUBLIC_KEY, 1, 0, path);
            byte[] encodedA = Wei25519Map.encode(wA);
            byte[] wR = card.innerOk(WalletSession.INS_SIGN_ED25519, 0, 0, path);
            byte[] encodedR = Wei25519Map.encode(wR);

            // §12.3: the card hashes encode(R)‖encode(A)‖M, so the updates carry that stream;
            // stream[0..236) is one update record → Lc = 248 on the wire, finish carries the rest
            byte[] message = new byte[236];
            new SecureRandom().nextBytes(message);
            byte[] stream = Ed25519.stream(encodedR, encodedA, message);
            byte[] first = new byte[236];
            System.arraycopy(stream, 0, first, 0, 236);
            card.innerOk(WalletSession.INS_SIGN_ED25519, 1, 0, first);
            byte[] rest = new byte[stream.length - 236];
            System.arraycopy(stream, 236, rest, 0, rest.length);
            byte[] s = card.innerOk(WalletSession.INS_SIGN_ED25519, 2, 0, rest);
            assertEquals(32, s.length);

            byte[] signature = Ed25519.signature(encodedR, s);
            assertTrue(
                    Ed25519.verify(encodedA, message, signature),
                    "Ed25519 signature over the 236-byte-chunk stream must verify");
            Results.row("APDU", "Lc=248", "pass", "236-byte update chunk received and signed");
        } finally {
            try {
                card.innerOk(WalletSession.INS_ERASE, 0, 0);
            } catch (RuntimeException ignored) {
            }
        }
    }
}
