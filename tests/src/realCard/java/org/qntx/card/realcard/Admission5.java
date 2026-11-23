// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

/**
 * Admission 5 (protocol §3 item 5): the Wei25519 and secp256k1 domain parameters are accepted by
 * persistent and {@code TRANSIENT_DESELECT} 256-bit EC keys — {@code setup} must allocate them all
 * and {@code setS}/{@code setW} must round-trip on each.
 */
final class Admission5 extends Suite {
    @Test
    void domainsAcceptedOnAllKeyTypes() {
        Probe probe = Suite.prepareProbe();
        SecureRandom rng = new SecureRandom();

        // transient private keys: 0 = secp256k1, 1 = wei25519; persistent: 2 = secp256k1, 3 =
        // wei25519
        Curve[] curves = {Curve.SECP256K1, Curve.WEI25519, Curve.SECP256K1, Curve.WEI25519};
        for (int which = 0; which < 4; which++) {
            BigInteger s = curves[which].scalar(rng);
            Probe.Rsp r = probe.setS(which, Curve.u32(s));
            assertEquals(0x9000, r.sw(), curves[which].name + " setS #" + which);
            assertArrayEquals(Curve.u32(s), r.data(), "setS/getS round trip #" + which);
        }

        // persistent public keys: 0 = secp256k1, 1 = wei25519
        Curve[] pubCurves = {Curve.SECP256K1, Curve.WEI25519};
        for (int which = 0; which < 2; which++) {
            Curve.Point pt = pubCurves[which].mul(pubCurves[which].scalar(rng), pubCurves[which].g);
            Probe.Rsp r = probe.setW(which, pubCurves[which].enc(pt));
            assertEquals(0x9000, r.sw(), pubCurves[which].name + " setW");
            assertArrayEquals(pubCurves[which].enc(pt), r.data(), "setW/getW round trip");
        }
        Results.row(
                "Admission 5",
                "domains",
                "pass",
                "both domains on persistent and TRANSIENT_DESELECT keys");
    }
}
