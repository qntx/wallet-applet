// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review3;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Fault;

/**
 * What it shows: a single skipped {@code Kdf.kdf} inside EXPORT {@code P1 = 0x00} (§9.13) leaves
 * the pending export keys {@code K_te ‖ K_tm} equal to the zeroed scratch they are staged from, so
 * the EXPORT {@code P1 = 0x01} record encrypts the wallet seed under publicly known keys. The
 * decryption uses no secret of the member: the target's offer is obtainable through an unverified
 * OPEN + OFFER on it (§9.12), or replayed — a repeated OFFER returns the same {@code LK}.
 *
 * <p>The single fault: {@code Fault.armSkip("Kdf.kdf", 1)} over the plain weave — the first (and
 * only) {@code Kdf.kdf} call of the command, which is the transfer-key derivation {@code K_te ‖
 * K_tm = KDF(Z, "qntx-card/v1/kdf-transfer", TH, 32)} of §9.13 {@code P1 = 0x00}. The count is
 * established on the unfaulted command by {@code Fault.countCalls}.
 */
final class ExportKeyFaultTest {

    private Ca3 ca;
    private Card3 x;
    private Session3 s;
    private Peer3 m;
    private byte[] seed;
    private byte[] accessHash;
    private byte[] accessHashT;
    private byte[] certT;
    private byte[] lkT;
    private byte[] sigT;

    /**
     * Card X, personalised under the review3 CA, holds the known seed via CREATE {@code P1 = 0x01}
     * (§9.4) with the emulated member M as the only other member; VERIFY sets the session verified
     * (§9.5).
     */
    @BeforeEach
    void setup() {
        ca = new Ca3();
        x = new Card3(ca);
        s = new Session3(x, ca);
        m = new Peer3(ca);
        seed = H3.sha512(H3.label("review3-export-seed"));
        accessHash = H3.sha256(H3.label("review3-export-access"));
        accessHashT = H3.sha256(H3.label("review3-export-access-target"));
        Session3.Resp created = s.createImport(accessHash, seed, m.id());
        assertEquals(0x9000, created.sw);
        assertEquals(0x02, created.data[33], "origin must be imported for CREATE P1=01");
        Session3.Resp verified = s.verify(accessHash);
        assertEquals(0x9000, verified.sw);
        byte[] offer = m.offer();
        certT = m.cert();
        lkT = Arrays.copyOf(offer, 65);
        sigT = Arrays.copyOfRange(offer, 65, 129);
    }

    /**
     * Control: unfaulted EXPORT (§9.13) — the member derives the same {@code K_te ‖ K_tm} from its
     * link private key and opens the payload; the all-zero key material does not verify the tag.
     * Also establishes the {@code Kdf.kdf} call count the fault test arms on.
     */
    @Test
    void controlExportsUnderCorrectKeys() {
        Fault.countCalls();
        Session3.Resp head = s.export0(certT, lkT, sigT);
        assertEquals(0x9000, head.sw);
        assertEquals(129, head.data.length);
        int kdfCalls = Fault.calls("Kdf.kdf");
        Fault.reset();
        assertEquals(1, kdfCalls, "expected one Kdf.kdf inside EXPORT P1=00 (transferKeys)");

        Session3.Resp record = s.export1(accessHashT);
        assertEquals(0x9000, record.sw);
        byte[] e = Arrays.copyOf(head.data, 65);
        byte[][] keys = m.importKeys(x.a(), e);
        byte[] payload = Peer3.unseal(keys[0], keys[1], record.data);
        assertNotNull(payload, "the member's correctly derived keys must open the record");
        assertArrayEquals(
                seed, Arrays.copyOfRange(payload, 1, 65), "payload seed = X's seed (§9.13)");
        // under K_te = K_tm = 0¹⁶ the tag does NOT verify
        assertNull(
                Peer3.unseal(H3.zeros(16), H3.zeros(16), record.data),
                "the all-zero keys must not open a genuine export record");
    }

    /**
     * Fault: with the single {@code Kdf.kdf} of EXPORT {@code P1 = 0x00} skipped, the staged key
     * material is the zeroed scratch, so {@code tag = CMAC(0¹⁶, ct)} and {@code CBC⁻¹(0¹⁶, ct)}
     * yields the payload — X's seed — to anyone, without any secret of the member.
     */
    @Test
    void skippedKdfExportsSeedUnderPublicKeys() {
        Fault.countCalls();
        Session3.Resp head = s.export0(certT, lkT, sigT);
        assertEquals(0x9000, head.sw);
        int kdfCalls = Fault.calls("Kdf.kdf");
        Fault.reset();
        assertEquals(1, kdfCalls, "expected one Kdf.kdf inside EXPORT P1=00 (transferKeys)");
        assertEquals(0x9000, s.export1(accessHashT).sw);

        Fault.armSkip("Kdf.kdf", 1);
        Session3.Resp fhead = s.export0(certT, lkT, sigT);
        Fault.reset();
        assertEquals(0x9000, fhead.sw);
        Session3.Resp record = s.export1(accessHashT);
        assertEquals(0x9000, record.sw);

        byte[] ct = Arrays.copyOf(record.data, record.data.length - 16);
        byte[] tag = Arrays.copyOfRange(record.data, record.data.length - 16, record.data.length);
        assertArrayEquals(
                H3.cmac(H3.zeros(16), ct),
                tag,
                "the tag must equal CMAC(0¹⁶, ct): the stale key material is zero");
        byte[] payload = Peer3.unseal(H3.zeros(16), H3.zeros(16), record.data);
        assertNotNull(payload, "the zero-key record must open");
        assertArrayEquals(
                seed,
                Arrays.copyOfRange(payload, 1, 65),
                "CBC⁻¹(0¹⁶, ct) reveals X's seed (§9.13 payload offset 1)");
    }
}
