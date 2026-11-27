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
 * Inverted review3 PoC: EXPORT {@code P1 = 0x00} (§9.13) now derives the transfer keys twice —
 * {@code K_te ‖ K_tm = KDF(Z, "qntx-card/v1/kdf-transfer", TH, 32)} — once per ECDH product in
 * separate buffers, and {@code loadKeys} compares the two derivations plus a {@code getKey}
 * read-back before any key is loaded (§16.2 item 5). A single skipped {@code Kdf.kdf} therefore
 * faults the command ({@code 6F00}) instead of leaving zeroed staged keys.
 *
 * <p>The single fault: {@code Fault.armSkip("Kdf.kdf", k)} over the plain weave for every {@code k}
 * the unfaulted command counts — now 2. The count is established on the unfaulted command by {@code
 * Fault.countCalls} and asserted so a regression to one derivation fails.
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
        assertEquals(2, kdfCalls, "expected two Kdf.kdf inside EXPORT P1=00 (dual derivation)");

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
     * Fault, inverted: each of the {@code Kdf.kdf} calls the unfaulted command counts is skipped in
     * turn — the derivation whose KDF is missing no longer matches the other, {@code loadKeys}
     * refuses with {@code 6F00}, and a fresh session's {@code EXPORT P1 = 0x01} finds no pending
     * export ({@code 6985}). No record under public keys is produced at all.
     */
    @Test
    void skippedKdfIsRefused() {
        Fault.countCalls();
        Session3.Resp head = s.export0(certT, lkT, sigT);
        assertEquals(0x9000, head.sw);
        int kdfCalls = Fault.calls("Kdf.kdf");
        Fault.reset();
        assertEquals(2, kdfCalls, "expected two Kdf.kdf inside EXPORT P1=00 (dual derivation)");
        assertEquals(0x9000, s.export1(accessHashT).sw);

        for (int k = 1; k <= kdfCalls; k++) {
            Fault.armSkip("Kdf.kdf", k);
            Session3.Resp fhead = s.export0(certT, lkT, sigT);
            Fault.reset();
            assertEquals(
                    0x6F00,
                    fhead.sw,
                    "Kdf.kdf skip " + k + " must fault the dual derivation, not release");
            // the faulted command tears the session down: a fresh verified session has no
            // pending export
            x.select();
            s = new Session3(x, ca);
            assertEquals(0x9000, s.verify(accessHash).sw);
            assertEquals(
                    0x6985,
                    s.export1(accessHashT).sw,
                    "no pending export may follow the faulted P1 = 0x00");
        }
    }
}
