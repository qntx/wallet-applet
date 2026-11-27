// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Fault;

/**
 * Inverted review3 PoC: IMPORT {@code P1 = 0x00} (§9.14) now derives the pending import keys twice
 * — {@code K_te ‖ K_tm = KDF(Z, "qntx-card/v1/kdf-transfer", TH, 32)} — once per ECDH product in
 * separate buffers, and {@code loadKeys} compares the two derivations plus a {@code getKey}
 * read-back before any key is loaded (§16.2 item 5). A single skipped {@code Kdf.kdf} therefore
 * faults the command ({@code 6F00}) instead of leaving zeroed staged keys, and the BLANK target
 * stays BLANK: the zero-key forged record is refused by the MAC check and the attacker's access
 * hash never verifies.
 *
 * <p>The single fault: {@code Fault.armSkip("Kdf.kdf", k)} over the plain weave for every {@code k}
 * the unfaulted command counts — now 2. The count is established on the unfaulted command by {@code
 * Fault.countCalls} and asserted so a regression to one derivation fails.
 */
final class ImportKeyFaultTest {

    private Ca3 ca;
    private Card3 t;
    private Session3 s;
    private Peer3 sender;
    private Peer3.ExportHead head;
    private byte[] attackerSeed;
    private byte[] attackerHash;
    private byte[] forged;

    /**
     * A BLANK target T under the review3 CA whose OFFER is valid (§9.12), a genuine sender S of the
     * same CA whose export head S produced for T's offer, and the forged payload record — {@code
     * origin 0x01 ‖ attacker seed ‖ attacker accessHash ‖ c = 2 ‖ ID(S) ‖ ID(T)} — sealed under the
     * all-zero keys (§9.13 {@code P1 = 0x01} format).
     */
    @BeforeEach
    void setup() {
        ca = new Ca3();
        t = new Card3(ca);
        s = new Session3(t, ca);
        Session3.Resp offer = s.offer();
        assertEquals(0x9000, offer.sw);
        assertEquals(129, offer.data.length);
        byte[] lkT = Arrays.copyOf(offer.data, 65);
        sender = new Peer3(ca);
        head = sender.exportHead(t.a(), lkT);

        attackerSeed = H3.sha512(H3.label("review3-import-seed"));
        attackerHash = H3.sha256(H3.label("review3-import-access"));
        assertNotNull(
                H3.bip32Master(attackerSeed), "the attacker seed must have a valid BIP-32 master");
        byte[] payload =
                H3.cat(
                        new byte[] {0x01},
                        attackerSeed,
                        attackerHash,
                        new byte[] {0x02},
                        sender.id(),
                        t.id());
        forged = Peer3.seal(H3.zeros(16), H3.zeros(16), payload);
        assertEquals(160, forged.length, "c = 2 gives the 160-byte record of §9.14");
    }

    /**
     * Control: unfaulted IMPORT {@code P1 = 0x00} derives the genuine transfer keys; the forged
     * zero-key record fails the MAC check ({@code 6A80}, §9.14 check 1) and the card stays BLANK.
     * Also establishes the {@code Kdf.kdf} call count the fault test arms on.
     */
    @Test
    void controlRejectsForgedRecord() {
        Fault.countCalls();
        Session3.Resp imported = s.import0(head.head);
        assertEquals(0x9000, imported.sw);
        int kdfCalls = Fault.calls("Kdf.kdf");
        Fault.reset();
        assertEquals(2, kdfCalls, "expected two Kdf.kdf inside IMPORT P1=00 (dual derivation)");

        Session3.Resp forgedResp =
                s.import1(
                        Arrays.copyOf(forged, forged.length - 16),
                        Arrays.copyOfRange(forged, forged.length - 16, forged.length));
        assertEquals(
                0x6A80,
                forgedResp.sw,
                "the forged zero-key record must fail the MAC check of §9.14 check 1");

        t.select();
        Session3 fresh = new Session3(t, ca);
        Session3.Resp status = fresh.status();
        assertEquals(0x9000, status.sw);
        assertEquals(0x01, status.data[0], "T must still be BLANK (§9.3)");
    }

    /**
     * Fault, inverted: each of the {@code Kdf.kdf} calls the unfaulted command counts is skipped in
     * turn — the derivation whose KDF is missing no longer matches the other, {@code loadKeys}
     * refuses with {@code 6F00}, and the target stays BLANK: a subsequent unfaulted pending import
     * still refuses the forged zero-key record ({@code 6A80}) and the attacker's access hash does
     * not verify.
     */
    @Test
    void skippedKdfLeavesBlankTarget() {
        Fault.countCalls();
        assertEquals(0x9000, s.import0(head.head).sw);
        int kdfCalls = Fault.calls("Kdf.kdf");
        Fault.reset();
        assertEquals(2, kdfCalls, "expected two Kdf.kdf inside IMPORT P1=00 (dual derivation)");
        // the unfaulted import0 only derived keys; the faulted import0's dispatch ends that
        // pending import (§9.2), and offer stays VALID until T-INSTALL (§9.12)

        for (int k = 1; k <= kdfCalls; k++) {
            Fault.armSkip("Kdf.kdf", k);
            assertEquals(
                    0x6F00,
                    s.import0(head.head).sw,
                    "Kdf.kdf skip " + k + " must fault the dual derivation, not release");
            Fault.reset();
            // the faulted command tears the session down before the next arm
            t.select();
            s = new Session3(t, ca);
        }

        // the forged zero-key record is still refused on an unfaulted pending import
        assertEquals(0x9000, s.import0(head.head).sw);
        Session3.Resp forgedResp =
                s.import1(
                        Arrays.copyOf(forged, forged.length - 16),
                        Arrays.copyOfRange(forged, forged.length - 16, forged.length));
        assertEquals(0x6A80, forgedResp.sw, "the forged record fails the MAC check");

        t.select();
        Session3 fresh = new Session3(t, ca);
        Session3.Resp status = fresh.status();
        assertEquals(0x9000, status.sw);
        assertEquals(0x01, status.data[0], "T must still be BLANK (§9.3)");
        assertNotEquals(
                0x9000,
                fresh.verify(attackerHash).sw,
                "the attacker's access code must not verify");
    }
}
