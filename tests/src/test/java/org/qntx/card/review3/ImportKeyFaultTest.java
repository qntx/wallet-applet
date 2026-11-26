// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review3;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Fault;

/**
 * What it shows: a single skipped {@code Kdf.kdf} inside IMPORT {@code P1 = 0x00} (§9.14) leaves
 * the pending import keys {@code K_te ‖ K_tm} equal to the zeroed scratch they are staged from, so
 * a payload record sealed under the public all-zero key passes the MAC check and installs an
 * attacker-chosen seed, access hash and member list on a BLANK target — a full wallet replacement
 * the attacker then opens with their own access code. In the field the sender S is the attacker's
 * own genuine card whose CREATE named {@code ID(T)} (§11.1 allows this); the attacker never learns
 * S's export secret {@code e}.
 *
 * <p>The single fault: {@code Fault.armSkip("Kdf.kdf", 1)} over the plain weave — the first (and
 * only) {@code Kdf.kdf} call of the command, which is the transfer-key derivation {@code K_te ‖
 * K_tm = KDF(Z, "qntx-card/v1/kdf-transfer", TH, 32)} of §9.14 {@code P1 = 0x00}. The count is
 * established on the unfaulted command by {@code Fault.countCalls}.
 */
final class ImportKeyFaultTest {

    // §9.8: the fixed derivation path the installed wallet is checked at — m/0'.
    private static final long[] PATH = {0x80000000L};

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

    private static void assertWalletInfo(byte[] info, byte[] masterPub, int origin, byte[]... ids) {
        assertArrayEquals(masterPub, Arrays.copyOfRange(info, 0, 33), "masterPublicKey");
        assertEquals(origin, info[33] & 0xFF, "origin");
        assertEquals(ids.length, info[34] & 0xFF, "member count");
        for (int i = 0; i < ids.length; i++) {
            assertArrayEquals(
                    ids[i],
                    Arrays.copyOfRange(info, 35 + i * 16, 35 + (i + 1) * 16),
                    "member " + i);
        }
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
        assertEquals(1, kdfCalls, "expected one Kdf.kdf inside IMPORT P1=00 (transferKeys)");

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
     * Fault: with the single {@code Kdf.kdf} of IMPORT {@code P1 = 0x00} skipped, the pending
     * import keys are the all-zero staged bytes, the forged record installs, and a fresh session
     * finds T LOADED with the attacker's origin, member list and access code; PUBLIC_KEY at the
     * fixed path equals the host's BIP-32 derivation from the attacker seed.
     */
    @Test
    void skippedKdfInstallsAttackerSeed() {
        Fault.countCalls();
        assertEquals(0x9000, s.import0(head.head).sw);
        int kdfCalls = Fault.calls("Kdf.kdf");
        Fault.reset();
        assertEquals(1, kdfCalls, "expected one Kdf.kdf inside IMPORT P1=00 (transferKeys)");
        // the unfaulted import0 only derived keys; the faulted import0's dispatch ends that
        // pending import (§9.2), and offer stays VALID until T-INSTALL (§9.12)

        Fault.armSkip("Kdf.kdf", 1);
        assertEquals(0x9000, s.import0(head.head).sw);
        Fault.reset();
        Session3.Resp installed =
                s.import1(
                        Arrays.copyOf(forged, forged.length - 16),
                        Arrays.copyOfRange(forged, forged.length - 16, forged.length));
        assertEquals(
                0x9000, installed.sw, "the forged zero-key record must install under the fault");
        assertWalletInfo(
                installed.data, H3.masterPublicKey(attackerSeed), 0x01, sender.id(), t.id());

        t.select();
        Session3 fresh = new Session3(t, ca);
        Session3.Resp status = fresh.status();
        assertEquals(0x9000, status.sw);
        assertEquals(0x02, status.data[0], "T must be LOADED (§9.3)");

        Session3.Resp verified = fresh.verify(attackerHash);
        assertEquals(0x9000, verified.sw, "the attacker's access code must verify");
        assertWalletInfo(
                verified.data, H3.masterPublicKey(attackerSeed), 0x01, sender.id(), t.id());

        Session3.Resp pub = fresh.publicKey(0, PATH);
        assertEquals(0x9000, pub.sw);
        byte[][] node = H3.derivePriv(attackerSeed, PATH);
        assertArrayEquals(
                node[2], Arrays.copyOfRange(pub.data, 0, 33), "publicKey at m/0' = BIP-32 leaf");
        assertArrayEquals(
                node[1], Arrays.copyOfRange(pub.data, 33, 65), "chainCode at m/0' = BIP-32 leaf");
    }
}
