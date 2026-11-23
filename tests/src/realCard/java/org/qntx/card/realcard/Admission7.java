// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * Admission 7 (protocol §3 item 7): persistent key objects participate in transactions — {@code
 * setKey}, {@code setS}, {@code setW}, {@code setExponent} and {@code genKeyPair} inside a
 * transaction that is then aborted must restore the previous value. The persistent array write of
 * sub 5 is the control that must revert on every JCRE.
 */
final class Admission7 extends Suite {
    @Test
    void abortRestoresArrayControl() {
        Probe probe = Suite.prepareProbe();
        Probe.Rsp r = probe.tx(5, Apdu.EMPTY);
        assertEquals(0x9000, r.sw());
        assertEquals(r.data()[0], r.data()[1], "aborted array write must be rolled back");
        Results.row("Admission 7", "array control", "pass", "abort restored the persistent array");
    }

    @Test
    void abortRestoresAesKey() {
        Probe probe = Suite.prepareProbe();
        byte[] key = new byte[16];
        for (int i = 0; i < 16; i++) {
            key[i] = (byte) (i + 1);
        }
        Probe.Rsp r = probe.tx(0, key);
        assertEquals(0x9000, r.sw());
        byte[] before = Arrays.copyOfRange(r.data(), 0, 16);
        byte[] after = Arrays.copyOfRange(r.data(), 16, 32);
        revert(before, after, "AES setKey");
        Results.row(
                "Admission 7",
                "AES setKey",
                "pass",
                "reverted; unusedCommit " + Apdu.u16(r.data(), 32) + "->" + Apdu.u16(r.data(), 36));
    }

    @Test
    void abortRestoresEcPublicW() {
        Probe probe = Suite.prepareProbe();
        Curve.Point pt =
                Curve.SECP256K1.mul(java.math.BigInteger.valueOf(12345), Curve.SECP256K1.g);
        Probe.Rsp r = probe.tx(1, Curve.SECP256K1.enc(pt));
        assertEquals(0x9000, r.sw());
        byte[] before = Arrays.copyOfRange(r.data(), 0, 65);
        byte[] after = Arrays.copyOfRange(r.data(), 65, 130);
        revert(before, after, "EC setW");
        Results.row("Admission 7", "EC setW", "pass", "reverted");
    }

    @Test
    void abortRestoresGenKeyPair() {
        Probe probe = Suite.prepareProbe();
        Probe.Rsp r = probe.tx(2, Apdu.EMPTY);
        if (r.sw() != 0x9000) {
            if (reader.isSim()) {
                Results.row(
                        "Admission 7",
                        "genKeyPair",
                        "skip",
                        "simulator cannot run genKeyPair inside a transaction (jcardsim)");
            }
            simOnly("genKeyPair inside a transaction throws on the simulator");
            throw new IllegalStateException("genKeyPair in transaction failed: sw=" + r.sw());
        }
        byte[] before = Arrays.copyOfRange(r.data(), 0, 65);
        byte[] after = Arrays.copyOfRange(r.data(), 65, 130);
        revert(before, after, "genKeyPair");
        Results.row("Admission 7", "genKeyPair", "pass", "reverted");
    }

    @Test
    void abortRestoresExponent() {
        Probe probe = Suite.prepareProbe();
        probe.rsaSetModulus(0, Curve.u64(Curve.SECP256K1.n));
        probe.rsaSetExponent(0, new byte[] {3});
        Probe.Rsp r = probe.tx(4, new byte[] {5});
        assertEquals(0x9000, r.sw());
        int len0 = r.data()[0] & 0xFF;
        int p = len0 + 1;
        int len2 = r.data()[p] & 0xFF;
        byte[] before = Arrays.copyOfRange(r.data(), 1, 1 + len0);
        byte[] after = Arrays.copyOfRange(r.data(), p + 1, p + 1 + len2);
        revert(before, after, "RSA setExponent");
        Results.row("Admission 7", "RSA setExponent", "pass", "reverted");
    }

    @Test
    void abortRestoresEcPrivateS() {
        Probe probe = Suite.prepareProbe();
        byte[] s = new byte[32];
        s[31] = 9;
        Probe.Rsp r = probe.tx(12, s);
        assertEquals(0x9000, r.sw());
        byte[] before = Arrays.copyOfRange(r.data(), 0, 32);
        byte[] after = Arrays.copyOfRange(r.data(), 32, 64);
        revert(before, after, "EC setS");
        Results.row("Admission 7", "EC setS", "pass", "reverted");
    }

    @Test
    void uncommittedWriteIsRolledBack() {
        Probe probe = Suite.prepareProbe();
        byte[] base = probe.failctr();
        Probe.Rsp r = probe.tx(6, Apdu.EMPTY);
        // the JCRE aborts a transaction left open at process() return; the SW it then answers is
        // implementation-defined (the simulator reports SW_UNKNOWN), the sent data still arrives
        assertEquals(1, r.data()[4], "in-transaction read-back sees the new value");
        assertEquals(1, r.data()[5], "transaction depth inside the command");
        byte[] after = probe.failctr();
        assertEquals(
                base[0] + "," + base[1],
                after[0] + "," + after[1],
                "the uncommitted increment must be rolled back by the JCRE");
        Results.row("Admission 7", "uncommitted", "pass", "JCRE rolled back the open transaction");
    }

    /**
     * Asserts before == after; on the simulator a non-restoring key object is a platform limitation
     * (the sim models array rollback but not key-object rollback), not a card failure.
     */
    private static void revert(byte[] before, byte[] after, String what) {
        if (!Arrays.equals(before, after) && reader.isSim()) {
            Results.row(
                    "Admission 7",
                    what,
                    "skip",
                    "simulator does not restore key objects on abortTransaction (jcardsim)");
            org.junit.jupiter.api.Assumptions.abort(
                    "simulator does not restore key objects on abortTransaction (jcardsim)");
        }
        assertTrue(Arrays.equals(before, after), what + " aborted write must restore the value");
    }
}
