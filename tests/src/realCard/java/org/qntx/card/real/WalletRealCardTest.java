// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.qntx.card.host.Bip32;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Slip10;
import org.qntx.card.host.WalletInfo;
import org.qntx.card.tests.Vecs;

/**
 * Wallet life-cycle commands on card A: STATUS, CREATE both flavours, VERIFY/CHANGE/ERASE/
 * PUBLIC_KEY/WAIT, the §9.5 failure-limit story (run once: the ~110 real WAITs are seconds each)
 * and the derivation vectors of {@code derivation.json} — one CREATE P1 = 1 per distinct 64-byte
 * seed. The power-loss sequences of {@code verify-sequence.json} are not run (no programmable
 * reader); the count of wrong VERIFYs stays inside the agreed ~40.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
final class WalletRealCardTest {
    private Session session;

    private void blank() throws Exception {
        Fixture.ensureBlank();
        session = Fixture.open();
    }

    private void loaded() throws Exception {
        Fixture.ensureLoaded();
        session = Fixture.open();
    }

    private Response inner(int ins, int p1, byte[] data) throws Exception {
        return Fixture.cmd(session, ins, p1, 0, data);
    }

    private Response status() throws Exception {
        return inner(0x20, 0, new byte[0]);
    }

    private void assertStatus(String hex) throws Exception {
        Response r = status();
        assertEquals(0x9000, r.sw());
        assertArrayEquals(Vecs.unhex(hex), r.data(), "STATUS");
    }

    private void create(byte[] seed) throws Exception {
        byte[] data = new byte[32 + seed.length];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(seed, 0, data, 32, seed.length);
        assertEquals(0x9000, inner(0x21, 1, data).sw(), "CREATE imported");
        Fixture.ensureFactoryField(Fixture.Life.LOADED);
    }

    /** Resets the persistent failure count with a right VERIFY (15 WAITs first if gated). */
    private void resetFails() throws Exception {
        Fixture.ensureLoaded();
        session = Fixture.open();
        Response st = status();
        if (st.sw() == 0x9000 && st.data().length == 2 && st.data()[1] != 10) {
            Response r = inner(0x22, 0, Vecs.accessHash());
            if (r.sw() == 0x6985) {
                for (int i = 0; i < 15; i++) {
                    assertEquals(0x9000, inner(0x25, 0, new byte[0]).sw(), "WAIT");
                }
                r = inner(0x22, 0, Vecs.accessHash());
            }
            assertEquals(0x9000, r.sw(), "reset VERIFY");
        }
    }

    @Test
    @Order(1)
    void statusReportsLifeAndFreeTries() throws Exception {
        Fixture.require();
        blank();
        assertStatus("0100");
        loaded();
        assertStatus("020a");
    }

    @Test
    @Order(2)
    void verifyReturnsWalletInfoAndUnlocks() throws Exception {
        Fixture.require();
        loaded();
        Response r = inner(0x22, 0, Vecs.accessHash());
        assertEquals(0x9000, r.sw());
        WalletInfo info = WalletInfo.parse(r.data());
        assertArrayEquals(Vecs.seedMasterPublicKey(), info.masterPublicKey());
        assertEquals(0x02, info.origin(), "imported origin (§9.4)");
        r = inner(0x30, 0, Vecs.pathSecpEvm());
        assertEquals(0x9000, r.sw(), "PUBLIC_KEY after VERIFY");
        assertArrayEquals(Vecs.pkSecpEvm(), r.data());
    }

    @Test
    @Order(3)
    void createOnLoadedCardIsRejected() throws Exception {
        Fixture.require();
        loaded();
        byte[] data = new byte[96];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        assertEquals(0x6985, inner(0x21, 1, data).sw());
    }

    @Test
    @Order(4)
    void commandGatesPrecedeEffects() throws Exception {
        Fixture.require();
        loaded();
        // §14.2 order on a command the life gate refuses: CREATE is BLANK-only, so on a
        // LOADED card the life gate answers 6985 before the P1 range check is reached
        assertEquals(0x6985, inner(0x21, 2, new byte[0]).sw(), "CREATE on LOADED: life first");
        assertEquals(0x6700, inner(0x22, 0, new byte[31]).sw(), "VERIFY needs 32 bytes");
        assertEquals(0x6A86, inner(0x30, 2, Vecs.pathSecpEvm()).sw(), "PUBLIC_KEY P1 range");
        assertEquals(0x6700, inner(0x20, 0, new byte[1]).sw(), "STATUS takes no data");
    }

    @Test
    @Order(5)
    void verifyWrongCountsAndBlocksVerifiedCommands() throws Exception {
        Fixture.require();
        resetFails();
        Response r = inner(0x22, 0, Vecs.accessHashWrong());
        assertEquals(0x63C9, r.sw());
        assertEquals(0, r.data().length, "no output on a wrong code");
        assertStatus("0209");
        assertEquals(0x6982, inner(0x30, 0, Vecs.pathSecpEvm()).sw(), "needs verified");
        resetFails();
    }

    @Test
    @Order(6)
    void unverifiedSessionWritesOnlyWhatItMay() throws Exception {
        Fixture.require();
        resetFails();
        // §16.1 item 7: without VERIFY the only persistent effect is the counted failure
        assertEquals(0x6982, inner(0x24, 0, new byte[0]).sw(), "ERASE needs verified");
        assertEquals(0x6982, inner(0x30, 0, Vecs.pathSecpEvm()).sw(), "PUBLIC_KEY needs verified");
        assertEquals(0x6982, inner(0x23, 0, Vecs.accessHashNew()).sw(), "CHANGE needs verified");
        assertEquals(0x6982, inner(0x31, 0, new byte[33]).sw(), "SIGN_ECDSA needs verified");
        resetFails();
    }

    @Test
    @Order(7)
    void failureLimitSequences() throws Exception {
        Fixture.require();
        // the no-tear sequences of verify-sequence.json, ~35 wrong VERIFYs in all
        List<String> names =
                List.of(
                        "right-resets-at-f-0",
                        "right-resets-at-f-1",
                        "right-resets-at-f-2",
                        "right-resets-at-f-3",
                        "right-needs-wait",
                        "waited-lost-on-open",
                        "wait-beyond-W");
        for (Map<String, Object> seq : Vecs.list(Vecs.load("verify-sequence.json"), "sequences")) {
            if (!names.contains(seq.get("name"))) {
                continue;
            }
            runSequence(seq);
        }
    }

    @SuppressWarnings("unchecked")
    private void runSequence(Map<String, Object> seq) throws Exception {
        String name = (String) seq.get("name");
        resetFails();
        session = Fixture.open();
        for (Map<String, Object> step : (List<Map<String, Object>>) seq.get("steps")) {
            String command = (String) step.get("command");
            int repeat = ((Number) step.getOrDefault("repeat", 1)).intValue();
            if (command.equals("OPEN")) {
                session = Fixture.open();
            } else {
                byte[] data =
                        command.equals("WAIT")
                                ? new byte[0]
                                : step.get("code").equals("right")
                                        ? Vecs.accessHash()
                                        : Vecs.accessHashWrong();
                int ins = command.equals("WAIT") ? 0x25 : 0x22;
                for (int i = 0; i < repeat; i++) {
                    Response r = inner(ins, 0, data);
                    assertEquals(
                            Integer.parseInt((String) step.get("sw"), 16),
                            r.sw(),
                            name + " " + command + " (" + i + ")");
                }
            }
            Response st = status();
            assertEquals(0x9000, st.sw());
            assertArrayEquals(Vecs.unhex((String) step.get("status")), st.data(), name + " status");
        }
    }

    @Test
    @Order(8)
    void failureLimitStoryRunsOnce() throws Exception {
        Fixture.require();
        resetFails();
        // §9.5: three free attempts (63C9..63C7), then 6985 until W = 15 WAITs, one attempt
        // per W WAITs, the L = 10th failure erases with 6983 — the wrong-to-limit sequence
        for (int i = 0; i < 3; i++) {
            assertEquals(
                    0x63C0 | (9 - i),
                    inner(0x22, 0, Vecs.accessHashWrong()).sw(),
                    "free attempt " + i);
        }
        assertEquals(0x6985, inner(0x22, 0, Vecs.accessHashWrong()).sw(), "gated");
        for (int f = 3; f < 10; f++) {
            for (int w = 0; w < 15; w++) {
                assertEquals(0x9000, inner(0x25, 0, new byte[0]).sw(), "WAIT " + w);
            }
            int expected = f < 9 ? 0x63C0 | (9 - f) : 0x6983;
            assertEquals(expected, inner(0x22, 0, Vecs.accessHashWrong()).sw(), "attempt f=" + f);
        }
        // the wallet is gone; VERIFY and WAIT are refused in BLANK
        assertStatus("0100");
        assertEquals(0x6985, inner(0x22, 0, Vecs.accessHash()).sw());
        assertEquals(0x6985, inner(0x25, 0, new byte[0]).sw());
        Fixture.ensureFactoryField(Fixture.Life.BLANK);
    }

    @Test
    @Order(9)
    void eraseFlowAndChangeRewrap() throws Exception {
        Fixture.require();
        loaded();
        // ERASE refuses without VERIFY, erases under it, leaves a live BLANK session
        assertEquals(0x6982, inner(0x24, 0, new byte[0]).sw(), "unverified ERASE");
        Fixture.verify(session);
        byte[] info = inner(0x22, 0, Vecs.accessHash()).data().clone();
        assertEquals(0x9000, inner(0x24, 0, new byte[0]).sw(), "ERASE");
        Fixture.ensureFactoryField(Fixture.Life.BLANK);
        assertStatus("0100");
        assertEquals(0x6985, inner(0x30, 0, Vecs.pathSecpEvm()).sw(), "BLANK gates PUBLIC_KEY");
        // re-create, then CHANGE re-wraps without altering WalletInfo
        // (CREATE itself leaves the session verified, §9.4)
        create(Vecs.seed());
        assertEquals(0x9000, inner(0x23, 0, Vecs.accessHashNew()).sw(), "CHANGE");
        session = Fixture.open();
        assertEquals(0x63C9, inner(0x22, 0, Vecs.accessHash()).sw(), "old code fails after CHANGE");
        session = Fixture.open();
        Response r = inner(0x22, 0, Vecs.accessHashNew());
        assertEquals(0x9000, r.sw());
        assertArrayEquals(info, r.data(), "WalletInfo unchanged by rewrap");
        // restore the standard access hash for the rest of the run
        assertEquals(0x9000, inner(0x23, 0, Vecs.accessHash()).sw(), "CHANGE back");
        session = Fixture.open();
        assertEquals(0x9000, inner(0x22, 0, Vecs.accessHash()).sw(), "restored");
        session.close();
    }

    @Test
    @Order(10)
    void derivationVectors() throws Exception {
        Fixture.require();
        Map<String, Object> doc = Vecs.load("derivation.json");
        // one CREATE P1 = 1 per distinct 64-byte seed, then PUBLIC_KEY of every listed path
        for (Map<String, Object> v : Vecs.list(doc, "bip32")) {
            byte[] seed = Vecs.hex(v, "seed");
            if (seed.length != 64) {
                continue;
            }
            createOnBlank(seed);
            Response r = inner(0x22, 0, Vecs.accessHash());
            assertArrayEquals(
                    Bip32.masterPublicKey(seed),
                    Arrays.copyOf(r.data(), 33),
                    (String) v.get("name") + " master");
            for (Map<String, Object> node : Vecs.list(v, "nodes")) {
                String path = (String) node.get("path");
                if (path.equals("m")) {
                    continue;
                }
                r = inner(0x30, 0, org.qntx.card.host.Paths.wire(path));
                assertEquals(0x9000, r.sw(), path);
                byte[] expected = new byte[65];
                System.arraycopy(Vecs.hex(node, "publicKey"), 0, expected, 0, 33);
                System.arraycopy(Vecs.hex(node, "chainCode"), 0, expected, 33, 32);
                assertArrayEquals(expected, r.data(), path);
            }
        }
        Map<String, Object> v2 = Vecs.list(doc, "slip10").get(1);
        createOnBlank(Vecs.hex(v2, "seed"));
        Fixture.verify(session);
        for (Map<String, Object> node : Vecs.list(v2, "nodes")) {
            String path = (String) node.get("path");
            if (path.equals("m")) {
                continue;
            }
            Response r = inner(0x30, 1, org.qntx.card.host.Paths.wire(path));
            assertEquals(0x9000, r.sw(), path);
            assertArrayEquals(Vecs.hex(node, "wei"), r.data(), path);
        }
        byte[] tseed = Vecs.hex(Vecs.obj(doc, "templates"), "seed");
        createOnBlank(tseed);
        Fixture.verify(session);
        for (Map<String, Object> t : Vecs.list(Vecs.obj(doc, "templates"), "secp256k1")) {
            Response r = inner(0x30, 0, Vecs.hex(t, "wire"));
            assertEquals(0x9000, r.sw(), (String) t.get("name"));
            byte[] expected = new byte[65];
            System.arraycopy(Vecs.hex(t, "publicKey"), 0, expected, 0, 33);
            System.arraycopy(Vecs.hex(t, "chainCode"), 0, expected, 33, 32);
            assertArrayEquals(expected, r.data(), (String) t.get("name"));
        }
        for (Map<String, Object> t : Vecs.list(Vecs.obj(doc, "templates"), "ed25519")) {
            Response r = inner(0x30, 1, Vecs.hex(t, "wire"));
            assertEquals(0x9000, r.sw(), (String) t.get("name"));
            assertArrayEquals(Vecs.hex(t, "wei"), r.data(), (String) t.get("name"));
            assertArrayEquals(Slip10.wei(Vecs.hex(t, "privateKey")), r.data(), "host map");
        }
        // leave the development card with the standard test seed for the next suites
        Fixture.ensureFactoryField(Fixture.Life.LOADED);
        Fixture.ensureLoaded();
    }

    private void createOnBlank(byte[] seed) throws Exception {
        loaded();
        Fixture.verify(session);
        Fixture.erase(session);
        session = Fixture.open();
        create(seed);
        session = Fixture.open();
    }
}
