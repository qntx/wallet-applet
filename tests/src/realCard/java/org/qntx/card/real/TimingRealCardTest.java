// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.qntx.card.host.Open;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.tests.Vecs;

/**
 * The §16.6 timing suite on card A: 20 runs per command (n = 1 for GET_IDENTITY and PERSONALIZE,
 * which only exist in FACTORY), host-measured nanoseconds around the transmit call only. Asserts
 * every single command ≤ 1,500 ms and the WAIT median within the §3 item 9 bound of 900–1,100 ms;
 * writes {@code timing.json} and {@code timing.md}.
 *
 * <p>Wear budget: the CREATE/ERASE phase costs 20 CREATE + 20 ERASE persistent cycles per variant
 * as listed — inside the agreed allowance; the VERIFY rounds contribute the expected 40
 * verifications (20 right + 20 wrong-then-right pairs).
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
final class TimingRealCardTest {
    private static final long LIMIT_NS = 1_500_000_000L;
    private static final int RUNS = 20;

    /** Predicted card time from §16.6, milliseconds; {@code null} where §16.6 gives none. */
    private static final Map<String, Double> PREDICTED =
            Map.ofEntries(
                    Map.entry("OPEN", 160.0),
                    Map.entry("VERIFY right", 124.0),
                    Map.entry("VERIFY wrong", 124.0),
                    Map.entry("WAIT", 965.0),
                    Map.entry("CREATE P1=0", 106.0),
                    Map.entry("CREATE P1=1", 106.0),
                    Map.entry("PUBLIC_KEY secp depth5 cold", 411.0),
                    Map.entry("PUBLIC_KEY ed25519 depth5 cold", 217.0),
                    Map.entry("SIGN_ECDSA depth5 cold", 411.0),
                    Map.entry("SIGN_BIP340 untweaked cold", 724.0),
                    Map.entry("SIGN_BIP340 tweak cold", 724.0),
                    Map.entry("SIGN_ED25519 begin cold", 430.0),
                    Map.entry("SIGN_ED25519 update", 21.0),
                    Map.entry("SIGN_ED25519 finish cold", 486.0));

    private record Row(String name, List<Long> nanos) {
        double median() {
            long[] s = sorted();
            return s.length % 2 == 1
                    ? s[s.length / 2] / 1e6
                    : (s[s.length / 2 - 1] + s[s.length / 2]) / 2e6;
        }

        double p95() {
            long[] s = sorted();
            return s[(int) Math.ceil(0.95 * s.length) - 1] / 1e6;
        }

        double min() {
            return sorted()[0] / 1e6;
        }

        double max() {
            return sorted()[sorted().length - 1] / 1e6;
        }

        private long[] sorted() {
            long[] s = nanos.stream().mapToLong(Long::longValue).toArray();
            Arrays.sort(s);
            return s;
        }
    }

    private static final List<Row> ROWS = new ArrayList<>();

    private static void sample(String name, long nanos) {
        for (Row r : ROWS) {
            if (r.name().equals(name)) {
                r.nanos().add(nanos);
                return;
            }
        }
        ROWS.add(new Row(name, new ArrayList<>(List.of(nanos))));
    }

    private static long timed(byte[] apdu) {
        RealCard.Timed t = Fixture.card().timed(apdu);
        return t.nanos();
    }

    private static RealCard.Timed timedFull(byte[] apdu) {
        return Fixture.card().timed(apdu);
    }

    /** Depth-3/depth-5 paths of each family. */
    private static final byte[] SECP_D3 = Vecs.unhex("03800000548000000080000000"); // m/84'/0'/0'

    private static final byte[] SECP_D5 = Vecs.pathSecpEvm(); // m/44'/60'/0'/0/0
    private static final byte[] ED_D3 = Vecs.unhex("038000002c800001f580000000"); // m/44'/501'/0'
    private static final byte[] ED_D5 = Vecs.unhex("058000000080000001800000028000000380000004");

    @Test
    @Order(1)
    void identityAndPersonaliseOnce() throws Exception {
        Fixture.require();
        // GET_IDENTITY/PERSONALIZE exist only in FACTORY — a fresh install, n = 1
        Fixture.connect();
        Fixture.card()
                .reinstall(
                        Fixture.capPath(Fixture.CapKind.PROD),
                        RealCard.PACKAGE_AID,
                        RealCard.PACKAGE_AID,
                        RealCard.APPLET_AID);
        Fixture.markInstalled(Fixture.CapKind.PROD);
        // the first SELECT after install runs the deferred construction on the lazy build —
        // measure it (n = the installs this suite does anyway, §16.6 table notes n = 1)
        RealCard.Timed t = timedFull(RealCard.SELECT);
        assertEquals(0x9000, RealCard.sw(t.rapdu()), "SELECT after install");
        sample("FIRST_SELECT", t.nanos());
        t = timedFull(Vecs.unhex("80E0000000"));
        assertEquals(0x9000, RealCard.sw(t.rapdu()), "GET_IDENTITY");
        sample("GET_IDENTITY", t.nanos());
        assertTrue(t.nanos() <= LIMIT_NS, "GET_IDENTITY " + t.nanos());
        t = timedFull(Fixture.personalizeApdu());
        assertEquals(0x9000, RealCard.sw(t.rapdu()), "PERSONALIZE");
        sample("PERSONALIZE", t.nanos());
        assertTrue(t.nanos() <= LIMIT_NS, "PERSONALIZE " + t.nanos());
        Fixture.ensureFactoryField(Fixture.Life.BLANK);
    }

    @Test
    @Order(2)
    void commandTimings() throws Exception {
        Fixture.require();
        Fixture.ensureLoaded();
        byte[] rnd = new byte[32];
        Vecs.RND.nextBytes(rnd);
        byte[] rndTweak = new byte[32];
        byte[] tb = new java.math.BigInteger(1, rnd).mod(org.qntx.card.host.Crypto.N).toByteArray();
        System.arraycopy(
                tb,
                Math.max(0, tb.length - 32),
                rndTweak,
                Math.max(0, 32 - tb.length),
                Math.min(32, tb.length));
        byte[] bip86wire = Vecs.hex(Vecs.secpTemplate("btc-bip86"), "wire");
        // one selection epoch for the whole table: a further SELECT would clear the
        // CLEAR_ON_DESELECT key domains (defect D2) and every OPEN after it would 6F00
        for (int i = 0; i < RUNS; i++) {
            Open.Request req = Open.request(Vecs.RND);
            RealCard.Timed t = timedFull(req.apdu());
            sample("OPEN", t.nanos());
            Session s =
                    Open.response(req.secret(), req.apdu(), t.rapdu(), List.of(Vecs.caPublic()));
            // wrong-then-right VERIFY pair, each timed separately
            sample("VERIFY wrong", timedInner(s, 0x22, Vecs.accessHashWrong()));
            sample("VERIFY right", timedInner(s, 0x22, Vecs.accessHash()));
            sample("STATUS", timedInner(s, 0x20, new byte[0]));
            publicKey(s, "secp depth3", SECP_D3, 0);
            publicKey(s, "secp depth5", SECP_D5, 0);
            publicKey(s, "ed25519 depth3", ED_D3, 1);
            publicKey(s, "ed25519 depth5", ED_D5, 1);
            signEcdsa(s, "depth5");
            signBip340(s, "untweaked", new byte[32], bip86wire);
            signBip340(s, "tweak", rndTweak, bip86wire);
            for (int size : new int[] {64, 1232, 4032}) {
                signEd(s, size, "cold");
                signEd(s, size, "warm");
            }
            sample("WAIT", timedInner(s, 0x25, new byte[0]));
            s.close();
        }
    }

    private static long timedInner(Session s, int ins, byte[] data) throws Exception {
        byte[] apdu = s.wrap(ins, 0, 0, data);
        RealCard.Timed t = timedFull(apdu);
        s.unwrap(t.rapdu());
        return t.nanos();
    }

    private static void publicKey(Session s, String name, byte[] wire, int p1) throws Exception {
        byte[] apdu = s.wrap(0x30, p1, 0, wire);
        RealCard.Timed t = timedFull(apdu);
        s.unwrap(t.rapdu());
        sample("PUBLIC_KEY " + name + " cold", t.nanos());
        apdu = s.wrap(0x30, p1, 0, wire);
        t = timedFull(apdu);
        s.unwrap(t.rapdu());
        sample("PUBLIC_KEY " + name + " warm", t.nanos());
        assertTrue(t.nanos() <= LIMIT_NS, "PUBLIC_KEY warm " + t.nanos());
    }

    private static void signEcdsa(Session s, String name) throws Exception {
        byte[] data = new byte[32 + SECP_D5.length];
        System.arraycopy(Vecs.digest(), 0, data, 0, 32);
        System.arraycopy(SECP_D5, 0, data, 32, SECP_D5.length);
        byte[] apdu = s.wrap(0x31, 0, 0, data);
        RealCard.Timed t = timedFull(apdu);
        s.unwrap(t.rapdu());
        sample("SIGN_ECDSA " + name + " cold", t.nanos());
        apdu = s.wrap(0x31, 0, 0, data);
        t = timedFull(apdu);
        s.unwrap(t.rapdu());
        sample("SIGN_ECDSA " + name + " warm", t.nanos());
    }

    private static void signBip340(Session s, String name, byte[] tweak, byte[] wire)
            throws Exception {
        byte[] data = new byte[64 + wire.length];
        System.arraycopy(Vecs.message(), 0, data, 0, 32);
        System.arraycopy(tweak, 0, data, 32, 32);
        System.arraycopy(wire, 0, data, 64, wire.length);
        byte[] apdu = s.wrap(0x32, 0, 0, data);
        RealCard.Timed t = timedFull(apdu);
        s.unwrap(t.rapdu());
        sample("SIGN_BIP340 " + name + " cold", t.nanos());
        apdu = s.wrap(0x32, 0, 0, data);
        t = timedFull(apdu);
        s.unwrap(t.rapdu());
        sample("SIGN_BIP340 " + name + " warm", t.nanos());
    }

    private static void signEd(Session s, int size, String phase) throws Exception {
        byte[] message = new byte[size];
        Vecs.RND.nextBytes(message);
        // PUBLIC_KEY first: any other inner command would end the pending stream (§9.2)
        Response pk = s.unwrap(Fixture.card().transmit(s.wrap(0x30, 1, 0, Vecs.pathEdSolana())));
        byte[] encodedA = org.qntx.card.host.Wei25519Map.encode(pk.data());
        long total = 0;
        RealCard.Timed t;
        byte[] apdu = s.wrap(0x33, 0, 0, Vecs.pathEdSolana());
        t = timedFull(apdu);
        total += t.nanos();
        Response begin = s.unwrap(t.rapdu());
        assertEquals(0x9000, begin.sw(), "ed begin");
        sample("SIGN_ED25519 begin " + phase, t.nanos());
        byte[] encodedR = org.qntx.card.host.Wei25519Map.encode(begin.data());
        byte[] stream = org.qntx.card.host.Ed25519.stream(encodedR, encodedA, message);
        int off = 0;
        while (stream.length - off > 236) {
            apdu = s.wrap(0x33, 1, 0, Arrays.copyOfRange(stream, off, off + 236));
            t = timedFull(apdu);
            total += t.nanos();
            s.unwrap(t.rapdu());
            sample("SIGN_ED25519 update", t.nanos());
            off += 236;
        }
        apdu = s.wrap(0x33, 2, 0, Arrays.copyOfRange(stream, off, stream.length));
        t = timedFull(apdu);
        total += t.nanos();
        Response fin = s.unwrap(t.rapdu());
        assertEquals(0x9000, fin.sw(), "ed finish");
        sample("SIGN_ED25519 finish " + phase, t.nanos());
        sample("SIGN_ED25519 " + size + "B total " + phase, total);
    }

    @Test
    @Order(3)
    void createEraseTimings() throws Exception {
        Fixture.require();
        for (int i = 0; i < RUNS; i++) {
            Fixture.ensureBlank();
            Session s = Fixture.open();
            byte[] gen = new byte[64];
            System.arraycopy(Vecs.accessHash(), 0, gen, 0, 32);
            System.arraycopy(Vecs.entropy(), 0, gen, 32, 32);
            byte[] apdu = s.wrap(0x21, 0, 0, gen);
            RealCard.Timed t = timedFull(apdu);
            assertEquals(0x9000, s.unwrap(t.rapdu()).sw(), "CREATE P1=0");
            sample("CREATE P1=0", t.nanos());
            apdu = s.wrap(0x24, 0, 0, new byte[0]);
            t = timedFull(apdu);
            assertEquals(0x9000, s.unwrap(t.rapdu()).sw(), "ERASE");
            sample("ERASE", t.nanos());
            Fixture.ensureFactoryField(Fixture.Life.BLANK);
            byte[] imp = new byte[96];
            System.arraycopy(Vecs.accessHash(), 0, imp, 0, 32);
            System.arraycopy(Vecs.seed(), 0, imp, 32, 64);
            apdu = s.wrap(0x21, 1, 0, imp);
            t = timedFull(apdu);
            assertEquals(0x9000, s.unwrap(t.rapdu()).sw(), "CREATE P1=1");
            sample("CREATE P1=1", t.nanos());
            apdu = s.wrap(0x24, 0, 0, new byte[0]);
            t = timedFull(apdu);
            assertEquals(0x9000, s.unwrap(t.rapdu()).sw(), "ERASE");
            sample("ERASE", t.nanos());
            Fixture.ensureFactoryField(Fixture.Life.BLANK);
            s.close();
        }
        // leave the card LOADED with the test seed for the differential suite
        Fixture.ensureLoaded();
    }

    @Test
    @Order(4)
    void selectTimings() throws Exception {
        Fixture.require();
        Fixture.ensureSelected();
        RealCard card = Fixture.card();
        // SELECT runs last: every select past the epoch's first is itself D2-triggering
        for (int i = 0; i < RUNS; i++) {
            RealCard.Timed t = timedFull(org.qntx.card.tests.Spec.SELECT);
            assertEquals(0x9000, RealCard.sw(t.rapdu()), "SELECT");
            sample("SELECT", t.nanos());
        }
    }

    @Test
    @Order(5)
    void writeReportAndAssertBounds() throws Exception {
        Fixture.require();
        StringBuilder md =
                new StringBuilder(
                        "| command | n | min | median | p95 | max | predicted ms (§16.6) | ≤1500 |\n");
        md.append("| --- | --- | --- | --- | --- | --- | --- | --- |\n");
        Map<String, Object> json = new LinkedHashMap<>();
        boolean waitChecked = false;
        for (Row r : ROWS) {
            // FIRST_SELECT is report-only: on the lazy test build it pays the deferred
            // constructor that production pays inside install — not a §16.6 command row
            boolean bound = !r.name().equals("FIRST_SELECT");
            md.append(
                    String.format(
                            "| %s | %d | %.1f | %.1f | %.1f | %.1f | %s | %s |\n",
                            r.name(),
                            r.nanos().size(),
                            r.min(),
                            r.median(),
                            r.p95(),
                            r.max(),
                            PREDICTED.containsKey(r.name())
                                    ? String.format("%.0f", PREDICTED.get(r.name()))
                                    : "—",
                            bound ? (r.max() <= 1500 ? "yes" : "NO") : "—"));
            Map<String, Object> j = new LinkedHashMap<>();
            j.put("n", r.nanos().size());
            j.put("minMs", r.min());
            j.put("medianMs", r.median());
            j.put("p95Ms", r.p95());
            j.put("maxMs", r.max());
            j.put("predictedMs", PREDICTED.get(r.name()));
            json.put(r.name(), j);
        }
        Files.writeString(
                Fixture.out().resolve("timing.json"),
                com.fasterxml.jackson.jr.ob.JSON.std.asString(json));
        Files.writeString(Fixture.out().resolve("timing.md"), md.toString());
        for (Row r : ROWS) {
            if (r.name().equals("FIRST_SELECT")) {
                continue; // report-only row (deferred construction), no §16.6 bound
            }
            assertTrue(r.max() <= 1500, r.name() + " max " + r.max() + " ms > 1500");
            if (r.name().equals("WAIT")) {
                waitChecked = true;
                assertTrue(
                        r.median() >= 900 && r.median() <= 1100,
                        "WAIT median " + r.median() + " outside 900–1100 (§3 item 9)");
            }
        }
        assertTrue(waitChecked, "WAIT was not measured");
    }
}
