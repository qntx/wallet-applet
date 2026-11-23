// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Assumptions;
import org.qntx.card.host.Certificates;
import org.qntx.card.host.Open;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.tests.Vecs;

/**
 * The named card states of architecture.md §10 brought about with as few NVM writes as possible
 * (one development card; the wear allowance is a rule of the run). {@link #require()} is the
 * architecture §14.7 R4 "reported as not run" gate: without {@code -PrealCard} every suite is
 * skipped, never failed.
 */
public final class Fixture {
    public static final String SKIP = "not run: no reader (-PrealCard=<reader>)";

    /** Which CAP is installed; a {@code reinstall} is the only transition. */
    public enum CapKind {
        PROD,
        MEM,
        PROBE
    }

    /** The wallet life cycle of §9.1 as this JVM last observed it. */
    public enum Life {
        FACTORY,
        BLANK,
        LOADED
    }

    /** §9.1 GET_IDENTITY, also the §4.3 initialisation driver (6283 per step). */
    public static final byte[] GET_IDENTITY = {(byte) 0x80, (byte) 0xE0, 0, 0, 0};

    private static RealCard card;
    private static CapKind installed;
    private static Life life;
    private static byte[] cardA;
    private static byte[] cert;
    // selection and §4.3 initialisation state as this JVM last observed it: a fresh install
    // starts uninitialised, a reset or another applet's select drops the selection
    private static boolean selected;
    private static boolean initialized;

    private Fixture() {}

    /** True when {@code -PrealCard=<reader>} was given. */
    public static boolean available() {
        return !System.getProperty("qntx.reader", "").isEmpty();
    }

    /** The R4 assumption — call first in every test. */
    public static void require() {
        // -PrealCardList only enumerates the suite (every test reports "listed"), never runs it
        Assumptions.assumeFalse(
                Boolean.parseBoolean(System.getProperty("qntx.realcard.list", "false")),
                "listed (-PrealCardList)");
        Assumptions.assumeTrue(available(), SKIP);
    }

    public static RealCard card() {
        return card;
    }

    public static Path capPath(CapKind kind) {
        String prop =
                switch (kind) {
                    case PROD -> "qntx.cap";
                    case MEM -> "qntx.memcap";
                    case PROBE -> "qntx.probecap";
                };
        return Path.of(System.getProperty(prop));
    }

    /** The unmodified production CAP. */
    public static Path productionCap() {
        return Path.of(System.getProperty("qntx.cap"));
    }

    public static int differential() {
        return Integer.parseInt(System.getProperty("qntx.realcard.differential", "1000"));
    }

    public static long rngBytes() {
        return Long.parseLong(System.getProperty("qntx.realcard.rng", "1048576"));
    }

    public static Path out() {
        return Path.of(System.getProperty("qntx.realcard.out", "build/realcard"));
    }

    /** Connects once per JVM; an ATR other than card A's stops everything. */
    public static RealCard connect() throws Exception {
        if (card == null) {
            card = RealCard.connect();
        }
        return card;
    }

    /** A CAP kind whose install already failed: it is not retried once per test. */
    private static CapKind installFailed;

    /** Installs {@code kind}'s CAP unless it already is; a reinstall resets the wallet state. */
    public static void ensureInstalled(CapKind kind) throws Exception {
        connect();
        if (installed == kind) {
            return;
        }
        doInstall(kind);
    }

    private static void doInstall(CapKind kind) throws Exception {
        if (installFailed == kind) {
            throw new IllegalStateException("CAP " + kind + " already failed to install");
        }
        try {
            switch (kind) {
                case PROD, MEM ->
                        card.reinstall(
                                capPath(kind),
                                RealCard.PACKAGE_AID,
                                RealCard.PACKAGE_AID,
                                RealCard.APPLET_AID,
                                RealCard.NDEF_INSTANCE_AID);
                case PROBE ->
                        card.reinstall(
                                capPath(kind),
                                RealCard.PROBE_PACKAGE_AID,
                                RealCard.PROBE_PACKAGE_AID,
                                RealCard.PROBE_APPLET_AID);
            }
        } catch (Exception e) {
            installFailed = kind;
            throw e;
        }
        installed = kind;
        // a fresh wallet install always starts uninitialised in FACTORY; the probe has no
        // wallet state
        life = kind == CapKind.PROBE ? null : Life.FACTORY;
        // A is generated per instance: a cert issued for the previous install would be
        // refused with 6A80, so the cached identity must be refetched
        cardA = null;
        cert = null;
        selected = false;
        initialized = false;
    }

    /**
     * The §14.3 end state for teardown: our packages deleted, nothing reinstalled — skipped when
     * {@code -PrealCardKeep} leaves the card as the run ended it.
     */
    public static void cleanupCard() throws Exception {
        if (card == null
                || Boolean.parseBoolean(System.getProperty("qntx.realcard.keep", "false"))) {
            return;
        }
        card.deleteOurs();
        installed = null;
        life = null;
        cardA = null;
        cert = null;
        selected = false;
        initialized = false;
    }

    /** A power cycle deselects the applet (and drops CLEAR_ON_DESELECT state). */
    static void noteReset() {
        selected = false;
    }

    /** A select-by-name moved the selection; only a wallet AID keeps the wallet selected. */
    static void noteSelect(byte[] apdu) {
        // case-3 or case-4 select: AID at offset 5, Lc at 4, an optional Le byte may follow
        int lc = apdu.length >= 5 ? apdu[4] & 0xFF : -1;
        if (apdu.length >= 5
                && (apdu[1] & 0xFF) == 0xA4
                && (apdu[2] & 0xFF) == 0x04
                && (apdu.length == 5 + lc || apdu.length == 6 + lc)) {
            byte[] aid = java.util.HexFormat.of().parseHex(RealCard.APPLET_AID);
            selected = java.util.Arrays.equals(aid, 0, aid.length, apdu, 5, 5 + lc);
        }
    }

    /** SELECTs the wallet applet when it is not the selected one already. */
    public static void select() throws Exception {
        if (!selected) {
            card.ok(RealCard.SELECT);
            selected = true;
        }
    }

    /** SELECTs the admission probe applet. */
    public static void selectProbe() throws Exception {
        card.ok(RealCard.SELECT_PROBE);
        selected = false;
    }

    /**
     * SELECT + GET_IDENTITY until it answers other than {@code 6283} — the §4.3/§14.3
     * initialisation drive, bounded at 16 repetitions. Returns the identity data of the final
     * {@code 9000} response.
     */
    public static byte[] driveInit() throws Exception {
        select();
        for (int i = 0; i <= 16; i++) {
            byte[] r = card.transmit(GET_IDENTITY);
            int sw = RealCard.sw(r);
            if (sw == 0x6283) {
                continue;
            }
            if (sw != 0x9000) {
                throw new IllegalStateException(
                        "GET_IDENTITY failed: " + String.format("%04X", sw));
            }
            return Arrays.copyOf(r, r.length - 2);
        }
        throw new IllegalStateException("initialisation did not finish within 16 steps");
    }

    /** Drives §4.3 initialisation to completion if this install has not run it yet. */
    private static void ensureInitialized() throws Exception {
        if (!initialized) {
            byte[] data = driveInit();
            cardA = Arrays.copyOf(data, 33);
            cert = Certificates.issue(Vecs.caPrivate(), cardA);
            initialized = true;
        }
    }

    /** The precondition of a wire check that needs no particular life state. */
    public static void ensureSelected() throws Exception {
        ensureInstalled(CapKind.PROD);
        select();
        ensureInitialized();
    }

    /** A selected wallet applet in a known life state — FACTORY/BLANK/LOADED all allowed. */
    public static void ensureFactory() throws Exception {
        if (life != Life.FACTORY && life != Life.BLANK && life != Life.LOADED) {
            // unknown state (e.g. after the probe CAP): a reinstall is the only guaranteed
            // FACTORY and the install budget allows it
            connect();
            doInstall(CapKind.PROD);
        }
        select();
        ensureInitialized();
    }

    /**
     * True FACTORY for tests that cannot run in a later life state (a BLANK/LOADED card has no way
     * back): reinstalls the wallet CAP unless the card is already known FACTORY.
     */
    public static void ensureStrictFactory() throws Exception {
        if (life != Life.FACTORY) {
            connect();
            doInstall(CapKind.PROD);
        }
        select();
        ensureInitialized();
    }

    /** A PERSONALIZE payload: {@code cert(97) ‖ caPublic(65)} for the card's own A (§5.2). */
    public static byte[] personalizeApdu() throws Exception {
        ensureInitialized();
        byte[] apdu = new byte[5 + 162];
        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0xE2;
        apdu[4] = (byte) 162;
        System.arraycopy(cert, 0, apdu, 5, 97);
        System.arraycopy(Vecs.caPublic(), 0, apdu, 102, 65);
        return apdu;
    }

    /** The card's A and its ca1 certificate, fetched via GET_IDENTITY (FACTORY only). */
    public static byte[] identity() throws Exception {
        if (cert == null) {
            ensureInitialized();
        }
        return cert;
    }

    public static byte[] cardA() throws Exception {
        identity();
        return cardA;
    }

    /** BLANK: FACTORY + PERSONALIZE under ca1 (§7); a LOADED card is ERASEd back (§9.6). */
    public static void ensureBlank() throws Exception {
        ensureFactory();
        if (life == Life.FACTORY) {
            card.ok(personalizeApdu());
            life = Life.BLANK;
        }
        if (life == Life.LOADED) {
            Session s = open();
            if (verifyWithWaits(s) != 0x9000) {
                s.close();
                throw new IllegalStateException("card holds a wallet we cannot erase — stopping");
            }
            assertEquals(0x9000, cmd(s, 0x24, 0, 0, new byte[0]).sw(), "ERASE");
            s.close();
            life = Life.BLANK;
        }
    }

    /** OPEN against the card's cert; anchors the test CA (§8.1). */
    public static Session open() throws Exception {
        Open.Request req = Open.request(Vecs.RND);
        byte[] rapdu = card.transmit(req.apdu());
        return Open.response(req.secret(), req.apdu(), rapdu, List.of(Vecs.caPublic()));
    }

    /** A session command round trip (§8.3/§8.4). */
    public static Response cmd(Session session, int ins, int p1, int p2, byte[] data)
            throws Exception {
        return session.unwrap(card.transmit(session.wrap(ins, p1, p2, data)));
    }

    /** VERIFY with the test access hash; asserts 9000. */
    public static void verify(Session session) throws Exception {
        Response r = cmd(session, 0x22, 0, 0, Vecs.accessHash());
        assertEquals(0x9000, r.sw(), "VERIFY(accessHash)");
    }

    /**
     * VERIFY with the test access hash, absorbing a gated counter first: at f ≥ 3 the card demands
     * W = 15 WAITs before every attempt (§9.5) — a bare VERIFY then answers 6986, which must not be
     * misread as a wrong access code. Returns the inner SW.
     */
    private static int verifyWithWaits(Session s) throws Exception {
        int sw = cmd(s, 0x22, 0, 0, Vecs.accessHash()).sw();
        if (sw == 0x6986) {
            for (int i = 0; i < 15; i++) {
                int w = cmd(s, 0x25, 0, 0, new byte[0]).sw();
                if (w != 0x9000) {
                    return w; // WAIT refused — not a gated LOADED card (e.g. BLANK)
                }
            }
            sw = cmd(s, 0x22, 0, 0, Vecs.accessHash()).sw();
        }
        return sw;
    }

    /**
     * LOADED with the imported test seed (§9.4 P1 = 1). Reuses an already-loaded test wallet —
     * VERIFY + the master public key proves it — instead of spending an ERASE + CREATE.
     */
    public static void ensureLoaded() throws Exception {
        ensureFactory();
        if (life == Life.LOADED) {
            Session s = open();
            if (verifyWithWaits(s) == 0x9000) {
                Response r = cmd(s, 0x30, 0, 0, new byte[] {0});
                if (r.sw() == 0x9000
                        && Arrays.equals(Arrays.copyOf(r.data(), 33), Vecs.seedMasterPublicKey())) {
                    s.close();
                    return;
                }
                // right access code, other seed: erase it on this verified session
                assertEquals(0x9000, cmd(s, 0x24, 0, 0, new byte[0]).sw(), "ERASE");
                s.close();
                life = Life.BLANK;
            } else {
                s.close();
                // the access hash was refused: either the fixture's life flag is stale (the
                // wallet is actually gone) or a foreign wallet — STATUS is legal in both
                Session p = open();
                Response st = cmd(p, 0x20, 0, 0, new byte[0]);
                p.close();
                if (st.sw() == 0x9000 && st.data().length == 2 && st.data()[0] == 0x01) {
                    life = Life.BLANK;
                } else {
                    throw new IllegalStateException(
                            "card holds a wallet we cannot erase — stopping");
                }
            }
        }
        ensureBlank();
        assertEquals(Life.BLANK, life);
        Session s = open();
        byte[] data = new byte[96];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        assertEquals(0x9000, cmd(s, 0x21, 1, 0, data).sw(), "CREATE imported");
        life = Life.LOADED;
        s.close();
    }

    /** Records an install a test did itself (e.g. for a FACTORY-only timing). */
    public static void markInstalled(CapKind kind) {
        installed = kind;
        life = kind == CapKind.PROBE ? null : Life.FACTORY;
        cardA = null;
        cert = null;
        selected = false;
        initialized = false;
    }

    /** Records a life-cycle change a test made outside the ensure* helpers. */
    public static void ensureFactoryField(Life newLife) {
        life = newLife;
    }

    public static Life life() {
        return life;
    }

    /** VERIFY + returns the verified session. */
    public static Session verified() throws Exception {
        Session s = open();
        verify(s);
        return s;
    }

    /** ERASE under a verified session (needed after CREATE timing runs). */
    public static void erase(Session session) throws Exception {
        assertEquals(0x9000, cmd(session, 0x24, 0, 0, new byte[0]).sw(), "ERASE");
        life = Life.BLANK;
    }

    public static void assertSw(int expected, Response r, String what) {
        assertEquals(expected, r.sw(), what + " — inner SW " + String.format("%04X", r.sw()));
    }
}
