// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    private static RealCard card;
    private static CapKind installed;
    private static Life life;
    private static byte[] cardA;
    private static byte[] cert;

    private Fixture() {}

    /** True when {@code -PrealCard=<reader>} was given. */
    public static boolean available() {
        return !System.getProperty("qntx.reader", "").isEmpty();
    }

    /** The R4 assumption — call first in every test. */
    public static void require() {
        Assumptions.assumeTrue(available(), SKIP);
    }

    public static RealCard card() {
        return card;
    }

    public static Path capPath(CapKind kind) {
        String prop =
                switch (kind) {
                    case PROD -> walletProp();
                    case MEM -> "qntx.memcap";
                    case PROBE -> "qntx.probecap";
                };
        return Path.of(System.getProperty(prop));
    }

    /**
     * {@code -PrealCardWallet=lazy} substitutes the deferred-construction test build for the wallet
     * CAP the suites exercise; {@code InstallRealCardTest} still uses the real one.
     */
    private static String walletProp() {
        return "lazy".equals(System.getProperty("qntx.wallet", "production"))
                ? "qntx.lazycap"
                : "qntx.cap";
    }

    /** The unmodified production CAP — never affected by {@code -PrealCardWallet}. */
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
        if (installFailed == kind) {
            throw new IllegalStateException("CAP " + kind + " already failed to install");
        }
        try {
            doInstall(kind);
        } catch (Exception e) {
            installFailed = kind;
            throw e;
        }
    }

    private static void doInstall(CapKind kind) throws Exception {
        switch (kind) {
            case PROD, MEM ->
                    card.reinstall(
                            capPath(kind),
                            RealCard.PACKAGE_AID,
                            RealCard.PACKAGE_AID,
                            RealCard.APPLET_AID);
            case PROBE ->
                    card.reinstall(
                            capPath(kind),
                            RealCard.PROBE_PACKAGE_AID,
                            RealCard.PROBE_PACKAGE_AID,
                            RealCard.PROBE_APPLET_AID);
        }
        installed = kind;
        // a fresh wallet install always starts in FACTORY; the probe has no wallet state
        life = kind == CapKind.PROBE ? null : Life.FACTORY;
        // A is generated per instance: a cert issued for the previous install would be
        // refused with 6A80, so the cached identity must be refetched
        cardA = null;
        cert = null;
    }

    /** The CAP that should be on the card again before the suite ends (§14.3). */
    public static void restoreProd() throws Exception {
        ensureInstalled(CapKind.PROD);
        life = null;
        card.ok(RealCard.SELECT);
    }

    /** FACTORY: the production CAP installed and selected. */
    public static void ensureFactory() throws Exception {
        ensureInstalled(CapKind.PROD);
        if (life != Life.FACTORY && life != Life.BLANK && life != Life.LOADED) {
            // unknown state (e.g. after the probe CAP): a reinstall is the only guaranteed
            // FACTORY and the install budget allows it
            card.reinstall(
                    capPath(CapKind.PROD),
                    RealCard.PACKAGE_AID,
                    RealCard.PACKAGE_AID,
                    RealCard.APPLET_AID);
            life = Life.FACTORY;
        }
        card.ok(RealCard.SELECT);
    }

    /**
     * True FACTORY for tests that cannot run in a later life state (a BLANK/LOADED card has no way
     * back): reinstalls the selected wallet CAP unless the card is already known FACTORY.
     */
    public static void ensureStrictFactory() throws Exception {
        if (life != Life.FACTORY) {
            connect();
            card.reinstall(
                    capPath(CapKind.PROD),
                    RealCard.PACKAGE_AID,
                    RealCard.PACKAGE_AID,
                    RealCard.APPLET_AID);
            markInstalled(CapKind.PROD);
        }
        card.ok(RealCard.SELECT);
    }

    /** A PERSONALIZE payload: {@code cert(97) ‖ caPublic(65)} for the card's own A (§5.2). */
    public static byte[] personalizeApdu() {
        identity();
        byte[] apdu = new byte[5 + 162];
        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0xE2;
        apdu[4] = (byte) 162;
        System.arraycopy(cert, 0, apdu, 5, 97);
        System.arraycopy(Vecs.caPublic(), 0, apdu, 102, 65);
        return apdu;
    }

    /** The card's A and its ca1 certificate, fetched via GET_IDENTITY (FACTORY only). */
    public static byte[] identity() {
        if (cert == null) {
            byte[] data = card.ok(new byte[] {(byte) 0x80, (byte) 0xE0, 0, 0, 0});
            cardA = Arrays.copyOf(data, 33);
            cert = Certificates.issue(Vecs.caPrivate(), cardA);
        }
        return cert;
    }

    public static byte[] cardA() {
        identity();
        return cardA;
    }

    /** BLANK: FACTORY + PERSONALIZE under ca1 (§7). */
    public static void ensureBlank() throws Exception {
        ensureFactory();
        if (life == Life.FACTORY) {
            card.ok(personalizeApdu());
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
     * LOADED with the imported test seed (§9.4 P1 = 1). Reuses an already-loaded test wallet —
     * VERIFY + the master public key proves it — instead of spending an ERASE + CREATE.
     */
    public static void ensureLoaded() throws Exception {
        ensureBlank();
        if (life == Life.LOADED) {
            Session s = open();
            if (cmd(s, 0x22, 0, 0, Vecs.accessHash()).sw() == 0x9000) {
                Response r = cmd(s, 0x30, 0, 0, new byte[] {0});
                if (r.sw() == 0x9000
                        && Arrays.equals(Arrays.copyOf(r.data(), 33), Vecs.seedMasterPublicKey())) {
                    s.close();
                    return;
                }
            }
            s.close();
            // a foreign wallet: erase under a verified session, then re-create
            Session e = open();
            if (cmd(e, 0x22, 0, 0, Vecs.accessHash()).sw() == 0x9000) {
                assertEquals(0x9000, cmd(e, 0x24, 0, 0, new byte[0]).sw(), "ERASE");
                life = Life.BLANK;
            } else {
                throw new IllegalStateException("card holds a wallet we cannot erase — stopping");
            }
        }
        assertTrue(life == Life.BLANK);
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
