// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Transfer;
import org.qntx.card.sim.Agent;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.tests.EmuMember;
import org.qntx.card.tests.Vecs;

/**
 * The review's two single-point mutants as persistent instruction-site faults ({@code nth = 0}):
 * {@link #SETW} skips the {@code setW} invoke inside {@code Transfer.setPeer} on every call (the
 * review's patched-out write), {@link #CMP} inverts the compare branch that guards it. For each
 * mutant the F-01 export and F-02 import attacks must still be refused and the legitimate
 * export/import flow must not complete — the mutant is killed by the second evaluation. Skipped
 * when the agent runs without the {@code sites} weave.
 */
final class ReviewMutantTest {
    // Transfer.setPeer's bytecode: peer[slot].getW (i1), Bytes.equal (i2),
    // peer[slot].setW (i3); the equal != CHECK_OK compare is b1
    private static final String SETW = "Transfer.setPeer#i3";
    private static final String CMP = "Transfer.setPeer#b1";

    private static final int INS_OFFER = 0x40;
    private static final int INS_EXPORT = 0x41;
    private static final int INS_IMPORT = 0x42;
    private static final int INS_VERIFY = 0x22;
    private static final int INS_CREATE = 0x21;
    private static final byte[] EMPTY = new byte[0];

    @BeforeEach
    void needsSites() {
        assumeTrue(Agent.siteWeaving(), "instruction-site weaving is not enabled");
    }

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    @Test
    void q01SkippedSetWIsKilled() throws Exception {
        mutant(SETW, Fault.SITE_SKIP);
    }

    @Test
    void q02InvertedCompareIsKilled() throws Exception {
        mutant(CMP, Fault.SITE_INVERT);
    }

    /** Both review attacks stay refused under the mutant; the legitimate flow fails first. */
    private static void mutant(String site, int mode) throws Exception {
        // sanity: both fault targets really are sites on the export path of an
        // unfaulted run — a key that does not exist means the bytecode changed
        Object[] f = loaded();
        Card probe = (Card) f[0];
        Session ps = (Session) f[1];
        EmuMember pm = (EmuMember) f[2];
        Fault.countCalls();
        try {
            Response probe0 = Vecs.roundtrip(probe, ps, INS_EXPORT, 0, 0, pm.exportRequest());
            Map<String, Integer> sites = Fault.siteCounts();
            assertEquals(0x9000, probe0.sw(), "probe export");
            assertTrue(sites.containsKey(SETW), "setW site: " + sites.keySet());
            assertTrue(sites.containsKey(CMP), "compare site: " + sites.keySet());
        } finally {
            Fault.reset();
        }

        // the cards are built BEFORE arming: new Card() resets the fault slots
        Object[] x = loaded();
        Card cardX = (Card) x[0];
        Session xs = (Session) x[1];
        EmuMember m = (EmuMember) x[2];
        EmuMember s1 = new EmuMember();
        EmuMember s2 = new EmuMember();
        Object[] y1 = blankImport(s1, true);
        Object[] y2 = blankImport(s2, false);

        Fault.armSite(site, 0, mode);

        // F-01: cert_M, attacker LK, sig_T under private key 1 — the skipped write
        // leaves PEER_INIT, a NUMS point whose discrete log is unknown: no signature
        // verifies under it, so the first evaluation refuses with 6A80
        byte[] lk = Crypto.publicKey(BigInteger.valueOf(0x5EED));
        byte[] sigT = Crypto.sign(BigInteger.ONE, Crypto.sha256(Transfer.LABEL_OFFER, lk));
        Response r = Vecs.roundtrip(cardX, xs, INS_EXPORT, 0, 0, cat(m.cert, lk, sigT));
        assertEquals(0x6A80, r.sw(), "F-01 under the mutant");

        // F-02: BLANK card, real cert_S, attacker E, sig_S under private key 1 — same
        Response ri =
                Vecs.roundtrip((Card) y1[0], (Session) y1[1], INS_IMPORT, 0, 0, (byte[]) y1[2]);
        assertEquals(0x6A80, ri.sw(), "F-02 under the mutant");

        // the legitimate export: the skipped write leaves PEER_INIT, under which the
        // genuine sig_T fails the first verification (6A80) — the mutant is killed
        Response ok = Vecs.roundtrip(cardX, xs, INS_EXPORT, 0, 0, m.exportRequest());
        assertEquals(0x6A80, ok.sw(), "legitimate export under the mutant");

        // the legitimate import on a BLANK card: same skipped write, same first-eval
        // failure
        Response rz =
                Vecs.roundtrip((Card) y2[0], (Session) y2[1], INS_IMPORT, 0, 0, (byte[]) y2[2]);
        assertEquals(0x6A80, rz.sw(), "legitimate import under the mutant");
    }

    /** A LOADED verified card with one member: {card, session, member}. */
    private static Object[] loaded() throws Exception {
        EmuMember m = new EmuMember();
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        Vecs.blankFor(card, a);
        Session session = Vecs.open(card);
        assertEquals(
                0x9000,
                Vecs.roundtrip(
                                card,
                                session,
                                INS_CREATE,
                                1,
                                0,
                                cat(Vecs.accessHash(), Vecs.seed(), m.cardId))
                        .sw(),
                "CREATE");
        assertEquals(
                0x9000,
                Vecs.roundtrip(card, session, INS_VERIFY, 0, 0, Vecs.accessHash()).sw(),
                "VERIFY");
        return new Object[] {card, session, m};
    }

    /**
     * A BLANK card that has already made its OFFER: {card, session, import0 data}. {@code attack}
     * sends a private-key-1 sig_S over an attacker E; otherwise the sender's genuine import head.
     */
    private static Object[] blankImport(EmuMember s, boolean attack) throws Exception {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        Vecs.blankFor(card, a);
        Session session = Vecs.open(card);
        Response offer = Vecs.roundtrip(card, session, INS_OFFER, 0, 0, EMPTY);
        assertEquals(0x9000, offer.sw(), "OFFER");
        byte[] lkT = Arrays.copyOf(offer.data(), 65);
        byte[] head;
        if (attack) {
            BigInteger e = BigInteger.valueOf(0xE11E);
            byte[] ep = Crypto.publicKey(e);
            byte[] m = EmuMember.transcript(s.a, a, lkT, ep);
            head = cat(s.cert, ep, Crypto.sign(BigInteger.ONE, Crypto.sha256(m)));
        } else {
            head = s.importHead(a, lkT)[0];
        }
        return new Object[] {card, session, head};
    }

    private static byte[] cat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }
}
