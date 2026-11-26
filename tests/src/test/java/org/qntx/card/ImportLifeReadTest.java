// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.util.Arrays;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Transfer;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.tests.EmuMember;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The fresh life reads of §16.2 item 4 (A6): {@code import0}'s membership recompute and {@code
 * import1}'s T-INSTALL guard read {@code state.life()} again instead of re-testing the local the
 * first evaluation read — so one forced read of {@code LIFE_BLANK} cannot skip a check in both
 * evaluations.
 */
final class ImportLifeReadTest {
    private static final int INS_STATUS = 0x20;
    private static final int INS_CREATE = 0x21;
    private static final int INS_VERIFY = 0x22;
    private static final int INS_OFFER = 0x40;
    private static final int INS_IMPORT = 0x42;

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    /** A LOADED card with members {card, member}, an open (unverified) session returned too. */
    private static Object[] loaded(EmuMember member) throws Exception {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        Vecs.blankFor(card, a);
        Session session = Vecs.open(card);
        byte[] create = new byte[96 + 16];
        System.arraycopy(Vecs.accessHash(), 0, create, 0, 32);
        System.arraycopy(Vecs.seed(), 0, create, 32, 64);
        System.arraycopy(member.cardId, 0, create, 96, 16);
        assertEquals(
                0x9000, Vecs.roundtrip(card, session, INS_CREATE, 1, 0, create).sw(), "CREATE");
        return new Object[] {card, session, a};
    }

    /** OFFER + genuine {@code IMPORT P1=00} of {@code source}; returns {@code {data, e}}. */
    private static byte[][] beginImport(Card card, Session session, byte[] a, EmuMember source)
            throws Exception {
        Response offer = Vecs.roundtrip(card, session, INS_OFFER, 0, 0, new byte[0]);
        assertEquals(0x9000, offer.sw(), "OFFER");
        byte[] lk = Arrays.copyOf(offer.data(), 65);
        byte[][] head = source.importHead(a, lk);
        assertEquals(
                0x9000,
                Vecs.roundtrip(card, session, INS_IMPORT, 0, 0, head[0]).sw(),
                "IMPORT P1=00");
        return new byte[][] {lk, head[1], Arrays.copyOfRange(head[0], 97, 162)};
    }

    /** The {@code State.life} calls of one passing {@code IMPORT} command. */
    private static int lifeCalls(Card card, Session session, int p1, byte[] data) throws Exception {
        try {
            Fault.countCalls();
            Response r = Vecs.roundtrip(card, session, INS_IMPORT, p1, 0, data);
            System.out.println("measure P1=" + p1 + " sw=" + Integer.toHexString(r.sw()));
            return Fault.calls("State.life");
        } finally {
            Fault.reset();
        }
    }

    /**
     * A LOADED target and a genuine, CA-certified sender who is not a member: forcing {@code
     * import0}'s first life read to {@code BLANK} skips the member check once — the second
     * evaluation's fresh read still runs it and refuses before the peer slot is written.
     */
    @Test
    void import0FreshLifeReadCatchesForcedBlank() throws Exception {
        EmuMember member = new EmuMember();
        EmuMember stranger = new EmuMember(); // a genuine cert, but not a member
        // measure on a member's genuine head so the second evaluation's fresh read runs
        Object[] f0 = loaded(member);
        Card m0 = (Card) f0[0];
        Session s0 = (Session) f0[1];
        Response o0 = Vecs.roundtrip(m0, s0, INS_OFFER, 0, 0, new byte[0]);
        assertEquals(0x9000, o0.sw(), "measure OFFER");
        byte[][] h0 = member.importHead((byte[]) f0[2], Arrays.copyOf(o0.data(), 65));
        int lives = lifeCalls(m0, s0, 0, h0[0]);
        assertEquals(3, lives, "State.life calls per IMPORT P1=00");

        Object[] f = loaded(member);
        Card card = (Card) f[0];
        Session session = (Session) f[1];
        byte[] a = (byte[]) f[2];
        byte[] before0 = Internals.peerW(card.applet(Spec.WALLET_AID), 0);
        byte[] before1 = Internals.peerW(card.applet(Spec.WALLET_AID), 1);
        Response offer = Vecs.roundtrip(card, session, INS_OFFER, 0, 0, new byte[0]);
        assertEquals(0x9000, offer.sw(), "OFFER");
        byte[][] head = stranger.importHead(a, Arrays.copyOf(offer.data(), 65));
        Response r;
        try {
            // the second State.life of the command is import0's local read — forced
            // BLANK, it skips the member check; the fresh read below still runs it
            Fault.arm("State.life", 2, Const.LIFE_BLANK);
            r = Vecs.roundtrip(card, session, INS_IMPORT, 0, 0, head[0]);
        } finally {
            Fault.reset();
        }
        assertEquals(
                0x6A80,
                r.sw(),
                () ->
                        "IMPORT P1=00 with a forced BLANK first read: "
                                + Integer.toHexString(r.sw()));
        assertArrayEquals(
                before0, Internals.peerW(card.applet(Spec.WALLET_AID), 0), "slot 0 was written");
        assertArrayEquals(
                before1, Internals.peerW(card.applet(Spec.WALLET_AID), 1), "slot 1 was written");
        // and no pending import: P1=01 is refused whatever follows
        Response r1 = Vecs.roundtrip(card, session, INS_IMPORT, 1, 0, new byte[160]);
        assertEquals(0x6985, r1.sw(), "IMPORT P1=01 without a pending import");
    }

    /**
     * Forcing {@code import1}'s local {@code life} to {@code BLANK} skips the re-seal block once;
     * the T-INSTALL guard's fresh read still enters and its equality checks refuse a payload sealed
     * for a different wallet — the stored wallet is unchanged.
     */
    @Test
    void import1FreshLifeReadCatchesForcedBlank() throws Exception {
        EmuMember source = new EmuMember();
        EmuMember extra = new EmuMember();
        // measure with a record sealed for the stored wallet so the T-INSTALL
        // guard's fresh read runs (c = 2, the members of the CREATE)
        Object[] f0 = loaded(source);
        Card m0 = (Card) f0[0];
        Session s0 = (Session) f0[1];
        byte[] a0 = (byte[]) f0[2];
        byte[][] i0 = beginImport(m0, s0, a0, source);
        byte[] z0 = EmuMember.ecdhX(new BigInteger(1, i0[1]), i0[0]);
        byte[] msg0 = EmuMember.transcript(source.a, a0, i0[0], i0[2]);
        // the stored members block is c ‖ ID(A) ‖ others — own ID first; CREATE
        // P1=01 stores ORIGIN_IMPORTED, so the matching payload's origin is 0x02
        byte[] rec0 =
                EmuMember.sealRecord(
                        z0,
                        msg0,
                        EmuMember.payload(
                                0x02,
                                Vecs.seed(),
                                Vecs.accessHash(),
                                Ids.cardId(a0),
                                source.cardId));
        int lives = lifeCalls(m0, s0, 1, Transfer.import1(rec0));
        // dispatch(1) + import1 local + T-INSTALL guard + Wallet.install's own double read
        assertEquals(5, lives, "State.life calls per IMPORT P1=01");

        Object[] f = loaded(source);
        Card card = (Card) f[0];
        Session session = (Session) f[1];
        byte[] a = (byte[]) f[2];
        byte[][] i1 = beginImport(card, session, a, source);
        byte[] z = EmuMember.ecdhX(new BigInteger(1, i1[1]), i1[0]);
        byte[] msg = EmuMember.transcript(source.a, a, i1[0], i1[2]);
        // a record under this import's keys but for a DIFFERENT wallet: c = 3 adds a
        // member the stored wallet does not have — reseal would refuse it
        byte[] record =
                EmuMember.sealRecord(
                        z,
                        msg,
                        EmuMember.payload(
                                0x02,
                                Vecs.seed(),
                                Vecs.accessHash(),
                                Ids.cardId(a),
                                source.cardId,
                                extra.cardId));
        Response r;
        try {
            // the second State.life of the command is import1's local — forced BLANK,
            // it skips the re-seal block; the T-INSTALL guard still runs its checks
            Fault.arm("State.life", 2, Const.LIFE_BLANK);
            r = Vecs.roundtrip(card, session, INS_IMPORT, 1, 0, Transfer.import1(record));
        } finally {
            Fault.reset();
        }
        assertEquals(
                0x6F00,
                r.sw(),
                () -> "IMPORT P1=01 with a forced BLANK local: " + Integer.toHexString(r.sw()));
        // the wallet is unchanged: a fresh session reports LOADED and verifies
        Session again = Vecs.open(card);
        Response status = Vecs.roundtrip(card, again, INS_STATUS, 0, 0, new byte[0]);
        assertArrayEquals(new byte[] {0x02, 0x0A}, status.data(), "wallet changed");
        Response verify = Vecs.roundtrip(card, again, INS_VERIFY, 0, 0, Vecs.accessHash());
        assertEquals(0x9000, verify.sw(), "VERIFY after the refused import");
    }
}
