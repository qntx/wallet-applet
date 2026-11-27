// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import javacard.framework.Applet;
import javacard.framework.Util;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Transfer;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.sim.Rng;
import org.qntx.card.tests.EmuMember;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The single-fault sweep of spec section 9 / architecture §6: for each attack scenario the
 * unfaulted run is counted — every branch/invoke/data/store/arithmetic site the agent's {@code
 * sites} weave executed, every woven call and every wrapped ECDSA verify — and the attack is then
 * re-run once per (site, occurrence, mode) on a fresh card under a watchdog of 50 times the
 * counting run's hits. Modes: branches TAKE/FALL; invokes SKIP and, for {@code short/byte/boolean}
 * results, FORCED to every coded value; data ZERO/ONES/FLIP; stores SKIP; arithmetic keeps the left
 * operand; woven calls forced; verifies forced true. Branch and invoke sites are swept at every
 * occurrence; data/store/arithmetic sites with more than 8 occurrences are sampled at {1, 2, 3,
 * last} plus 4 evenly spaced (the row's {@code sampled} flag). The test fails when any run is
 * RELEASED; DEVIATED (the effect's keys differ from correct but are outside the public candidate
 * set), ERROR and HANG are reported but not failures. One {@code <scenario>.csv} per scenario lands
 * in {@code <reports>/gate-sweep/}.
 */
final class GateSweepTest {
    static final int INS_STATUS = 0x20;
    private static final int INS_CREATE = 0x21;
    static final int INS_VERIFY = 0x22;
    static final int INS_CHANGE = 0x23;
    static final int INS_ERASE = 0x24;
    private static final int INS_WAIT = 0x25;
    static final int INS_PUBLIC_KEY = 0x30;
    static final int INS_SIGN_ECDSA = 0x31;
    static final int INS_SIGN_BIP340 = 0x32;
    static final int INS_SIGN_ED25519 = 0x33;
    private static final int INS_OFFER = 0x40;
    private static final int INS_EXPORT = 0x41;
    private static final int INS_IMPORT = 0x42;

    /**
     * The applet classes of the CAP: only their sites are swept — the agent also instruments the
     * {@code org.qntx.card} test classes, whose sites are counted but never a fault target.
     */
    private static final java.util.Set<String> APPLET =
            java.util.Set.of(
                    "Bip340",
                    "Bytes",
                    "Const",
                    "Derivation",
                    "Ecdsa",
                    "Ed25519",
                    "Identity",
                    "Kdf",
                    "Mem",
                    "ModArith",
                    "NdefApplet",
                    "Secp256k1",
                    "Session",
                    "State",
                    "Transfer",
                    "Wallet",
                    "WalletApplet",
                    "Wei25519");

    static final byte[] EMPTY = new byte[0];
    private static final byte[] PATH5 = {0x01, 0, 0, 0, 0};
    private static final byte[] RNG_BLOCK = new byte[256];
    private static final byte[] ATTACKER_SEED =
            Crypto.sha512("qntx-sweep/attacker seed".getBytes());
    private static final byte[] ATTACKER_ACCESS =
            Crypto.sha256("qntx-sweep/attacker code".getBytes());
    // the second SX variant signs with this arbitrary known scalar instead of 1
    static final BigInteger KNOWN_K = new BigInteger("5192296858534827628530496329220097");

    /**
     * Every coded result a woven short call is forced to, plus plain 0 and 1. The shadow codewords
     * are literals so this file also compiles against the pre-fix Const of the before-worktree run
     * (§9 sweep).
     */
    private static final short[] FORCED = {
        Const.CHECK_OK,
        Const.VERIFIED_YES,
        (short) 0xA55A, // Const.VERIFIED_SHADOW
        Const.PENDING_EXPORT,
        (short) 0xC33C, // Const.PENDING_EXPORT_SHADOW
        Const.PENDING_IMPORT,
        Const.LIFE_BLANK,
        Const.LIFE_LOADED,
        Const.OFFER_VALID,
        (short) 0,
        (short) 1,
    };

    static {
        for (int i = 0; i < RNG_BLOCK.length; i++) {
            RNG_BLOCK[i] = (byte) (i * 31 + 7);
        }
    }

    @BeforeAll
    static void seedHostRandomness() {
        Vecs.RND.setSeed(new byte[] {55, 44, 33, 22, 11});
    }

    @AfterEach
    void disarm() {
        Fault.reset();
        Rng.reset();
    }

    static final int REFUSED = 0;
    static final int RELEASED = 1;
    static final int DEVIATED = 2;
    static final int ERROR = 3;
    static final int HANG = 4;
    static final String[] OUTCOME = {"REFUSED", "RELEASED", "DEVIATED", "ERROR", "HANG"};

    /**
     * One attack attempt on a fresh card: {@link #run} sends the APDUs, {@link #outcome} judges the
     * protected effect afterwards, {@link #sws} records every SW for the CSV.
     */
    abstract static class Run {
        final List<Integer> sws = new ArrayList<>();
        Throwable threw;

        abstract void run() throws Exception;

        int outcome() throws Exception {
            return released() ? RELEASED : REFUSED;
        }

        boolean released() throws Exception {
            return false;
        }

        final String swSequence() {
            StringBuilder out = new StringBuilder();
            for (int sw : sws) {
                if (out.length() > 0) {
                    out.append(';');
                }
                out.append(sw < 0 ? "EXC" : String.format("%04x", sw));
            }
            return out.toString();
        }
    }

    interface Factory {
        Run fresh() throws Exception;
    }

    record Attempt(int outcome, String sws) {}

    /** A wrapped command: the SW is recorded; a thrown host-side error records {@code EXC}. */
    private static int cmd(Run r, Card c, Session s, int ins, int p1, byte[] data) {
        try {
            Response res = Vecs.roundtrip(c, s, ins, p1, 0, data);
            r.sws.add(res.sw());
            return res.sw();
        } catch (Exception e) {
            r.sws.add(-1);
            return -1;
        }
    }

    private static Response lastCmd(Run r, Card c, Session s, int ins, int p1, byte[] data)
            throws Exception {
        Response res = Vecs.roundtrip(c, s, ins, p1, 0, data);
        r.sws.add(res.sw());
        return res;
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

    /**
     * A LOADED verified card, members {@code own ‖ members[0] ‖ …}, its open session and its
     * compressed A (GET_IDENTITY is FACTORY-only, read before personalize).
     */
    static Object[] loaded(EmuMember... members) throws Exception {
        Rng.fix(RNG_BLOCK);
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        Vecs.blankFor(card, a);
        Session session = Vecs.open(card);
        byte[] ids = new byte[16 * members.length];
        for (int i = 0; i < members.length; i++) {
            System.arraycopy(members[i].cardId, 0, ids, 16 * i, 16);
        }
        assertEquals(
                0x9000,
                Vecs.roundtrip(
                                card,
                                session,
                                INS_CREATE,
                                1,
                                0,
                                cat(Vecs.accessHash(), Vecs.seed(), ids))
                        .sw(),
                "CREATE");
        assertEquals(
                0x9000,
                Vecs.roundtrip(card, session, INS_VERIFY, 0, 0, Vecs.accessHash()).sw(),
                "VERIFY");
        return new Object[] {card, session, a};
    }

    private static byte[] state(Card card) {
        return Internals.stateArray(card.applet(Spec.WALLET_AID)).clone();
    }

    /** True when {@code record} unseals under {@code z ‖ m} to a payload holding {@code seed}. */
    private static boolean releasedSeed(byte[] z, byte[] m, byte[] record, byte[] seed) {
        byte[] payload = EmuMember.unsealRecord(z, m, record);
        return payload != null && Arrays.equals(seed, Arrays.copyOfRange(payload, 1, 65));
    }

    /** True when {@code ct ‖ tag} authenticates and decrypts under raw {@code kte ‖ ktm}. */
    private static boolean releasedUnder(byte[] kte, byte[] ktm, byte[] record, byte[] seed) {
        byte[] ct = Arrays.copyOf(record, record.length - 16);
        byte[] tag = Arrays.copyOfRange(record, record.length - 16, record.length);
        if (!Arrays.equals(Crypto.cmac(ktm, ct), tag)) {
            return false;
        }
        byte[] payload = Crypto.m2unpad(Crypto.aesCbc(kte, new byte[16], ct, false));
        return payload != null && Arrays.equals(seed, Arrays.copyOfRange(payload, 1, 65));
    }

    // ── scenario factories ───────────────────────────────────────────────────

    /** SX: EXPORT to an attacker whose {@code sig_T} is signed under {@code priv} (1 or k). */
    static Factory exportToAttacker(BigInteger priv) {
        return () -> {
            EmuMember m = new EmuMember();
            Object[] f = loaded(m);
            Card card = (Card) f[0];
            Session session = (Session) f[1];
            byte[] a = (byte[]) f[2];
            BigInteger l = BigInteger.valueOf(0x5EED);
            byte[] lk = Crypto.publicKey(l);
            byte[] sigT = Crypto.sign(priv, Crypto.sha256(Transfer.LABEL_OFFER, lk));
            byte[] export0 = cat(m.cert, lk, sigT);
            return new Run() {
                Response r0;
                Response r1;

                void run() throws Exception {
                    r0 = lastCmd(this, card, session, INS_EXPORT, 0, export0);
                    if (r0.sw() == 0x9000) {
                        r1 = lastCmd(this, card, session, INS_EXPORT, 1, ATTACKER_ACCESS);
                    }
                }

                @Override
                boolean released() {
                    if (r0 == null
                            || r1 == null
                            || r0.sw() != 0x9000
                            || r1.sw() != 0x9000
                            || r0.data().length < 65) {
                        return false;
                    }
                    byte[] e = Arrays.copyOf(r0.data(), 65);
                    byte[] z = EmuMember.ecdhX(l, e);
                    byte[] transcript = EmuMember.transcript(a, m.a, lk, e);
                    return releasedSeed(z, transcript, r1.data(), Vecs.seed());
                }
            };
        };
    }

    /** SXn/SXc: EXPORT to a non-member — genuine (ca1) or forged (ca2) certificate. */
    static Factory exportToNonMember(EmuMember attacker) {
        return () -> {
            EmuMember member = new EmuMember();
            Object[] f = loaded(member);
            Card card = (Card) f[0];
            Session session = (Session) f[1];
            byte[] a = (byte[]) f[2];
            byte[] offer = attacker.exportRequest(); // cert ‖ LK ‖ genuine sig_T
            return new Run() {
                Response r0;
                Response r1;

                void run() throws Exception {
                    r0 = lastCmd(this, card, session, INS_EXPORT, 0, offer);
                    if (r0.sw() == 0x9000) {
                        r1 = lastCmd(this, card, session, INS_EXPORT, 1, ATTACKER_ACCESS);
                    }
                }

                @Override
                boolean released() {
                    if (r0 == null
                            || r1 == null
                            || r0.sw() != 0x9000
                            || r1.sw() != 0x9000
                            || r0.data().length < 65) {
                        return false;
                    }
                    byte[] e = Arrays.copyOf(r0.data(), 65);
                    byte[] z = attacker.z(e);
                    byte[] m = EmuMember.transcript(a, attacker.a, attacker.lk(), e);
                    return releasedSeed(z, m, r1.data(), Vecs.seed());
                }
            };
        };
    }

    /** SP: EXPORT P1=01 in a verified session with no pending export. */
    static Factory exportNoPending() {
        return exportNoPending(() -> {});
    }

    /**
     * SP with a hook run between the successful P1=00 import and the refused P1=01 that ends it.
     * The predicate self-check arms {@code Session.endPending} skips there: an arm made before
     * {@code fresh()} is wiped by the {@code Card} constructor's {@code Fault.reset}, so a
     * setup-side fault has to be injected at this point.
     */
    static Factory exportNoPending(Runnable afterImport) {
        return () -> {
            EmuMember m = new EmuMember();
            Object[] f = loaded(m);
            Card card = (Card) f[0];
            Session session = (Session) f[1];
            byte[] a = (byte[]) f[2];
            // an attacker-controlled pending import that is then killed: its keys
            // are a guessable candidate for whatever K_te/K_tm may still hold
            Response offer = Vecs.roundtrip(card, session, INS_OFFER, 0, 0, EMPTY);
            assertEquals(0x9000, offer.sw(), "OFFER");
            byte[] lkT = Arrays.copyOf(offer.data(), 65);
            byte[][] head = m.importHead(a, lkT);
            byte[] e65 = Arrays.copyOfRange(head[0], 97, 162);
            byte[] z = EmuMember.ecdhX(new BigInteger(1, head[1]), lkT);
            byte[] mi = EmuMember.transcript(m.a, a, lkT, e65);
            assertEquals(
                    0x9000,
                    Vecs.roundtrip(card, session, INS_IMPORT, 0, 0, head[0]).sw(),
                    "IMPORT0");
            afterImport.run();
            // a refused P1=01 ends the pending import — the keys it leaves are the
            // candidate set: {zeros, the import keys the attacker knows}
            Vecs.roundtrip(card, session, INS_IMPORT, 1, 0, new byte[160]);
            byte[][] importKeys = EmuMember.transferKeys(z, mi);
            return new Run() {
                Response r;

                void run() throws Exception {
                    r = lastCmd(this, card, session, INS_EXPORT, 1, ATTACKER_ACCESS);
                }

                @Override
                boolean released() {
                    if (r == null || r.sw() != 0x9000 || r.data().length < 32) {
                        return false;
                    }
                    return releasedUnder(new byte[16], new byte[16], r.data(), Vecs.seed())
                            || releasedUnder(importKeys[0], importKeys[1], r.data(), Vecs.seed());
                }
            };
        };
    }

    /** SI: BLANK target, genuine cert_S, attacker E and sig_S under {@code priv}. */
    static Factory importAttackerSeed(BigInteger priv) {
        return () -> {
            Rng.fix(RNG_BLOCK);
            EmuMember source = new EmuMember();
            Card card = Vecs.factory();
            byte[] a = Vecs.cardA(card);
            Vecs.blankFor(card, a);
            Session session = Vecs.open(card);
            Response offer = Vecs.roundtrip(card, session, INS_OFFER, 0, 0, EMPTY);
            assertEquals(0x9000, offer.sw(), "OFFER");
            byte[] lkT = Arrays.copyOf(offer.data(), 65);
            BigInteger e = BigInteger.valueOf(0xE11E);
            byte[] ep = Crypto.publicKey(e);
            byte[] m = EmuMember.transcript(source.a, a, lkT, ep);
            byte[] sigS = Crypto.sign(priv, Crypto.sha256(m));
            byte[] z = EmuMember.ecdhX(e, lkT);
            byte[] payload =
                    EmuMember.payload(
                            0x02, ATTACKER_SEED, ATTACKER_ACCESS, Ids.cardId(a), source.cardId);
            byte[] record = EmuMember.sealRecord(z, m, payload);
            byte[] import0 = cat(source.cert, ep, sigS);
            return new Run() {
                void run() throws Exception {
                    cmd(this, card, session, INS_IMPORT, 0, import0);
                    cmd(this, card, session, INS_IMPORT, 1, record);
                }

                @Override
                boolean released() throws Exception {
                    Session s2 = Vecs.open(card);
                    Response st = Vecs.roundtrip(card, s2, INS_STATUS, 0, 0, EMPTY);
                    if (st.sw() != 0x9000 || st.data()[0] == 0x01) {
                        return false; // still BLANK
                    }
                    Response v = Vecs.roundtrip(card, s2, INS_VERIFY, 0, 0, ATTACKER_ACCESS);
                    // the attacker code must really verify — a skipped dispatch's bare
                    // 9000 leaves the session unverified and the probe refuses
                    return v.sw() == 0x9000 && verified(card, s2);
                }
            };
        };
    }

    /** SIr: LOADED target, genuine member sender whose record carries a different wallet. */
    static Factory importDifferentWallet() {
        return () -> {
            EmuMember s = new EmuMember();
            EmuMember extra = new EmuMember();
            Object[] f = loaded(s);
            Card card = (Card) f[0];
            Session session = (Session) f[1];
            byte[] a = (byte[]) f[2];
            Response offer = Vecs.roundtrip(card, session, INS_OFFER, 0, 0, EMPTY);
            assertEquals(0x9000, offer.sw(), "OFFER");
            byte[] lkT = Arrays.copyOf(offer.data(), 65);
            byte[][] head = s.importHead(a, lkT);
            byte[] e65 = Arrays.copyOfRange(head[0], 97, 162);
            byte[] z = EmuMember.ecdhX(new BigInteger(1, head[1]), lkT);
            byte[] mi = EmuMember.transcript(s.a, a, lkT, e65);
            // c = 3 members where the stored wallet has c = 2: a different wallet
            byte[] payload =
                    EmuMember.payload(
                            0x02,
                            Vecs.seed(),
                            Vecs.accessHash(),
                            Ids.cardId(a),
                            s.cardId,
                            extra.cardId);
            byte[] record = EmuMember.sealRecord(z, mi, payload);
            byte[] before = state(card);
            return new Run() {
                void run() throws Exception {
                    cmd(this, card, session, INS_IMPORT, 0, head[0]);
                    cmd(this, card, session, INS_IMPORT, 1, record);
                }

                @Override
                boolean released() {
                    return gatedChange(before, state(card)) == RELEASED;
                }
            };
        };
    }

    /** SIm: a genuine pending import whose ct ‖ tag is replaced by a zero-key record. */
    static Factory importZeroKeyRecord() {
        return () -> {
            EmuMember s = new EmuMember();
            Object[] f = loaded(s);
            Card card = (Card) f[0];
            Session session = (Session) f[1];
            byte[] a = (byte[]) f[2];
            Response offer = Vecs.roundtrip(card, session, INS_OFFER, 0, 0, EMPTY);
            assertEquals(0x9000, offer.sw(), "OFFER");
            byte[] lkT = Arrays.copyOf(offer.data(), 65);
            byte[][] head = s.importHead(a, lkT);
            // sealed under K_te ‖ K_tm = 0 — keys the attacker knows without a fault
            byte[] payload =
                    EmuMember.payload(
                            0x02, ATTACKER_SEED, ATTACKER_ACCESS, Ids.cardId(a), s.cardId);
            byte[] ct = Crypto.aesCbc(new byte[16], new byte[16], Crypto.m2pad(payload), true);
            byte[] record = cat(ct, Crypto.cmac(new byte[16], ct));
            byte[] before = state(card);
            return new Run() {
                void run() throws Exception {
                    cmd(this, card, session, INS_IMPORT, 0, head[0]);
                    cmd(this, card, session, INS_IMPORT, 1, record);
                }

                @Override
                boolean released() {
                    return gatedChange(before, state(card)) == RELEASED;
                }
            };
        };
    }

    /** SV: VERIFY of a wrong code at {@code fails}; the required waits are done first. */
    static Factory verifyWrong(int fails, int waits) {
        return () -> {
            Object[] f = loaded(new EmuMember());
            Card card = (Card) f[0];
            // the attack runs on a fresh unverified session: VERIFY is an unverified
            // command, and only a genuinely flipped verified word makes the probe pass
            Session session = Vecs.open(card);
            // the required waits are pre-state, not part of the attack: they only
            // accumulate the session's waited units the way an attacker who waits
            // legitimately would
            for (int i = 0; i < waits; i++) {
                assertEquals(
                        0x9000, Vecs.roundtrip(card, session, INS_WAIT, 0, 0, EMPTY).sw(), "WAIT");
            }
            if (fails > 0) {
                byte[] st = Internals.stateArray(card.applet(Spec.WALLET_AID));
                st[2] = (byte) (fails >>> 8);
                st[3] = (byte) fails;
                st[4] = (byte) (~fails >>> 8);
                st[5] = (byte) ~fails;
            }
            return new Run() {
                int sw;

                void run() throws Exception {
                    sw = cmd(this, card, session, INS_VERIFY, 0, Vecs.accessHashWrong());
                }

                @Override
                boolean released() {
                    // a 9000 from a skipped inner() verified nothing: only a genuinely
                    // verified session passes the gated probe
                    return sw == 0x9000 && verified(card, session);
                }
            };
        };
    }

    /**
     * SC/SE: CHANGE or ERASE in an opened but unverified session. A bare 9000 is not a release — a
     * skipped inner() dispatch returns 9000 without applying the effect; the release is the stored
     * ct/tag/wrap or life actually changing.
     */
    static Factory unverifiedEffect(int ins, byte[] data) {
        return () -> {
            Object[] f = loaded(new EmuMember());
            Card card = (Card) f[0];
            Session session = Vecs.open(card); // a fresh, unverified session
            byte[] before = state(card);
            return new Run() {
                void run() throws Exception {
                    cmd(this, card, session, ins, 0, data);
                }

                @Override
                boolean released() {
                    return gatedChange(before, state(card)) == RELEASED;
                }
            };
        };
    }

    /**
     * {@code RELEASED} when the persistent image differs outside the bookkeeping words an
     * unverified command may legitimately commit: {@code OFF_FAILS} (bytes 2–5, committed on every
     * refused verification) and {@code OFF_OFFER} (bytes 8–9, committed by OFFER, which §9.2 allows
     * in an unverified session — an INS-corrupting unwrap fault can dispatch either one).
     */
    private static int gatedChange(byte[] before, byte[] after) {
        for (int i = 0; i < before.length; i++) {
            if (before[i] != after[i] && (i < 2 || i > 5) && (i < 8 || i > 9)) {
                return RELEASED;
            }
        }
        return REFUSED;
    }

    /** SS: an unverified PUBLIC_KEY / SIGN_* command (+ ED25519 finish) — 9000 with data. */
    static Factory unverifiedSign(int[][] commands) {
        return () -> {
            Object[] f = loaded(new EmuMember());
            Card card = (Card) f[0];
            Session session = Vecs.open(card);
            return new Run() {
                boolean out;

                void run() throws Exception {
                    for (int[] c : commands) {
                        try {
                            Response r =
                                    Vecs.roundtrip(
                                            card, session, c[0], c[1], 0, dataFor(c[0], c[1]));
                            sws.add(r.sw());
                            // a release is the gated payload itself — at least a compressed
                            // public key — not the session record's framing bytes a faulted
                            // {@code inner} length could wrap under sw 9000
                            if (r.sw() == 0x9000 && r.data().length >= 33) {
                                out = true;
                            }
                        } catch (Exception e) {
                            sws.add(-1);
                        }
                    }
                }

                @Override
                boolean released() {
                    return out;
                }
            };
        };
    }

    /** True when {@code session} is verified: a gated PUBLIC_KEY returns data. */
    private static boolean verified(Card card, Session session) {
        try {
            Response r = Vecs.roundtrip(card, session, INS_PUBLIC_KEY, 0, 0, PATH5);
            return r.sw() == 0x9000 && r.data().length > 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] dataFor(int ins, int p1) {
        return switch (ins) {
            case INS_PUBLIC_KEY -> PATH5;
            case INS_SIGN_ECDSA -> cat(Vecs.message(), PATH5);
            case INS_SIGN_BIP340 -> cat(Vecs.message(), Vecs.tweakBip86(), PATH5);
            case INS_SIGN_ED25519 -> p1 == 2 ? new byte[] {9} : Vecs.pathEdSolana();
            default -> EMPTY;
        };
    }

    // ── the public candidate set (architecture §6) ──────────────────────────

    /** x-coordinate of the secp256k1 generator — a public point of every transcript. */
    private static final byte[] X_G = Arrays.copyOf(Crypto.publicKey(BigInteger.ONE), 32);

    /** Clones of the card's scratch arrays {@code P, W, H, N, sender}. */
    private static byte[][] scratch(Card card) {
        javacard.framework.Applet ap = card.applet(Spec.WALLET_AID);
        return new byte[][] {
            Internals.pBytes(ap).clone(),
            Internals.wBytes(ap).clone(),
            Internals.hBytes(ap).clone(),
            Internals.nBytes(ap).clone(),
            ((byte[]) Internals.memField(ap, "sender")).clone()
        };
    }

    private static int indexOf(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /**
     * The public candidate set of architecture §6: all-zero; every 32-byte window of the captured
     * scratch arrays that occurs in {@code blob} (the concatenated public values); the KDF grid
     * over {@code Zc ∈ {0³², x of every public point}} × {@code ctx ∈ {TH, 0³²}}; and the KDF with
     * {@code Z}, label or ctx omitted (the latter two only when {@code z} is host-known).
     */
    private static Map<String, byte[]> candidates(
            byte[][] scratch,
            byte[] th,
            byte[] aCard,
            byte[] aPeer,
            byte[] lk,
            byte[] e,
            byte[] zOrNull,
            byte[] blob) {
        Map<String, byte[]> out = new LinkedHashMap<>();
        out.put("zero", new byte[32]);
        String[] arrName = {"P", "W", "H", "N", "sender"};
        for (int a = 0; a < scratch.length; a++) {
            for (int i = 0; i + 32 <= scratch[a].length; i++) {
                byte[] w = Arrays.copyOfRange(scratch[a], i, i + 32);
                boolean zero = true;
                for (byte b : w) {
                    zero &= b == 0;
                }
                if (!zero && indexOf(blob, w) >= 0) {
                    out.putIfAbsent("win:" + arrName[a] + "@" + i, w);
                }
            }
        }
        byte[][] zs = {
            new byte[32],
            aCard != null && aCard.length == 33
                    ? Arrays.copyOf(Crypto.decompress(aCard), 32)
                    : null,
            aPeer != null && aPeer.length == 33
                    ? Arrays.copyOf(Crypto.decompress(aPeer), 32)
                    : null,
            lk != null && lk.length == 65 ? Arrays.copyOf(lk, 32) : null,
            e != null && e.length == 65 ? Arrays.copyOf(e, 32) : null,
            X_G
        };
        String[] zn = {"0", "xA", "xAT", "xLK", "xE", "xG"};
        byte[][] ctxs = {th, new byte[32]};
        String[] cn = {"TH", "0"};
        for (int zi = 0; zi < zs.length; zi++) {
            if (zs[zi] == null) {
                continue;
            }
            for (int ci = 0; ci < ctxs.length; ci++) {
                out.put(
                        "kdf:" + zn[zi] + ":" + cn[ci],
                        Crypto.kdf(zs[zi], EmuMember.LABEL_KDF_TRANSFER, ctxs[ci], 32));
            }
        }
        out.put("kdf:noZ", Crypto.kdf(new byte[0], EmuMember.LABEL_KDF_TRANSFER, th, 32));
        if (zOrNull != null) {
            out.put("kdf:noLabel", Crypto.kdf(zOrNull, new byte[0], th, 32));
            out.put(
                    "kdf:noCtx",
                    Crypto.kdf(zOrNull, EmuMember.LABEL_KDF_TRANSFER, new byte[0], 32));
        }
        return out;
    }

    /** Raw {@code kTe ‖ kTm} of the pending transfer, or {@code null} when none is staged. */
    private static byte[] memKeys(Card card, String f1, String f2) throws Exception {
        javacard.framework.Applet ap = card.applet(Spec.WALLET_AID);
        javacard.security.AESKey k1 = (javacard.security.AESKey) Internals.memField(ap, f1);
        javacard.security.AESKey k2 = (javacard.security.AESKey) Internals.memField(ap, f2);
        byte[] out = new byte[32];
        try {
            if (k1.getKey(out, (short) 0) != 16 || k2.getKey(out, (short) 16) != 16) {
                return null;
            }
        } catch (javacard.security.CryptoException e) {
            return null;
        }
        return out;
    }

    /**
     * The access-hash candidates of §6 (R-A): {@code 0³²}, {@code SHA-256(A)} of every involved
     * card, every 32-byte scratch window in the public blob.
     */
    private static List<byte[]> accessCandidates(byte[][] scratch, byte[] blob, byte[]... as) {
        List<byte[]> out = new ArrayList<>();
        out.add(new byte[32]);
        for (byte[] a : as) {
            if (a != null) {
                out.add(Crypto.sha256(a));
            }
        }
        for (byte[] arr : scratch) {
            for (int i = 0; i + 32 <= arr.length; i++) {
                byte[] w = Arrays.copyOfRange(arr, i, i + 32);
                if (indexOf(blob, w) >= 0) {
                    out.add(w);
                }
            }
        }
        return out;
    }

    /** True when {@code candidate} verifies against the stored wallet of {@code card}. */
    private static boolean verifies(Card card, byte[] candidate) throws Exception {
        Session s2 = Vecs.open(card);
        Response v = Vecs.roundtrip(card, s2, INS_VERIFY, 0, 0, candidate);
        return v.sw() == 0x9000 && verified(card, s2);
    }

    /**
     * SXe: a legitimate verified EXPORT to a genuine member. R-X: the record opens under a
     * public-candidate key; R-A/R-S on the payload: {@code accessHash_T} must be the sent one and
     * the seed the source seed — a public-but-wrong field is RELEASED, a non-public difference is
     * DEVIATED, as are {@code kTe ‖ kTm} outside both the correct and the candidate sets.
     */
    static Factory exportLegit() {
        return () -> {
            EmuMember m = new EmuMember();
            Object[] f = loaded(m);
            Card card = (Card) f[0];
            Session session = (Session) f[1];
            byte[] a = (byte[]) f[2];
            byte[] offer = m.exportRequest(); // cert ‖ LK ‖ genuine sig_T
            byte[] lk = Arrays.copyOfRange(offer, m.cert.length, m.cert.length + 65);
            return new Run() {
                Response r0;
                Response r1;
                byte[][] dump;
                byte[] actual;

                void run() throws Exception {
                    r0 = lastCmd(this, card, session, INS_EXPORT, 0, offer);
                    if (r0.sw() == 0x9000 && r0.data().length >= 65) {
                        // the scratch that a skipped keys write would leak, captured
                        // right before the record is sealed
                        dump = scratch(card);
                        actual = memKeys(card, "kTe", "kTm");
                    }
                    r1 = lastCmd(this, card, session, INS_EXPORT, 1, Vecs.accessHash());
                }

                @Override
                int outcome() {
                    if (r0 == null
                            || r1 == null
                            || r0.sw() != 0x9000
                            || r1.sw() != 0x9000
                            || r0.data().length < 65) {
                        return REFUSED;
                    }
                    try {
                        return outcome0();
                    } catch (Throwable t) {
                        return DEVIATED;
                    }
                }

                private int outcome0() {
                    byte[] e = Arrays.copyOf(r0.data(), 65);
                    byte[] m1 = EmuMember.transcript(a, m.a, lk, e);
                    byte[] th = Crypto.sha256(m1);
                    byte[] z = m.z(e);
                    byte[][] correct = EmuMember.transferKeys(z, m1);
                    byte[] blob =
                            cat(
                                    a,
                                    Crypto.sha256(a),
                                    m.a,
                                    m.cert,
                                    m.cardId,
                                    Ids.cardId(a),
                                    lk,
                                    e,
                                    th,
                                    X_G,
                                    offer);
                    for (byte[] c : candidates(dump, th, a, m.a, lk, e, null, blob).values()) {
                        if (releasedUnder(
                                Arrays.copyOf(c, 16),
                                Arrays.copyOfRange(c, 16, 32),
                                r1.data(),
                                Vecs.seed())) {
                            return RELEASED;
                        }
                    }
                    // row E8: the output E is s·G for a scalar the attacker can pick —
                    // correct keys hide it, so it is checked on its own
                    if (publicEphemeral(
                            e,
                            dump,
                            blob,
                            Crypto.sha256(Transfer.LABEL_OFFER, lk),
                            th,
                            Arrays.copyOfRange(Crypto.decompress(a), 1, 33),
                            Arrays.copyOfRange(Crypto.decompress(m.a), 1, 33),
                            Arrays.copyOfRange(lk, 1, 33),
                            Arrays.copyOfRange(e, 1, 33),
                            X_G)) {
                        return RELEASED;
                    }
                    byte[] payload = EmuMember.unsealRecord(z, m1, r1.data());
                    if (payload == null || payload.length < 97) {
                        return DEVIATED;
                    }
                    // R-A: the carried accessHash_T must be the sent one
                    byte[] sent = Vecs.accessHash();
                    byte[] carriedAccess = Arrays.copyOfRange(payload, 65, 97);
                    if (!Arrays.equals(sent, carriedAccess)) {
                        for (byte[] cand : accessCandidates(dump, blob, a, m.a)) {
                            if (Arrays.equals(cand, carriedAccess)) {
                                return RELEASED;
                            }
                        }
                        return DEVIATED;
                    }
                    // R-S: the carried seed must be the source seed
                    byte[] carriedSeed = Arrays.copyOfRange(payload, 1, 65);
                    if (!Arrays.equals(Vecs.seed(), carriedSeed)) {
                        boolean zero = true;
                        for (byte b : carriedSeed) {
                            zero &= b == 0;
                        }
                        return zero || indexOf(blob, carriedSeed) >= 0 ? RELEASED : DEVIATED;
                    }
                    return actual != null && !Arrays.equals(actual, cat(correct[0], correct[1]))
                            ? DEVIATED
                            : REFUSED;
                }
            };
        };
    }

    /**
     * SIe: a legitimate head from a genuine source into a BLANK target. R-I: when the pending
     * {@code kTe ‖ kTm} equal a public candidate, a forged record sealed under it installs the
     * attacker's wallet — RELEASED. Keys outside both sets are DEVIATED.
     */
    static Factory importLegit() {
        return () -> {
            EmuMember snd = new EmuMember();
            Rng.fix(RNG_BLOCK);
            Card card = Vecs.factory();
            byte[] a = Vecs.cardA(card);
            Vecs.blankFor(card, a);
            Session session = Vecs.open(card);
            Response offer = Vecs.roundtrip(card, session, INS_OFFER, 0, 0, EMPTY);
            assertEquals(0x9000, offer.sw(), "OFFER");
            byte[] lkT = Arrays.copyOf(offer.data(), 65);
            byte[][] head = snd.importHead(a, lkT);
            byte[] e65 = Arrays.copyOfRange(head[0], 97, 162);
            byte[] z = EmuMember.ecdhX(new BigInteger(1, head[1]), lkT);
            byte[] m = EmuMember.transcript(snd.a, a, lkT, e65);
            byte[] th = Crypto.sha256(m);
            return new Run() {
                Response r0;
                byte[][] dump;
                byte[] actual;
                Response forged;

                void run() throws Exception {
                    r0 = lastCmd(this, card, session, INS_IMPORT, 0, head[0]);
                    if (r0.sw() == 0x9000) {
                        dump = scratch(card);
                        actual = memKeys(card, "kTe", "kTm");
                        if (actual != null) {
                            byte[] blob =
                                    cat(
                                            a,
                                            Crypto.sha256(a),
                                            snd.a,
                                            snd.cert,
                                            snd.cardId,
                                            Ids.cardId(a),
                                            lkT,
                                            e65,
                                            th,
                                            X_G,
                                            head[0]);
                            for (byte[] c :
                                    candidates(dump, th, a, snd.a, lkT, e65, z, blob).values()) {
                                if (Arrays.equals(actual, c)) {
                                    // keys the attacker can compute: a forged record
                                    // sealed under them carries his wallet
                                    byte[] payload =
                                            EmuMember.payload(
                                                    0x02,
                                                    ATTACKER_SEED,
                                                    ATTACKER_ACCESS,
                                                    Ids.cardId(a),
                                                    snd.cardId);
                                    byte[] ct =
                                            Crypto.aesCbc(
                                                    Arrays.copyOf(c, 16),
                                                    new byte[16],
                                                    Crypto.m2pad(payload),
                                                    true);
                                    byte[] record =
                                            cat(ct, Crypto.cmac(Arrays.copyOfRange(c, 16, 32), ct));
                                    forged = lastCmd(this, card, session, INS_IMPORT, 1, record);
                                    break;
                                }
                            }
                        }
                    }
                }

                @Override
                int outcome() throws Exception {
                    if (r0 == null || r0.sw() != 0x9000 || actual == null) {
                        return REFUSED;
                    }
                    if (forged != null && forged.sw() == 0x9000) {
                        Session s2 = Vecs.open(card);
                        Response st = Vecs.roundtrip(card, s2, INS_STATUS, 0, 0, EMPTY);
                        if (st.sw() == 0x9000 && st.data()[0] != 0x01) {
                            Response v =
                                    Vecs.roundtrip(card, s2, INS_VERIFY, 0, 0, ATTACKER_ACCESS);
                            if (v.sw() == 0x9000 && verified(card, s2)) {
                                return RELEASED;
                            }
                        }
                        return REFUSED;
                    }
                    byte[][] correct = EmuMember.transferKeys(z, m);
                    return !Arrays.equals(actual, cat(correct[0], correct[1])) ? DEVIATED : REFUSED;
                }
            };
        };
    }

    /**
     * SIn: a legitimate full transfer into a BLANK target and a re-seal into a LOADED one. R-A: the
     * installed wallet verifies under a public access candidate other than the sent one; R-S: its
     * master public key is that of a public seed candidate other than the source seed.
     */
    static Factory installLegit() {
        return () -> {
            EmuMember s = new EmuMember();
            // sub-run 0: a BLANK target installs the genuine record
            Rng.fix(RNG_BLOCK);
            Card t1 = Vecs.factory();
            byte[] a1 = Vecs.cardA(t1);
            Vecs.blankFor(t1, a1);
            // sub-run 1: a LOADED member target re-seals the same wallet
            EmuMember extra = new EmuMember();
            Object[] f2 = loaded(s, extra);
            Card t2 = (Card) f2[0];
            byte[] a2 = (byte[]) f2[2];
            return new Run() {
                void run() throws Exception {
                    importWallet(t1, a1, s, Vecs.seed(), Vecs.accessHash(), s.cardId);
                    importWallet(t2, a2, s, Vecs.seed(), Vecs.accessHash(), s.cardId, extra.cardId);
                }

                @Override
                int outcome() throws Exception {
                    byte[][] as = {a1, a2};
                    int i = 0;
                    for (Card t : new Card[] {t1, t2}) {
                        if (!installed(t)) {
                            i++;
                            continue;
                        }
                        byte[] a = as[i++];
                        byte[] blob =
                                cat(
                                        a,
                                        Crypto.sha256(a),
                                        s.a,
                                        s.cert,
                                        s.cardId,
                                        extra.cardId,
                                        Ids.cardId(a),
                                        X_G);
                        byte[][] bound = new byte[1][];
                        byte[] keys =
                                accessBound(t, accessCandidates(scratch(t), blob, a, s.a), bound);
                        if (keys != null && !Arrays.equals(bound[0], Vecs.accessHash())) {
                            // R-A: the wallet is sealed under a public access hash that is
                            // not the one the host sent (SHA-256(A_T), 0³², a scratch window)
                            return RELEASED;
                        }
                        byte[] sentKeys = accessBound(t, List.of(Vecs.accessHash()), new byte[1][]);
                        if (sentKeys == null) {
                            return DEVIATED;
                        }
                        byte[] st = Internals.stateArray(t.applet(Spec.WALLET_AID));
                        byte[] seed =
                                unwrappedSeed(
                                        sentKeys,
                                        Arrays.copyOfRange(st, State.OFF_CT, State.OFF_TAG));
                        if (seed != null && !Arrays.equals(Vecs.seed(), seed)) {
                            // R-S: a public or zero seed — never the source seed
                            boolean zero = true;
                            for (byte b : seed) {
                                zero &= b == 0;
                            }
                            if (zero || indexOf(blob, seed) >= 0) {
                                return RELEASED;
                            }
                            return DEVIATED;
                        }
                    }
                    return REFUSED;
                }
            };
        };
    }

    /** The stored seal {@code ct ‖ tag ‖ wrapKey} — changes on every committed re-seal. */
    private static byte[] sealOf(Card card) throws Exception {
        Applet ap = card.applet(Spec.WALLET_AID);
        byte[] st = Internals.stateArray(ap);
        byte[] seal = Arrays.copyOfRange(st, State.OFF_CT, State.OFF_TAG + 16);
        byte[] wkey = new byte[16];
        Internals.wrapKey(ap).getKey(wkey, (short) 0);
        byte[] out = new byte[seal.length + 16];
        System.arraycopy(seal, 0, out, 0, seal.length);
        System.arraycopy(wkey, 0, out, seal.length, 16);
        return out;
    }

    /** True when {@code card} is LOADED (read offline from {@link State}, no session). */
    private static boolean installed(Card card) throws Exception {
        byte[] st = Internals.stateArray(card.applet(Spec.WALLET_AID));
        return Util.getShort(st, State.OFF_LIFE) != Const.LIFE_BLANK;
    }

    /**
     * Offline access binding (architecture §6): the stored {@code wrapKey} (reflection), {@code ct}
     * and {@code tag} let the host evaluate {@code KDF108(wrapKey, LABEL_WRAP, h*)} for every
     * access-hash candidate and check {@code CMAC(kMac, ct) == tag} — the same check the card's
     * {@code match()} does on VERIFY — without opening a session on a card that may be broken.
     * Returns the 32 derived key bytes ({@code kEnc ‖ kMac}) of the matching candidate, or {@code
     * null}. Writes the matching hash into {@code bound[0]}.
     */
    static byte[] accessBound(Card card, List<byte[]> cands, byte[][] bound) throws Exception {
        Applet ap = card.applet(Spec.WALLET_AID);
        byte[] st = Internals.stateArray(ap);
        byte[] ct = Arrays.copyOfRange(st, State.OFF_CT, State.OFF_TAG);
        byte[] tag = Arrays.copyOfRange(st, State.OFF_TAG, State.OFF_TAG + 16);
        javacard.security.AESKey wk = Internals.wrapKey(ap);
        byte[] wkey = new byte[16];
        wk.getKey(wkey, (short) 0);
        for (byte[] h : cands) {
            byte[] keys = Crypto.kdf108(wkey, Const.LABEL_WRAP, h);
            if (Arrays.equals(Crypto.cmac(Arrays.copyOfRange(keys, 16, 32), ct), tag)) {
                bound[0] = h;
                return keys;
            }
        }
        return null;
    }

    /**
     * The seed wrapped under {@code keys} ({@code kEnc ‖ kMac}), or {@code null} when malformed.
     */
    private static byte[] unwrappedSeed(byte[] keys, byte[] ct) {
        byte[] plain = Crypto.aesCbc(Arrays.copyOf(keys, 16), new byte[16], ct, false);
        return Crypto.m2unpad(plain);
    }

    /**
     * Runs the genuine two-step import of {@code seed ‖ access ‖ members} into {@code target} from
     * member {@code s}; returns the target's compressed A on success, else {@code null}.
     */
    private static byte[] importWallet(
            Card target, byte[] a, EmuMember s, byte[] seed, byte[] access, byte[]... members)
            throws Exception {
        Session session = Vecs.open(target);
        Response offer = Vecs.roundtrip(target, session, INS_OFFER, 0, 0, EMPTY);
        if (offer.sw() != 0x9000) {
            return null;
        }
        byte[] lkT = Arrays.copyOf(offer.data(), 65);
        byte[][] head = s.importHead(a, lkT);
        byte[] e65 = Arrays.copyOfRange(head[0], 97, 162);
        byte[] z = EmuMember.ecdhX(new BigInteger(1, head[1]), lkT);
        byte[] m = EmuMember.transcript(s.a, a, lkT, e65);
        byte[][] ids = new byte[members.length + 1][];
        ids[0] = Ids.cardId(a);
        System.arraycopy(members, 0, ids, 1, members.length);
        byte[] payload = EmuMember.payload(0x02, seed, access, ids);
        byte[] record = EmuMember.sealRecord(z, m, payload);
        if (Vecs.roundtrip(target, session, INS_IMPORT, 0, 0, head[0]).sw() != 0x9000) {
            return null;
        }
        if (Vecs.roundtrip(target, session, INS_IMPORT, 1, 0, record).sw() != 0x9000) {
            return null;
        }
        return a;
    }

    /**
     * SCr: CREATE P1=00 on a fresh BLANK card, twice under two RNG blocks. R-C: identical stored
     * seeds, the zero-t candidate, or a seed whose t is the pre-draw scratch content the host saw
     * (a skipped {@code nextBytes} leaves stale scratch).
     */
    static Factory createGenerate() {
        return () -> {
            // the two cards are made in fresh(): an arm happens between fresh() and run()
            // and a Card constructor would wipe it
            Card[] cards = new Card[2];
            Session[] sessions = new Session[2];
            for (int i = 0; i < 2; i++) {
                byte[] rng = new byte[256];
                for (int k = 0; k < rng.length; k++) {
                    rng[k] = (byte) (i * 97 + k * 31 + 7);
                }
                Rng.fix(rng);
                cards[i] = Vecs.factory();
                Vecs.blankFor(cards[i], Vecs.cardA(cards[i]));
                sessions[i] = Vecs.open(cards[i]);
            }
            return new Run() {
                final byte[][] seeds = new byte[2][];
                final byte[][] tLeft = new byte[2][];

                void run() throws Exception {
                    for (int i = 0; i < 2; i++) {
                        byte[] rng = new byte[256];
                        for (int k = 0; k < rng.length; k++) {
                            rng[k] = (byte) (i * 97 + k * 31 + 7);
                        }
                        Rng.fix(rng);
                        // W_T's pre-draw content: what a skipped nextBytes would leave
                        tLeft[i] =
                                Arrays.copyOfRange(
                                        Internals.wBytes(cards[i].applet(Spec.WALLET_AID)), 32, 64);
                        byte[] data = cat(Vecs.accessHash(), Vecs.entropy());
                        int sw = cmd(this, cards[i], sessions[i], INS_CREATE, 0, data);
                        if (sw == 0x9000) {
                            seeds[i] =
                                    Internals.seedBytes(cards[i].applet(Spec.WALLET_AID)).clone();
                        }
                    }
                }

                @Override
                int outcome() {
                    if (seeds[0] == null || seeds[1] == null) {
                        return REFUSED;
                    }
                    if (Arrays.equals(seeds[0], seeds[1])) {
                        return RELEASED;
                    }
                    byte[] zeroT =
                            Crypto.sha512(
                                    cat(
                                            "qntx-card/v1/seed".getBytes(),
                                            new byte[32],
                                            Vecs.entropy()));
                    if (Arrays.equals(seeds[0], zeroT) || Arrays.equals(seeds[1], zeroT)) {
                        return RELEASED;
                    }
                    for (int i = 0; i < 2; i++) {
                        if (Arrays.equals(
                                seeds[i],
                                Crypto.sha512(
                                        cat(
                                                "qntx-card/v1/seed".getBytes(),
                                                tLeft[i],
                                                Vecs.entropy())))) {
                            return RELEASED;
                        }
                    }
                    return REFUSED;
                }
            };
        };
    }

    /**
     * SCi: CREATE P1=01 installs a host-sent seed. R-A: the wallet verifies under a public access
     * candidate other than the sent one; R-S: the master public key is a public seed candidate's.
     */
    static Factory createImport() {
        return () -> {
            EmuMember m = new EmuMember();
            Rng.fix(RNG_BLOCK);
            Card card = Vecs.factory();
            byte[] a = Vecs.cardA(card);
            Vecs.blankFor(card, a);
            Session session = Vecs.open(card);
            return new Run() {
                void run() throws Exception {
                    byte[] data = cat(Vecs.accessHash(), Vecs.seed(), m.cardId);
                    cmd(this, card, session, INS_CREATE, 1, data);
                }

                @Override
                int outcome() throws Exception {
                    if (!installed(card)) {
                        return REFUSED;
                    }
                    byte[][] dump = scratch(card);
                    byte[] blob = cat(a, Crypto.sha256(a), m.a, m.cert, m.cardId, X_G);
                    byte[][] bound = new byte[1][];
                    byte[] keys = accessBound(card, accessCandidates(dump, blob, a, m.a), bound);
                    if (keys != null && !Arrays.equals(bound[0], Vecs.accessHash())) {
                        return RELEASED;
                    }
                    byte[] sentKeys = accessBound(card, List.of(Vecs.accessHash()), new byte[1][]);
                    if (sentKeys == null) {
                        return DEVIATED;
                    }
                    byte[] st = Internals.stateArray(card.applet(Spec.WALLET_AID));
                    byte[] seed =
                            unwrappedSeed(
                                    sentKeys, Arrays.copyOfRange(st, State.OFF_CT, State.OFF_TAG));
                    if (seed == null) {
                        return DEVIATED;
                    }
                    if (Arrays.equals(Vecs.seed(), seed)) {
                        return REFUSED;
                    }
                    boolean zero = true;
                    for (byte b : seed) {
                        zero &= b == 0;
                    }
                    return zero || indexOf(blob, seed) >= 0 ? RELEASED : DEVIATED;
                }
            };
        };
    }

    /**
     * SCh: CHANGE in a verified session. R-A: afterwards the wallet verifies under a public access
     * candidate other than the new code the host sent.
     */
    static Factory changeCheck() {
        return () -> {
            EmuMember m = new EmuMember();
            Object[] f = loaded(m);
            Card card = (Card) f[0];
            Session session = (Session) f[1];
            byte[] a = (byte[]) f[2];
            return new Run() {
                int sw;
                byte[] sealBefore;

                void run() throws Exception {
                    sealBefore = sealOf(card);
                    sw = cmd(this, card, session, INS_CHANGE, 0, Vecs.accessHashNew());
                }

                @Override
                int outcome() throws Exception {
                    // only a committed change can bind the wallet to a wrong hash: a refused
                    // or silently dropped run (a skipped inner dispatch or T-CHANGE) leaves
                    // the old binding, which was legitimately the wallet's own
                    if (sw != 0x9000 || Arrays.equals(sealBefore, sealOf(card))) {
                        return REFUSED;
                    }
                    byte[][] dump = scratch(card);
                    byte[] blob = cat(a, Crypto.sha256(a), m.a, m.cert, m.cardId, X_G);
                    List<byte[]> cands = accessCandidates(dump, blob, a, m.a);
                    cands.add(Vecs.accessHash());
                    byte[][] bound = new byte[1][];
                    byte[] keys = accessBound(card, cands, bound);
                    if (keys != null && !Arrays.equals(bound[0], Vecs.accessHashNew())) {
                        return RELEASED;
                    }
                    return keys == null ? DEVIATED : REFUSED;
                }
            };
        };
    }

    /**
     * SO: OPEN with a fixed host ephemeral, twice on different RNG blocks. R-O: the derived host
     * keys equal — the card's ephemeral came out the same under a faulted draw — or the card
     * answers while its four session keys all sit in the public candidate set and its {@code kRm}
     * is the host's (the card's keys are publicly computable but consistent).
     */
    static Factory openTwice() {
        return openTwiceWith((i, k) -> (byte) (i * 97 + k * 31 + 7));
    }

    /**
     * {@link #openTwice} with the per-card RNG blocks drawn by {@code rand(i, k)} — the self-test
     * for the public-ephemeral clause drives the card's draw to a known scalar.
     */
    static Factory openTwiceWith(java.util.function.IntBinaryOperator rand) {
        return () -> {
            Card[] cards = new Card[2];
            for (int i = 0; i < 2; i++) {
                byte[] rng = new byte[256];
                for (int k = 0; k < rng.length; k++) {
                    rng[k] = (byte) rand.applyAsInt(i, k);
                }
                Rng.fix(rng);
                cards[i] = Vecs.factory();
                Vecs.blankFor(cards[i], Vecs.cardA(cards[i]));
            }
            return new Run() {
                final byte[][] keys = new byte[2][];
                final byte[][] resp = new byte[2][];
                final byte[][] hostEph = new byte[2][];
                final byte[][] cardEph = new byte[2][];
                final byte[][] as = new byte[2][];

                void run() throws Exception {
                    for (int i = 0; i < 2; i++) {
                        byte[] rng = new byte[256];
                        for (int k = 0; k < rng.length; k++) {
                            rng[k] = (byte) rand.applyAsInt(i, k);
                        }
                        Rng.fix(rng);
                        Vecs.RND.setSeed(new byte[] {7, 7, 7, 7});
                        org.qntx.card.host.Open.Request req =
                                org.qntx.card.host.Open.request(Vecs.RND);
                        byte[] rapdu = cards[i].transmit(req.apdu());
                        hostEph[i] = Arrays.copyOfRange(req.apdu(), 5, 70);
                        if (rapdu.length >= 67 && rapdu[rapdu.length - 2] == (byte) 0x90) {
                            cardEph[i] = Arrays.copyOf(rapdu, 65);
                            Session session = null;
                            try {
                                session =
                                        org.qntx.card.host.Open.response(
                                                req.secret(),
                                                req.apdu(),
                                                rapdu,
                                                List.of(Vecs.caPublic()));
                                keys[i] = sessionKeys(session);
                            } catch (Exception e) {
                                // a faulted OPEN whose response the host rejects
                            }
                            as[i] = Arrays.copyOfRange(rapdu, 129, 129 + 33);
                            // the card's session keys are transient AESKey objects the sim
                            // cannot getKey, and process() → wipeScratch clears Mem.P's
                            // read-back: probe K_re/K_rm functionally — a CREATE0 answered
                            // as a session record carries them in its ct and tag
                            if (session != null) {
                                byte[] data = new byte[64];
                                System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
                                System.arraycopy(Vecs.entropy(), 0, data, 32, 32);
                                resp[i] = cards[i].transmit(session.wrap(INS_CREATE, 0, 0, data));
                            }
                        }
                    }
                }

                @Override
                int outcome() {
                    if (keys[0] != null && keys[1] != null && Arrays.equals(keys[0], keys[1])) {
                        return RELEASED;
                    }
                    // the card's own response keys equal under two RNG blocks: one (kre,
                    // krm) pair that proves both answers — correct host pairs and the
                    // public candidates all count
                    List<byte[]>[] proven = new List[2];
                    for (int i = 0; i < 2; i++) {
                        proven[i] =
                                provenResponseKeys(
                                        resp[i], hostEph[i], cardEph[i], as[i], keys[0], keys[1]);
                    }
                    if (proven[0] != null && proven[1] != null) {
                        for (byte[] p : proven[0]) {
                            for (byte[] q : proven[1]) {
                                if (Arrays.equals(p, q)) {
                                    return RELEASED;
                                }
                            }
                        }
                    }
                    for (int i = 0; i < 2; i++) {
                        if (keys[i] == null || resp[i] == null) {
                            continue;
                        }
                        // R-O: the response tags under the host's K_rm while its ct opens
                        // under a public K_re candidate
                        if (!recordTag(resp[i], Arrays.copyOfRange(keys[i], 48, 64))) {
                            continue;
                        }
                        for (byte[] kre : sessionCandidates(hostEph[i], cardEph[i], as[i])) {
                            if (recordOpens(resp[i], kre)) {
                                return RELEASED;
                            }
                        }
                    }
                    for (int i = 0; i < 2; i++) {
                        if (cardEph[i] == null) {
                            continue;
                        }
                        // row E8: the card's ephemeral is s·G for a public scalar — the
                        // host's transcript hash and the public points are attacker-known
                        byte[] th =
                                Crypto.sha256(
                                        org.qntx.card.host.Open.LABEL_SESSION,
                                        hostEph[i],
                                        cardEph[i],
                                        as[i]);
                        byte[] blob = cat(hostEph[i], cardEph[i], as[i], th, X_G);
                        if (publicEphemeral(
                                cardEph[i],
                                null,
                                blob,
                                th,
                                Arrays.copyOfRange(hostEph[i], 1, 33),
                                Arrays.copyOfRange(cardEph[i], 1, 33),
                                as[i] != null && as[i].length == 33
                                        ? Arrays.copyOfRange(Crypto.decompress(as[i]), 1, 33)
                                        : null,
                                X_G)) {
                            return RELEASED;
                        }
                    }
                    return REFUSED;
                }
            };
        };
    }

    /**
     * The session-key candidates of §6 (R-O): {@code 0¹⁶} and every 16-byte block of {@code KDF(Zc,
     * "qntx-card/v1/kdf-session", ctx, 64)} for public {@code Zc} and {@code ctx ∈ {TH, 0³²}} — as
     * hex strings for set membership.
     */
    private static List<byte[]> sessionCandidates(byte[] hostEph, byte[] cardEph, byte[] a) {
        List<byte[]> out = new ArrayList<>();
        byte[] th = Crypto.sha256(org.qntx.card.host.Open.LABEL_SESSION, hostEph, cardEph, a);
        byte[][] zs = {
            new byte[32],
            Arrays.copyOf(hostEph, 32),
            Arrays.copyOf(cardEph, 32),
            a != null && a.length == 33 ? Arrays.copyOf(Crypto.decompress(a), 32) : null,
            X_G
        };
        byte[][] ctxs = {th, new byte[32], new byte[0]};
        out.add(new byte[16]);
        for (byte[] z : zs) {
            if (z == null) {
                continue;
            }
            for (byte[] ctx : ctxs) {
                byte[] keys = Crypto.kdf(z, org.qntx.card.host.Open.LABEL_SESSION, ctx, 64);
                for (int b = 0; b < 4; b++) {
                    out.add(Arrays.copyOfRange(keys, 16 * b, 16 * b + 16));
                }
            }
        }
        return out;
    }

    /**
     * The public-ephemeral check of §6 (row E8): {@code e65} equals {@code s·G} for a 32-byte
     * scalar {@code s} an attacker can pick — {@code 0x00…01}, every 32-byte window of {@code blob}
     * (the concatenated public values), every 32-byte scratch window that is public data (occurs in
     * {@code blob}), and {@code extras} (the offer hash, TH, x-coordinates of public points). A
     * public scalar hides under correct keys, so it is its own release clause. The {@code s·G}
     * table is memoized: the candidates repeat heavily across runs.
     */
    private static final Map<BigInteger, byte[]> SCALAR_POINTS = new HashMap<>();

    private static boolean publicEphemeral(
            byte[] e65, byte[][] scratch, byte[] blob, byte[]... extras) {
        Set<BigInteger> scalars = new LinkedHashSet<>();
        scalars.add(BigInteger.ONE);
        for (byte[] x : extras) {
            if (x != null && x.length == 32) {
                scalars.add(new BigInteger(1, x));
            }
        }
        for (int i = 0; i + 32 <= blob.length; i++) {
            scalars.add(new BigInteger(1, Arrays.copyOfRange(blob, i, i + 32)));
        }
        if (scratch != null) {
            for (byte[] arr : scratch) {
                if (arr == null) {
                    continue;
                }
                for (int i = 0; i + 32 <= arr.length; i++) {
                    byte[] w = Arrays.copyOfRange(arr, i, i + 32);
                    if (indexOf(blob, w) >= 0) {
                        scalars.add(new BigInteger(1, w));
                    }
                }
            }
        }
        for (BigInteger s : scalars) {
            if (s.signum() == 0) {
                continue;
            }
            byte[] p = SCALAR_POINTS.computeIfAbsent(s, Crypto::publicKey);
            if (Arrays.equals(p, e65)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether a session-record response tags under {@code krm} — {@code CMAC(krm, u16(ctr) ‖ ct)}
     * over the whole record body, tried for the first few record counters (§8.4).
     */
    private static boolean recordTag(byte[] rapdu, byte[] krm) {
        if (rapdu == null || rapdu.length < 26) {
            return false;
        }
        int bodyLen = rapdu.length - 2;
        byte[] ct = Arrays.copyOf(rapdu, bodyLen - 8);
        byte[] tag = Arrays.copyOfRange(rapdu, bodyLen - 8, bodyLen);
        for (int ctr = 0; ctr <= 2; ctr++) {
            byte[] expected = new byte[8];
            System.arraycopy(Crypto.cmac(krm, Crypto.u16(ctr), ct), 0, expected, 0, 8);
            if (Crypto.equalConstantTime(expected, tag)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether a session-record response decrypts to a valid {@code data ‖ 9000} plaintext under
     * {@code kre} (§8.4), tried for the first few record counters.
     */
    private static boolean recordOpens(byte[] rapdu, byte[] kre) {
        if (rapdu == null || rapdu.length < 26) {
            return false;
        }
        int bodyLen = rapdu.length - 2;
        byte[] ct = Arrays.copyOf(rapdu, bodyLen - 8);
        for (int ctr = 0; ctr <= 2; ctr++) {
            byte[] seed = new byte[16];
            seed[0] = 0x02;
            byte[] c = Crypto.u16(ctr);
            seed[14] = c[0];
            seed[15] = c[1];
            byte[] plain =
                    Crypto.m2unpad(Crypto.aesCbc(kre, Crypto.aesBlock(kre, seed), ct, false));
            if (plain != null
                    && plain.length >= 2
                    && ((plain[plain.length - 2] & 0xFF) << 8 | (plain[plain.length - 1] & 0xFF))
                            == 0x9000) {
                return true;
            }
        }
        return false;
    }

    /**
     * Every {@code kre ‖ krm} pair under which {@code resp} is a valid session record: the two
     * host-derived key blocks and the public {@link #sessionCandidates} grid.
     */
    private static List<byte[]> provenResponseKeys(
            byte[] resp, byte[] hostEph, byte[] cardEph, byte[] a, byte[] keys0, byte[] keys1) {
        if (resp == null) {
            return null;
        }
        List<byte[]> kres = sessionCandidates(hostEph, cardEph, a);
        List<byte[]> krms = new ArrayList<>(kres);
        for (byte[] k : new byte[][] {keys0, keys1}) {
            if (k != null) {
                kres.add(Arrays.copyOfRange(k, 32, 48));
                krms.add(Arrays.copyOfRange(k, 48, 64));
            }
        }
        List<byte[]> proven = new ArrayList<>();
        for (byte[] kre : kres) {
            if (!recordOpens(resp, kre)) {
                continue;
            }
            for (byte[] krm : krms) {
                if (!recordTag(resp, krm)) {
                    continue;
                }
                byte[] pair = new byte[32];
                System.arraycopy(kre, 0, pair, 0, 16);
                System.arraycopy(krm, 0, pair, 16, 16);
                proven.add(pair);
            }
        }
        return proven;
    }

    /** The host session's four derived keys {@code kCe ‖ kCm ‖ kRe ‖ kRm}. */
    private static byte[] sessionKeys(Session session) {
        try {
            byte[] out = new byte[64];
            int off = 0;
            for (String f : new String[] {"kce", "kcm", "kre", "krm"}) {
                java.lang.reflect.Field fd = Session.class.getDeclaredField(f);
                fd.setAccessible(true);
                byte[] v = (byte[]) fd.get(session);
                if (v == null) {
                    return null;
                }
                System.arraycopy(v, 0, out, off, v.length);
                off += v.length;
            }
            return off == 64 ? out : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** The card session's four derived keys {@code kCe ‖ kCm ‖ kRe ‖ kRm} (read-back). */
    // ── the sweep engine ─────────────────────────────────────────────────────

    static Run once(Factory f) {
        try {
            return f.fresh();
        } catch (Exception e) {
            throw new IllegalStateException("scenario setup failed", e);
        }
    }

    static Attempt attempt(Factory f, Runnable arm, long watchdog) {
        Run r;
        try {
            r = once(f);
        } catch (Throwable t) {
            Fault.reset();
            return new Attempt(ERROR, "");
        }
        arm.run();
        Fault.watchdog(watchdog);
        try {
            r.run();
        } catch (Throwable t) {
            r.threw = t;
        } finally {
            Fault.reset();
        }
        if (r.threw instanceof Fault.Hang) {
            return new Attempt(HANG, r.swSequence());
        }
        int out;
        try {
            out = r.outcome();
        } catch (Throwable t) {
            out = ERROR;
        }
        return new Attempt(out, r.swSequence());
    }

    /**
     * The occurrences swept for a site with {@code n} executions, {@code int[]{occurrence,
     * sampled}}. Branch and invoke sites are never sampled; data/store/arithmetic sites with more
     * than 8 occurrences are sampled at {1, 2, 3, last} plus 4 evenly spaced (architecture §6).
     */
    static List<int[]> occurrences(int n, char cat) {
        List<int[]> out = new ArrayList<>();
        if (n <= 8 || cat == 'b' || cat == 'i') {
            for (int i = 1; i <= n; i++) {
                out.add(new int[] {i, 0});
            }
            return out;
        }
        TreeSet<Integer> s = new TreeSet<>(List.of(1, 2, 3, n));
        for (int i = 1; i <= 4; i++) {
            s.add((int) Math.round(1.0 + i * (n - 1.0) / 5.0));
        }
        for (int v : s) {
            out.add(new int[] {v, 1});
        }
        return out;
    }

    /** The modes swept for a site kind: {@code int[]{site-mode, value, sampled-never}}. */
    private static List<int[]> siteModes(String kind) {
        List<int[]> out = new ArrayList<>();
        switch (kind.charAt(0)) {
            case 'b' -> {
                out.add(new int[] {Fault.SITE_TAKE, 0});
                out.add(new int[] {Fault.SITE_FALL, 0});
            }
            case 'i' -> {
                out.add(new int[] {Fault.SITE_SKIP, 0});
                char ret = kind.length() > 1 ? kind.charAt(1) : '?';
                if (ret == 'S' || ret == 'B' || ret == 'Z') {
                    for (short v : FORCED) {
                        out.add(new int[] {Fault.SITE_FORCED, v});
                    }
                }
            }
            case 'd' -> {
                out.add(new int[] {Fault.SITE_ZERO, 0});
                out.add(new int[] {Fault.SITE_ONES, 0});
                out.add(new int[] {Fault.SITE_FLIP, 0});
            }
            case 's', 'a' -> out.add(new int[] {Fault.SITE_SKIP, 0});
            default -> {}
        }
        return out;
    }

    private static String modeName(String kind, int mode, int value) {
        return switch (mode) {
            case Fault.SITE_SKIP -> kind.charAt(0) == 'a' ? "left" : "skip";
            case Fault.SITE_TAKE -> "take";
            case Fault.SITE_FALL -> "fall";
            case Fault.SITE_FORCED -> "ret=0x" + String.format("%04x", value & 0xFFFF);
            case Fault.SITE_ZERO -> "zero";
            case Fault.SITE_ONES -> "ones";
            case Fault.SITE_FLIP -> "flip";
            default -> "?";
        };
    }

    private void sweep(String name, Factory factory) throws Exception {
        // CI shards the sweep rows across matrix jobs (-Dqntx.sweepShard=i/N): every
        // (site, occurrence, mode) attempt is hashed to a shard, so the split is balanced
        // by attempt count — a heavy scenario like SIn spreads over all shards instead of
        // dominating one. String.hashCode is specified, so the split is deterministic
        // everywhere
        String shard = System.getProperty("qntx.sweepShard", "0/1");
        int slash = shard.indexOf('/');
        int shardIdx = 0;
        int shardCnt = 1;
        if (slash > 0) {
            shardIdx = Integer.parseInt(shard.substring(0, slash));
            shardCnt = Integer.parseInt(shard.substring(slash + 1));
        }
        // qntx.sweepCount=N enumerates the attempts without running them and reports the
        // row count each shard of an N-way split would get — CI balancing diagnostics
        int countBuckets = Integer.parseInt(System.getProperty("qntx.sweepCount", "0"));
        int buckets = countBuckets > 0 ? countBuckets : Math.max(1, shardCnt);
        long[] shardRows = countBuckets > 0 ? new long[buckets] : null;
        // the counting run: unfaulted, must be refused
        Run probe = once(factory);
        Fault.countCalls();
        try {
            probe.run();
        } catch (Throwable t) {
            probe.threw = t;
        }
        Map<String, Integer> sites = new TreeMap<>(Fault.siteCounts());
        Map<String, Integer> calls = new TreeMap<>(Fault.callCounts());
        Fault.reset();
        int probeOutcome;
        try {
            probeOutcome = probe.outcome();
        } catch (Throwable t) {
            probeOutcome = ERROR;
        }
        assertFalse(probeOutcome == RELEASED, name + ": the unfaulted attack must be refused");
        long hits = 0;
        for (int n : sites.values()) {
            hits += n;
        }
        for (int n : calls.values()) {
            hits += n;
        }
        long watchdog = Math.max(1, hits) * 50;

        Map<String, String> kinds = org.qntx.card.sim.Agent.siteKinds();
        List<String> rows = new ArrayList<>();
        int[] counts = new int[OUTCOME.length];
        int runs = 0;
        for (Map.Entry<String, Integer> e : sites.entrySet()) {
            String key = e.getKey();
            if (!APPLET.contains(key.substring(0, key.indexOf('.')))) {
                continue;
            }
            String kind = kinds.get(key);
            if (kind == null) {
                continue;
            }
            for (int[] o : occurrences(e.getValue(), kind.charAt(0))) {
                for (int[] m : siteModes(kind)) {
                    String mode = modeName(kind, m[0], m[1]);
                    int bucket =
                            Math.floorMod(
                                    (name + '|' + key + '|' + o[0] + '|' + mode).hashCode(),
                                    buckets);
                    if (shardRows != null) {
                        shardRows[bucket]++;
                        continue;
                    }
                    if (shardCnt > 1 && bucket != shardIdx) {
                        continue;
                    }
                    Attempt a =
                            attempt(
                                    factory,
                                    () -> Fault.armSite(key, o[0], m[0], (short) m[1]),
                                    watchdog);
                    runs++;
                    counts[a.outcome()]++;
                    rows.add(
                            name
                                    + ','
                                    + key
                                    + ','
                                    + o[0]
                                    + ','
                                    + mode
                                    + ','
                                    + o[1]
                                    + ",\""
                                    + a.sws()
                                    + "\","
                                    + OUTCOME[a.outcome()]);
                }
            }
        }
        for (Map.Entry<String, Integer> e : calls.entrySet()) {
            String method = e.getKey();
            if (method.equals(Fault.ECDSA_VERIFY)
                    || !APPLET.contains(method.substring(0, method.indexOf('.')))) {
                continue;
            }
            for (int occ = 1; occ <= e.getValue(); occ++) {
                int o = occ;
                for (short v : FORCED) {
                    String mode = "ret=0x" + String.format("%04x", v & 0xFFFF);
                    int bucket =
                            Math.floorMod(
                                    (name + '|' + method + '|' + o + '|' + mode).hashCode(),
                                    buckets);
                    if (shardRows != null) {
                        shardRows[bucket]++;
                        continue;
                    }
                    if (shardCnt > 1 && bucket != shardIdx) {
                        continue;
                    }
                    Attempt a = attempt(factory, () -> Fault.arm(method, o, v), watchdog);
                    runs++;
                    counts[a.outcome()]++;
                    rows.add(
                            name
                                    + ','
                                    + method
                                    + ','
                                    + o
                                    + ","
                                    + mode
                                    + ",0,\""
                                    + a.sws()
                                    + "\","
                                    + OUTCOME[a.outcome()]);
                }
            }
        }
        int verifies = calls.getOrDefault(Fault.ECDSA_VERIFY, 0);
        for (int occ = 1; occ <= verifies; occ++) {
            int o = occ;
            int bucket = Math.floorMod((name + "|verify|" + o).hashCode(), buckets);
            if (shardRows != null) {
                shardRows[bucket]++;
                continue;
            }
            if (shardCnt > 1 && bucket != shardIdx) {
                continue;
            }
            Attempt a = attempt(factory, () -> Fault.armVerifyTrue(o), watchdog);
            runs++;
            counts[a.outcome()]++;
            rows.add(
                    name
                            + ','
                            + Fault.ECDSA_VERIFY
                            + ','
                            + o
                            + ",verifyTrue,0,\""
                            + a.sws()
                            + "\","
                            + OUTCOME[a.outcome()]);
        }

        if (shardRows != null) {
            for (int i = 0; i < shardRows.length; i++) {
                System.out.printf(
                        "sweep-count %s shard %d/%d: %d attempts%n",
                        name, i, shardRows.length, shardRows[i]);
            }
            return;
        }
        Path dir = Path.of(System.getProperty("qntx.reports", "build/reports"), "gate-sweep");
        Files.createDirectories(dir);
        Files.write(
                dir.resolve(name + ".csv"),
                ("scenario,site,occurrence,mode,sampled,sw-sequence,outcome\n"
                                + String.join("\n", rows)
                                + "\n")
                        .getBytes());
        System.out.printf(
                "sweep %s: runs=%d refused=%d released=%d deviated=%d error=%d hang=%d%n",
                name,
                runs,
                counts[REFUSED],
                counts[RELEASED],
                counts[DEVIATED],
                counts[ERROR],
                counts[HANG]);
        assertEquals(0, counts[RELEASED], name + " released under single faults");
    }

    // ── the scenarios ────────────────────────────────────────────────────────

    @Test
    void sxExportToAttackerKey1() throws Exception {
        sweep("SX", exportToAttacker(BigInteger.ONE));
    }

    @Test
    void sxExportToAttackerKnownK() throws Exception {
        sweep("SXk", exportToAttacker(KNOWN_K));
    }

    @Test
    void sxnExportToGenuineNonMember() throws Exception {
        sweep("SXn", exportToNonMember(new EmuMember()));
    }

    @Test
    void sxcExportToForgedCertificate() throws Exception {
        sweep("SXc", exportToNonMember(new EmuMember(Vecs.ca2Private())));
    }

    @Test
    void spExportWithoutPending() throws Exception {
        sweep("SP", exportNoPending());
    }

    @Test
    void siImportAttackerSeed() throws Exception {
        sweep("SI", importAttackerSeed(BigInteger.ONE));
    }

    @Test
    void sirImportDifferentWallet() throws Exception {
        sweep("SIr", importDifferentWallet());
    }

    @Test
    void simImportZeroKeyRecord() throws Exception {
        sweep("SIm", importZeroKeyRecord());
    }

    @Test
    void svVerifyWrongCode() throws Exception {
        sweep("SV-f0", verifyWrong(0, 0));
        sweep("SV-fF", verifyWrong(3, 15));
        sweep("SV-fL1", verifyWrong(9, 15));
    }

    @Test
    void scChangeUnverified() throws Exception {
        sweep("SC", unverifiedEffect(INS_CHANGE, Vecs.accessHashNew()));
    }

    @Test
    void seEraseUnverified() throws Exception {
        // a released erase shows as life = BLANK in the state array
        sweep("SE", unverifiedEffect(INS_ERASE, EMPTY));
    }

    @Test
    void ssUnverifiedCommands() throws Exception {
        sweep("SS-pubkey", unverifiedSign(new int[][] {{INS_PUBLIC_KEY, 0}}));
        sweep("SS-ecdsa", unverifiedSign(new int[][] {{INS_SIGN_ECDSA, 0}}));
        sweep("SS-bip340", unverifiedSign(new int[][] {{INS_SIGN_BIP340, 0}}));
        sweep(
                "SS-ed25519",
                unverifiedSign(new int[][] {{INS_SIGN_ED25519, 0}, {INS_SIGN_ED25519, 2}}));
    }

    @Test
    void sxeExportLegitimate() throws Exception {
        sweep("SXe", exportLegit());
    }

    @Test
    void sieImportLegitimate() throws Exception {
        sweep("SIe", importLegit());
    }

    @Test
    void sinInstallLegitimate() throws Exception {
        sweep("SIn", installLegit());
    }

    @Test
    void scrCreateGenerate() throws Exception {
        sweep("SCr", createGenerate());
    }

    @Test
    void sciCreateImport() throws Exception {
        sweep("SCi", createImport());
    }

    @Test
    void schChangeCheck() throws Exception {
        sweep("SCh", changeCheck());
    }

    @Test
    void soOpenTwice() throws Exception {
        sweep("SO", openTwice());
    }
}
