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
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
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
 * unfaulted run is counted — every conditional-branch and invoke instruction occurrence the agent's
 * {@code sites} weave executed, every woven call and every wrapped ECDSA verify — and the attack is
 * then re-run once per (site, occurrence, mode) on a fresh card: branch sites skipped and inverted,
 * invoke sites skipped, woven calls forced to each coded value, verifies forced true. The test
 * fails when any run leaves the protected effect released. One {@code <scenario>.csv} per scenario
 * plus a {@code summary.csv} land in {@code <reports>/gate-sweep/}.
 */
final class GateSweepTest {
    private static final int INS_STATUS = 0x20;
    private static final int INS_CREATE = 0x21;
    private static final int INS_VERIFY = 0x22;
    private static final int INS_CHANGE = 0x23;
    private static final int INS_ERASE = 0x24;
    private static final int INS_WAIT = 0x25;
    private static final int INS_PUBLIC_KEY = 0x30;
    private static final int INS_SIGN_ECDSA = 0x31;
    private static final int INS_SIGN_BIP340 = 0x32;
    private static final int INS_SIGN_ED25519 = 0x33;
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

    private static final byte[] EMPTY = new byte[0];
    private static final byte[] PATH5 = {0x01, 0, 0, 0, 0};
    private static final byte[] RNG_BLOCK = new byte[256];
    private static final byte[] ATTACKER_SEED =
            Crypto.sha512("qntx-sweep/attacker seed".getBytes());
    private static final byte[] ATTACKER_ACCESS =
            Crypto.sha256("qntx-sweep/attacker code".getBytes());
    // the second SX variant signs with this arbitrary known scalar instead of 1
    private static final BigInteger KNOWN_K = new BigInteger("5192296858534827628530496329220097");

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

    /**
     * One attack attempt on a fresh card: {@link #run} sends the APDUs, {@link #released} checks
     * the protected effect afterwards, {@link #sws} records every SW for the CSV.
     */
    private abstract static class Run {
        final List<Integer> sws = new ArrayList<>();
        Throwable threw;

        abstract void run() throws Exception;

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

    private interface Factory {
        Run fresh() throws Exception;
    }

    private record Attempt(boolean released, String sws) {}

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
    private static Object[] loaded(EmuMember... members) throws Exception {
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
    private static Factory exportToAttacker(BigInteger priv) {
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
    private static Factory exportToNonMember(EmuMember attacker) {
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
    private static Factory exportNoPending() {
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
    private static Factory importAttackerSeed(BigInteger priv) {
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
    private static Factory importDifferentWallet() {
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
                    return !Arrays.equals(before, state(card));
                }
            };
        };
    }

    /** SIm: a genuine pending import whose ct ‖ tag is replaced by a zero-key record. */
    private static Factory importZeroKeyRecord() {
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
                    return !Arrays.equals(before, state(card));
                }
            };
        };
    }

    /** SV: VERIFY of a wrong code at {@code fails}; the required waits are done first. */
    private static Factory verifyWrong(int fails, int waits) {
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
    private static Factory unverifiedEffect(int ins, byte[] data) {
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
                    return !Arrays.equals(before, state(card));
                }
            };
        };
    }

    /** SS: an unverified PUBLIC_KEY / SIGN_* command (+ ED25519 finish) — 9000 with data. */
    private static Factory unverifiedSign(int[][] commands) {
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
                            if (r.sw() == 0x9000 && r.data().length > 0) {
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

    // ── the sweep engine ─────────────────────────────────────────────────────

    private static Run once(Factory f) {
        try {
            return f.fresh();
        } catch (Exception e) {
            throw new IllegalStateException("scenario setup failed", e);
        }
    }

    private static Attempt attempt(Factory f, Runnable arm) {
        Run r = once(f);
        arm.run();
        try {
            r.run();
        } catch (Throwable t) {
            r.threw = t;
        } finally {
            Fault.reset();
        }
        boolean rel;
        try {
            rel = r.released();
        } catch (Throwable t) {
            rel = false;
        }
        return new Attempt(rel, r.swSequence());
    }

    private void sweep(String name, Factory factory) throws Exception {
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
        boolean unfaultedRelease;
        try {
            unfaultedRelease = probe.released();
        } catch (Throwable t) {
            unfaultedRelease = false;
        }
        assertFalse(unfaultedRelease, name + ": the unfaulted attack must be refused");

        List<String> rows = new ArrayList<>();
        int runs = 0;
        int released = 0;
        for (Map.Entry<String, Integer> e : sites.entrySet()) {
            String key = e.getKey();
            if (!APPLET.contains(key.substring(0, key.indexOf('.')))) {
                continue;
            }
            boolean branch = key.contains("#b");
            for (int occ = 1; occ <= e.getValue(); occ++) {
                int o = occ;
                Attempt a = attempt(factory, () -> Fault.armSite(key, o, Fault.SITE_SKIP));
                runs++;
                released += a.released() ? 1 : 0;
                rows.add(
                        name
                                + ','
                                + key
                                + ','
                                + o
                                + ",skip,\""
                                + a.sws()
                                + "\","
                                + (a.released() ? "RELEASED" : "REFUSED"));
                if (branch) {
                    a = attempt(factory, () -> Fault.armSite(key, o, Fault.SITE_INVERT));
                    runs++;
                    released += a.released() ? 1 : 0;
                    rows.add(
                            name
                                    + ','
                                    + key
                                    + ','
                                    + o
                                    + ",invert,\""
                                    + a.sws()
                                    + "\","
                                    + (a.released() ? "RELEASED" : "REFUSED"));
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
                    Attempt a = attempt(factory, () -> Fault.arm(method, o, v));
                    runs++;
                    released += a.released() ? 1 : 0;
                    rows.add(
                            name
                                    + ','
                                    + method
                                    + ','
                                    + o
                                    + ",ret=0x"
                                    + String.format("%04x", v & 0xFFFF)
                                    + ",\""
                                    + a.sws()
                                    + "\","
                                    + (a.released() ? "RELEASED" : "REFUSED"));
                }
            }
        }
        int verifies = calls.getOrDefault(Fault.ECDSA_VERIFY, 0);
        for (int occ = 1; occ <= verifies; occ++) {
            int o = occ;
            Attempt a = attempt(factory, () -> Fault.armVerifyTrue(o));
            runs++;
            released += a.released() ? 1 : 0;
            rows.add(
                    name
                            + ','
                            + Fault.ECDSA_VERIFY
                            + ','
                            + o
                            + ",verifyTrue,\""
                            + a.sws()
                            + "\","
                            + (a.released() ? "RELEASED" : "REFUSED"));
        }

        Path dir = Path.of(System.getProperty("qntx.reports", "build/reports"), "gate-sweep");
        Files.createDirectories(dir);
        Files.write(
                dir.resolve(name + ".csv"),
                ("scenario,site,occurrence,mode,sw-sequence,outcome\n"
                                + String.join("\n", rows)
                                + "\n")
                        .getBytes());
        System.out.printf(
                "sweep %s: runs=%d refused=%d released=%d%n",
                name, runs, runs - released, released);
        assertEquals(0, released, name + " released under single faults");
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
}
