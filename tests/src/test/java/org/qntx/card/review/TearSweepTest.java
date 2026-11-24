// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review;

import static org.qntx.card.review.ReviewHost.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.qntx.card.sim.TornException;

/**
 * Tearing sweep: the oracle of {@code $A/review/tear-oracle.md} (T1–T20 + U1–U5). For every
 * scenario the pre-state is rebuilt deterministically; the command is first run untorn to measure
 * {@code N = card.writes()}, then torn at every {@code k = 1…N} (expect {@link TornException},
 * power cycle, check post-state) and at {@code k = N + 1} as the control. One CSV row per
 * (scenario, k); the summary collects N per command and every VIOLATION.
 */
@EnabledIfEnvironmentVariable(named = "QNTX_REVIEW", matches = "full")
final class TearSweepTest {

    private static final Path DIR =
            Paths.get(System.getenv().getOrDefault("QNTX_REVIEW_OUT", "build/review"));

    private static final byte INS_STATUS = 0x20,
            INS_CREATE = 0x21,
            INS_VERIFY = 0x22,
            INS_CHANGE = 0x23,
            INS_ERASE = 0x24,
            INS_WAIT = 0x25,
            INS_PUBLIC_KEY = 0x30,
            INS_SIGN_ECDSA = 0x31,
            INS_SIGN_BIP340 = 0x32,
            INS_SIGN_ED25519 = 0x33,
            INS_OFFER = 0x40,
            INS_EXPORT = 0x41,
            INS_IMPORT = 0x42;

    private static final byte[] S0 =
            unhex(
                    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
                            + "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
    private static final byte[] H0 = sha256(utf8("tear H0"));
    private static final byte[] H1 = sha256(utf8("tear H1"));
    private static final byte[] H3 = sha256(utf8("tear H3"));
    private static final byte[] HT = sha256(utf8("tear HT"));
    private static final byte[] H9 = sha256(utf8("tear wrong"));
    private static final byte[] DG = sha256(utf8("tear digest"));

    private static byte[] utf8(String s) {
        return s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static byte[] pathBytes(long... idx) {
        byte[] out = new byte[1 + 4 * idx.length];
        out[0] = (byte) idx.length;
        for (int i = 0; i < idx.length; i++) {
            byte[] b = u32(idx[i]);
            System.arraycopy(b, 0, out, 1 + 4 * i, 4);
        }
        return out;
    }

    private static String hx(int sw) {
        return String.format("%04X", sw < 0 ? -sw : sw & 0xFFFF);
    }

    /** Everything the sweep needs for one command: a fresh pre-state and its torn APDU. */
    private static final class Ctx {
        ReviewCard c;
        byte[] cmdApdu; // the command under test (record-wrapped or raw)
        byte[] lk; // OFFER's LK when the pre-state holds one (T14/T15/T16)
        byte[] export0; // IMPORT P1=00 request bytes when the pre-state holds one
        byte[][] sealed; // IMPORT P1=01 record when the pre-state holds one (T15/T16)
        byte[] skey; // host H for verify checks
        long edctr; // edCounter snapshot for T17
    }

    private interface Mk {
        Ctx make();
    }

    private interface Post {
        /** Checks the allowed post-states; returns "OK …" or "VIOLATION …". */
        String check(Ctx t);
    }

    private final List<String[]> rows = new ArrayList<>();
    private final List<String> violations = new ArrayList<>();
    private final List<String> notes = new ArrayList<>();

    /** Session-record APDU for an inner command (session must be open). */
    private static byte[] rec(ReviewSession s, byte ins, byte p1, byte[] data) {
        return s.recordApdu((byte) 0, (byte) 0, s.record(ins, p1, (byte) 0, data));
    }

    // post-state probes

    /** 1 = uninit, 2 = factory, 3 = blank, 4 = loaded. */
    private static int lifeOf(ReviewCard c) {
        c.transmit(ReviewHost.SELECT_WALLET);
        try {
            ReviewSession s = c.open();
            ReviewSession.Inner st = s.cmd(INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
            if (st.sw != 0x9000) {
                return -1;
            }
            return st.data[0] == 0x01 ? 3 : 4;
        } catch (Throwable t) {
            byte[] r = c.transmit(unhex("80E0000000"));
            return sw(r) == 0x6283 ? 1 : 2;
        }
    }

    private static int triesOf(ReviewCard c) {
        ReviewSession s = c.open();
        ReviewSession.Inner st = s.cmd(INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
        return st.sw == 0x9000 ? st.data[1] & 0xFF : -1;
    }

    private static int verifySw(ReviewCard c, byte[] h) {
        ReviewSession s = c.open();
        return s.cmd(INS_VERIFY, (byte) 0, (byte) 0, h).sw;
    }

    private static byte[] mpk(ReviewCard c) {
        ReviewSession s = c.open();
        s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
        ReviewSession.Inner pk = s.cmd(INS_PUBLIC_KEY, (byte) 0, (byte) 0, pathBytes(0));
        return pk.sw == 0x9000 ? slice(pk.data, 0, 33) : null;
    }

    // the sweep

    /**
     * Runs one scenario: measures N on a fresh pre-state, tears at every k = 1..N, runs the control
     * k = N + 1. Universal checks U1–U5 run on every torn row.
     */
    private void sweep(String id, Mk mk, Post post) {
        sweep(id, mk, post, 1);
    }

    /**
     * As {@link #sweep(String, Mk, Post)} but the torn run starts at {@code kMin}: used by T20 to
     * skip the writes that belong to the committed T-FAIL itself.
     */
    private void sweep(String id, Mk mk, Post post, int kMin) {
        Ctx dry = mk.make();
        dry.c.transmit(dry.cmdApdu);
        int n = dry.c.card.writes();
        notes.add(id + " N=" + n + " commits=" + dry.c.card.commits());
        for (int k = kMin; k <= n + 1; k++) {
            Ctx t = mk.make();
            String detail;
            boolean torn;
            if (k <= n) {
                t.c.card.tearAt(k);
                try {
                    t.c.transmit(t.cmdApdu);
                    torn = false;
                } catch (TornException e) {
                    torn = true;
                }
                t.c.card.powerCycle();
                if (!torn) {
                    detail = "VIOLATION tearAt(" + k + ") did not fire (writes=" + n + ")";
                } else {
                    String u = universal(t);
                    detail = post.check(t);
                    if (u != null) {
                        detail = detail.startsWith("VIOLATION") ? detail : "OK " + detail;
                        detail += " | " + u;
                    }
                }
            } else {
                try {
                    t.c.transmit(t.cmdApdu);
                    torn = false;
                } catch (TornException e) {
                    torn = true;
                }
                detail = torn ? "VIOLATION control tore" : "OK control: " + post.check(t);
            }
            if (detail.startsWith("VIOLATION")) {
                violations.add(id + " k=" + k + " " + detail);
            }
            rows.add(new String[] {id, Integer.toString(k), detail});
        }
    }

    /** U1 no brick, U3 STATUS sane, U4/U5 replay rejection (when a record existed). */
    private static String universal(Ctx t) {
        StringBuilder u = new StringBuilder();
        byte[] sel = t.c.transmit(ReviewHost.SELECT_WALLET);
        if (sw(sel) != 0x9000) {
            u.append("VIOLATION U1 select=").append(hx(sw(sel)));
            return u.toString();
        }
        int life = lifeOf(t.c);
        if (life < 0) {
            u.append("VIOLATION U1/U3 no usable state");
            return u.toString();
        }
        if (life >= 3) {
            // U3: STATUS must answer, fails consistent; U4/U5: old record rejected
            if (triesOf(t.c) < 0) {
                u.append("VIOLATION U3 STATUS fails");
            }
            if (t.cmdApdu.length > 4 && (t.cmdApdu[1] & 0xFF) == 0x12) {
                ReviewSession s = t.c.open();
                ReviewSession.Raw rr = s.raw(t.cmdApdu);
                if (rr.outer == 0x9000) {
                    u.append("VIOLATION U5 replayed record accepted");
                }
            }
        }
        return u.length() == 0 ? null : u.toString();
    }

    private static ReviewCard blank() {
        ReviewCard c = ReviewCard.uninitialised();
        c.blank();
        return c;
    }

    private static ReviewCard loaded() {
        ReviewCard c = blank();
        c.create(S0, H0);
        return c;
    }

    /** LOADED f=f with 15 waits armed when f ≥ 3. */
    private static Ctx loadedAt(int f) {
        ReviewCard c = loaded();
        if (f > 0) {
            c.injectFails(f);
        }
        Ctx t = new Ctx();
        t.c = c;
        return t;
    }

    @Test
    void sweepAll() throws IOException {
        t1();
        t2();
        t3t4();
        t5t6();
        t7t8();
        t9();
        t10();
        t11();
        t12();
        t13();
        t14();
        t15();
        t16();
        t17();
        t18();
        t19();
        t20();
        write();
    }

    /** T1: uninitialised, torn GET_IDENTITY after j steps, j = 0…6. */
    private void t1() {
        for (int j = 0; j <= 6; j++) {
            final int jj = j;
            sweep(
                    "T1-j" + j,
                    () -> {
                        Ctx t = new Ctx();
                        t.c = ReviewCard.uninitialised();
                        t.c.transmit(ReviewHost.SELECT_WALLET);
                        for (int i = 0; i < jj; i++) {
                            t.c.transmit(unhex("80E0000000"));
                        }
                        t.cmdApdu = unhex("80E0000000");
                        return t;
                    },
                    t -> {
                        byte[] r = t.c.transmit(ReviewHost.SELECT_WALLET);
                        int calls = 0;
                        do {
                            r = t.c.transmit(unhex("80E0000000"));
                        } while (sw(r) == 0x6283 && ++calls < 20);
                        if (sw(r) != 0x9000 || respData(r).length != 33) {
                            return "VIOLATION init does not complete: " + hx(sw(r));
                        }
                        return "OK init completes, A=" + hex(slice(respData(r), 0, 8)) + "…";
                    });
        }
    }

    /** T2: FACTORY, torn PERSONALIZE. */
    private void t2() {
        sweep(
                "T2",
                () -> {
                    Ctx t = new Ctx();
                    t.c = ReviewCard.uninitialised();
                    t.c.factory();
                    byte[] cert = ReviewCard.CA.issue(t.c.cardA);
                    byte[] data = concat(cert, ReviewCard.CA.pub65);
                    t.cmdApdu =
                            concat(
                                    unhex("80E20000"),
                                    new byte[] {(byte) data.length},
                                    data,
                                    new byte[] {0x00});
                    return t;
                },
                t -> {
                    int life = lifeOf(t.c);
                    if (life == 2) {
                        // FACTORY: GET_IDENTITY works and PERSONALIZE can still complete
                        byte[] cert = ReviewCard.CA.issue(t.c.cardA);
                        byte[] data = concat(cert, ReviewCard.CA.pub65);
                        byte[] r =
                                t.c.transmit(
                                        concat(
                                                unhex("80E20000"),
                                                new byte[] {(byte) data.length},
                                                data,
                                                new byte[] {0x00}));
                        return sw(r) == 0x9000
                                ? "OK still FACTORY, re-personalize 9000"
                                : "VIOLATION FACTORY but re-personalize " + hx(sw(r));
                    }
                    if (life == 3) {
                        ReviewSession s = t.c.open();
                        boolean v = certVerify(ReviewCard.CA.pub65, s.cert);
                        return v
                                ? "OK BLANK with valid new cert"
                                : "VIOLATION BLANK, cert does not verify";
                    }
                    return "VIOLATION unexpected life " + life;
                });
    }

    /** T3/T4: BLANK s, torn CREATE P1=01 (S0,H0) / P1=00. */
    private void t3t4() {
        sweep(
                "T3",
                () -> {
                    Ctx t = new Ctx();
                    t.c = blank();
                    ReviewSession s = t.c.open();
                    t.cmdApdu = rec(s, INS_CREATE, (byte) 1, concat(H0, S0));
                    return t;
                },
                t -> {
                    int life = lifeOf(t.c);
                    if (life == 3) {
                        // BLANK: CREATE must still succeed
                        ReviewSession s = t.c.open();
                        ReviewSession.Inner cr =
                                s.cmd(INS_CREATE, (byte) 1, (byte) 0, concat(H0, S0));
                        return cr.sw == 0x9000
                                ? "OK still BLANK, CREATE again 9000"
                                : "VIOLATION BLANK but CREATE " + hx(cr.sw);
                    }
                    if (life == 4) {
                        int v = verifySw(t.c, H0);
                        byte[] mpk = mpk(t.c);
                        BigInteger d = bip32Leaf(S0, path(0));
                        byte[] exp = compr(g().multiply(d));
                        if (v == 0x9000 && mpk != null && ReviewCard.eq(mpk, exp)) {
                            return "OK LOADED, VERIFY H0 9000, mpk matches";
                        }
                        return "VIOLATION LOADED verify=" + hx(v) + " mpkMatch=" + (mpk != null);
                    }
                    return "VIOLATION life " + life;
                });
        sweep(
                "T4",
                () -> {
                    Ctx t = new Ctx();
                    t.c = blank();
                    ReviewSession s = t.c.open();
                    FakeMember m1 = new FakeMember(ReviewCard.CA);
                    FakeMember m2 = new FakeMember(ReviewCard.CA);
                    t.cmdApdu = rec(s, INS_CREATE, (byte) 0, concat(H0, m1.cardId, m2.cardId));
                    return t;
                },
                t -> {
                    int life = lifeOf(t.c);
                    if (life == 3) {
                        return "OK still BLANK";
                    }
                    if (life == 4) {
                        int v = verifySw(t.c, H0);
                        return v == 0x9000
                                ? "OK LOADED consistent (VERIFY 9000)"
                                : "VIOLATION LOADED but VERIFY " + hx(v);
                    }
                    return "VIOLATION life " + life;
                });
    }

    /** T5/T6: LOADED f=0, torn VERIFY wrong / right. */
    private void t5t6() {
        sweep(
                "T5",
                () -> {
                    Ctx t = loadedAt(0);
                    ReviewSession s = t.c.open();
                    t.cmdApdu = rec(s, INS_VERIFY, (byte) 0, H9);
                    return t;
                },
                t -> {
                    int tr = triesOf(t.c);
                    return tr == 10 || tr == 9
                            ? "OK tries=" + tr
                            : "VIOLATION tries=" + tr + " (f∉{0,1})";
                });
        sweep(
                "T6",
                () -> {
                    Ctx t = loadedAt(0);
                    ReviewSession s = t.c.open();
                    t.cmdApdu = rec(s, INS_VERIFY, (byte) 0, H0);
                    return t;
                },
                t -> {
                    int tr = triesOf(t.c);
                    byte[] mpk = mpk(t.c);
                    BigInteger d = bip32Leaf(S0, path(0));
                    boolean sameWallet = mpk != null && ReviewCard.eq(mpk, compr(g().multiply(d)));
                    return (tr == 10 || tr == 9) && sameWallet
                            ? "OK tries=" + tr + " same wallet"
                            : "VIOLATION tries=" + tr + " walletChanged=" + !sameWallet;
                });
    }

    /** T7/T8: f=9 (waits done), torn VERIFY wrong / right. */
    private void t7t8() {
        sweep(
                "T7",
                () -> {
                    Ctx t = loadedAt(9);
                    ReviewSession s = t.c.open();
                    ReviewCard.waitW(s);
                    t.cmdApdu = rec(s, INS_VERIFY, (byte) 0, H9);
                    return t;
                },
                t -> {
                    int life = lifeOf(t.c);
                    if (life == 3) {
                        return "OK BLANK (T-ERASE committed)";
                    }
                    if (life != 4) {
                        return "VIOLATION life " + life;
                    }
                    int tr = triesOf(t.c);
                    if (tr == 1) {
                        return "OK f=9";
                    }
                    if (tr == 0) {
                        int v = verifySw(t.c, H9);
                        return v == 0x6983 || v == 0x6985
                                ? "OK f=10, next VERIFY " + hx(v)
                                : "VIOLATION f=10 but VERIFY " + hx(v);
                    }
                    return "VIOLATION tries=" + tr;
                });
        sweep(
                "T8",
                () -> {
                    Ctx t = loadedAt(9);
                    ReviewSession s = t.c.open();
                    ReviewCard.waitW(s);
                    t.cmdApdu = rec(s, INS_VERIFY, (byte) 0, H0);
                    return t;
                },
                t -> {
                    int life = lifeOf(t.c);
                    if (life == 3) {
                        return "OK BLANK (T-ERASE committed — wallet lost on torn correct attempt)";
                    }
                    if (life != 4) {
                        return "VIOLATION life " + life;
                    }
                    int tr = triesOf(t.c);
                    if (tr == 1 || tr == 10) {
                        return "OK f=" + (tr == 1 ? 9 : 0);
                    }
                    if (tr == 0) {
                        int v = verifySw(t.c, H9);
                        return v == 0x6983 || v == 0x6985
                                ? "OK f=10 (wallet lost at next VERIFY)"
                                : "VIOLATION f=10 but VERIFY " + hx(v);
                    }
                    return "VIOLATION tries=" + tr;
                });
    }

    /** T9: f=3 + 15 WAIT, torn VERIFY wrong. */
    private void t9() {
        sweep(
                "T9",
                () -> {
                    Ctx t = loadedAt(3);
                    ReviewSession s = t.c.open();
                    ReviewCard.waitW(s);
                    t.cmdApdu = rec(s, INS_VERIFY, (byte) 0, H9);
                    return t;
                },
                t -> {
                    int tr = triesOf(t.c);
                    if (tr != 7 && tr != 6) {
                        return "VIOLATION tries=" + tr + " (f∉{3,4})";
                    }
                    int v = verifySw(t.c, H9);
                    return v == 0x6986
                            ? "OK f=" + (10 - tr) + ", VERIFY needs waits (6986)"
                            : "VIOLATION f=" + (10 - tr) + " VERIFY no-wait " + hx(v);
                });
    }

    /** T10: LOADED v, torn CHANGE(H1). */
    private void t10() {
        sweep(
                "T10",
                () -> {
                    Ctx t = loadedAt(0);
                    ReviewSession s = t.c.open();
                    s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
                    t.cmdApdu = rec(s, INS_CHANGE, (byte) 0, H1);
                    return t;
                },
                t -> {
                    int tr = triesOf(t.c);
                    int v0 = verifySw(t.c, H0);
                    int v1 = verifySw(t.c, H1);
                    boolean one = v0 == 0x9000 ^ v1 == 0x9000;
                    int other = v0 == 0x9000 ? v1 : v0;
                    boolean other63 = (other & 0xFFF0) == 0x63C0;
                    return one && other63 && tr == 10
                            ? "OK exactly one code works, fails=0"
                            : "VIOLATION v0=" + hx(v0) + " v1=" + hx(v1) + " tries=" + tr;
                });
    }

    /** T11: LOADED v, torn ERASE. */
    private void t11() {
        sweep(
                "T11",
                () -> {
                    Ctx t = loadedAt(0);
                    ReviewSession s = t.c.open();
                    s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
                    t.cmdApdu = rec(s, INS_ERASE, (byte) 0, new byte[0]);
                    return t;
                },
                t -> {
                    int life = lifeOf(t.c);
                    if (life == 4) {
                        int v = verifySw(t.c, H0);
                        return v == 0x9000
                                ? "OK LOADED, H0 works"
                                : "VIOLATION LOADED verify " + hx(v);
                    }
                    if (life == 3) {
                        int v = verifySw(t.c, H0);
                        ReviewSession s = t.c.open();
                        ReviewSession.Inner of = s.cmd(INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                        return v != 0x9000 && of.sw == 0x9000
                                ? "OK BLANK, VERIFY " + hx(v) + ", fresh LK"
                                : "VIOLATION BLANK verify=" + hx(v) + " offer=" + hx(of.sw);
                    }
                    return "VIOLATION life " + life;
                });
    }

    /** T12: BLANK s, torn OFFER. */
    private void t12() {
        sweep(
                "T12",
                () -> {
                    Ctx t = new Ctx();
                    t.c = blank();
                    ReviewSession s = t.c.open();
                    t.cmdApdu = rec(s, INS_OFFER, (byte) 0, new byte[0]);
                    return t;
                },
                t -> {
                    ReviewSession s = t.c.open();
                    ReviewSession.Inner o1 = s.cmd(INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                    if (o1.sw != 0x9000) {
                        return "VIOLATION OFFER " + hx(o1.sw);
                    }
                    byte[] lk = slice(o1.data, 0, 65);
                    byte[] sig = slice(o1.data, 65, 64);
                    boolean v = ecdsaVerify(s.cardA, concat(LABEL_OFFER, lk), sig);
                    ReviewSession.Inner o2 = s.cmd(INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                    boolean stable = o2.sw == 0x9000 && ReviewCard.eq(slice(o2.data, 0, 65), lk);
                    return v && stable
                            ? "OK offer valid+stable"
                            : "VIOLATION sigOk=" + v + " stable=" + stable;
                });
    }

    /** T13: L2 v, torn EXPORT P1=00. */
    private void t13() {
        sweep(
                "T13",
                () -> {
                    Ctx t = new Ctx();
                    t.c = blank();
                    FakeMember m = new FakeMember(ReviewCard.CA);
                    ReviewSession s = t.c.create(S0, H0, m.cardId);
                    s = t.c.open();
                    s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
                    t.cmdApdu = rec(s, INS_EXPORT, (byte) 0, m.exportRequest());
                    t.skey = m.exportRequest();
                    return t;
                },
                t -> {
                    ReviewSession s = t.c.open();
                    s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
                    ReviewSession.Inner e = s.cmd(INS_EXPORT, (byte) 0, (byte) 0, t.skey);
                    return e.sw == 0x9000 ? "OK re-export 9000" : "VIOLATION re-export " + hx(e.sw);
                });
    }

    /** T14: BLANK after OFFER, torn IMPORT P1=00. */
    private void t14() {
        sweep(
                "T14",
                () -> {
                    Ctx t = new Ctx();
                    t.c = blank();
                    FakeMember m = new FakeMember(ReviewCard.CA);
                    ReviewSession s = t.c.open();
                    byte[] lk =
                            slice(s.cmd(INS_OFFER, (byte) 0, (byte) 0, new byte[0]).data, 0, 65);
                    t.lk = lk;
                    t.export0 = m.exportOffer(s.cardA, lk)[0];
                    t.cmdApdu = rec(s, INS_IMPORT, (byte) 0, t.export0);
                    return t;
                },
                t -> {
                    ReviewSession s = t.c.open();
                    ReviewSession.Inner of = s.cmd(INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                    if (of.sw != 0x9000 || !ReviewCard.eq(slice(of.data, 0, 65), t.lk)) {
                        return "VIOLATION offer not VALID/same LK";
                    }
                    ReviewSession.Inner i = s.cmd(INS_IMPORT, (byte) 0, (byte) 0, t.export0);
                    return i.sw == 0x9000
                            ? "OK offer VALID same LK, re-import 9000"
                            : "VIOLATION re-import " + hx(i.sw);
                });
    }

    /** T15: BLANK after OFFER + IMPORT P1=00, torn IMPORT P1=01. */
    private void t15() {
        sweep(
                "T15",
                () -> {
                    Ctx t = new Ctx();
                    t.c = blank();
                    FakeMember m = new FakeMember(ReviewCard.CA);
                    ReviewSession s = t.c.open();
                    byte[] lk =
                            slice(s.cmd(INS_OFFER, (byte) 0, (byte) 0, new byte[0]).data, 0, 65);
                    t.lk = lk;
                    byte[][] eo = m.exportOffer(s.cardA, lk);
                    s.cmd(INS_IMPORT, (byte) 0, (byte) 0, eo[0]);
                    t.export0 = eo[0];
                    byte[] z = ecdhX(b2i(eo[1]), lk);
                    byte[] em = concat(LABEL_EXPORT, m.a, s.cardA, lk, slice(eo[0], 97, 65));
                    byte[] payload =
                            concat(
                                    new byte[] {2},
                                    S0,
                                    H0,
                                    new byte[] {2},
                                    cardId(s.cardA),
                                    m.cardId);
                    t.sealed = FakeMember.sealRecord(z, em, payload);
                    t.cmdApdu = rec(s, INS_IMPORT, (byte) 1, t.sealed[0]);
                    return t;
                },
                t -> {
                    int life = lifeOf(t.c);
                    if (life == 3) {
                        ReviewSession s = t.c.open();
                        ReviewSession.Inner of = s.cmd(INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                        boolean same =
                                of.sw == 0x9000 && ReviewCard.eq(slice(of.data, 0, 65), t.lk);
                        ReviewSession.Inner i0 = s.cmd(INS_IMPORT, (byte) 0, (byte) 0, t.export0);
                        ReviewSession.Inner i1 = s.cmd(INS_IMPORT, (byte) 1, (byte) 0, t.sealed[0]);
                        boolean redo = i0.sw == 0x9000 && i1.sw == 0x9000;
                        return same && redo
                                ? "OK BLANK, same offer, redo IMPORT 9000"
                                : "VIOLATION BLANK sameOffer="
                                        + same
                                        + " redo="
                                        + hx(i0.sw)
                                        + "/"
                                        + hx(i1.sw);
                    }
                    if (life == 4) {
                        int v = verifySw(t.c, H0);
                        return v == 0x9000
                                ? "OK LOADED payload wallet under H0"
                                : "VIOLATION LOADED verify " + hx(v);
                    }
                    return "VIOLATION life " + life;
                });
    }

    /** T16: L2 f=2 after OFFER + IMPORT P1=00, torn IMPORT P1=01 re-seal (same wallet, H3). */
    private void t16() {
        sweep(
                "T16",
                () -> {
                    Ctx t = new Ctx();
                    t.c = blank();
                    FakeMember m = new FakeMember(ReviewCard.CA);
                    t.c.create(S0, H0, m.cardId);
                    ReviewSession prior = t.c.open();
                    ReviewCard.failTo(prior, H9, 2);
                    ReviewSession s = t.c.open();
                    byte[] lk =
                            slice(s.cmd(INS_OFFER, (byte) 0, (byte) 0, new byte[0]).data, 0, 65);
                    t.lk = lk;
                    byte[][] eo = m.exportOffer(s.cardA, lk);
                    s.cmd(INS_IMPORT, (byte) 0, (byte) 0, eo[0]);
                    byte[] z = ecdhX(b2i(eo[1]), lk);
                    byte[] em = concat(LABEL_EXPORT, m.a, s.cardA, lk, slice(eo[0], 97, 65));
                    byte[] payload =
                            concat(
                                    new byte[] {2},
                                    S0,
                                    H3,
                                    new byte[] {2},
                                    cardId(s.cardA),
                                    m.cardId);
                    t.sealed = FakeMember.sealRecord(z, em, payload);
                    t.cmdApdu = rec(s, INS_IMPORT, (byte) 1, t.sealed[0]);
                    return t;
                },
                t -> {
                    if (lifeOf(t.c) != 4) {
                        return "VIOLATION not LOADED";
                    }
                    int tr = triesOf(t.c);
                    int v0 = verifySw(t.c, H0);
                    int v3 = verifySw(t.c, H3);
                    int f = 10 - tr;
                    if (v0 == 0x9000 && f == 2) {
                        return "OK old code H0, f=2";
                    }
                    if (v3 == 0x9000 && f == 0) {
                        return "OK new code H3, f=0";
                    }
                    return "VIOLATION v0=" + hx(v0) + " v3=" + hx(v3) + " f=" + f;
                });
    }

    /** T17: LOADED v, torn SIGN_ED25519 begin. */
    private void t17() {
        sweep(
                "T17",
                () -> {
                    Ctx t = loadedAt(0);
                    ReviewSession s = t.c.open();
                    s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
                    t.cmdApdu = rec(s, INS_SIGN_ED25519, (byte) 0, pathBytes(0x80000000L));
                    t.edctr = t.c.readEdCounter();
                    return t;
                },
                t -> {
                    long ctr = t.c.readEdCounter();
                    if (ctr != t.edctr && ctr != t.edctr + 1) {
                        return "VIOLATION edCounter " + t.edctr + " -> " + ctr;
                    }
                    ReviewSession s = t.c.open();
                    s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
                    ReviewSession.Inner b =
                            s.cmd(INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(0x80000000L));
                    if (b.sw != 0x9000) {
                        return "VIOLATION new begin " + hx(b.sw);
                    }
                    return "OK edCounter " + t.edctr + "->" + ctr + ", new begin 9000";
                });
    }

    /** T18: LOADED v, torn SIGN_ECDSA; next SIGN_ECDSA must sign. */
    private void t18() {
        sweep(
                "T18",
                () -> {
                    Ctx t = loadedAt(0);
                    ReviewSession s = t.c.open();
                    s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
                    t.cmdApdu = rec(s, INS_SIGN_ECDSA, (byte) 0, concat(DG, pathBytes(0)));
                    return t;
                },
                t -> {
                    ReviewSession s = t.c.open();
                    s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
                    ReviewSession.Inner r =
                            s.cmd(INS_SIGN_ECDSA, (byte) 0, (byte) 0, concat(DG, pathBytes(0)));
                    if (r.sw != 0x9000) {
                        return "VIOLATION next sign " + hx(r.sw);
                    }
                    BigInteger d = bip32Leaf(S0, path(0));
                    boolean ok = ecdsaVerifyHash(compr(g().multiply(d)), DG, r.data);
                    return ok ? "OK next sign valid" : "VIOLATION next sign invalid";
                });
    }

    /** T19: expected N=0 commands; N is recorded by the sweep notes. */
    private void t19() {
        record(
                "T19-SIGN_BIP340",
                () -> {
                    Ctx t = loadedAt(0);
                    ReviewSession s = t.c.open();
                    s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
                    t.cmdApdu =
                            rec(
                                    s,
                                    INS_SIGN_BIP340,
                                    (byte) 0,
                                    concat(DG, new byte[32], pathBytes(0)));
                    return t;
                });
        record(
                "T19-PUBLIC_KEY",
                () -> {
                    Ctx t = loadedAt(0);
                    ReviewSession s = t.c.open();
                    s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
                    t.cmdApdu = rec(s, INS_PUBLIC_KEY, (byte) 0, pathBytes(0));
                    return t;
                });
        record(
                "T19-WAIT",
                () -> {
                    Ctx t = loadedAt(0);
                    ReviewSession s = t.c.open();
                    t.cmdApdu = rec(s, INS_WAIT, (byte) 0, new byte[0]);
                    return t;
                });
        record(
                "T19-STATUS",
                () -> {
                    Ctx t = loadedAt(0);
                    ReviewSession s = t.c.open();
                    t.cmdApdu = rec(s, INS_STATUS, (byte) 0, new byte[0]);
                    return t;
                });
        record(
                "T19-OPEN",
                () -> {
                    Ctx t = loadedAt(0);
                    t.cmdApdu =
                            concat(
                                    unhex("80100000"),
                                    new byte[] {65},
                                    uncomp(g().multiply(randomScalar())),
                                    new byte[] {0x00});
                    return t;
                });
        record(
                "T19-SELECT",
                () -> {
                    Ctx t = loadedAt(0);
                    t.cmdApdu = ReviewHost.SELECT_WALLET;
                    return t;
                });
    }

    /** T19 helper: measure N, then sweep tears (likely N = 0 → only the control row). */
    private void record(String id, Mk mk) {
        sweep(id, mk, t -> "OK post-state unchanged");
    }

    /**
     * T20: f=9 (waits done), torn VERIFY wrong after the T-FAIL commit — post is BLANK or f = 10,
     * never LOADED with f < 10. Tears at k ≤ n_fail land inside T-FAIL itself, where f = 9
     * unchanged is correct (the T7 cell), so n_fail is measured as the write count of a pure
     * T-FAIL: an untorn VERIFY wrong at f = 3 with the waits done (no erase follows).
     */
    private void t20() {
        Ctx dryF = loadedAt(3);
        ReviewSession ds = dryF.c.open();
        ReviewCard.waitW(ds);
        dryF.c.transmit(rec(ds, INS_VERIFY, (byte) 0, H9));
        int nFail = dryF.c.card.writes();
        notes.add("T20 n_fail=" + nFail + " (pure T-FAIL writes, VERIFY wrong at f=3)");
        sweep(
                "T20",
                () -> {
                    Ctx t = loadedAt(9);
                    ReviewSession s = t.c.open();
                    ReviewCard.waitW(s);
                    t.cmdApdu = rec(s, INS_VERIFY, (byte) 0, H9);
                    return t;
                },
                t -> {
                    int life = lifeOf(t.c);
                    if (life == 3) {
                        return "OK BLANK";
                    }
                    if (life != 4) {
                        return "VIOLATION life " + life;
                    }
                    int tr = triesOf(t.c);
                    if (tr == 0) {
                        return "OK f=10";
                    }
                    return "VIOLATION tries=" + tr + " (f<10 and not BLANK)";
                },
                nFail + 1);
    }

    private void write() throws IOException {
        Files.createDirectories(DIR);
        StringBuilder csv = new StringBuilder("scenario,k,verdict_detail\n");
        for (String[] r : rows) {
            csv.append(r[0])
                    .append(',')
                    .append(r[1])
                    .append(',')
                    .append(r[2].replace(',', ';'))
                    .append('\n');
        }
        Files.writeString(DIR.resolve("tear.csv"), csv.toString());
        StringBuilder md = new StringBuilder("# Tear sweep summary\n\n");
        for (String n : notes) {
            md.append("- ").append(n).append('\n');
        }
        md.append("\nRows: ")
                .append(rows.size())
                .append(", VIOLATIONS: ")
                .append(violations.size())
                .append('\n');
        for (String v : violations) {
            md.append("\n## ").append(v).append('\n');
        }
        Files.writeString(DIR.resolve("tear-summary.md"), md.toString());
    }
}
