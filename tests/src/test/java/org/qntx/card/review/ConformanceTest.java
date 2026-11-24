// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review;

import static org.qntx.card.review.ReviewHost.*;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.qntx.card.review.ReviewSession.Inner;
import org.qntx.card.review.ReviewSession.Raw;
import org.qntx.card.sim.TornException;

/**
 * The conformance runner for the review matrix (matrix.md, the oracle authored from
 * spec/protocol.md). Every cell is one CSV row; sub-cases are suffixed a/b/c. Expectations are
 * never adapted to observed values: a mismatch is recorded DIVERGE with the spec citation.
 *
 * <p>Gated on the environment variable QNTX_REVIEW=full (forwarded to the forked test JVM unlike a
 * -D property): the normal build skips this class. Output dir QNTX_REVIEW_OUT, default {@code
 * build/review} relative to the test working directory.
 */
@EnabledIfEnvironmentVariable(named = "QNTX_REVIEW", matches = "full")
final class ConformanceTest {

    private static final Path OUT =
            Path.of(System.getenv().getOrDefault("QNTX_REVIEW_OUT", "build/review"));

    private static final byte[] S0 =
            unhex(
                    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
                            + "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
    private static final byte[] S1 =
            unhex(
                    "F0E1D2C3B4A5968778695A4B3C2D1E0FF0E1D2C3B4A5968778695A4B3C2D1E0F"
                            + "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
    private static final byte[] H0 = sha256("review access hash H0".getBytes());
    private static final byte[] H1 = sha256("review access hash H1".getBytes());
    private static final byte[] H2 = sha256("review access hash H2".getBytes());
    private static final byte[] H3 = sha256("review access hash H3".getBytes());
    private static final byte[] HT = sha256("review access hash HT".getBytes());
    private static final byte[] X_ID = unhex("11111111111111111111111111111111");
    private static final byte[] Y_ID = unhex("22222222222222222222222222222222");
    private static final byte[] DIGEST = sha256("review digest".getBytes());
    private static final byte[] MSG32 = sha256("review bip340 message".getBytes());
    private static final long HP = 0x8000_0000L; // hardened bit

    // inner INS codes (§9.2)
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

    private Report rep;

    @Test
    void run() {
        if (!bip32MasterValid(S0) || !bip32MasterValid(S1)) {
            throw new IllegalStateException("review seed has an invalid BIP-32 master");
        }
        rep = new Report(OUT);
        long t0 = System.nanoTime();
        try {
            sectionA();
            sectionB();
            sectionC();
            sectionD();
            sectionE();
            sectionF();
            sectionG();
            sectionH();
            sectionI();
        } finally {
            rep.finish(
                    "HEAD under test: review/rewrite. Wall time: "
                            + (System.nanoTime() - t0) / 1_000_000_000L
                            + " s. Response records §8.4-checked: "
                            + ReviewSession.responsesCheckedTotal
                            + ", violations: "
                            + ReviewSession.checkViolations.size());
        }
        // the runner does not fail the build on divergences: the CSV/summary is the deliverable
    }

    // row helpers

    private static String s4(int sw) {
        return String.format("%04X", sw);
    }

    private void cell(String id, String setup, String command, Runnable r) {
        try {
            r.run();
        } catch (Throwable t) {
            rep.row(id, setup, command, "(see matrix)", "threw " + t, "DIVERGE", "cell threw");
        }
    }

    private void row(
            String cell, String setup, String cmd, String expected, String observed, boolean ok) {
        rep.row(cell, setup, cmd, expected, observed, ok ? "PASS" : "DIVERGE", null);
    }

    private void outer(String cell, String setup, String cmd, int expected, byte[] resp) {
        row(
                cell,
                setup,
                cmd,
                s4(expected),
                s4(ReviewHost.sw(resp)),
                ReviewHost.sw(resp) == expected);
    }

    /** Inner SW expectation: observed is "[xxxx]" only when the record layer delivered one. */
    private void inSw(String cell, String setup, String cmd, int expected, Raw r) {
        String obs;
        if (r.outer != 0x9000) {
            obs = "outer " + s4(r.outer);
        } else if (r.inner == null || r.inner.sw < 0) {
            obs =
                    "outer 9000, record check failed ("
                            + (r.inner == null ? "none" : r.inner.sw)
                            + ")";
        } else {
            obs = "[" + s4(r.inner.sw) + "]";
        }
        row(
                cell,
                setup,
                cmd,
                "[" + s4(expected) + "]",
                obs,
                r.outer == 0x9000 && r.inner != null && r.inner.sw == expected);
    }

    private Inner in(ReviewSession s, byte ins, byte p1, byte p2, byte[] data) {
        return s.cmd(ins, p1, p2, data);
    }

    private Raw send(ReviewSession s, byte ins, byte p1, byte p2, byte[] data) {
        return s.send(ins, p1, p2, data);
    }

    private static byte[] apdu(byte cla, byte ins, byte p1, byte p2, byte[] data) {
        return concat(new byte[] {cla, ins, p1, p2, (byte) data.length}, data, new byte[] {0x00});
    }

    private static byte[] pathBytes(long... indices) {
        byte[] out = new byte[1 + 4 * indices.length];
        out[0] = (byte) indices.length;
        for (int i = 0; i < indices.length; i++) {
            byte[] b = u32(indices[i]);
            System.arraycopy(b, 0, out, 1 + 4 * i, 4);
        }
        return out;
    }

    // A. Outer dispatch (§6, §9.1, §4.3, §14)

    private void sectionA() {
        for (String st : new String[] {"U", "F", "B", "L1"}) {
            cell(
                    "A1-" + st,
                    st,
                    "SELECT wallet",
                    () -> {
                        ReviewCard c = ReviewCard.uninitialised();
                        if (!st.equals("U")) {
                            c.factory();
                            if (st.equals("B") || st.equals("L1")) {
                                if (st.equals("L1")) {
                                    c.blank();
                                    c.create(S0, H0);
                                } else {
                                    c.blank();
                                }
                            }
                        }
                        byte[] r = c.transmit(SELECT_WALLET);
                        row(
                                "A1-" + st,
                                st,
                                "SELECT wallet",
                                "9000, no data",
                                s4(ReviewHost.sw(r)) + ", data " + respData(r).length + " B",
                                ReviewHost.sw(r) == 0x9000 && respData(r).length == 0);
                    });
        }

        for (String st : new String[] {"F", "B", "L1"}) {
            for (String cla : new String[] {"00", "84"}) {
                String id = "A" + (cla.equals("00") ? "2" : "3") + "-" + st;
                cell(
                        id,
                        st,
                        "CLA " + cla + " INS E0",
                        () -> {
                            ReviewCard c = prepared(st);
                            outer(
                                    id,
                                    st,
                                    "CLA " + cla + " INS E0",
                                    0x6E00,
                                    c.transmit(unhex(cla + "E0000000")));
                        });
            }
        }

        cell(
                "A4",
                "U",
                "CLA 00 INS E0",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    c.transmit(SELECT_WALLET);
                    outer("A4", "U", "CLA 00 INS E0", 0x6E00, c.transmit(unhex("00E0000000")));
                });

        cell(
                "A5",
                "U",
                "INS 10,12,E2,99,00 with CLA 80",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    c.transmit(SELECT_WALLET);
                    StringBuilder obs = new StringBuilder();
                    for (int ins : new int[] {0x10, 0x12, 0xE2, 0x99, 0x00}) {
                        byte[] r = c.transmit(new byte[] {(byte) 0x80, (byte) ins, 0, 0, 0});
                        obs.append(s4(ReviewHost.sw(r))).append(' ');
                    }
                    int after = initCalls(c);
                    ReviewCard ref = ReviewCard.uninitialised();
                    ref.transmit(SELECT_WALLET);
                    int pristine = initCalls(ref);
                    row(
                            "A5",
                            "U",
                            "INS 10,12,E2,99,00 CLA 80",
                            "6283 each; init not advanced",
                            obs.toString().trim()
                                    + "; calls after "
                                    + after
                                    + " vs pristine "
                                    + pristine,
                            obs.toString().trim().equals("6283 6283 6283 6283 6283")
                                    && after == pristine);
                });

        cell(
                "A6",
                "U",
                "GET_IDENTITY repeated",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    c.transmit(SELECT_WALLET);
                    int calls = 0;
                    byte[] r;
                    boolean allBeforeWere6283 = true;
                    do {
                        r = c.transmit(unhex("80E0000000"));
                        calls++;
                        if (ReviewHost.sw(r) != 0x6283 && ReviewHost.sw(r) != 0x9000) {
                            allBeforeWere6283 = false;
                        }
                    } while (ReviewHost.sw(r) == 0x6283 && calls < 20);
                    byte[] a = respData(r);
                    boolean ok =
                            ReviewHost.sw(r) == 0x9000
                                    && a.length == 33
                                    && (a[0] == 0x02 || a[0] == 0x03)
                                    && decompress(a) != null
                                    && calls <= 16
                                    && allBeforeWere6283;
                    row(
                            "A6",
                            "U",
                            "GET_IDENTITY repeated",
                            "6283…6283 then 9000 + A(33) decompressing, ≤16 calls",
                            ok
                                    ? s4(ReviewHost.sw(r))
                                            + ", "
                                            + a.length
                                            + " B, decompresses, "
                                            + calls
                                            + " calls"
                                    : "last "
                                            + s4(ReviewHost.sw(r))
                                            + ", "
                                            + a.length
                                            + " B, "
                                            + calls
                                            + " calls, prior-6283 "
                                            + allBeforeWere6283
                                            + ", decompress "
                                            + (decompress(a) != null),
                            ok);
                });

        cell(
                "A7",
                "U",
                "GET_IDENTITY P1=01 repeated",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    c.transmit(SELECT_WALLET);
                    int calls = 0;
                    byte[] r;
                    do {
                        r = c.transmit(unhex("80E0010000"));
                        calls++;
                    } while (ReviewHost.sw(r) == 0x6283 && calls < 20);
                    int completing = ReviewHost.sw(r);
                    byte[] after = c.transmit(unhex("80E0000000"));
                    row(
                            "A7",
                            "U",
                            "GET_IDENTITY P1=01 repeated",
                            "6283 while steps remain; completing call 6A86; then 9000",
                            "completing "
                                    + s4(completing)
                                    + " after "
                                    + calls
                                    + " calls; then "
                                    + s4(ReviewHost.sw(after)),
                            completing == 0x6A86 && ReviewHost.sw(after) == 0x9000);
                });

        cell(
                "A8",
                "U",
                "GET_IDENTITY Lc=1 repeated",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    c.transmit(SELECT_WALLET);
                    int calls = 0;
                    byte[] r;
                    do {
                        r = c.transmit(unhex("80E000000100"));
                        calls++;
                    } while (ReviewHost.sw(r) == 0x6283 && calls < 20);
                    int completing = ReviewHost.sw(r);
                    byte[] after = c.transmit(unhex("80E0000000"));
                    row(
                            "A8",
                            "U",
                            "GET_IDENTITY Lc=1 repeated",
                            "6283 …; completing call 6700; then 9000",
                            "completing "
                                    + s4(completing)
                                    + " after "
                                    + calls
                                    + " calls; then "
                                    + s4(ReviewHost.sw(after)),
                            completing == 0x6700 && ReviewHost.sw(after) == 0x9000);
                });

        for (String st : new String[] {"F", "B", "L1"}) {
            for (int ins : new int[] {0x00, 0x20, 0xFF, 0xE4}) {
                String id = "A9-" + st + "-" + String.format("%02X", ins);
                cell(
                        id,
                        st,
                        "INS " + String.format("%02X", ins),
                        () -> {
                            ReviewCard c = prepared(st);
                            outer(
                                    id,
                                    st,
                                    "INS " + String.format("%02X", ins),
                                    0x6D00,
                                    c.transmit(new byte[] {(byte) 0x80, (byte) ins, 0, 0, 0}));
                        });
            }
        }

        cell(
                "A10",
                "F",
                "GET_IDENTITY",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    byte[] a = c.factory();
                    byte[] r = c.transmit(unhex("80E0000000"));
                    row(
                            "A10",
                            "F",
                            "GET_IDENTITY",
                            "9000, 33 B, equal to A6's A",
                            s4(ReviewHost.sw(r))
                                    + ", "
                                    + respData(r).length
                                    + " B, "
                                    + (Arrays.equals(respData(r), a) ? "equal" : "DIFFERENT"),
                            ReviewHost.sw(r) == 0x9000
                                    && respData(r).length == 33
                                    && Arrays.equals(respData(r), a));
                });

        for (String st : new String[] {"B", "L1"}) {
            for (String p : new String[] {"00", "01"}) {
                String id = "A11-" + st + "-p" + p;
                cell(
                        id,
                        st,
                        "GET_IDENTITY P1=" + p,
                        () -> {
                            ReviewCard c = prepared(st);
                            outer(
                                    id,
                                    st,
                                    "GET_IDENTITY P1=" + p,
                                    0x6985,
                                    c.transmit(unhex("80E0" + p + "0000")));
                        });
            }
        }

        cell(
                "A12a",
                "F",
                "GET_IDENTITY P1=01",
                () -> {
                    ReviewCard c = prepared("F");
                    outer(
                            "A12a",
                            "F",
                            "GET_IDENTITY P1=01",
                            0x6A86,
                            c.transmit(unhex("80E0010000")));
                });
        cell(
                "A12b",
                "F",
                "GET_IDENTITY P2=01",
                () -> {
                    ReviewCard c = prepared("F");
                    outer(
                            "A12b",
                            "F",
                            "GET_IDENTITY P2=01",
                            0x6A86,
                            c.transmit(unhex("80E0000100")));
                });
        cell(
                "A13",
                "F",
                "GET_IDENTITY Lc=1",
                () -> {
                    ReviewCard c = prepared("F");
                    outer(
                            "A13",
                            "F",
                            "GET_IDENTITY Lc=1",
                            0x6700,
                            c.transmit(unhex("80E000000100")));
                });
    }

    private int initCalls(ReviewCard c) {
        int calls = 0;
        byte[] r;
        do {
            r = c.transmit(unhex("80E0000000"));
            calls++;
        } while (ReviewHost.sw(r) == 0x6283 && calls < 20);
        return calls;
    }

    /** A card prepared to setup F, B or L1 (wallet selected, uninitialised driven on). */
    private ReviewCard prepared(String setup) {
        ReviewCard c = ReviewCard.uninitialised();
        switch (setup) {
            case "F":
                c.factory();
                break;
            case "B":
                c.blank();
                break;
            case "L1":
                c.blank();
                c.create(S0, H0);
                break;
            default:
                break;
        }
        return c;
    }

    // B. PERSONALIZE (§14.2, §5.2)

    private void personalizeCheck(
            String cell,
            String setup,
            String cmd,
            ReviewCard c,
            byte[] data,
            int expectedSw,
            byte p1) {
        byte[] r =
                c.transmit(
                        concat(
                                unhex("80E2"),
                                new byte[] {p1, 0, (byte) data.length},
                                data,
                                new byte[] {0x00}));
        outer(cell, setup, cmd, expectedSw, r);
    }

    private void sectionB() {
        ReviewCard.Ca ca = ReviewCard.CA;

        for (String st : new String[] {"B", "L1"}) {
            cell(
                    "B1-" + st,
                    st,
                    "PERSONALIZE valid / P1=01 / Lc=161",
                    () -> {
                        ReviewCard c = prepared(st);
                        byte[] a = c.cardA;
                        byte[] good = concat(ca.issue(a), ca.pub65);
                        StringBuilder obs = new StringBuilder();
                        obs.append(
                                s4(
                                        ReviewHost.sw(
                                                c.transmit(
                                                        apdu(
                                                                (byte) 0x80,
                                                                (byte) 0xE2,
                                                                (byte) 0,
                                                                (byte) 0,
                                                                good)))));
                        byte[] r2 =
                                c.transmit(
                                        concat(
                                                unhex("80E20100"),
                                                new byte[] {(byte) good.length},
                                                good,
                                                new byte[] {0x00}));
                        obs.append(' ').append(s4(ReviewHost.sw(r2)));
                        byte[] short161 = slice(good, 0, 161);
                        byte[] r3 =
                                c.transmit(
                                        concat(
                                                unhex("80E20000"),
                                                new byte[] {(byte) 161},
                                                short161,
                                                new byte[] {0x00}));
                        obs.append(' ').append(s4(ReviewHost.sw(r3)));
                        row(
                                "B1-" + st,
                                st,
                                "PERSONALIZE valid / P1=01 / Lc=161",
                                "6985 6985 6985",
                                obs.toString(),
                                obs.toString().equals("6985 6985 6985"));
                    });
        }

        cell(
                "B2",
                "F",
                "P1=01 (also Lc=161)",
                () -> {
                    ReviewCard c = prepared("F");
                    byte[] a = c.cardA;
                    byte[] good = concat(ca.issue(a), ca.pub65);
                    byte[] r1 =
                            c.transmit(
                                    concat(
                                            unhex("80E20100"),
                                            new byte[] {(byte) good.length},
                                            good,
                                            new byte[] {0x00}));
                    byte[] r2 =
                            c.transmit(
                                    concat(
                                            unhex("80E20100"),
                                            new byte[] {(byte) 161},
                                            slice(good, 0, 161),
                                            new byte[] {0x00}));
                    row(
                            "B2",
                            "F",
                            "P1=01 (also Lc=161)",
                            "6A86 6A86",
                            s4(ReviewHost.sw(r1)) + " " + s4(ReviewHost.sw(r2)),
                            ReviewHost.sw(r1) == 0x6A86 && ReviewHost.sw(r2) == 0x6A86);
                });

        cell(
                "B3",
                "F",
                "Lc=161, Lc=163",
                () -> {
                    ReviewCard c = prepared("F");
                    byte[] a = c.cardA;
                    byte[] good = concat(ca.issue(a), ca.pub65);
                    StringBuilder obs = new StringBuilder();
                    for (int lc : new int[] {161, 163}) {
                        byte[] d = new byte[lc];
                        System.arraycopy(good, 0, d, 0, Math.min(lc, good.length));
                        byte[] r =
                                c.transmit(
                                        concat(
                                                unhex("80E20000"),
                                                new byte[] {(byte) lc},
                                                d,
                                                new byte[] {0x00}));
                        obs.append(s4(ReviewHost.sw(r))).append(' ');
                    }
                    row(
                            "B3",
                            "F",
                            "Lc=161, Lc=163",
                            "6700 6700",
                            obs.toString().trim(),
                            obs.toString().trim().equals("6700 6700"));
                });

        // B4–B8, B10 share one FACTORY card: every failed attempt must leave it FACTORY
        {
            ReviewCard c = prepared("F");
            byte[] a = c.cardA;

            cell(
                    "B4",
                    "F",
                    "cert[0..33) = another valid compressed key, CA-signed",
                    () -> {
                        byte[] other = compr(g().multiply(BigInteger.valueOf(4242)));
                        byte[] bad = concat(ca.issue(other), ca.pub65);
                        personalizeCheck(
                                "B4", "F", "cert of another key", c, bad, 0x6A80, (byte) 0);
                    });

            cell(
                    "B5a",
                    "F",
                    "caKey[0]=05",
                    () -> {
                        byte[] w = ca.pub65.clone();
                        w[0] = 0x05;
                        personalizeCheck(
                                "B5a",
                                "F",
                                "caKey[0]=05",
                                c,
                                concat(ca.issue(a), w),
                                0x6A80,
                                (byte) 0);
                    });
            cell(
                    "B5b",
                    "F",
                    "caKey x = p",
                    () -> {
                        byte[] w = concat(new byte[] {0x04}, i2b(P, 32), i2b(BigInteger.ONE, 32));
                        personalizeCheck(
                                "B5b",
                                "F",
                                "caKey x = p",
                                c,
                                concat(ca.issue(a), w),
                                0x6A80,
                                (byte) 0);
                    });
            cell(
                    "B5c",
                    "F",
                    "caKey y = p",
                    () -> {
                        byte[] w = concat(new byte[] {0x04}, i2b(BigInteger.ONE, 32), i2b(P, 32));
                        personalizeCheck(
                                "B5c",
                                "F",
                                "caKey y = p",
                                c,
                                concat(ca.issue(a), w),
                                0x6A80,
                                (byte) 0);
                    });
            cell(
                    "B5d",
                    "F",
                    "caKey off-curve (y+1)",
                    () -> {
                        BigInteger x = g().getXCoord().toBigInteger();
                        BigInteger y = g().getYCoord().toBigInteger().add(BigInteger.ONE).mod(P);
                        byte[] w = concat(new byte[] {0x04}, i2b(x, 32), i2b(y, 32));
                        personalizeCheck(
                                "B5d",
                                "F",
                                "caKey off-curve",
                                c,
                                concat(ca.issue(a), w),
                                0x6A80,
                                (byte) 0);
                    });
            cell(
                    "B5e",
                    "F",
                    "caKey = 04‖0⁶⁴",
                    () -> {
                        byte[] w = concat(new byte[] {0x04}, new byte[64]);
                        personalizeCheck(
                                "B5e",
                                "F",
                                "caKey 04‖0⁶⁴",
                                c,
                                concat(ca.issue(a), w),
                                0x6A80,
                                (byte) 0);
                    });

            cell(
                    "B6",
                    "F",
                    "cert signed by a different CA",
                    () -> {
                        ReviewCard.Ca other = new ReviewCard.Ca(BigInteger.valueOf(0xBEEF));
                        byte[] bad = concat(other.issue(a), ca.pub65);
                        personalizeCheck(
                                "B6", "F", "cert under another CA", c, bad, 0x6A80, (byte) 0);
                    });

            byte[] goodSig = ca.sign(concat(LABEL_CERT, a));
            BigInteger r0 = b2i(slice(goodSig, 0, 32));
            BigInteger s0 = b2i(slice(goodSig, 32, 32));
            cell(
                    "B7a",
                    "F",
                    "r = 0",
                    () -> {
                        byte[] bad = concat(a, new byte[32], i2b(s0, 32), ca.pub65);
                        personalizeCheck("B7a", "F", "r = 0", c, bad, 0x6A80, (byte) 0);
                    });
            cell(
                    "B7b",
                    "F",
                    "s = 0",
                    () -> {
                        byte[] bad = concat(a, i2b(r0, 32), new byte[32], ca.pub65);
                        personalizeCheck("B7b", "F", "s = 0", c, bad, 0x6A80, (byte) 0);
                    });
            cell(
                    "B7c",
                    "F",
                    "s = n",
                    () -> {
                        byte[] bad = concat(a, i2b(r0, 32), i2b(N, 32), ca.pub65);
                        personalizeCheck("B7c", "F", "s = n", c, bad, 0x6A80, (byte) 0);
                    });
            cell(
                    "B7d",
                    "F",
                    "r = n",
                    () -> {
                        byte[] bad = concat(a, i2b(N, 32), i2b(s0, 32), ca.pub65);
                        personalizeCheck("B7d", "F", "r = n", c, bad, 0x6A80, (byte) 0);
                    });

            cell(
                    "B10",
                    "F",
                    "after failed B4–B7: still FACTORY",
                    () -> {
                        byte[] gi = c.transmit(unhex("80E0000000"));
                        byte[] op =
                                c.transmit(
                                        apdu(
                                                (byte) 0x80,
                                                (byte) 0x10,
                                                (byte) 0,
                                                (byte) 0,
                                                uncomp(g().multiply(BigInteger.valueOf(7)))));
                        row(
                                "B10",
                                "F",
                                "still FACTORY",
                                "GET_IDENTITY 9000; OPEN 6985",
                                "GET_IDENTITY "
                                        + s4(ReviewHost.sw(gi))
                                        + "; OPEN "
                                        + s4(ReviewHost.sw(op)),
                                ReviewHost.sw(gi) == 0x9000 && ReviewHost.sw(op) == 0x6985);
                    });
        }

        cell(
                "B8",
                "F",
                "cert with high s (n − s of a valid signature)",
                () -> {
                    ReviewCard c = prepared("F");
                    byte[] a = c.cardA;
                    byte[] sig = ca.sign(concat(LABEL_CERT, a));
                    BigInteger r = b2i(slice(sig, 0, 32));
                    BigInteger s = b2i(slice(sig, 32, 32));
                    BigInteger sh = N.subtract(s);
                    byte[] cert = concat(a, i2b(r, 32), i2b(sh, 32), ca.pub65);
                    personalizeCheck("B8", "F", "high-s cert", c, cert, 0x9000, (byte) 0);
                });

        cell(
                "B9",
                "F",
                "valid",
                () -> {
                    ReviewCard c = prepared("F");
                    byte[] a = c.cardA;
                    byte[] cert = ca.issue(a);
                    personalizeCheck(
                            "B9a",
                            "F",
                            "valid personalize",
                            c,
                            concat(cert, ca.pub65),
                            0x9000,
                            (byte) 0);
                    byte[] gi = c.transmit(unhex("80E0000000"));
                    String giObs = s4(ReviewHost.sw(gi));
                    ReviewSession s = new ReviewSession(c.card::transmit, ca.pub65);
                    byte[] opened = s.open();
                    String certObs =
                            opened != null && Arrays.equals(slice(opened, 129, 97), cert)
                                    ? "returns this cert"
                                    : "cert mismatch/open failed";
                    row(
                            "B9b",
                            "F",
                            "GET_IDENTITY; OPEN returns cert",
                            "6985; returns this cert",
                            giObs + "; " + certObs,
                            ReviewHost.sw(gi) == 0x6985 && certObs.equals("returns this cert"));
                });
    }

    // C. OPEN (§8.1)

    private byte[] openApdu(byte p1, byte p2, byte[] hostEph) {
        return concat(
                unhex("8010"),
                new byte[] {p1, p2, (byte) hostEph.length},
                hostEph,
                new byte[] {0x00});
    }

    private void sectionC() {
        cell(
                "C1",
                "F",
                "OPEN valid and P1=01",
                () -> {
                    ReviewCard c = prepared("F");
                    byte[] eph = uncomp(g().multiply(BigInteger.valueOf(9)));
                    byte[] r1 = c.transmit(openApdu((byte) 0, (byte) 0, eph));
                    byte[] r2 = c.transmit(openApdu((byte) 1, (byte) 0, eph));
                    row(
                            "C1",
                            "F",
                            "OPEN valid, P1=01",
                            "6985 6985",
                            s4(ReviewHost.sw(r1)) + " " + s4(ReviewHost.sw(r2)),
                            ReviewHost.sw(r1) == 0x6985 && ReviewHost.sw(r2) == 0x6985);
                });

        for (String st : new String[] {"B", "L1"}) {
            for (String pp : new String[] {"01", "0001"}) {
                boolean p1 = pp.equals("01");
                String id = "C2-" + st + "-" + (p1 ? "P1" : "P2");
                cell(
                        id,
                        st,
                        "OPEN " + (p1 ? "P1=01" : "P2=01"),
                        () -> {
                            ReviewCard c = prepared(st);
                            byte[] eph = uncomp(g().multiply(BigInteger.valueOf(9)));
                            byte[] r =
                                    c.transmit(openApdu(p1 ? (byte) 1 : 0, p1 ? (byte) 0 : 1, eph));
                            outer(id, st, "OPEN " + (p1 ? "P1=01" : "P2=01"), 0x6A86, r);
                        });
            }
        }

        cell(
                "C3",
                "B",
                "Lc=64, Lc=66",
                () -> {
                    ReviewCard c = prepared("B");
                    byte[] eph = uncomp(g().multiply(BigInteger.valueOf(9)));
                    StringBuilder obs = new StringBuilder();
                    for (int len : new int[] {64, 66}) {
                        byte[] d = new byte[len];
                        System.arraycopy(eph, 0, d, 0, Math.min(len, 65));
                        byte[] r = c.transmit(openApdu((byte) 0, (byte) 0, d));
                        obs.append(s4(ReviewHost.sw(r))).append(' ');
                    }
                    row(
                            "C3",
                            "B",
                            "Lc=64, Lc=66",
                            "6700 6700",
                            obs.toString().trim(),
                            obs.toString().trim().equals("6700 6700"));
                });

        cell(
                "C4",
                "B",
                "hostEph[0] = 02, 00, 06",
                () -> {
                    ReviewCard c = prepared("B");
                    StringBuilder obs = new StringBuilder();
                    for (byte b : new byte[] {0x02, 0x00, 0x06}) {
                        byte[] eph = uncomp(g().multiply(BigInteger.valueOf(9)));
                        eph[0] = b;
                        byte[] r = c.transmit(openApdu((byte) 0, (byte) 0, eph));
                        obs.append(s4(ReviewHost.sw(r))).append(' ');
                    }
                    row(
                            "C4",
                            "B",
                            "hostEph[0] = 02, 00, 06",
                            "6A80 6A80 6A80",
                            obs.toString().trim(),
                            obs.toString().trim().equals("6A80 6A80 6A80"));
                });

        cell(
                "C5a",
                "B",
                "04‖x‖y off-curve",
                () -> {
                    ReviewCard c = prepared("B");
                    byte[] eph =
                            concat(
                                    new byte[] {0x04},
                                    i2b(BigInteger.ONE, 32),
                                    i2b(BigInteger.valueOf(3), 32));
                    outer(
                            "C5a",
                            "B",
                            "off-curve point",
                            0x6A80,
                            c.transmit(openApdu((byte) 0, (byte) 0, eph)));
                });
        cell(
                "C5b",
                "B",
                "x = p",
                () -> {
                    ReviewCard c = prepared("B");
                    byte[] eph = concat(new byte[] {0x04}, i2b(P, 32), i2b(BigInteger.ONE, 32));
                    outer(
                            "C5b",
                            "B",
                            "x = p",
                            0x6A80,
                            c.transmit(openApdu((byte) 0, (byte) 0, eph)));
                });
        cell(
                "C5c",
                "B",
                "y = p",
                () -> {
                    ReviewCard c = prepared("B");
                    byte[] eph = concat(new byte[] {0x04}, i2b(BigInteger.ONE, 32), i2b(P, 32));
                    outer(
                            "C5c",
                            "B",
                            "y = p",
                            0x6A80,
                            c.transmit(openApdu((byte) 0, (byte) 0, eph)));
                });
        cell(
                "C5d",
                "B",
                "04‖0⁶⁴",
                () -> {
                    ReviewCard c = prepared("B");
                    byte[] eph = concat(new byte[] {0x04}, new byte[64]);
                    outer(
                            "C5d",
                            "B",
                            "04‖0⁶⁴",
                            0x6A80,
                            c.transmit(openApdu((byte) 0, (byte) 0, eph)));
                });
        cell(
                "C5e",
                "B",
                "twist x (no curve y)",
                () -> {
                    ReviewCard c = prepared("B");
                    BigInteger x = BigInteger.ZERO;
                    for (long i = 1; ; i++) {
                        BigInteger cand = BigInteger.valueOf(i);
                        BigInteger z =
                                cand.modPow(BigInteger.valueOf(3), P)
                                        .add(BigInteger.valueOf(7))
                                        .mod(P);
                        if (z.modPow(P.subtract(BigInteger.ONE).shiftRight(1), P)
                                .equals(P.subtract(BigInteger.ONE))) {
                            x = cand;
                            break;
                        }
                    }
                    byte[] eph =
                            concat(new byte[] {0x04}, i2b(x, 32), i2b(BigInteger.valueOf(5), 32));
                    outer(
                            "C5e",
                            "B",
                            "non-residue x",
                            0x6A80,
                            c.transmit(openApdu((byte) 0, (byte) 0, eph)));
                });
        cell(
                "C5f",
                "B",
                "small-order point on invalid curve",
                () -> {
                    ReviewCard c = prepared("B");
                    // (1, 3) satisfies y² = x³ + 8 (mod p), a curve that is not secp256k1
                    byte[] eph =
                            concat(
                                    new byte[] {0x04},
                                    i2b(BigInteger.ONE, 32),
                                    i2b(BigInteger.valueOf(3), 32));
                    outer(
                            "C5f",
                            "B",
                            "point on y² = x³ + 8",
                            0x6A80,
                            c.transmit(openApdu((byte) 0, (byte) 0, eph)));
                });

        cell(
                "C6",
                "B",
                "valid OPEN",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = new ReviewSession(c.card::transmit, ReviewCard.CA.pub65);
                    byte[] resp = s.open();
                    boolean ok = resp != null && resp.length == 226;
                    String detail;
                    if (!ok) {
                        detail = "open failed: " + s.openFailure;
                    } else {
                        Raw st = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                        detail =
                                "226 B; cardEph on curve; sig under cert A; STATUS "
                                        + (st.inner != null ? s4(st.inner.sw) : "record failed");
                    }
                    row(
                            "C6",
                            "B",
                            "valid OPEN",
                            "9000, 226 B; cardEph on curve; sig verifies under cert A; STATUS works",
                            detail,
                            ok && detail.endsWith("STATUS 9000"));
                });

        cell(
                "C7",
                "B s",
                "OPEN P1=01 (rejected)",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    byte[] eph = uncomp(g().multiply(BigInteger.valueOf(11)));
                    byte[] r = c.transmit(openApdu((byte) 1, (byte) 0, eph));
                    Raw st = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "C7",
                            "B s",
                            "OPEN P1=01 then STATUS",
                            "6A86; STATUS still works",
                            s4(ReviewHost.sw(r))
                                    + "; STATUS "
                                    + (st.inner != null
                                            ? s4(st.inner.sw)
                                            : "outer " + s4(st.outer)),
                            ReviewHost.sw(r) == 0x6A86
                                    && st.inner != null
                                    && st.inner.sw == 0x9000);
                });

        cell(
                "C8",
                "B s",
                "OPEN off-curve hostEph",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    byte[] eph =
                            concat(
                                    new byte[] {0x04},
                                    i2b(BigInteger.ONE, 32),
                                    i2b(BigInteger.valueOf(3), 32));
                    byte[] r = c.transmit(openApdu((byte) 0, (byte) 0, eph));
                    Raw st = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "C8",
                            "B s",
                            "OPEN off-curve then record",
                            "6A80; record → outer 6985",
                            s4(ReviewHost.sw(r)) + "; record outer " + s4(st.outer),
                            ReviewHost.sw(r) == 0x6A80 && st.outer == 0x6985);
                });

        cell(
                "C9",
                "B",
                "20 OPENs distinct cardEph",
                () -> {
                    ReviewCard c = prepared("B");
                    HashSet<String> seen = new HashSet<>();
                    int ok = 0;
                    for (int i = 0; i < 20; i++) {
                        byte[] eph = uncomp(g().multiply(randomScalar()));
                        byte[] r = c.transmit(openApdu((byte) 0, (byte) 0, eph));
                        if (ReviewHost.sw(r) == 0x9000 && respData(r).length == 226) {
                            seen.add(hex(slice(respData(r), 0, 65)));
                            ok++;
                        }
                    }
                    row(
                            "C9",
                            "B",
                            "20 OPENs",
                            "20 pairwise distinct cardEph",
                            ok + " succeeded, " + seen.size() + " distinct",
                            ok == 20 && seen.size() == 20);
                });
    }

    // D. SESSION record layer (§8.3–8.5)

    private void sectionD() {
        for (String st : new String[] {"B", "L1"}) {
            cell(
                    "D1-" + st,
                    st + " .",
                    "any record, no session",
                    () -> {
                        ReviewCard c = prepared(st);
                        c.transmit(SELECT_WALLET);
                        byte[] rec = new byte[32];
                        byte[] r =
                                c.transmit(
                                        concat(
                                                unhex("80120000"),
                                                new byte[] {(byte) rec.length},
                                                rec,
                                                new byte[] {0x00}));
                        outer("D1-" + st, st + " .", "record without session", 0x6985, r);
                    });
        }

        cell(
                "D2",
                "F",
                "any record",
                () -> {
                    ReviewCard c = prepared("F");
                    byte[] rec = new byte[32];
                    byte[] r =
                            c.transmit(
                                    concat(
                                            unhex("80120000"),
                                            new byte[] {(byte) rec.length},
                                            rec,
                                            new byte[] {0x00}));
                    outer("D2", "F", "record without session", 0x6985, r);
                });

        cell(
                "D3",
                "B s",
                "outer P1=01",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    byte[] rec = s.record(INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    byte[] r = c.transmit(s.recordApdu((byte) 1, (byte) 0, rec));
                    int first = ReviewHost.sw(r);
                    Raw next = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "D3",
                            "B s",
                            "outer P1=01; next valid record",
                            "6982; 6985",
                            s4(first) + "; " + s4(next.outer),
                            first == 0x6982 && next.outer == 0x6985);
                });

        cell(
                "D4",
                "B s",
                "Lc=16, 23, 40, 25",
                () -> {
                    StringBuilder obs = new StringBuilder();
                    ReviewCard c = prepared("B");
                    for (int lc : new int[] {16, 23, 40, 25}) {
                        ReviewSession s = c.open();
                        byte[] r =
                                c.transmit(
                                        concat(
                                                unhex("80120000"),
                                                new byte[] {(byte) lc},
                                                new byte[lc],
                                                new byte[] {0x00}));
                        Raw next = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                        obs.append(s4(ReviewHost.sw(r)))
                                .append('/')
                                .append(s4(next.outer))
                                .append(' ');
                    }
                    row(
                            "D4",
                            "B s",
                            "Lc=16, 23, 40, 25",
                            "6982 each; session gone",
                            obs.toString().trim(),
                            obs.toString()
                                    .trim()
                                    .equals("6982/6985 6982/6985 6982/6985 6982/6985"));
                });

        cell(
                "D5",
                "B s",
                "tag with one bit flipped",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    byte[] rec = s.record(INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    rec[rec.length - 1] ^= 0x01;
                    byte[] r = c.transmit(s.recordApdu((byte) 0, (byte) 0, rec));
                    Raw next = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "D5",
                            "B s",
                            "flipped tag; next record",
                            "6982; 6985",
                            s4(ReviewHost.sw(r)) + "; " + s4(next.outer),
                            ReviewHost.sw(r) == 0x6982 && next.outer == 0x6985);
                });

        cell(
                "D6",
                "B s",
                "record built with ctr+1",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    s.ctr += 1;
                    byte[] rec = s.record(INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    s.ctr -= 1;
                    byte[] r = c.transmit(s.recordApdu((byte) 0, (byte) 0, rec));
                    Raw next = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "D6",
                            "B s",
                            "ctr+1 record; next record",
                            "6982; 6985",
                            s4(ReviewHost.sw(r)) + "; " + s4(next.outer),
                            ReviewHost.sw(r) == 0x6982 && next.outer == 0x6985);
                });

        cell(
                "D7",
                "B s",
                "replay of the previous accepted record",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    byte[] apdu =
                            s.recordApdu(
                                    (byte) 0,
                                    (byte) 0,
                                    s.record(INS_STATUS, (byte) 0, (byte) 0, new byte[0]));
                    byte[] first = c.transmit(apdu);
                    byte[] second = c.transmit(apdu);
                    row(
                            "D7",
                            "B s",
                            "accepted then replayed",
                            "9000; 6982",
                            s4(ReviewHost.sw(first)) + "; " + s4(ReviewHost.sw(second)),
                            ReviewHost.sw(first) == 0x9000 && ReviewHost.sw(second) == 0x6982);
                });

        for (String variant : new String[] {"last block all zero", "last non-zero byte 81"}) {
            cell(
                    "D8-" + (variant.contains("zero") ? "a" : "b"),
                    "B s",
                    "valid tag, bad M2: " + variant,
                    () -> {
                        ReviewCard c = prepared("B");
                        ReviewSession s = c.open();
                        byte[] plain = new byte[32];
                        plain[0] = INS_STATUS;
                        if (!variant.contains("zero")) {
                            plain[3] = (byte) 0x81;
                        }
                        byte[] iv =
                                aesBlock(
                                        s.kce, concat(new byte[] {0x01}, new byte[13], u16(s.ctr)));
                        byte[] ct = cbc(s.kce, iv, plain);
                        byte[] tag = slice(cmac(s.kcm, u16(s.ctr), ct), 0, 8);
                        byte[] r = c.transmit(s.recordApdu((byte) 0, (byte) 0, concat(ct, tag)));
                        row(
                                "D8",
                                "B s",
                                "valid tag over bad-M2 plaintext (" + variant + ")",
                                "6982",
                                s4(ReviewHost.sw(r)),
                                ReviewHost.sw(r) == 0x6982);
                    });
        }

        cell(
                "D9",
                "B s",
                "reflection: card's last response record",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    byte[] r = c.transmit(s.recordApdu((byte) 0, (byte) 0, s.lastResponseRecord));
                    row(
                            "D9",
                            "B s",
                            "reflected response record",
                            "6982",
                            s4(ReviewHost.sw(r)),
                            ReviewHost.sw(r) == 0x6982);
                });

        cell(
                "D10",
                "B s",
                "plaintext of 2 bytes",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    byte[] plain = m2(new byte[] {0x20, 0x00});
                    byte[] iv =
                            aesBlock(s.kce, concat(new byte[] {0x01}, new byte[13], u16(s.ctr)));
                    byte[] ct = cbc(s.kce, iv, plain);
                    byte[] tag = slice(cmac(s.kcm, u16(s.ctr), ct), 0, 8);
                    Raw r = s.raw(s.recordApdu((byte) 0, (byte) 0, concat(ct, tag)));
                    Raw next = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "D10",
                            "B s",
                            "2-byte plaintext; next STATUS",
                            "outer 9000 [6700]; session survives",
                            "outer "
                                    + s4(r.outer)
                                    + " ["
                                    + (r.inner != null ? s4(r.inner.sw) : "?")
                                    + "]; next "
                                    + (next.inner != null
                                            ? s4(next.inner.sw)
                                            : "outer " + s4(next.outer)),
                            r.outer == 0x9000
                                    && r.inner != null
                                    && r.inner.sw == 0x6700
                                    && next.inner != null
                                    && next.inner.sw == 0x9000);
                });

        cell(
                "D11",
                "B s",
                "plaintext 20 00 00",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    Raw r = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "D11",
                            "B s",
                            "3-byte plaintext = STATUS",
                            "[9000] 01 00",
                            r.inner != null
                                    ? "[" + s4(r.inner.sw) + "] " + hex(r.inner.data)
                                    : "outer " + s4(r.outer),
                            r.inner != null
                                    && r.inner.sw == 0x9000
                                    && Arrays.equals(r.inner.data, new byte[] {0x01, 0x00}));
                });

        cell(
                "D12",
                "L1 v",
                "max record Lc=248, SIGN_ED25519 update 236 B",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    Raw begin =
                            send(s, INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(HP, HP + 1));
                    Raw upd = send(s, INS_SIGN_ED25519, (byte) 1, (byte) 0, new byte[236]);
                    row(
                            "D12",
                            "L1 v",
                            "236-B update after begin",
                            "[9000]",
                            (begin.inner != null ? s4(begin.inner.sw) : "?")
                                    + " → "
                                    + (upd.inner != null
                                            ? "[" + s4(upd.inner.sw) + "]"
                                            : "outer " + s4(upd.outer))
                                    + " (record Lc "
                                    + (236 + 3 + 1 + 8)
                                    + ")",
                            upd.inner != null && upd.inner.sw == 0x9000);
                });

        cell(
                "D13",
                "B s",
                "65536 STATUS records",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    long t0 = System.nanoTime();
                    int good = 0;
                    int badAt = -1;
                    for (int i = 0; i < 65536; i++) {
                        Raw r = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                        if (r.outer == 0x9000 && r.inner != null && r.inner.sw == 0x9000) {
                            good++;
                        } else {
                            badAt = i;
                            break;
                        }
                    }
                    Raw after = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    long ms = (System.nanoTime() - t0) / 1_000_000;
                    row(
                            "D13",
                            "B s",
                            "65536 STATUS records; then one more",
                            "all [9000]; ctr 0xFFFF response valid; next → 6985",
                            good
                                    + " good"
                                    + (badAt >= 0 ? ", first bad at record " + badAt : "")
                                    + "; next outer "
                                    + s4(after.outer)
                                    + "; "
                                    + ms
                                    + " ms",
                            good == 65536 && after.outer == 0x6985);
                });

        cell(
                "D14",
                "every cell",
                "response record §8.4 checks",
                () -> {
                    row(
                            "D14",
                            "every cell",
                            "outer 9000, K_rm tag, IV 02‖ctr, valid M2",
                            "all response records pass",
                            ReviewSession.checkViolations.isEmpty()
                                    ? "all "
                                            + ReviewSession.responsesCheckedTotal
                                            + " checked responses pass"
                                    : ReviewSession.checkViolations.size()
                                            + " violations: "
                                            + ReviewSession.checkViolations.get(0),
                            ReviewSession.checkViolations.isEmpty());
                });

        cell(
                "D15",
                "L1 v",
                "SELECT wallet then a record; new OPEN + PUBLIC_KEY",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    c.transmit(SELECT_WALLET);
                    Raw rec = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    ReviewSession s2 = c.open();
                    Raw pk = send(s2, INS_PUBLIC_KEY, (byte) 0, (byte) 0, pathBytes(0));
                    row(
                            "D15",
                            "L1 v",
                            "SELECT; record; new session PUBLIC_KEY",
                            "6985; [6982]",
                            s4(rec.outer)
                                    + "; ["
                                    + (pk.inner != null ? s4(pk.inner.sw) : "outer " + s4(pk.outer))
                                    + "]",
                            rec.outer == 0x6985 && pk.inner != null && pk.inner.sw == 0x6982);
                });

        cell(
                "D16",
                "L1 v",
                "SELECT NDEF, SELECT wallet, record",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    c.transmit(SELECT_NDEF);
                    c.transmit(SELECT_WALLET);
                    Raw rec = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "D16",
                            "L1 v",
                            "record after reselect",
                            "6985",
                            s4(rec.outer),
                            rec.outer == 0x6985);
                });

        cell(
                "D17",
                "L1 v",
                "power cycle, SELECT, record",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    c.card.powerCycle();
                    c.transmit(SELECT_WALLET);
                    Raw rec = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "D17",
                            "L1 v",
                            "record after power cycle",
                            "6985",
                            s4(rec.outer),
                            rec.outer == 0x6985);
                });

        cell(
                "D18",
                "L1 v",
                "second OPEN in same selection, PUBLIC_KEY",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    ReviewSession s2 = c.open();
                    Raw pk = send(s2, INS_PUBLIC_KEY, (byte) 0, (byte) 0, pathBytes(0));
                    row(
                            "D18",
                            "L1 v",
                            "PUBLIC_KEY in second session",
                            "[6982]",
                            pk.inner != null
                                    ? "[" + s4(pk.inner.sw) + "]"
                                    : "outer " + s4(pk.outer),
                            pk.inner != null && pk.inner.sw == 0x6982);
                });
    }

    // E. Inner checking order (§9.2)

    private void sectionE() {
        for (int ins : new int[] {0x00, 0x26, 0x43, 0x34, 0xFF}) {
            for (String st : new String[] {"B s", "L1 s", "L1 v"}) {
                String id = "E1-" + st.replace(' ', '_') + "-" + String.format("%02X", ins);
                cell(
                        id,
                        st,
                        "INS " + String.format("%02X", ins) + " P1=05",
                        () -> {
                            ReviewCard c = prepared(st.startsWith("L") ? "L1" : "B");
                            ReviewSession s = c.open();
                            if (st.endsWith("v")) {
                                in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                            }
                            inSw(
                                    id,
                                    st,
                                    "INS " + String.format("%02X", ins),
                                    0x6D00,
                                    send(s, (byte) ins, (byte) 5, (byte) 0, new byte[4]));
                        });
            }
        }

        for (String name :
                new String[] {
                    "VERIFY",
                    "CHANGE",
                    "ERASE",
                    "WAIT",
                    "PUBLIC_KEY",
                    "SIGN_ECDSA",
                    "SIGN_BIP340",
                    "SIGN_ED25519",
                    "EXPORT"
                }) {
            byte ins = insOf(name);
            cell(
                    "E2-" + name,
                    "B s",
                    name + " P1=05 wrong length",
                    () -> {
                        ReviewCard c = prepared("B");
                        ReviewSession s = c.open();
                        inSw(
                                "E2-" + name,
                                "B s",
                                name + " P1=05",
                                0x6985,
                                send(s, ins, (byte) 5, (byte) 0, new byte[3]));
                    });
        }

        cell(
                "E3",
                "L1 v",
                "CREATE P1=05 wrong length",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    inSw(
                            "E3",
                            "L1 v",
                            "CREATE P1=05",
                            0x6985,
                            send(s, INS_CREATE, (byte) 5, (byte) 0, new byte[3]));
                });

        cell(
                "E4",
                "B s",
                "STATUS P1=01/P2=01; CREATE P1=02; OFFER P1=01; IMPORT P1=02",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    StringBuilder obs = new StringBuilder();
                    Object[][] cases = {
                        {INS_STATUS, (byte) 1, (byte) 0, new byte[4]},
                        {INS_STATUS, (byte) 0, (byte) 1, new byte[4]},
                        {INS_CREATE, (byte) 2, (byte) 0, new byte[4]},
                        {INS_OFFER, (byte) 1, (byte) 0, new byte[4]},
                        {INS_IMPORT, (byte) 2, (byte) 0, new byte[4]},
                    };
                    for (Object[] k : cases) {
                        Raw r = send(s, (byte) k[0], (byte) k[1], (byte) k[2], (byte[]) k[3]);
                        obs.append(r.inner != null ? s4(r.inner.sw) : "outer " + s4(r.outer))
                                .append(' ');
                    }
                    row(
                            "E4",
                            "B s",
                            "P1/P2 wrong, wrong length too",
                            "[6A86] ×5",
                            obs.toString().trim(),
                            obs.toString().trim().equals("6A86 6A86 6A86 6A86 6A86"));
                });

        cell(
                "E5",
                "L1 s",
                "P1/P2 variants, unverified",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    StringBuilder obs = new StringBuilder();
                    Object[][] cases = {
                        {INS_PUBLIC_KEY, (byte) 2, (byte) 0, new byte[9]},
                        {INS_SIGN_ED25519, (byte) 3, (byte) 0, new byte[9]},
                        {INS_EXPORT, (byte) 2, (byte) 0, new byte[9]},
                        {INS_SIGN_ECDSA, (byte) 1, (byte) 0, new byte[9]},
                        {INS_VERIFY, (byte) 0, (byte) 1, new byte[9]},
                    };
                    for (Object[] k : cases) {
                        Raw r = send(s, (byte) k[0], (byte) k[1], (byte) k[2], (byte[]) k[3]);
                        obs.append(r.inner != null ? s4(r.inner.sw) : "outer " + s4(r.outer))
                                .append(' ');
                    }
                    row(
                            "E5",
                            "L1 s",
                            "P1/P2 before length and verified",
                            "[6A86] ×5",
                            obs.toString().trim(),
                            obs.toString().trim().equals("6A86 6A86 6A86 6A86 6A86"));
                });

        cell(
                "E6",
                "B s",
                "wrong lengths",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    StringBuilder obs = new StringBuilder();
                    Object[][] cases = {
                        {"STATUS 1B", INS_STATUS, (byte) 0, new byte[1]},
                        {"CREATE P1=00 63B", INS_CREATE, (byte) 0, new byte[63]},
                        {"CREATE P1=00 65B", INS_CREATE, (byte) 0, new byte[65]},
                        {"CREATE P1=00 112B", INS_CREATE, (byte) 0, new byte[112]},
                        {"CREATE P1=01 95B", INS_CREATE, (byte) 1, new byte[95]},
                        {"CREATE P1=01 97B", INS_CREATE, (byte) 1, new byte[97]},
                        {"CREATE P1=01 144B", INS_CREATE, (byte) 1, new byte[144]},
                        {"OFFER 1B", INS_OFFER, (byte) 0, new byte[1]},
                        {"IMPORT P1=00 225B", INS_IMPORT, (byte) 0, new byte[225]},
                        {"IMPORT P1=00 227B", INS_IMPORT, (byte) 0, new byte[227]},
                        {"IMPORT P1=01 144B", INS_IMPORT, (byte) 1, new byte[144]},
                        {"IMPORT P1=01 159B", INS_IMPORT, (byte) 1, new byte[159]},
                        {"IMPORT P1=01 161B", INS_IMPORT, (byte) 1, new byte[161]},
                        {"IMPORT P1=01 177B", INS_IMPORT, (byte) 1, new byte[177]},
                    };
                    List<String> bad = new ArrayList<>();
                    for (Object[] k : cases) {
                        Raw r = send(s, (byte) k[1], (byte) k[2], (byte) 0, (byte[]) k[3]);
                        String got = r.inner != null ? s4(r.inner.sw) : "outer " + s4(r.outer);
                        if (!got.equals("6700")) {
                            bad.add(k[0] + "=" + got);
                        }
                        obs.append(s4(r.inner != null ? r.inner.sw : -r.outer)).append(' ');
                    }
                    row(
                            "E6",
                            "B s",
                            "14 wrong lengths",
                            "[6700] ×14",
                            bad.isEmpty() ? "[6700] ×14" : "mismatches: " + String.join("; ", bad),
                            bad.isEmpty());
                });

        cell(
                "E7",
                "L1 s",
                "wrong lengths (length before verified)",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    List<String> bad = new ArrayList<>();
                    Object[][] cases = {
                        {"VERIFY 31B", INS_VERIFY, (byte) 0, new byte[31]},
                        {"VERIFY 33B", INS_VERIFY, (byte) 0, new byte[33]},
                        {"CHANGE 31B", INS_CHANGE, (byte) 0, new byte[31]},
                        {"ERASE 1B", INS_ERASE, (byte) 0, new byte[1]},
                        {"WAIT 1B", INS_WAIT, (byte) 0, new byte[1]},
                        {"PUBLIC_KEY depth-2 header 5B", INS_PUBLIC_KEY, (byte) 0, new byte[5]},
                        {"PUBLIC_KEY empty", INS_PUBLIC_KEY, (byte) 0, new byte[0]},
                        {"SIGN_ECDSA 32B", INS_SIGN_ECDSA, (byte) 0, new byte[32]},
                        {"SIGN_BIP340 64B", INS_SIGN_BIP340, (byte) 0, new byte[64]},
                        {"SIGN_ED25519 begin empty", INS_SIGN_ED25519, (byte) 0, new byte[0]},
                        {"SIGN_ED25519 update empty", INS_SIGN_ED25519, (byte) 1, new byte[0]},
                        {"SIGN_ED25519 finish empty", INS_SIGN_ED25519, (byte) 2, new byte[0]},
                        {"EXPORT P1=00 225B", INS_EXPORT, (byte) 0, new byte[225]},
                        {"EXPORT P1=01 31B", INS_EXPORT, (byte) 1, new byte[31]},
                    };
                    for (Object[] k : cases) {
                        byte[] data = (byte[]) k[3];
                        if (k[0].equals("PUBLIC_KEY depth-2 header 5B")) {
                            data = concat(new byte[] {0x02}, u32(0));
                        }
                        Raw r = send(s, (byte) k[1], (byte) k[2], (byte) 0, data);
                        String got = r.inner != null ? s4(r.inner.sw) : "outer " + s4(r.outer);
                        if (!got.equals("6700")) {
                            bad.add(k[0] + "=" + got);
                        }
                    }
                    row(
                            "E7",
                            "L1 s",
                            "14 wrong lengths",
                            "[6700] ×14",
                            bad.isEmpty() ? "[6700] ×14" : "mismatches: " + String.join("; ", bad),
                            bad.isEmpty());
                });

        cell(
                "E8",
                "L1 s",
                "correct lengths, unverified",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    List<String> bad = new ArrayList<>();
                    Object[][] cases = {
                        {"CHANGE", INS_CHANGE, (byte) 0, new byte[32]},
                        {"ERASE", INS_ERASE, (byte) 0, new byte[0]},
                        {"PUBLIC_KEY 00", INS_PUBLIC_KEY, (byte) 0, pathBytes(HP)},
                        {"PUBLIC_KEY 01", INS_PUBLIC_KEY, (byte) 1, pathBytes(HP)},
                        {
                            "SIGN_ECDSA",
                            INS_SIGN_ECDSA,
                            (byte) 0,
                            concat(new byte[32], pathBytes(HP))
                        },
                        {
                            "SIGN_BIP340",
                            INS_SIGN_BIP340,
                            (byte) 0,
                            concat(new byte[64], pathBytes(HP))
                        },
                        {"SIGN_ED25519 begin", INS_SIGN_ED25519, (byte) 0, pathBytes(HP)},
                        {"SIGN_ED25519 update", INS_SIGN_ED25519, (byte) 1, new byte[1]},
                        {"SIGN_ED25519 finish", INS_SIGN_ED25519, (byte) 2, new byte[1]},
                        {"EXPORT P1=00", INS_EXPORT, (byte) 0, new byte[226]},
                        {"EXPORT P1=01", INS_EXPORT, (byte) 1, new byte[32]},
                    };
                    for (Object[] k : cases) {
                        Raw r = send(s, (byte) k[1], (byte) k[2], (byte) 0, (byte[]) k[3]);
                        String got = r.inner != null ? s4(r.inner.sw) : "outer " + s4(r.outer);
                        if (!got.equals("6982")) {
                            bad.add(k[0] + "=" + got);
                        }
                    }
                    row(
                            "E8",
                            "L1 s",
                            "11 commands, verified required",
                            "[6982] ×11",
                            bad.isEmpty() ? "[6982] ×11" : "mismatches: " + String.join("; ", bad),
                            bad.isEmpty());
                });

        cell(
                "E9",
                "L1 s",
                "update without stream; EXPORT P1=01 without pending",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    Raw u = send(s, INS_SIGN_ED25519, (byte) 1, (byte) 0, new byte[10]);
                    ReviewSession s2 = c.open();
                    Raw e = send(s2, INS_EXPORT, (byte) 1, (byte) 0, HT);
                    row(
                            "E9",
                            "L1 s",
                            "update; export1 (verified before preconditions)",
                            "[6982] [6982]",
                            "["
                                    + (u.inner != null ? s4(u.inner.sw) : "?")
                                    + "] ["
                                    + (e.inner != null ? s4(e.inner.sw) : "?")
                                    + "]",
                            u.inner != null
                                    && u.inner.sw == 0x6982
                                    && e.inner != null
                                    && e.inner.sw == 0x6982);
                });

        cell(
                "E10",
                "L1 v",
                "update/finish without stream; EXPORT P1=01 without pending",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    StringBuilder obs = new StringBuilder();
                    for (Object[] k :
                            new Object[][] {
                                {INS_SIGN_ED25519, (byte) 1, new byte[10]},
                                {INS_SIGN_ED25519, (byte) 2, new byte[10]},
                            }) {
                        Raw r = send(s, (byte) k[0], (byte) k[1], (byte) 0, (byte[]) k[2]);
                        obs.append(r.inner != null ? s4(r.inner.sw) : "outer " + s4(r.outer))
                                .append(' ');
                    }
                    ReviewSession s2 = c.open();
                    in(s2, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    Raw e = send(s2, INS_EXPORT, (byte) 1, (byte) 0, HT);
                    obs.append(e.inner != null ? s4(e.inner.sw) : "outer " + s4(e.outer));
                    row(
                            "E10",
                            "L1 v",
                            "update; finish; export1",
                            "[6985] [6985] [6985]",
                            obs.toString(),
                            obs.toString().equals("6985 6985 6985"));
                });

        cell(
                "E11",
                "L1 v, edCounter=FFFFFFFF",
                "begin with depth-0 path",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    c.injectEdCounter(0xFFFF_FFFFL); // setup injection, between commands
                    inSw(
                            "E11",
                            "L1 v",
                            "SIGN_ED25519 begin depth 0",
                            0x6985,
                            send(s, INS_SIGN_ED25519, (byte) 0, (byte) 0, new byte[] {0x00}));
                });

        cell(
                "E12a",
                "B s, offer=NONE",
                "IMPORT P1=00 garbage 226 B",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    inSw(
                            "E12a",
                            "B s",
                            "IMPORT P1=00 garbage",
                            0x6985,
                            send(s, INS_IMPORT, (byte) 0, (byte) 0, new byte[226]));
                });
        cell(
                "E12b",
                "L1 s, offer=NONE",
                "IMPORT P1=00 garbage 226 B",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    inSw(
                            "E12b",
                            "L1 s",
                            "IMPORT P1=00 garbage",
                            0x6985,
                            send(s, INS_IMPORT, (byte) 0, (byte) 0, new byte[226]));
                });

        cell(
                "E13",
                "B s after OFFER",
                "IMPORT P1=01 without pending",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    in(s, INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                    inSw(
                            "E13",
                            "B s after OFFER",
                            "IMPORT P1=01 160 B garbage",
                            0x6985,
                            send(s, INS_IMPORT, (byte) 1, (byte) 0, new byte[160]));
                });

        cell(
                "E14",
                "L1 f=3 s",
                "VERIFY(H0) without WAIT; STATUS tries",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    ReviewCard.failTo(s, H1, 3);
                    ReviewSession s2 = c.open();
                    Raw v = send(s2, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    Raw st = send(s2, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "E14",
                            "L1 f=3 s",
                            "VERIFY right code, no wait; STATUS",
                            "[6986]; tries 7",
                            "["
                                    + (v.inner != null ? s4(v.inner.sw) : "?")
                                    + "]; STATUS "
                                    + (st.inner != null ? hex(st.inner.data) : "?"),
                            v.inner != null
                                    && v.inner.sw == 0x6986
                                    && st.inner != null
                                    && Arrays.equals(st.inner.data, new byte[] {0x02, 0x07}));
                });

        cell(
                "E15",
                "L1 v",
                "VERIFY 31 B",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    Raw v = send(s, INS_VERIFY, (byte) 0, (byte) 0, new byte[31]);
                    Raw pk = send(s, INS_PUBLIC_KEY, (byte) 0, (byte) 0, pathBytes(HP));
                    row(
                            "E15",
                            "L1 v",
                            "VERIFY 31 B; session still verified",
                            "[6700]; PUBLIC_KEY works",
                            "["
                                    + (v.inner != null ? s4(v.inner.sw) : "?")
                                    + "]; PUBLIC_KEY ["
                                    + (pk.inner != null ? s4(pk.inner.sw) : "?")
                                    + "]",
                            v.inner != null
                                    && v.inner.sw == 0x6700
                                    && pk.inner != null
                                    && pk.inner.sw == 0x9000);
                });
    }

    // F. Data checks and effects per command

    private void sectionF() {
        cell(
                "F1",
                "B s",
                "STATUS",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    Raw r = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "F1",
                            "B s",
                            "STATUS",
                            "[9000] 01 00",
                            r.inner != null
                                    ? "[" + s4(r.inner.sw) + "] " + hex(r.inner.data)
                                    : "outer " + s4(r.outer),
                            r.inner != null
                                    && r.inner.sw == 0x9000
                                    && Arrays.equals(r.inner.data, new byte[] {0x01, 0x00}));
                });
        cell(
                "F2",
                "L1 s",
                "STATUS",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    Raw r = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "F2",
                            "L1 s",
                            "STATUS",
                            "[9000] 02 0A",
                            r.inner != null
                                    ? "[" + s4(r.inner.sw) + "] " + hex(r.inner.data)
                                    : "outer " + s4(r.outer),
                            r.inner != null
                                    && r.inner.sw == 0x9000
                                    && Arrays.equals(r.inner.data, new byte[] {0x02, 0x0A}));
                });

        cell(
                "F3",
                "B s",
                "CREATE P1=01 others=[ID(A)]",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    byte[] ownId = cardId(s.cardA);
                    Raw r = send(s, INS_CREATE, (byte) 1, (byte) 0, concat(H0, S0, ownId));
                    Raw st = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "F3",
                            "B s",
                            "CREATE others=[ID(A)]",
                            "[6A80], still BLANK",
                            "["
                                    + (r.inner != null ? s4(r.inner.sw) : "?")
                                    + "], STATUS "
                                    + (st.inner != null ? hex(st.inner.data) : "?"),
                            r.inner != null
                                    && r.inner.sw == 0x6A80
                                    && st.inner != null
                                    && Arrays.equals(st.inner.data, new byte[] {0x01, 0x00}));
                });
        cell(
                "F4",
                "B s",
                "CREATE P1=01 others=[X,X]",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    Raw r = send(s, INS_CREATE, (byte) 1, (byte) 0, concat(H0, S0, X_ID, X_ID));
                    row(
                            "F4",
                            "B s",
                            "CREATE others=[X,X]",
                            "[6A80]",
                            "[" + (r.inner != null ? s4(r.inner.sw) : "outer " + s4(r.outer)) + "]",
                            r.inner != null && r.inner.sw == 0x6A80);
                });
        cell(
                "F5",
                "B s",
                "CREATE P1=01 others=[X,Y]",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    Raw r = send(s, INS_CREATE, (byte) 1, (byte) 0, concat(H0, S0, X_ID, Y_ID));
                    byte[][] master = bip32Master(S0);
                    byte[] mpk = compr(g().multiply(b2i(master[0])));
                    byte[] expectWi =
                            concat(mpk, new byte[] {0x02, 0x03}, cardId(s.cardA), X_ID, Y_ID);
                    boolean wiOk =
                            r.inner != null
                                    && r.inner.sw == 0x9000
                                    && Arrays.equals(r.inner.data, expectWi);
                    Raw pk = send(s, INS_PUBLIC_KEY, (byte) 0, (byte) 0, pathBytes(0));
                    row(
                            "F5",
                            "B s",
                            "CREATE others=[X,Y]",
                            "[9000] WalletInfo mpk‖02‖03‖ID(A)‖X‖Y (83 B); PUBLIC_KEY works same session",
                            (r.inner != null
                                            ? "["
                                                    + s4(r.inner.sw)
                                                    + "] "
                                                    + r.inner.data.length
                                                    + " B, "
                                                    + (wiOk ? "mpk/fields match" : "MISMATCH")
                                            : "outer " + s4(r.outer))
                                    + "; PUBLIC_KEY ["
                                    + (pk.inner != null ? s4(pk.inner.sw) : "?")
                                    + "]",
                            wiOk && pk.inner != null && pk.inner.sw == 0x9000);
                });
        cell(
                "F6",
                "B s",
                "CREATE P1=00 generate",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    byte[] hostEntropy = sha256("host entropy F6".getBytes());
                    Raw r = send(s, INS_CREATE, (byte) 0, (byte) 0, concat(H0, hostEntropy));
                    boolean ok =
                            r.inner != null
                                    && r.inner.sw == 0x9000
                                    && r.inner.data.length == 51
                                    && r.inner.data[33] == 0x01
                                    && r.inner.data[34] == 0x01
                                    && Arrays.equals(slice(r.inner.data, 35, 16), cardId(s.cardA))
                                    && decompress(slice(r.inner.data, 0, 33)) != null;
                    row(
                            "F6",
                            "B s",
                            "CREATE generate",
                            "[9000] WalletInfo 51 B, origin 01, c 01, ID(A); mpk decompresses",
                            r.inner != null
                                    ? "["
                                            + s4(r.inner.sw)
                                            + "] "
                                            + r.inner.data.length
                                            + " B, ok="
                                            + ok
                                    : "outer " + s4(r.outer),
                            ok);
                });
        cell(
                "F7",
                "two B cards",
                "CREATE P1=00 same hostEntropy",
                () -> {
                    byte[] hostEntropy = sha256("host entropy F7".getBytes());
                    byte[] mpk1, mpk2;
                    {
                        ReviewCard c1 = prepared("B");
                        ReviewSession s1 = c1.open();
                        Raw r1 = send(s1, INS_CREATE, (byte) 0, (byte) 0, concat(H0, hostEntropy));
                        mpk1 = r1.inner != null ? slice(r1.inner.data, 0, 33) : null;
                    }
                    {
                        ReviewCard c2 = prepared("B");
                        ReviewSession s2 = c2.open();
                        Raw r2 = send(s2, INS_CREATE, (byte) 0, (byte) 0, concat(H0, hostEntropy));
                        mpk2 = r2.inner != null ? slice(r2.inner.data, 0, 33) : null;
                    }
                    row(
                            "F7",
                            "two B cards",
                            "same hostEntropy → different mpk",
                            "different mpk",
                            mpk1 != null && mpk2 != null
                                    ? (Arrays.equals(mpk1, mpk2) ? "IDENTICAL" : "different")
                                    : "create failed",
                            mpk1 != null && mpk2 != null && !Arrays.equals(mpk1, mpk2));
                });

        cell(
                "F8",
                "L1 s",
                "VERIFY(H1≠H0)",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    Raw v = send(s, INS_VERIFY, (byte) 0, (byte) 0, H1);
                    Raw st = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "F8",
                            "L1 s",
                            "VERIFY(H1)",
                            "[63C9]; STATUS 02 09",
                            "["
                                    + (v.inner != null ? s4(v.inner.sw) : "?")
                                    + "]; STATUS "
                                    + (st.inner != null ? hex(st.inner.data) : "?"),
                            v.inner != null
                                    && v.inner.sw == 0x63C9
                                    && st.inner != null
                                    && Arrays.equals(st.inner.data, new byte[] {0x02, 0x09}));
                });
        cell(
                "F9",
                "L1 s",
                "VERIFY(H0)",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    Raw v = send(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    byte[][] master = bip32Master(S0);
                    byte[] expectWi =
                            concat(
                                    compr(g().multiply(b2i(master[0]))),
                                    new byte[] {0x02, 0x01},
                                    cardId(s.cardA));
                    row(
                            "F9",
                            "L1 s",
                            "VERIFY(H0)",
                            "[9000] WalletInfo mpk‖02‖01‖ID(A)",
                            v.inner != null
                                    ? "["
                                            + s4(v.inner.sw)
                                            + "] "
                                            + (Arrays.equals(v.inner.data, expectWi)
                                                    ? "WalletInfo matches"
                                                    : "MISMATCH " + hex(v.inner.data))
                                    : "outer " + s4(v.outer),
                            v.inner != null
                                    && v.inner.sw == 0x9000
                                    && Arrays.equals(v.inner.data, expectWi));
                });

        cell(
                "F10",
                "L1 v",
                "CHANGE(H1); new session VERIFY H0/H1",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    Raw ch = send(s, INS_CHANGE, (byte) 0, (byte) 0, H1);
                    Raw pk = send(s, INS_PUBLIC_KEY, (byte) 0, (byte) 0, pathBytes(0));
                    ReviewSession s2 = c.open();
                    Raw v0 = send(s2, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    Raw v1 = send(s2, INS_VERIFY, (byte) 0, (byte) 0, H1);
                    row(
                            "F10",
                            "L1 v",
                            "CHANGE; PUBLIC_KEY; new session VERIFY(H0),(H1)",
                            "[9000]; works; [63C9]; [9000]",
                            "["
                                    + (ch.inner != null ? s4(ch.inner.sw) : "?")
                                    + "]; PUBLIC_KEY ["
                                    + (pk.inner != null ? s4(pk.inner.sw) : "?")
                                    + "]; ["
                                    + (v0.inner != null ? s4(v0.inner.sw) : "?")
                                    + "]; ["
                                    + (v1.inner != null ? s4(v1.inner.sw) : "?")
                                    + "]",
                            ch.inner != null
                                    && ch.inner.sw == 0x9000
                                    && pk.inner != null
                                    && pk.inner.sw == 0x9000
                                    && v0.inner != null
                                    && v0.inner.sw == 0x63C9
                                    && v1.inner != null
                                    && v1.inner.sw == 0x9000);
                });

        cell(
                "F11",
                "L1 v",
                "ERASE",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    Raw e = send(s, INS_ERASE, (byte) 0, (byte) 0, new byte[0]);
                    Raw st = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    Raw of = send(s, INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                    Raw pk = send(s, INS_PUBLIC_KEY, (byte) 0, (byte) 0, pathBytes(0));
                    row(
                            "F11",
                            "L1 v",
                            "ERASE; STATUS; OFFER; PUBLIC_KEY",
                            "[9000]; 01 00; OFFER works; PUBLIC_KEY [6985]",
                            "["
                                    + (e.inner != null ? s4(e.inner.sw) : "?")
                                    + "]; "
                                    + (st.inner != null ? hex(st.inner.data) : "?")
                                    + "; OFFER ["
                                    + (of.inner != null ? s4(of.inner.sw) : "?")
                                    + "]; PUBLIC_KEY ["
                                    + (pk.inner != null ? s4(pk.inner.sw) : "?")
                                    + "]",
                            e.inner != null
                                    && e.inner.sw == 0x9000
                                    && st.inner != null
                                    && Arrays.equals(st.inner.data, new byte[] {0x01, 0x00})
                                    && of.inner != null
                                    && of.inner.sw == 0x9000
                                    && pk.inner != null
                                    && pk.inner.sw == 0x6985);
                });

        cell(
                "F12",
                "L1 s",
                "WAIT",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    inSw(
                            "F12",
                            "L1 s",
                            "WAIT",
                            0x9000,
                            send(s, INS_WAIT, (byte) 0, (byte) 0, new byte[0]));
                });
        cell(
                "F13",
                "B s",
                "WAIT",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    inSw(
                            "F13",
                            "B s",
                            "WAIT",
                            0x6985,
                            send(s, INS_WAIT, (byte) 0, (byte) 0, new byte[0]));
                });

        long[][] f14paths = {
            {HP + 44, HP, HP, 0, 0},
            {HP + 84, HP, HP, 0, 5},
            {0},
            {1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
        };
        for (int i = 0; i < f14paths.length; i++) {
            final long[] path = f14paths[i];
            final int idx = i;
            cell(
                    "F14-" + (char) ('a' + i),
                    "L1 v",
                    "PUBLIC_KEY secp256k1 path " + i + " ×2",
                    () -> {
                        ReviewCard c = prepared("L1");
                        ReviewSession s = c.open();
                        in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                        List<String> obs = new ArrayList<>();
                        for (int rep = 0; rep < 2; rep++) {
                            Raw r = send(s, INS_PUBLIC_KEY, (byte) 0, (byte) 0, pathBytes(path));
                            byte[][] node = bip32Node(S0, path);
                            byte[] expect =
                                    node == null
                                            ? null
                                            : concat(compr(g().multiply(b2i(node[0]))), node[1]);
                            obs.add(
                                    r.inner != null
                                            ? "["
                                                    + s4(r.inner.sw)
                                                    + "] "
                                                    + r.inner.data.length
                                                    + " B "
                                                    + (Arrays.equals(r.inner.data, expect)
                                                            ? "match"
                                                            : "MISMATCH")
                                            : "outer " + s4(r.outer));
                        }
                        row(
                                "F14-" + (char) ('a' + idx),
                                "L1 v",
                                "PUBLIC_KEY secp256k1 path " + idx,
                                "65 B = host BIP-32 from S0 (×2)",
                                String.join("; ", obs),
                                obs.get(0).endsWith("match") && obs.get(1).endsWith("match"));
                    });
        }

        long[][] f15paths = {
            {HP + 44, HP + 501, HP, HP},
            {HP},
            {HP, HP + 1, HP + 2, HP + 3, HP + 4, HP + 5, HP + 6, HP + 7, HP + 8, HP + 9},
        };
        for (int i = 0; i < f15paths.length; i++) {
            final long[] path = f15paths[i];
            final int idx = i;
            cell(
                    "F15-" + (char) ('a' + i),
                    "L1 v",
                    "PUBLIC_KEY ed25519 path " + i,
                    () -> {
                        ReviewCard c = prepared("L1");
                        ReviewSession s = c.open();
                        in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                        Raw r = send(s, INS_PUBLIC_KEY, (byte) 1, (byte) 0, pathBytes(path));
                        byte[] expect = edPublic(slip10Leaf(S0, path));
                        boolean ok =
                                r.inner != null
                                        && r.inner.sw == 0x9000
                                        && r.inner.data.length == 64
                                        && Arrays.equals(weiToEdwards(r.inner.data), expect);
                        row(
                                "F15-" + (char) ('a' + idx),
                                "L1 v",
                                "PUBLIC_KEY ed25519 path " + idx,
                                "64 B W(A) mapping to host SLIP-10 pub",
                                r.inner != null
                                        ? "["
                                                + s4(r.inner.sw)
                                                + "] "
                                                + r.inner.data.length
                                                + " B, "
                                                + (ok
                                                        ? "maps to expected encode(A)"
                                                        : "map mismatch "
                                                                + hex(weiToEdwards(r.inner.data))
                                                                + " vs "
                                                                + hex(expect))
                                        : "outer " + s4(r.outer),
                                ok);
                    });
        }

        cell(
                "F16",
                "L1 v",
                "PUBLIC_KEY depth 0 / depth 11",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    Raw r0 = send(s, INS_PUBLIC_KEY, (byte) 0, (byte) 0, new byte[] {0x00});
                    byte[] d11 = new byte[45];
                    d11[0] = 11;
                    Raw r11 = send(s, INS_PUBLIC_KEY, (byte) 0, (byte) 0, d11);
                    row(
                            "F16",
                            "L1 v",
                            "depth 0, depth 11",
                            "[6A80] [6A80]",
                            "["
                                    + (r0.inner != null ? s4(r0.inner.sw) : "?")
                                    + "] ["
                                    + (r11.inner != null ? s4(r11.inner.sw) : "?")
                                    + "]",
                            r0.inner != null
                                    && r0.inner.sw == 0x6A80
                                    && r11.inner != null
                                    && r11.inner.sw == 0x6A80);
                });
        cell(
                "F17",
                "L1 v",
                "PUBLIC_KEY ed25519 non-hardened index",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    Raw r = send(s, INS_PUBLIC_KEY, (byte) 1, (byte) 0, pathBytes(HP, 5));
                    row(
                            "F17",
                            "L1 v",
                            "non-hardened index",
                            "[6A80]",
                            "[" + (r.inner != null ? s4(r.inner.sw) : "?") + "]",
                            r.inner != null && r.inner.sw == 0x6A80);
                });

        long[][] f18paths = {{HP + 44, HP + 60, HP, 0, 0}, {HP + 44, HP + 60, HP}};
        for (int i = 0; i < f18paths.length; i++) {
            final long[] path = f18paths[i];
            final int idx = i;
            cell(
                    "F18-" + (char) ('a' + i),
                    "L1 v",
                    "SIGN_ECDSA path " + i,
                    () -> {
                        ReviewCard c = prepared("L1");
                        ReviewSession s = c.open();
                        in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                        Raw r =
                                send(
                                        s,
                                        INS_SIGN_ECDSA,
                                        (byte) 0,
                                        (byte) 0,
                                        concat(DIGEST, pathBytes(path)));
                        BigInteger leaf = bip32Leaf(S0, path);
                        byte[] leafPub = compr(g().multiply(leaf));
                        boolean ok =
                                r.inner != null
                                        && r.inner.sw == 0x9000
                                        && r.inner.data.length == 64
                                        && ecdsaVerifyHash(leafPub, DIGEST, r.inner.data);
                        row(
                                "F18-" + (char) ('a' + idx),
                                "L1 v",
                                "SIGN_ECDSA path " + idx,
                                "r‖s valid under host-derived key (either s half)",
                                r.inner != null
                                        ? "["
                                                + s4(r.inner.sw)
                                                + "] "
                                                + r.inner.data.length
                                                + " B, "
                                                + (ok ? "verifies" : "does NOT verify")
                                        : "outer " + s4(r.outer),
                                ok);
                    });
        }

        cell(
                "F19",
                "L1 v",
                "SIGN_ECDSA depth 0 / 11",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    Raw r0 =
                            send(
                                    s,
                                    INS_SIGN_ECDSA,
                                    (byte) 0,
                                    (byte) 0,
                                    concat(DIGEST, new byte[] {0x00}));
                    byte[] p11 = new byte[45];
                    p11[0] = 11;
                    Raw r11 = send(s, INS_SIGN_ECDSA, (byte) 0, (byte) 0, concat(DIGEST, p11));
                    row(
                            "F19",
                            "L1 v",
                            "depth 0, depth 11",
                            "[6A80] [6A80]",
                            "["
                                    + (r0.inner != null ? s4(r0.inner.sw) : "?")
                                    + "] ["
                                    + (r11.inner != null ? s4(r11.inner.sw) : "?")
                                    + "]",
                            r0.inner != null
                                    && r0.inner.sw == 0x6A80
                                    && r11.inner != null
                                    && r11.inner.sw == 0x6A80);
                });

        final long[] tapPath = {HP + 86, HP, HP, 0, 0};
        cell(
                "F20",
                "L1 v",
                "SIGN_BIP340 tweak=0",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    Raw r =
                            send(
                                    s,
                                    INS_SIGN_BIP340,
                                    (byte) 0,
                                    (byte) 0,
                                    concat(MSG32, new byte[32], pathBytes(tapPath)));
                    BigInteger d0 = bip32Leaf(S0, tapPath);
                    byte[] px = i2b(g().multiply(d0).normalize().getXCoord().toBigInteger(), 32);
                    boolean ok =
                            r.inner != null
                                    && r.inner.sw == 0x9000
                                    && r.inner.data.length == 64
                                    && bip340Verify(px, MSG32, r.inner.data);
                    row(
                            "F20",
                            "L1 v",
                            "tweak = 0",
                            "64 B, BIP-340 valid under x(P_even)",
                            r.inner != null
                                    ? "["
                                            + s4(r.inner.sw)
                                            + "] "
                                            + r.inner.data.length
                                            + " B, "
                                            + (ok ? "verifies" : "does NOT verify")
                                    : "outer " + s4(r.outer),
                            ok);
                });
        cell(
                "F21",
                "L1 v",
                "SIGN_BIP340 BIP-86 tweak",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    BigInteger d0 = bip32Leaf(S0, tapPath);
                    byte[] px = i2b(g().multiply(d0).normalize().getXCoord().toBigInteger(), 32);
                    byte[] tweak = taggedHash("TapTweak", px);
                    Raw r =
                            send(
                                    s,
                                    INS_SIGN_BIP340,
                                    (byte) 0,
                                    (byte) 0,
                                    concat(MSG32, tweak, pathBytes(tapPath)));
                    byte[] qx = i2b(taprootQ(d0, b2i(tweak)).getXCoord().toBigInteger(), 32);
                    boolean ok =
                            r.inner != null
                                    && r.inner.sw == 0x9000
                                    && r.inner.data.length == 64
                                    && bip340Verify(qx, MSG32, r.inner.data);
                    row(
                            "F21",
                            "L1 v",
                            "BIP-86 tweak",
                            "valid under Q = P_even + t·G",
                            r.inner != null
                                    ? "["
                                            + s4(r.inner.sw)
                                            + "] "
                                            + r.inner.data.length
                                            + " B, "
                                            + (ok ? "verifies" : "does NOT verify")
                                    : "outer " + s4(r.outer),
                            ok);
                });
        cell(
                "F22",
                "L1 v",
                "SIGN_BIP340 tweak = n / FF…FF",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    StringBuilder obs = new StringBuilder();
                    for (byte[] tw : new byte[][] {i2b(N, 32), new byte[32]}) {
                        if (tw[0] == 0) {
                            Arrays.fill(tw, (byte) 0xFF);
                        }
                        Raw r =
                                send(
                                        s,
                                        INS_SIGN_BIP340,
                                        (byte) 0,
                                        (byte) 0,
                                        concat(MSG32, tw, pathBytes(tapPath)));
                        obs.append(r.inner != null ? s4(r.inner.sw) : "outer " + s4(r.outer))
                                .append(' ');
                    }
                    row(
                            "F22",
                            "L1 v",
                            "tweak = n, tweak = FF…FF",
                            "[6A80] [6A80]",
                            obs.toString().trim(),
                            obs.toString().trim().equals("6A80 6A80"));
                });
        cell(
                "F23",
                "L1 v",
                "tweak = n − d₀' (zero tweaked key)",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    BigInteger d0 = bip32Leaf(S0, tapPath);
                    boolean odd =
                            g().multiply(d0).normalize().getYCoord().toBigInteger().testBit(0);
                    BigInteger d0p = odd ? N.subtract(d0) : d0;
                    byte[] tweak = i2b(N.subtract(d0p), 32);
                    Raw r =
                            send(
                                    s,
                                    INS_SIGN_BIP340,
                                    (byte) 0,
                                    (byte) 0,
                                    concat(MSG32, tweak, pathBytes(tapPath)));
                    row(
                            "F23",
                            "L1 v",
                            "tweak = n − d₀'",
                            "[6A80]",
                            "[" + (r.inner != null ? s4(r.inner.sw) : "?") + "]",
                            r.inner != null && r.inner.sw == 0x6A80);
                });

        final long[] edPath = {HP + 44, HP + 501, HP, HP};
        for (int mlen : new int[] {0, 1, 100, 1000, 4032}) {
            cell(
                    "F24-m" + mlen,
                    "L1 v",
                    "SIGN_ED25519 |M|=" + mlen,
                    () -> {
                        ReviewCard c = prepared("L1");
                        ReviewSession s = c.open();
                        in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                        // encode(A) is the host's own SLIP-10 derivation, computed before begin:
                        // any
                        // command after begin (incl. PUBLIC_KEY) ends the stream
                        byte[] encA = edPublic(slip10Leaf(S0, edPath));
                        Raw beg = send(s, INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(edPath));
                        if (beg.inner == null || beg.inner.sw != 0x9000) {
                            row(
                                    "F24-m" + mlen,
                                    "L1 v",
                                    "|M|=" + mlen,
                                    "[9000] W(R); verify",
                                    "begin failed",
                                    false);
                            return;
                        }
                        byte[] encR = weiToEdwards(beg.inner.data);
                        byte[] msg = new byte[mlen];
                        for (int i = 0; i < mlen; i++) {
                            msg[i] = (byte) i;
                        }
                        byte[] stream = concat(encR, encA, msg);
                        int off = 0;
                        Inner fin = null;
                        String trail = "";
                        while (off < stream.length) {
                            int n = Math.min(236, stream.length - off);
                            boolean last = off + n == stream.length;
                            Raw r =
                                    send(
                                            s,
                                            INS_SIGN_ED25519,
                                            last ? (byte) 2 : (byte) 1,
                                            (byte) 0,
                                            slice(stream, off, n));
                            off += n;
                            if (last) {
                                fin = r.inner;
                                trail = "finish " + s4(fin.sw);
                            } else if (r.inner == null || r.inner.sw != 0x9000) {
                                trail =
                                        "update failed "
                                                + (r.inner != null ? s4(r.inner.sw) : "outer");
                                break;
                            }
                        }
                        boolean ok =
                                fin != null
                                        && fin.sw == 0x9000
                                        && fin.data.length == 32
                                        && edVerify(encA, msg, concat(encR, fin.data));
                        row(
                                "F24-m" + mlen,
                                "L1 v",
                                "|M|=" + mlen,
                                "W(R) 64 B; le32(S) 32 B; verifies under encode(A)",
                                trail + (ok ? "; verifies" : "; does NOT verify"),
                                ok);
                    });
        }

        cell(
                "F25",
                "L1 v",
                "stream with wrong encode(A)",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    byte[] encA =
                            edPublic(slip10Leaf(S0, edPath)); // before begin: any command ends it
                    Raw beg = send(s, INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(edPath));
                    byte[] encR = weiToEdwards(beg.inner.data);
                    byte[] wrongA = encA.clone();
                    wrongA[0] ^= 0x01;
                    byte[] msg = unhex("deadbeef");
                    byte[] stream = concat(encR, wrongA, msg);
                    int off = 0;
                    Inner fin = null;
                    while (off < stream.length) {
                        int n = Math.min(236, stream.length - off);
                        boolean last = off + n == stream.length;
                        Raw r =
                                send(
                                        s,
                                        INS_SIGN_ED25519,
                                        last ? (byte) 2 : (byte) 1,
                                        (byte) 0,
                                        slice(stream, off, n));
                        off += n;
                        if (last) {
                            fin = r.inner;
                        }
                    }
                    boolean bad =
                            fin != null
                                    && fin.sw == 0x9000
                                    && !edVerify(encA, msg, concat(encR, fin.data));
                    row(
                            "F25",
                            "L1 v",
                            "wrong encode(A) stream",
                            "[9000] but signature does NOT verify",
                            fin != null ? "[" + s4(fin.sw) + "], verify=" + !bad : "finish failed",
                            bad);
                });

        cell(
                "F26",
                "L1 v",
                "begin, STATUS, update",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    send(s, INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(edPath));
                    send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    Raw u = send(s, INS_SIGN_ED25519, (byte) 1, (byte) 0, new byte[8]);
                    inSw("F26", "L1 v", "update after STATUS", 0x6985, u);
                });
        cell(
                "F27",
                "L1 v",
                "begin, update P2=01, update",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    send(s, INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(edPath));
                    Raw bad = send(s, INS_SIGN_ED25519, (byte) 1, (byte) 1, new byte[8]);
                    Raw u = send(s, INS_SIGN_ED25519, (byte) 1, (byte) 0, new byte[8]);
                    row(
                            "F27",
                            "L1 v",
                            "update P2=01 then update",
                            "[6A86] then [6985]",
                            "["
                                    + (bad.inner != null ? s4(bad.inner.sw) : "?")
                                    + "] then ["
                                    + (u.inner != null ? s4(u.inner.sw) : "?")
                                    + "]",
                            bad.inner != null
                                    && bad.inner.sw == 0x6A86
                                    && u.inner != null
                                    && u.inner.sw == 0x6985);
                });
        cell(
                "F28",
                "L1 v",
                "begin, finish, update",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    send(s, INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(edPath));
                    send(s, INS_SIGN_ED25519, (byte) 2, (byte) 0, new byte[8]);
                    Raw u = send(s, INS_SIGN_ED25519, (byte) 1, (byte) 0, new byte[8]);
                    inSw("F28", "L1 v", "update after finish", 0x6985, u);
                });
        cell(
                "F29",
                "L1 v",
                "begin, begin, finish → second R",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    byte[] encA = edPublic(slip10Leaf(S0, edPath));
                    send(s, INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(edPath));
                    Raw beg2 = send(s, INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(edPath));
                    byte[] encR = weiToEdwards(beg2.inner.data);
                    byte[] msg = unhex("cafe");
                    byte[] stream = concat(encR, encA, msg);
                    int off = 0;
                    Inner fin = null;
                    while (off < stream.length) {
                        int n = Math.min(236, stream.length - off);
                        boolean last = off + n == stream.length;
                        Raw r =
                                send(
                                        s,
                                        INS_SIGN_ED25519,
                                        last ? (byte) 2 : (byte) 1,
                                        (byte) 0,
                                        slice(stream, off, n));
                        off += n;
                        if (last) {
                            fin = r.inner;
                        }
                    }
                    boolean ok =
                            fin != null
                                    && fin.sw == 0x9000
                                    && edVerify(encA, msg, concat(encR, fin.data));
                    row(
                            "F29",
                            "L1 v",
                            "second begin restarts",
                            "signature verifies with second R",
                            fin != null ? "[" + s4(fin.sw) + "], verify=" + ok : "finish failed",
                            ok);
                });
        cell(
                "F30",
                "L1 v",
                "begin depth 0 / non-hardened",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    Raw r0 = send(s, INS_SIGN_ED25519, (byte) 0, (byte) 0, new byte[] {0x00});
                    Raw r1 = send(s, INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(HP, 5));
                    row(
                            "F30",
                            "L1 v",
                            "depth 0, non-hardened index",
                            "[6A80] [6A80]",
                            "["
                                    + (r0.inner != null ? s4(r0.inner.sw) : "?")
                                    + "] ["
                                    + (r1.inner != null ? s4(r1.inner.sw) : "?")
                                    + "]",
                            r0.inner != null
                                    && r0.inner.sw == 0x6A80
                                    && r1.inner != null
                                    && r1.inner.sw == 0x6A80);
                });
        cell(
                "F31",
                "L1 v",
                "edCounter +1 per begin",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    long before = c.readEdCounter();
                    send(s, INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(edPath));
                    long mid = c.readEdCounter();
                    send(s, INS_SIGN_ED25519, (byte) 1, (byte) 0, new byte[8]);
                    send(s, INS_SIGN_ED25519, (byte) 2, (byte) 0, new byte[8]);
                    long after = c.readEdCounter();
                    row(
                            "F31",
                            "L1 v",
                            "edCounter per begin; unchanged by update/finish",
                            "+1 per begin, then unchanged",
                            "before "
                                    + before
                                    + ", after begin "
                                    + mid
                                    + ", after update/finish "
                                    + after,
                            mid == before + 1 && after == mid);
                });

        cell(
                "F32",
                "B s",
                "OFFER twice",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    Raw o1 = send(s, INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                    Raw o2 = send(s, INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                    boolean lens =
                            o1.inner != null
                                    && o1.inner.data.length == 129
                                    && o2.inner != null
                                    && o2.inner.data.length == 129;
                    boolean sameLk =
                            lens
                                    && Arrays.equals(
                                            slice(o1.inner.data, 0, 65),
                                            slice(o2.inner.data, 0, 65));
                    boolean sigs =
                            lens
                                    && ecdsaVerify(
                                            s.cardA,
                                            concat(LABEL_OFFER, slice(o1.inner.data, 0, 65)),
                                            slice(o1.inner.data, 65, 64))
                                    && ecdsaVerify(
                                            s.cardA,
                                            concat(LABEL_OFFER, slice(o2.inner.data, 0, 65)),
                                            slice(o2.inner.data, 65, 64));
                    boolean distinct =
                            lens
                                    && !Arrays.equals(
                                            slice(o1.inner.data, 65, 64),
                                            slice(o2.inner.data, 65, 64));
                    row(
                            "F32",
                            "B s",
                            "OFFER ×2",
                            "both [9000] 129 B; same LK; two different sigs, both valid under A",
                            (o1.inner != null && o2.inner != null
                                    ? "["
                                            + s4(o1.inner.sw)
                                            + "]["
                                            + s4(o2.inner.sw)
                                            + "] lens "
                                            + lens
                                            + "; sameLK "
                                            + sameLk
                                            + "; sigsValid "
                                            + sigs
                                            + "; distinct "
                                            + distinct
                                    : "offers failed"),
                            lens && sameLk && sigs && distinct);
                });
        cell(
                "F33",
                "L1 s",
                "OFFER",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    inSw(
                            "F33",
                            "L1 s",
                            "OFFER",
                            0x9000,
                            send(s, INS_OFFER, (byte) 0, (byte) 0, new byte[0]));
                });
    }

    // G. Transfer (§9.12–9.14, §11)

    /** Card X LOADED with S0 under H0, members (ID(A_X), ID(A_M)). */
    private static final class L2 {
        ReviewCard c;
        FakeMember m;
        ReviewSession s;
    }

    private L2 l2(boolean verified) {
        L2 r = new L2();
        r.c = prepared("B");
        r.m = new FakeMember(ReviewCard.CA);
        r.c.create(S0, H0, r.m.cardId);
        r.s = r.c.open();
        if (verified) {
            in(r.s, INS_VERIFY, (byte) 0, (byte) 0, H0);
        }
        return r;
    }

    private void sectionG() {
        cell(
                "G1",
                "L2 v",
                "EXPORT P1=00 with host-generated offer",
                () -> {
                    L2 r = l2(true);
                    Raw e0 = send(r.s, INS_EXPORT, (byte) 0, (byte) 0, r.m.exportRequest());
                    boolean ok =
                            e0.inner != null
                                    && e0.inner.sw == 0x9000
                                    && e0.inner.data.length == 129;
                    byte[] eph = ok ? slice(e0.inner.data, 0, 65) : null;
                    byte[] sigS = ok ? slice(e0.inner.data, 65, 64) : null;
                    boolean sigOk =
                            ok
                                    && ecdsaVerify(
                                            r.s.cardA,
                                            concat(LABEL_EXPORT, r.s.cardA, r.m.a, r.m.lk, eph),
                                            sigS);
                    row(
                            "G1",
                            "L2 v",
                            "EXPORT P1=00",
                            "[9000] E‖sig_S (129 B); sig_S verifies under A",
                            e0.inner != null
                                    ? "["
                                            + s4(e0.inner.sw)
                                            + "] "
                                            + e0.inner.data.length
                                            + " B, sig_S "
                                            + (sigOk ? "verifies" : "does NOT verify")
                                    : "outer " + s4(e0.outer),
                            ok && sigOk);
                });

        cell(
                "G2",
                "L2 v",
                "EXPORT P1=01 accessHash_T; host decrypts",
                () -> {
                    L2 r = l2(true);
                    Raw ex = send(r.s, INS_EXPORT, (byte) 0, (byte) 0, r.m.exportRequest());
                    byte[] eph = slice(ex.inner.data, 0, 65);
                    byte[] exportM = concat(LABEL_EXPORT, r.s.cardA, r.m.a, r.m.lk, eph);
                    Raw e1 = send(r.s, INS_EXPORT, (byte) 1, (byte) 0, HT);
                    byte[] z = r.m.z(eph);
                    byte[] payload =
                            e1.inner != null && e1.inner.sw == 0x9000
                                    ? FakeMember.unsealRecord(z, exportM, e1.inner.data)
                                    : null;
                    byte[] expect =
                            concat(
                                    new byte[] {0x02},
                                    S0,
                                    HT,
                                    new byte[] {0x02},
                                    cardId(r.s.cardA),
                                    r.m.cardId);
                    row(
                            "G2",
                            "L2 v",
                            "EXPORT P1=01",
                            "[9000] 160 B; payload = 02‖S0‖HT‖02‖ID(A)‖ID(A_M) under a valid CMAC",
                            e1.inner != null
                                    ? "["
                                            + s4(e1.inner.sw)
                                            + "] "
                                            + e1.inner.data.length
                                            + " B; payload "
                                            + (payload == null
                                                    ? "CMAC/unM2 failed"
                                                    : Arrays.equals(payload, expect)
                                                            ? "matches"
                                                            : "MISMATCH " + hex(payload))
                                    : "outer " + s4(e1.outer),
                            e1.inner != null
                                    && e1.inner.sw == 0x9000
                                    && e1.inner.data.length == 160
                                    && payload != null
                                    && Arrays.equals(payload, expect));
                });

        cell(
                "G2-L3",
                "L3 v",
                "EXPORT P1=01, c = 3 → 176 B",
                () -> {
                    ReviewCard c = prepared("B");
                    FakeMember m = new FakeMember(ReviewCard.CA);
                    FakeMember n = new FakeMember(ReviewCard.CA);
                    c.create(S0, H0, m.cardId, n.cardId);
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    send(s, INS_EXPORT, (byte) 0, (byte) 0, m.exportRequest());
                    Raw e1 = send(s, INS_EXPORT, (byte) 1, (byte) 0, HT);
                    row(
                            "G2-L3",
                            "L3 v",
                            "EXPORT P1=01",
                            "[9000] 176 B",
                            e1.inner != null
                                    ? "[" + s4(e1.inner.sw) + "] " + e1.inner.data.length + " B"
                                    : "outer " + s4(e1.outer),
                            e1.inner != null
                                    && e1.inner.sw == 0x9000
                                    && e1.inner.data.length == 176);
                });

        cell(
                "G3",
                "L2 v",
                "EXPORT P1=00 bad variants",
                () -> {
                    L2 r = l2(true);
                    List<String> obs = new ArrayList<>();
                    {
                        byte[] badCert = r.m.cert.clone();
                        badCert[96] ^= 0x01;
                        Raw e0 =
                                send(
                                        r.s,
                                        INS_EXPORT,
                                        (byte) 0,
                                        (byte) 0,
                                        concat(badCert, r.m.lk, r.m.offerSig()));
                        Raw e1 = send(r.s, INS_EXPORT, (byte) 1, (byte) 0, HT);
                        obs.add("certBad:" + s4(e0.inner.sw) + "/" + s4(e1.inner.sw));
                    }
                    {
                        Raw e0 =
                                send(
                                        r.s,
                                        INS_EXPORT,
                                        (byte) 0,
                                        (byte) 0,
                                        concat(r.s.cert, r.m.lk, r.m.offerSig()));
                        obs.add("ownCert:" + s4(e0.inner.sw));
                    }
                    {
                        FakeMember n = new FakeMember(ReviewCard.CA);
                        Raw e0 = send(r.s, INS_EXPORT, (byte) 0, (byte) 0, n.exportRequest());
                        obs.add("nonMember:" + s4(e0.inner.sw));
                    }
                    {
                        byte[] lk = r.m.lk.clone();
                        lk[0] = 0x05;
                        Raw e0 =
                                send(
                                        r.s,
                                        INS_EXPORT,
                                        (byte) 0,
                                        (byte) 0,
                                        concat(r.m.cert, lk, r.m.offerSig()));
                        obs.add("lkTag:" + s4(e0.inner.sw));
                    }
                    {
                        Raw e0 =
                                send(
                                        r.s,
                                        INS_EXPORT,
                                        (byte) 0,
                                        (byte) 0,
                                        concat(r.m.cert, r.m.lk, sha512("bad sig".getBytes())));
                        obs.add("sigBad:" + s4(e0.inner.sw));
                    }
                    {
                        byte[] lkBad =
                                concat(
                                        new byte[] {0x04},
                                        i2b(BigInteger.ONE, 32),
                                        i2b(BigInteger.valueOf(3), 32));
                        byte[] sig = ecdsaSign(r.m.id, concat(LABEL_OFFER, lkBad));
                        Raw e0 =
                                send(
                                        r.s,
                                        INS_EXPORT,
                                        (byte) 0,
                                        (byte) 0,
                                        concat(r.m.cert, lkBad, sig));
                        obs.add("lkOffCurve:" + s4(e0.inner.sw));
                    }
                    {
                        byte[] lkBad =
                                concat(new byte[] {0x04}, i2b(P, 32), i2b(BigInteger.ONE, 32));
                        byte[] sig = ecdsaSign(r.m.id, concat(LABEL_OFFER, lkBad));
                        Raw e0 =
                                send(
                                        r.s,
                                        INS_EXPORT,
                                        (byte) 0,
                                        (byte) 0,
                                        concat(r.m.cert, lkBad, sig));
                        Raw e1 = send(r.s, INS_EXPORT, (byte) 1, (byte) 0, HT);
                        obs.add("lkXp:" + s4(e0.inner.sw) + "/" + s4(e1.inner.sw));
                    }
                    row(
                            "G3",
                            "L2 v",
                            "EXPORT P1=00 bad variants",
                            "[6A80] each; no pending ([6985] on P1=01)",
                            String.join(" ", obs),
                            obs.stream()
                                    .allMatch(
                                            o ->
                                                    o.contains("6A80")
                                                            && (!o.contains("/")
                                                                    || o.endsWith("6985"))));
                });

        cell(
                "G3-d",
                "L(member A_bad)",
                "cert of member whose A does not decompress",
                () -> {
                    BigInteger x = BigInteger.ONE;
                    while (true) {
                        BigInteger z =
                                x.modPow(BigInteger.valueOf(3), P)
                                        .add(BigInteger.valueOf(7))
                                        .mod(P);
                        if (z.modPow(P.subtract(BigInteger.ONE).shiftRight(1), P)
                                .equals(P.subtract(BigInteger.ONE))) {
                            break;
                        }
                        x = x.add(BigInteger.ONE);
                    }
                    byte[] aBad = concat(new byte[] {0x02}, i2b(x, 32));
                    ReviewCard c = prepared("B");
                    c.create(S0, H0, cardId(aBad));
                    ReviewSession s = c.open();
                    in(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    byte[] certBad = ReviewCard.CA.issue(aBad);
                    byte[] lk = uncomp(g().multiply(BigInteger.valueOf(77)));
                    Raw e0 =
                            send(
                                    s,
                                    INS_EXPORT,
                                    (byte) 0,
                                    (byte) 0,
                                    concat(certBad, lk, sha512("no private key".getBytes())));
                    row(
                            "G3-d",
                            "L(member A_bad)",
                            "EXPORT P1=00 non-decompressing A_T",
                            "[6A80]",
                            "[" + (e0.inner != null ? s4(e0.inner.sw) : "?") + "]",
                            e0.inner != null && e0.inner.sw == 0x6A80);
                });

        cell(
                "G4",
                "L2 s",
                "EXPORT P1=00 valid, unverified",
                () -> {
                    L2 r = l2(false);
                    inSw(
                            "G4",
                            "L2 s",
                            "EXPORT P1=00",
                            0x6982,
                            send(r.s, INS_EXPORT, (byte) 0, (byte) 0, r.m.exportRequest()));
                });

        cell(
                "G5",
                "B s (target)",
                "OFFER then IMPORT P1=00 from host source M",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    Raw of = send(s, INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                    byte[] lkT = slice(of.inner.data, 0, 65);
                    FakeMember m = new FakeMember(ReviewCard.CA);
                    byte[][] offer = m.exportOffer(s.cardA, lkT);
                    Raw i0 = send(s, INS_IMPORT, (byte) 0, (byte) 0, offer[0]);
                    row(
                            "G5",
                            "B s",
                            "IMPORT P1=00",
                            "[9000] empty",
                            "["
                                    + (i0.inner != null ? s4(i0.inner.sw) : "?")
                                    + "] "
                                    + (i0.inner != null ? i0.inner.data.length : -1)
                                    + " B",
                            i0.inner != null && i0.inner.sw == 0x9000 && i0.inner.data.length == 0);
                });

        cell(
                "G6",
                "after G5",
                "IMPORT P1=01 host-encrypted payload",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    Raw of = send(s, INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                    byte[] lkT = slice(of.inner.data, 0, 65);
                    FakeMember m = new FakeMember(ReviewCard.CA);
                    byte[][] offer = m.exportOffer(s.cardA, lkT);
                    send(s, INS_IMPORT, (byte) 0, (byte) 0, offer[0]);
                    byte[] z = ecdhX(b2i(offer[1]), lkT);
                    byte[] exportM =
                            concat(LABEL_EXPORT, m.a, s.cardA, lkT, slice(offer[0], 97, 65));
                    byte[] payload =
                            concat(
                                    new byte[] {0x01},
                                    S1,
                                    H2,
                                    new byte[] {0x02},
                                    m.cardId,
                                    cardId(s.cardA));
                    byte[][] seal = FakeMember.sealRecord(z, exportM, payload);
                    Raw i1 = send(s, INS_IMPORT, (byte) 1, (byte) 0, seal[0]);
                    byte[] mpk = compr(g().multiply(b2i(bip32Master(S1)[0])));
                    byte[] expectWi =
                            concat(mpk, new byte[] {0x01, 0x02}, m.cardId, cardId(s.cardA));
                    boolean wiOk =
                            i1.inner != null
                                    && i1.inner.sw == 0x9000
                                    && Arrays.equals(i1.inner.data, expectWi);
                    Raw st = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    Raw pk = send(s, INS_PUBLIC_KEY, (byte) 0, (byte) 0, pathBytes(0));
                    ReviewSession s2 = c.open();
                    Raw v = send(s2, INS_VERIFY, (byte) 0, (byte) 0, H2);
                    ReviewSession s3 = c.open();
                    Raw i2 = send(s3, INS_IMPORT, (byte) 0, (byte) 0, offer[0]);
                    row(
                            "G6",
                            "B s after OFFER",
                            "IMPORT P1=01 → install",
                            "[9000] WalletInfo(01,c02,payload order); STATUS 02 0A; not verified; "
                                    + "new session VERIFY(H2) [9000]; second P1=00 [6985]",
                            (i1.inner != null
                                            ? "["
                                                    + s4(i1.inner.sw)
                                                    + "] "
                                                    + (wiOk ? "WalletInfo match" : "MISMATCH")
                                            : "?")
                                    + "; STATUS "
                                    + (st.inner != null ? hex(st.inner.data) : "?")
                                    + "; PK ["
                                    + (pk.inner != null ? s4(pk.inner.sw) : "?")
                                    + "]; VERIFY ["
                                    + (v.inner != null ? s4(v.inner.sw) : "?")
                                    + "]; 2nd P1=00 ["
                                    + (i2.inner != null ? s4(i2.inner.sw) : "?")
                                    + "]",
                            wiOk
                                    && st.inner != null
                                    && Arrays.equals(st.inner.data, new byte[] {0x02, 0x0A})
                                    && pk.inner != null
                                    && pk.inner.sw == 0x6982
                                    && v.inner != null
                                    && v.inner.sw == 0x9000
                                    && i2.inner != null
                                    && i2.inner.sw == 0x6985);
                });

        cell(
                "G7",
                "B s after OFFER",
                "IMPORT P1=00 bad variants",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    Raw of = send(s, INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                    byte[] lkT = slice(of.inner.data, 0, 65);
                    FakeMember m = new FakeMember(ReviewCard.CA);
                    List<String> obs = new ArrayList<>();
                    {
                        byte[] bad = m.cert.clone();
                        bad[96] ^= 0x01;
                        byte[] e65 = uncomp(g().multiply(randomScalar()));
                        byte[] sig = ecdsaSign(m.id, concat(LABEL_EXPORT, m.a, s.cardA, lkT, e65));
                        Raw r = send(s, INS_IMPORT, (byte) 0, (byte) 0, concat(bad, e65, sig));
                        obs.add("certBad:" + s4(r.inner.sw));
                    }
                    {
                        byte[] e65 = uncomp(g().multiply(randomScalar()));
                        Raw r =
                                send(
                                        s,
                                        INS_IMPORT,
                                        (byte) 0,
                                        (byte) 0,
                                        concat(s.cert, e65, sha512("x".getBytes())));
                        obs.add("ownCert:" + s4(r.inner.sw));
                    }
                    {
                        BigInteger x = BigInteger.ONE;
                        while (true) {
                            BigInteger z =
                                    x.modPow(BigInteger.valueOf(3), P)
                                            .add(BigInteger.valueOf(7))
                                            .mod(P);
                            if (z.modPow(P.subtract(BigInteger.ONE).shiftRight(1), P)
                                    .equals(P.subtract(BigInteger.ONE))) {
                                break;
                            }
                            x = x.add(BigInteger.ONE);
                        }
                        byte[] aBad = concat(new byte[] {0x02}, i2b(x, 32));
                        byte[] certBad = ReviewCard.CA.issue(aBad);
                        byte[] e65 = uncomp(g().multiply(randomScalar()));
                        Raw r =
                                send(
                                        s,
                                        INS_IMPORT,
                                        (byte) 0,
                                        (byte) 0,
                                        concat(certBad, e65, sha512("no key".getBytes())));
                        obs.add("aBad:" + s4(r.inner.sw));
                    }
                    {
                        byte[] e65 = uncomp(g().multiply(randomScalar()));
                        Raw r =
                                send(
                                        s,
                                        INS_IMPORT,
                                        (byte) 0,
                                        (byte) 0,
                                        concat(m.cert, e65, sha512("bad sig".getBytes())));
                        obs.add("sigBad:" + s4(r.inner.sw));
                    }
                    {
                        byte[] e65 = concat(new byte[] {0x02}, new byte[64]);
                        byte[] sig = ecdsaSign(m.id, concat(LABEL_EXPORT, m.a, s.cardA, lkT, e65));
                        Raw r = send(s, INS_IMPORT, (byte) 0, (byte) 0, concat(m.cert, e65, sig));
                        obs.add("eTag:" + s4(r.inner.sw));
                    }
                    {
                        byte[] e65 =
                                concat(
                                        new byte[] {0x04},
                                        i2b(BigInteger.ONE, 32),
                                        i2b(BigInteger.valueOf(3), 32));
                        byte[] sig = ecdsaSign(m.id, concat(LABEL_EXPORT, m.a, s.cardA, lkT, e65));
                        Raw r = send(s, INS_IMPORT, (byte) 0, (byte) 0, concat(m.cert, e65, sig));
                        obs.add("eOffCurve:" + s4(r.inner.sw));
                    }
                    {
                        byte[] e65 = concat(new byte[] {0x04}, i2b(P, 32), i2b(BigInteger.ONE, 32));
                        byte[] sig = ecdsaSign(m.id, concat(LABEL_EXPORT, m.a, s.cardA, lkT, e65));
                        Raw r = send(s, INS_IMPORT, (byte) 0, (byte) 0, concat(m.cert, e65, sig));
                        Raw after = send(s, INS_IMPORT, (byte) 1, (byte) 0, new byte[160]);
                        obs.add("eXp:" + s4(r.inner.sw) + "/" + s4(after.inner.sw));
                    }
                    {
                        byte[] e65 = uncomp(g().multiply(randomScalar()));
                        byte[] lkOther = uncomp(g().multiply(BigInteger.valueOf(99)));
                        byte[] sig =
                                ecdsaSign(m.id, concat(LABEL_EXPORT, m.a, s.cardA, lkOther, e65));
                        Raw r = send(s, INS_IMPORT, (byte) 0, (byte) 0, concat(m.cert, e65, sig));
                        Raw after = send(s, INS_IMPORT, (byte) 1, (byte) 0, new byte[160]);
                        obs.add("sigOtherLk:" + s4(r.inner.sw) + "/" + s4(after.inner.sw));
                    }
                    row(
                            "G7",
                            "B s after OFFER",
                            "IMPORT P1=00 bad variants",
                            "[6A80] each; IMPORT P1=01 → [6985]",
                            String.join(" ", obs),
                            obs.stream()
                                    .allMatch(
                                            o ->
                                                    o.contains("6A80")
                                                            && (!o.contains("/")
                                                                    || o.endsWith("6985"))));
                });

        cell(
                "G8",
                "L2 s after OFFER",
                "IMPORT P1=00 from non-member N",
                () -> {
                    L2 r = l2(false);
                    Raw of = send(r.s, INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                    byte[] lkT = slice(of.inner.data, 0, 65);
                    FakeMember n = new FakeMember(ReviewCard.CA);
                    byte[][] offer = n.exportOffer(r.s.cardA, lkT);
                    Raw i0 = send(r.s, INS_IMPORT, (byte) 0, (byte) 0, offer[0]);
                    row(
                            "G8",
                            "L2 s",
                            "IMPORT P1=00 non-member source",
                            "[6A80]",
                            "[" + (i0.inner != null ? s4(i0.inner.sw) : "?") + "]",
                            i0.inner != null && i0.inner.sw == 0x6A80);
                });

        cell(
                "G9",
                "B after G5",
                "IMPORT P1=01 bad payloads",
                () -> {
                    List<String> obs = new ArrayList<>();
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    FakeMember m = new FakeMember(ReviewCard.CA);
                    {
                        byte[][] ctx = pendingImport(s, m);
                        byte[] rec = ctx[2].clone();
                        rec[rec.length - 1] ^= 0x01;
                        Raw r = send(s, INS_IMPORT, (byte) 1, (byte) 0, rec);
                        obs.add("tagFlip:" + s4(r.inner.sw));
                    }
                    {
                        byte[][] ctx = pendingImport(s, m);
                        byte[][] keys = FakeMember.transferKeys(ctx[0], ctx[1]);
                        byte[] raw = new byte[144];
                        raw[0] = 0x01;
                        System.arraycopy(S1, 0, raw, 1, 40);
                        byte[] ct = cbc(keys[0], new byte[16], raw);
                        byte[] tag = cmac(keys[1], ct);
                        Raw r = send(s, INS_IMPORT, (byte) 1, (byte) 0, concat(ct, tag));
                        obs.add("badM2:" + s4(r.inner.sw));
                    }
                    {
                        obs.add(
                                "len:"
                                        + s4(
                                                importPayload(
                                                        s,
                                                        m,
                                                        concat(
                                                                new byte[] {0x01},
                                                                S1,
                                                                H2,
                                                                new byte[] {0x02},
                                                                m.cardId,
                                                                cardId(s.cardA),
                                                                new byte[] {0x77}))));
                    }
                    {
                        obs.add(
                                "origin03:"
                                        + s4(
                                                importPayload(
                                                        s,
                                                        m,
                                                        concat(
                                                                new byte[] {0x03},
                                                                S1,
                                                                H2,
                                                                new byte[] {0x02},
                                                                m.cardId,
                                                                cardId(s.cardA)))));
                    }
                    {
                        obs.add(
                                "dupIds:"
                                        + s4(
                                                importPayload(
                                                        s,
                                                        m,
                                                        concat(
                                                                new byte[] {0x01},
                                                                S1,
                                                                H2,
                                                                new byte[] {0x02},
                                                                m.cardId,
                                                                m.cardId))));
                    }
                    {
                        obs.add(
                                "ownAbsent:"
                                        + s4(
                                                importPayload(
                                                        s,
                                                        m,
                                                        concat(
                                                                new byte[] {0x01},
                                                                S1,
                                                                H2,
                                                                new byte[] {0x02},
                                                                m.cardId,
                                                                X_ID))));
                    }
                    {
                        obs.add(
                                "senderAbsent:"
                                        + s4(
                                                importPayload(
                                                        s,
                                                        m,
                                                        concat(
                                                                new byte[] {0x01},
                                                                S1,
                                                                H2,
                                                                new byte[] {0x02},
                                                                cardId(s.cardA),
                                                                X_ID))));
                    }
                    Raw again = send(s, INS_IMPORT, (byte) 1, (byte) 0, new byte[160]);
                    Raw st = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "G9",
                            "B after G5",
                            "IMPORT P1=01 bad payloads",
                            "[6A80] each; still BLANK; pending ended → [6985]",
                            String.join(" ", obs)
                                    + "; again "
                                    + (again.inner != null ? s4(again.inner.sw) : "?")
                                    + "; STATUS "
                                    + (st.inner != null ? hex(st.inner.data) : "?"),
                            obs.stream().allMatch(o -> o.endsWith("6A80"))
                                    && again.inner != null
                                    && again.inner.sw == 0x6985
                                    && st.inner != null
                                    && Arrays.equals(st.inner.data, new byte[] {0x01, 0x00}));
                });

        cell(
                "G10",
                "L2 (fails=2) s",
                "re-seal IMPORT of the same wallet",
                () -> {
                    L2 r = l2(false);
                    ReviewSession prior = r.c.open();
                    ReviewCard.failTo(prior, H1, 2);
                    ReviewSession s = r.c.open();
                    Raw of = send(s, INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                    byte[] lkT = slice(of.inner.data, 0, 65);
                    byte[][] offer = r.m.exportOffer(s.cardA, lkT);
                    Raw i0 = send(s, INS_IMPORT, (byte) 0, (byte) 0, offer[0]);
                    byte[] z = ecdhX(b2i(offer[1]), lkT);
                    byte[] exportM =
                            concat(LABEL_EXPORT, r.m.a, s.cardA, lkT, slice(offer[0], 97, 65));
                    byte[] payload =
                            concat(
                                    new byte[] {0x02},
                                    S0,
                                    H3,
                                    new byte[] {0x02},
                                    cardId(s.cardA),
                                    r.m.cardId);
                    byte[][] seal = FakeMember.sealRecord(z, exportM, payload);
                    Raw i1 = send(s, INS_IMPORT, (byte) 1, (byte) 0, seal[0]);
                    Raw st = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    ReviewSession s2 = r.c.open();
                    Raw v3 = send(s2, INS_VERIFY, (byte) 0, (byte) 0, H3);
                    ReviewSession s3 = r.c.open();
                    Raw v0 = send(s3, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    row(
                            "G10",
                            "L2 s",
                            "re-seal payload 02‖S0‖H3‖02‖ID(A_X)‖ID(A_M)",
                            "[9000] WalletInfo; VERIFY(H3) works; VERIFY(H0) fails; fails reset",
                            "i0 "
                                    + (i0.inner != null ? s4(i0.inner.sw) : "?")
                                    + "; i1 ["
                                    + (i1.inner != null ? s4(i1.inner.sw) : "?")
                                    + "]; STATUS "
                                    + (st.inner != null ? hex(st.inner.data) : "?")
                                    + "; VERIFY(H3) ["
                                    + (v3.inner != null ? s4(v3.inner.sw) : "?")
                                    + "]; VERIFY(H0) ["
                                    + (v0.inner != null ? s4(v0.inner.sw) : "?")
                                    + "]",
                            i0.inner != null
                                    && i0.inner.sw == 0x9000
                                    && i1.inner != null
                                    && i1.inner.sw == 0x9000
                                    && st.inner != null
                                    && Arrays.equals(st.inner.data, new byte[] {0x02, 0x0A})
                                    && v3.inner != null
                                    && v3.inner.sw == 0x9000
                                    && v0.inner != null
                                    && v0.inner.sw == 0x63C9);
                });

        cell(
                "G11",
                "as G10",
                "re-seal payload variants",
                () -> {
                    List<String> obs = new ArrayList<>();
                    L2 r = l2(false);
                    ReviewSession s = r.s;
                    Raw of = send(s, INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                    byte[] lkT = slice(of.inner.data, 0, 65);
                    Object[][] cases = {
                        {
                            "differentSeed",
                            concat(
                                    new byte[] {0x02},
                                    S1,
                                    H3,
                                    new byte[] {0x02},
                                    cardId(s.cardA),
                                    r.m.cardId)
                        },
                        {
                            "origin01",
                            concat(
                                    new byte[] {0x01},
                                    S0,
                                    H3,
                                    new byte[] {0x02},
                                    cardId(s.cardA),
                                    r.m.cardId)
                        },
                        {
                            "reordered",
                            concat(
                                    new byte[] {0x02},
                                    S0,
                                    H3,
                                    new byte[] {0x02},
                                    r.m.cardId,
                                    cardId(s.cardA))
                        },
                        {
                            "otherMember",
                            concat(
                                    new byte[] {0x02},
                                    S0,
                                    H3,
                                    new byte[] {0x02},
                                    cardId(s.cardA),
                                    Y_ID)
                        },
                    };
                    for (Object[] k : cases) {
                        byte[][] offer = r.m.exportOffer(s.cardA, lkT);
                        send(s, INS_IMPORT, (byte) 0, (byte) 0, offer[0]);
                        byte[] z = ecdhX(b2i(offer[1]), lkT);
                        byte[] exportM =
                                concat(LABEL_EXPORT, r.m.a, s.cardA, lkT, slice(offer[0], 97, 65));
                        byte[][] seal = FakeMember.sealRecord(z, exportM, (byte[]) k[1]);
                        Raw i1 = send(s, INS_IMPORT, (byte) 1, (byte) 0, seal[0]);
                        obs.add(k[0] + ":" + (i1.inner != null ? s4(i1.inner.sw) : "?"));
                    }
                    ReviewSession s2 = r.c.open();
                    Raw v0 = send(s2, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    row(
                            "G11",
                            "as G10",
                            "re-seal payload variants",
                            "[6A80] each; card keeps S0 and H0",
                            String.join(" ", obs)
                                    + "; VERIFY(H0) ["
                                    + (v0.inner != null ? s4(v0.inner.sw) : "?")
                                    + "]",
                            obs.stream().allMatch(o -> o.endsWith("6A80"))
                                    && v0.inner != null
                                    && v0.inner.sw == 0x9000);
                });

        cell(
                "G12",
                "B s",
                "IMPORT P1=00 twice with same export, then P1=01",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    Raw of = send(s, INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                    byte[] lkT = slice(of.inner.data, 0, 65);
                    FakeMember m = new FakeMember(ReviewCard.CA);
                    byte[][] offer = m.exportOffer(s.cardA, lkT);
                    Raw i0a = send(s, INS_IMPORT, (byte) 0, (byte) 0, offer[0]);
                    Raw i0b = send(s, INS_IMPORT, (byte) 0, (byte) 0, offer[0]);
                    byte[] z = ecdhX(b2i(offer[1]), lkT);
                    byte[] exportM =
                            concat(LABEL_EXPORT, m.a, s.cardA, lkT, slice(offer[0], 97, 65));
                    byte[][] seal =
                            FakeMember.sealRecord(
                                    z,
                                    exportM,
                                    concat(
                                            new byte[] {0x01},
                                            S1,
                                            H2,
                                            new byte[] {0x02},
                                            m.cardId,
                                            cardId(s.cardA)));
                    Raw i1 = send(s, INS_IMPORT, (byte) 1, (byte) 0, seal[0]);
                    row(
                            "G12",
                            "B s",
                            "IMPORT P1=00 ×2 then P1=01",
                            "[9000] all",
                            "["
                                    + s4(i0a.inner.sw)
                                    + "]["
                                    + s4(i0b.inner.sw)
                                    + "]["
                                    + (i1.inner != null ? s4(i1.inner.sw) : "?")
                                    + "]",
                            i0a.inner != null
                                    && i0a.inner.sw == 0x9000
                                    && i0b.inner != null
                                    && i0b.inner.sw == 0x9000
                                    && i1.inner != null
                                    && i1.inner.sw == 0x9000);
                });

        cell(
                "G13",
                "B s",
                "OFFER, IMPORT P1=00, STATUS, IMPORT P1=01",
                () -> {
                    ReviewCard c = prepared("B");
                    ReviewSession s = c.open();
                    Raw of = send(s, INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                    byte[] lkT = slice(of.inner.data, 0, 65);
                    FakeMember m = new FakeMember(ReviewCard.CA);
                    send(s, INS_IMPORT, (byte) 0, (byte) 0, m.exportOffer(s.cardA, lkT)[0]);
                    send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    Raw i1 = send(s, INS_IMPORT, (byte) 1, (byte) 0, new byte[160]);
                    inSw("G13", "B s", "IMPORT P1=01 after STATUS", 0x6985, i1);
                });

        cell(
                "G14",
                "L2 v",
                "EXPORT P1=00, STATUS, EXPORT P1=01",
                () -> {
                    L2 r = l2(true);
                    send(r.s, INS_EXPORT, (byte) 0, (byte) 0, r.m.exportRequest());
                    send(r.s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    Raw e1 = send(r.s, INS_EXPORT, (byte) 1, (byte) 0, HT);
                    inSw("G14", "L2 v", "EXPORT P1=01 after STATUS", 0x6985, e1);
                });

        cell(
                "G15",
                "L2 v",
                "EXPORT P1=01 wrong length ends pending",
                () -> {
                    L2 r = l2(true);
                    send(r.s, INS_EXPORT, (byte) 0, (byte) 0, r.m.exportRequest());
                    Raw bad = send(r.s, INS_EXPORT, (byte) 1, (byte) 0, new byte[31]);
                    Raw e1 = send(r.s, INS_EXPORT, (byte) 1, (byte) 0, HT);
                    row(
                            "G15",
                            "L2 v",
                            "EXPORT P1=01 31 B then P1=01",
                            "[6700] then [6985]",
                            "["
                                    + (bad.inner != null ? s4(bad.inner.sw) : "?")
                                    + "] then ["
                                    + (e1.inner != null ? s4(e1.inner.sw) : "?")
                                    + "]",
                            bad.inner != null
                                    && bad.inner.sw == 0x6700
                                    && e1.inner != null
                                    && e1.inner.sw == 0x6985);
                });

        cell(
                "G16",
                "cards X (L2) and Y (B)",
                "full §11.2 card-to-card flow",
                () -> {
                    ReviewCard y = prepared("B");
                    ReviewSession ys = y.open();
                    ReviewCard x = prepared("B");
                    ReviewSession xs = x.open();
                    x.create(S0, H0, cardId(ys.cardA));
                    ReviewSession xv = x.open();
                    in(xv, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    Raw of = send(ys, INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
                    byte[] lkY = slice(of.inner.data, 0, 65);
                    byte[] sigY = slice(of.inner.data, 65, 64);
                    Raw e0 = send(xv, INS_EXPORT, (byte) 0, (byte) 0, concat(ys.cert, lkY, sigY));
                    byte[] eph = slice(e0.inner.data, 0, 65);
                    byte[] sigS = slice(e0.inner.data, 65, 64);
                    Raw e1 = send(xv, INS_EXPORT, (byte) 1, (byte) 0, HT);
                    Raw i0 = send(ys, INS_IMPORT, (byte) 0, (byte) 0, concat(xs.cert, eph, sigS));
                    Raw i1 = send(ys, INS_IMPORT, (byte) 1, (byte) 0, e1.inner.data);
                    byte[] mpk = compr(g().multiply(b2i(bip32Master(S0)[0])));
                    boolean ok =
                            i1.inner != null
                                    && i1.inner.sw == 0x9000
                                    && Arrays.equals(slice(i1.inner.data, 0, 33), mpk);
                    row(
                            "G16",
                            "X↔Y",
                            "full transfer",
                            "Y LOADED with the same mpk as X",
                            "e0 "
                                    + (e0.inner != null ? s4(e0.inner.sw) : "?")
                                    + ", e1 "
                                    + (e1.inner != null ? s4(e1.inner.sw) : "?")
                                    + ", i0 "
                                    + (i0.inner != null ? s4(i0.inner.sw) : "?")
                                    + ", i1 ["
                                    + (i1.inner != null ? s4(i1.inner.sw) : "?")
                                    + "] mpk "
                                    + (ok ? "match" : "MISMATCH"),
                            e0.inner != null
                                    && e0.inner.sw == 0x9000
                                    && e1.inner != null
                                    && e1.inner.sw == 0x9000
                                    && i0.inner != null
                                    && i0.inner.sw == 0x9000
                                    && ok);
                });
    }

    /** Redoes a valid pending import on s with host source m; returns {z, exportM, record}. */
    private byte[][] pendingImport(ReviewSession s, FakeMember m) {
        Raw of = send(s, INS_OFFER, (byte) 0, (byte) 0, new byte[0]);
        byte[] lkT = slice(of.inner.data, 0, 65);
        byte[][] offer = m.exportOffer(s.cardA, lkT);
        send(s, INS_IMPORT, (byte) 0, (byte) 0, offer[0]);
        byte[] z = ecdhX(b2i(offer[1]), lkT);
        byte[] exportM = concat(LABEL_EXPORT, m.a, s.cardA, lkT, slice(offer[0], 97, 65));
        byte[][] seal =
                FakeMember.sealRecord(
                        z,
                        exportM,
                        concat(
                                new byte[] {0x01},
                                S1,
                                H2,
                                new byte[] {0x02},
                                m.cardId,
                                cardId(s.cardA)));
        return new byte[][] {z, exportM, seal[0]};
    }

    /** One pending import + one IMPORT P1=01 with a crafted payload; returns the inner SW. */
    private int importPayload(ReviewSession s, FakeMember m, byte[] payload) {
        byte[][] ctx = pendingImport(s, m);
        byte[][] seal = FakeMember.sealRecord(ctx[0], ctx[1], payload);
        Raw r = send(s, INS_IMPORT, (byte) 1, (byte) 0, seal[0]);
        return r.inner != null ? r.inner.sw : -1;
    }

    // H. VERIFY / WAIT sequences (§7.3, §9.5, §9.15)

    private void sectionH() {
        cell(
                "H1",
                "L1 s",
                "3 wrong VERIFYs",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    StringBuilder obs = new StringBuilder();
                    StringBuilder tries = new StringBuilder();
                    for (int i = 0; i < 3; i++) {
                        Raw v = send(s, INS_VERIFY, (byte) 0, (byte) 0, H1);
                        Raw st = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                        obs.append(v.inner != null ? s4(v.inner.sw) : "?").append(' ');
                        tries.append(st.inner != null ? hex(st.inner.data) : "?").append(' ');
                    }
                    row(
                            "H1",
                            "L1 s",
                            "3 wrong VERIFYs",
                            "[63C9] [63C8] [63C7]; tries 09 08 07",
                            obs.toString().trim() + "; " + tries.toString().trim(),
                            obs.toString().trim().equals("63C9 63C8 63C7")
                                    && tries.toString().trim().equals("0209 0208 0207"));
                });
        cell(
                "H2",
                "after H1",
                "wrong VERIFY without WAIT",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    ReviewCard.failTo(s, H1, 3);
                    Raw v = send(s, INS_VERIFY, (byte) 0, (byte) 0, H1);
                    Raw st = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "H2",
                            "L1 f=3 s",
                            "wrong VERIFY",
                            "[6986]; tries 7",
                            "["
                                    + (v.inner != null ? s4(v.inner.sw) : "?")
                                    + "]; STATUS "
                                    + (st.inner != null ? hex(st.inner.data) : "?"),
                            v.inner != null
                                    && v.inner.sw == 0x6986
                                    && st.inner != null
                                    && Arrays.equals(st.inner.data, new byte[] {0x02, 0x07}));
                });
        cell(
                "H3",
                "after H1",
                "14 WAIT + wrong",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    ReviewCard.failTo(s, H1, 3);
                    ReviewSession s2 = c.open();
                    for (int i = 0; i < 14; i++) {
                        in(s2, INS_WAIT, (byte) 0, (byte) 0, new byte[0]);
                    }
                    Raw v = send(s2, INS_VERIFY, (byte) 0, (byte) 0, H1);
                    inSw("H3", "L1 f=3 s", "14 WAIT + wrong VERIFY", 0x6986, v);
                });
        cell(
                "H4",
                "after H1",
                "15 WAIT + wrong, repeated to the limit",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    ReviewCard.failTo(s, H1, 3);
                    ReviewSession s2 = c.open();
                    StringBuilder obs = new StringBuilder();
                    for (int i = 0; i < 7; i++) {
                        ReviewCard.waitW(s2);
                        Raw v = send(s2, INS_VERIFY, (byte) 0, (byte) 0, H1);
                        obs.append(v.inner != null ? s4(v.inner.sw) : "?").append(' ');
                        if (v.inner == null || v.inner.sw == 0x6983) {
                            break;
                        }
                    }
                    Raw st = send(s2, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "H4",
                            "L1 f=3 s",
                            "waited wrongs to the limit",
                            "[63C6]…[63C1], 10th wrong [6983]; STATUS 01 00",
                            obs.toString().trim()
                                    + "; STATUS "
                                    + (st.inner != null
                                            ? "[" + s4(st.inner.sw) + "] " + hex(st.inner.data)
                                            : "?"),
                            obs.toString().trim().equals("63C6 63C5 63C4 63C3 63C2 63C1 6983")
                                    && st.inner != null
                                    && st.inner.sw == 0x9000
                                    && Arrays.equals(st.inner.data, new byte[] {0x01, 0x00}));
                });
        cell(
                "H5",
                "L1 f=3",
                "15 WAIT, new OPEN, wrong",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    ReviewCard.failTo(s, H1, 3);
                    ReviewSession s2 = c.open();
                    ReviewCard.waitW(s2);
                    ReviewSession s3 = c.open();
                    Raw v = send(s3, INS_VERIFY, (byte) 0, (byte) 0, H1);
                    inSw("H5", "L1 f=3", "new OPEN loses waited", 0x6986, v);
                });
        cell(
                "H6",
                "L1 f=3",
                "20 WAIT, wrong, wrong",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    ReviewCard.failTo(s, H1, 3);
                    ReviewSession s2 = c.open();
                    for (int i = 0; i < 20; i++) {
                        in(s2, INS_WAIT, (byte) 0, (byte) 0, new byte[0]);
                    }
                    Raw v1 = send(s2, INS_VERIFY, (byte) 0, (byte) 0, H1);
                    Raw v2 = send(s2, INS_VERIFY, (byte) 0, (byte) 0, H1);
                    row(
                            "H6",
                            "L1 f=3",
                            "20 WAIT, wrong, wrong",
                            "[63C6] [6986]",
                            "["
                                    + (v1.inner != null ? s4(v1.inner.sw) : "?")
                                    + "] ["
                                    + (v2.inner != null ? s4(v2.inner.sw) : "?")
                                    + "]",
                            v1.inner != null
                                    && v1.inner.sw == 0x63C6
                                    && v2.inner != null
                                    && v2.inner.sw == 0x6986);
                });
        for (int k = 0; k <= 9; k++) {
            final int kk = k;
            cell(
                    "H7-" + k,
                    "L1 f=" + k,
                    "right code" + (k >= 3 ? " (with waits)" : ""),
                    () -> {
                        ReviewCard c = prepared("L1");
                        ReviewSession s = c.open();
                        ReviewCard.failTo(s, H1, kk);
                        ReviewSession s2 = c.open();
                        if (kk >= 3) {
                            ReviewCard.waitW(s2);
                        }
                        Raw v = send(s2, INS_VERIFY, (byte) 0, (byte) 0, H0);
                        Raw st = send(s2, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                        row(
                                "H7-" + kk,
                                "L1 f=" + kk,
                                "right code",
                                "[9000]; tries 0A",
                                "["
                                        + (v.inner != null ? s4(v.inner.sw) : "?")
                                        + "]; STATUS "
                                        + (st.inner != null ? hex(st.inner.data) : "?"),
                                v.inner != null
                                        && v.inner.sw == 0x9000
                                        && st.inner != null
                                        && Arrays.equals(st.inner.data, new byte[] {0x02, 0x0A}));
                    });
        }
        cell(
                "H8",
                "L1 f=3",
                "right code without WAIT",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    ReviewCard.failTo(s, H1, 3);
                    ReviewSession s2 = c.open();
                    Raw v = send(s2, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    inSw("H8", "L1 f=3", "right code, no wait", 0x6986, v);
                });
        cell(
                "H9",
                "L1 f=10 (injected)",
                "STATUS; VERIFY(H0)",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    c.injectFails(10); // setup injection: f = L with valid complement
                    Raw st = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    Raw v = send(s, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    ReviewSession s2 = c.open();
                    Raw st2 = send(s2, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "H9",
                            "L1 f=10",
                            "STATUS; VERIFY → BLANK",
                            "02 00; [6983]; BLANK",
                            "STATUS "
                                    + (st.inner != null ? hex(st.inner.data) : "?")
                                    + "; VERIFY ["
                                    + (v.inner != null ? s4(v.inner.sw) : "?")
                                    + "]; STATUS "
                                    + (st2.inner != null ? hex(st2.inner.data) : "?"),
                            st.inner != null
                                    && Arrays.equals(st.inner.data, new byte[] {0x02, 0x00})
                                    && v.inner != null
                                    && v.inner.sw == 0x6983
                                    && st2.inner != null
                                    && Arrays.equals(st2.inner.data, new byte[] {0x01, 0x00}));
                });
        cell(
                "H10",
                "L1, fails complement corrupted",
                "STATUS; VERIFY",
                () -> {
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    c.injectFailsPair(0, 0x0000); // setup injection: complement torn
                    Raw st = send(s, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    ReviewSession s2 = c.open();
                    Raw v = send(s2, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    ReviewSession s3 = c.open();
                    Raw st3 = send(s3, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "H10",
                            "L1 corrupted fails",
                            "STATUS; new-session VERIFY; STATUS",
                            "[6F00]; [6F00]; BLANK 01 00",
                            "STATUS ["
                                    + (st.inner != null ? s4(st.inner.sw) : "?")
                                    + "]; VERIFY ["
                                    + (v.inner != null ? s4(v.inner.sw) : "?")
                                    + "]; STATUS "
                                    + (st3.inner != null ? hex(st3.inner.data) : "?"),
                            st.inner != null
                                    && st.inner.sw == 0x6F00
                                    && v.inner != null
                                    && v.inner.sw == 0x6F00
                                    && st3.inner != null
                                    && Arrays.equals(st3.inner.data, new byte[] {0x01, 0x00}));
                });
        cell(
                "H11",
                "L1 f=9 + waits",
                "torn right code at the last attempt",
                () -> {
                    ReviewCard scratch = prepared("L1");
                    ReviewSession ss = scratch.open();
                    ss.cmd(INS_VERIFY, (byte) 0, (byte) 0, H1);
                    int tfailWrites = scratch.card.writes();
                    ReviewCard c = prepared("L1");
                    ReviewSession s = c.open();
                    c.injectFails(9); // setup injection: f = 9 (as after the 9th T-FAIL)
                    ReviewCard.waitW(s);
                    c.card.tearAt(tfailWrites + 1); // power loss before T-OK's first write
                    boolean torn = false;
                    try {
                        s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
                    } catch (TornException t) {
                        torn = true;
                    }
                    c.card.powerCycle();
                    c.transmit(SELECT_WALLET);
                    ReviewSession s2 = c.open();
                    Raw st = send(s2, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    Raw v = send(s2, INS_VERIFY, (byte) 0, (byte) 0, H0);
                    ReviewSession s3 = c.open();
                    Raw st3 = send(s3, INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
                    row(
                            "H11",
                            "L1 f=9 + waits",
                            "right code torn after T-FAIL",
                            "torn; STATUS 02 00; VERIFY [6983]; BLANK",
                            "torn "
                                    + torn
                                    + " (tear at write "
                                    + (tfailWrites + 1)
                                    + ", T-FAIL writes "
                                    + tfailWrites
                                    + "); STATUS "
                                    + (st.inner != null ? hex(st.inner.data) : "?")
                                    + "; VERIFY ["
                                    + (v.inner != null ? s4(v.inner.sw) : "?")
                                    + "]; STATUS "
                                    + (st3.inner != null ? hex(st3.inner.data) : "?"),
                            torn
                                    && st.inner != null
                                    && Arrays.equals(st.inner.data, new byte[] {0x02, 0x00})
                                    && v.inner != null
                                    && v.inner.sw == 0x6983
                                    && st3.inner != null
                                    && Arrays.equals(st3.inner.data, new byte[] {0x01, 0x00}));
                });
    }

    // I. NDEF applet (§15)

    private void sectionI() {
        cell(
                "I1",
                "any",
                "SELECT NDEF",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    outer("I1", "any", "SELECT D2760000850101", 0x9000, c.transmit(SELECT_NDEF));
                });
        cell(
                "I2",
                "NDEF selected",
                "READ BINARY before SELECT file",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    c.transmit(SELECT_NDEF);
                    outer(
                            "I2",
                            "NDEF",
                            "READ 00 B0 0000 0F",
                            0x6985,
                            c.transmit(unhex("00B000000F")));
                });
        cell(
                "I3",
                "NDEF",
                "SELECT E103; READ CC",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    c.transmit(SELECT_NDEF);
                    byte[] sel = c.transmit(unhex("00A4000C02E103"));
                    byte[] read = c.transmit(unhex("00B000000F"));
                    byte[] expect = unhex("000F2000FF00FF0406E104000B00FF");
                    row(
                            "I3",
                            "NDEF",
                            "SELECT E103; READ",
                            "9000; CC = " + hex(expect),
                            s4(ReviewHost.sw(sel))
                                    + "; "
                                    + s4(ReviewHost.sw(read))
                                    + " "
                                    + (Arrays.equals(respData(read), expect)
                                            ? "match"
                                            : hex(respData(read))),
                            ReviewHost.sw(sel) == 0x9000
                                    && ReviewHost.sw(read) == 0x9000
                                    && Arrays.equals(respData(read), expect));
                });
        cell(
                "I4",
                "NDEF",
                "SELECT E104; READ",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    c.transmit(SELECT_NDEF);
                    byte[] sel = c.transmit(unhex("00A4000C02E104"));
                    byte[] read = c.transmit(unhex("00B0000000"));
                    byte[] expect = concat(u16(ReviewCard.NDEF_MSG.length), ReviewCard.NDEF_MSG);
                    row(
                            "I4",
                            "NDEF",
                            "SELECT E104; READ 0000 00",
                            "9000; u16(|msg|) ‖ msg",
                            s4(ReviewHost.sw(sel))
                                    + "; "
                                    + s4(ReviewHost.sw(read))
                                    + " "
                                    + (Arrays.equals(respData(read), expect)
                                            ? "match"
                                            : hex(respData(read))),
                            ReviewHost.sw(sel) == 0x9000
                                    && ReviewHost.sw(read) == 0x9000
                                    && Arrays.equals(respData(read), expect));
                });
        cell(
                "I5",
                "E104",
                "READ at off = size",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    c.transmit(SELECT_NDEF);
                    c.transmit(unhex("00A4000C02E104"));
                    int size = 2 + ReviewCard.NDEF_MSG.length;
                    byte[] r = c.transmit(unhex("00B0" + String.format("%04X", size) + "0F"));
                    row(
                            "I5",
                            "E104",
                            "READ off=size",
                            "9000, no data",
                            s4(ReviewHost.sw(r)) + ", " + respData(r).length + " B",
                            ReviewHost.sw(r) == 0x9000 && respData(r).length == 0);
                });
        cell(
                "I6",
                "E104",
                "READ off = size+1 / 8000",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    c.transmit(SELECT_NDEF);
                    c.transmit(unhex("00A4000C02E104"));
                    int size = 2 + ReviewCard.NDEF_MSG.length;
                    byte[] r1 = c.transmit(unhex("00B0" + String.format("%04X", size + 1) + "0F"));
                    byte[] r2 = c.transmit(unhex("00B080000F"));
                    row(
                            "I6",
                            "E104",
                            "READ off>size",
                            "6B00 6B00",
                            s4(ReviewHost.sw(r1)) + " " + s4(ReviewHost.sw(r2)),
                            ReviewHost.sw(r1) == 0x6B00 && ReviewHost.sw(r2) == 0x6B00);
                });
        cell(
                "I7",
                "E104",
                "READ 0002 03",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    c.transmit(SELECT_NDEF);
                    c.transmit(unhex("00A4000C02E104"));
                    byte[] r = c.transmit(unhex("00B0000203"));
                    row(
                            "I7",
                            "E104",
                            "READ 3 B of msg",
                            "9000, msg[0..3)",
                            s4(ReviewHost.sw(r))
                                    + " "
                                    + (Arrays.equals(respData(r), slice(ReviewCard.NDEF_MSG, 0, 3))
                                            ? "match"
                                            : hex(respData(r))),
                            ReviewHost.sw(r) == 0x9000
                                    && Arrays.equals(
                                            respData(r), slice(ReviewCard.NDEF_MSG, 0, 3)));
                });
        cell(
                "I8",
                "NDEF",
                "SELECT file bad P1P2",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    c.transmit(SELECT_NDEF);
                    byte[] r1 = c.transmit(unhex("00A4000002E103"));
                    byte[] r2 = c.transmit(unhex("00A4040C02E103"));
                    row(
                            "I8",
                            "NDEF",
                            "SELECT file P1P2=00 00 / 04 0C",
                            "6A86 6A86",
                            s4(ReviewHost.sw(r1)) + " " + s4(ReviewHost.sw(r2)),
                            ReviewHost.sw(r1) == 0x6A86 && ReviewHost.sw(r2) == 0x6A86);
                });
        cell(
                "I9",
                "E103",
                "SELECT E105 / Lc=3; READ",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    c.transmit(SELECT_NDEF);
                    c.transmit(unhex("00A4000C02E103"));
                    byte[] r1 = c.transmit(unhex("00A4000C02E105"));
                    byte[] r2 = c.transmit(unhex("00A4000C03AABBCC"));
                    byte[] read = c.transmit(unhex("00B000000F"));
                    byte[] expect = unhex("000F2000FF00FF0406E104000B00FF");
                    row(
                            "I9",
                            "E103",
                            "bad selects; READ still CC",
                            "6A82 6A82; CC unchanged",
                            s4(ReviewHost.sw(r1))
                                    + " "
                                    + s4(ReviewHost.sw(r2))
                                    + "; "
                                    + (Arrays.equals(respData(read), expect)
                                            ? "CC match"
                                            : hex(respData(read))),
                            ReviewHost.sw(r1) == 0x6A82
                                    && ReviewHost.sw(r2) == 0x6A82
                                    && Arrays.equals(respData(read), expect));
                });
        cell(
                "I10",
                "NDEF",
                "UPDATE BINARY",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    c.transmit(SELECT_NDEF);
                    c.transmit(unhex("00A4000C02E104"));
                    outer("I10", "NDEF", "UPDATE BINARY", 0x6985, c.transmit(unhex("00D6000000")));
                });
        cell(
                "I11",
                "NDEF",
                "INS CA",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    c.transmit(SELECT_NDEF);
                    outer("I11", "NDEF", "INS CA", 0x6D00, c.transmit(unhex("00CA000000")));
                });
        cell(
                "I12",
                "NDEF",
                "CLA 80",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    c.transmit(SELECT_NDEF);
                    outer("I12", "NDEF", "CLA 80", 0x6E00, c.transmit(unhex("80B000000F")));
                });
        cell(
                "I13",
                "install",
                "NDEF message 0 / 101 B",
                () -> {
                    StringBuilder obs = new StringBuilder();
                    for (int len : new int[] {0, 101}) {
                        try {
                            ReviewCard c = new ReviewCard();
                            c.card.install(AID_WALLET, org.qntx.card.WalletApplet.class);
                            c.card.install(AID_NDEF, org.qntx.card.NdefApplet.class, new byte[len]);
                            obs.append("installed");
                        } catch (Throwable t) {
                            obs.append(t.getClass().getSimpleName());
                        }
                        obs.append('/');
                    }
                    row(
                            "I13",
                            "install",
                            "NDEF msg 0 B / 101 B",
                            "install fails / install fails",
                            obs.substring(0, obs.length() - 1),
                            !obs.toString().contains("installed"));
                });
        cell(
                "I14",
                "E104",
                "SELECT NDEF again, READ",
                () -> {
                    ReviewCard c = ReviewCard.uninitialised();
                    c.transmit(SELECT_NDEF);
                    c.transmit(unhex("00A4000C02E104"));
                    c.transmit(SELECT_NDEF);
                    byte[] r = c.transmit(unhex("00B000000F"));
                    outer("I14", "E104", "READ after reselect", 0x6985, r);
                });
    }

    private static byte insOf(String name) {
        switch (name) {
            case "STATUS":
                return INS_STATUS;
            case "CREATE":
                return INS_CREATE;
            case "VERIFY":
                return INS_VERIFY;
            case "CHANGE":
                return INS_CHANGE;
            case "ERASE":
                return INS_ERASE;
            case "WAIT":
                return INS_WAIT;
            case "PUBLIC_KEY":
                return INS_PUBLIC_KEY;
            case "SIGN_ECDSA":
                return INS_SIGN_ECDSA;
            case "SIGN_BIP340":
                return INS_SIGN_BIP340;
            case "SIGN_ED25519":
                return INS_SIGN_ED25519;
            case "OFFER":
                return INS_OFFER;
            case "EXPORT":
                return INS_EXPORT;
            case "IMPORT":
                return INS_IMPORT;
            default:
                throw new IllegalArgumentException(name);
        }
    }
}
