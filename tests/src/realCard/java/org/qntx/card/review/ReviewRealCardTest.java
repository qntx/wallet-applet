// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review;

import static org.qntx.card.review.ReviewHost.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.qntx.card.real.Fixture;
import org.qntx.card.real.RealCard;
import org.qntx.card.review.ReviewSession.Inner;

/**
 * The independent review probes on card A silicon. Fixture/RealCard are used only for the
 * connection, the card-A identity policy and the CAP install; every protocol step goes through raw
 * APDUs ({@code Fixture.card().transmit}) and the independent review host/session. All expected
 * values come from spec/protocol.md and the official BIP-32/SLIP-10 test vector 2 files under
 * spec/vectors — never from card output. Each cell appends one row (cell, expected-from-spec,
 * observed, PASS/DIVERGE, ms) to {@code $realCardOut/review-realcard.csv}; a DIVERGE is reported,
 * never adapted to.
 */
class ReviewRealCardTest {

    private static final byte INS_STATUS = 0x20,
            INS_CREATE = 0x21,
            INS_VERIFY = 0x22,
            INS_PUBLIC_KEY = 0x30,
            INS_SIGN_ECDSA = 0x31,
            INS_SIGN_BIP340 = 0x32,
            INS_SIGN_ED25519 = 0x33,
            INS_ERASE = 0x24,
            INS_WAIT = 0x25;

    private static final long HP = 0x80000000L;

    /** BIP-32/SLIP-10 test vector 2 seed (both files carry the same one). */
    private static final byte[] SEED =
            unhex(
                    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");

    /**
     * spec/vectors/bip-0032.mediawiki "Test vector 2": chain → ext pub. m has depth 0 and is not
     * PUBLIC_KEY-addressable (§9.2: depth ∉ [1,10] → 6A80); its key is checked via WalletInfo in
     * cell c3.
     */
    private static final String[][] TV2 = {
        {
            "m",
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
        },
        {
            "m/0",
            "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
        },
        {
            "m/0/2147483647H",
            "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
        },
        {
            "m/0/2147483647H/1",
            "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
        },
        {
            "m/0/2147483647H/1/2147483646H",
            "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
        },
        {
            "m/0/2147483647H/1/2147483646H/2",
            "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
        }
    };

    /**
     * spec/vectors/slip-0010.md "Test vector 2 for ed25519": chain → public (the file's leading 00
     * pad byte dropped). m is checked via cell c3's WalletInfo.
     */
    private static final String[][] TV2ED = {
        {"m", "8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a"},
        {"m/0H", "86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037"},
        {"m/0H/2147483647H", "5ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d"},
        {"m/0H/2147483647H/1H", "2e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45"},
        {
            "m/0H/2147483647H/1H/2147483646H",
            "e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b"
        },
        {
            "m/0H/2147483647H/1H/2147483646H/2H",
            "47150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0"
        }
    };

    private static final byte[] H0 = sha256(utf8("review realcard access hash"));
    private static final byte[] H_WRONG = sha256(utf8("review realcard wrong access hash"));
    private static final SecureRandom RNG = new SecureRandom();
    private static final List<String[]> ROWS = new ArrayList<>();
    private static final List<String> NOTES = new ArrayList<>();

    private static byte[] pathBytes(long... idx) {
        byte[] out = new byte[1 + 4 * idx.length];
        out[0] = (byte) idx.length;
        for (int i = 0; i < idx.length; i++) {
            byte[] b = u32(idx[i]);
            System.arraycopy(b, 0, out, 1 + 4 * i, 4);
        }
        return out;
    }

    private static long[] parsePath(String p) {
        if (p.equals("m")) {
            return new long[0];
        }
        String[] parts = p.substring(2).split("/");
        long[] out = new long[parts.length];
        for (int i = 0; i < parts.length; i++) {
            char last = parts[i].charAt(parts[i].length() - 1);
            boolean h = last == 'H' || last == 'h' || last == '\'';
            long v = Long.parseLong(h ? parts[i].substring(0, parts[i].length() - 1) : parts[i]);
            out[i] = h ? v + HP : v;
        }
        return out;
    }

    private static byte[] rand(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    private static String hexSw(int sw) {
        return String.format("%04X", sw);
    }

    private static void cell(String name, String expected, String observed, boolean pass, long ns) {
        ROWS.add(
                new String[] {
                    name,
                    expected,
                    observed,
                    pass ? "PASS" : "DIVERGE",
                    String.valueOf((System.nanoTime() - ns) / 1_000_000)
                });
    }

    @Test
    void reviewProbes() throws Exception {
        Fixture.require();
        Fixture.ensureInstalled(Fixture.CapKind.PROD);
        RealCard card = Fixture.card();
        card.verifySilicon();
        NOTES.add("ATR " + card.atr());
        NOTES.add(
                "identify "
                        + new String(
                                        Files.readAllBytes(Fixture.out().resolve("identify.bin")),
                                        StandardCharsets.ISO_8859_1)
                                .strip());

        try {
            // a. SELECT, drive §4.3 initialisation, PERSONALIZE under the review CA.
            long ns = System.nanoTime();
            int sw = RealCard.sw(card.transmit(RealCard.SELECT));
            cell("a1 select", "9000", hexSw(sw), sw == 0x9000, ns);

            ns = System.nanoTime();
            byte[] a33 = null;
            int tries = 0;
            for (; tries <= 16; tries++) {
                byte[] r = card.transmit(Fixture.GET_IDENTITY);
                sw = RealCard.sw(r);
                if (sw == 0x6283) {
                    continue;
                }
                if (sw == 0x9000 && r.length - 2 >= 33) {
                    a33 = slice(r, 0, 33);
                }
                break;
            }
            cell(
                    "a2 identity",
                    "9000 within 16 drives, A(33)",
                    tries > 16 ? "6283 x16" : hexSw(sw) + " after " + tries,
                    a33 != null,
                    ns);

            ns = System.nanoTime();
            byte[] cert = ReviewCard.CA.issue(a33);
            byte[] perso =
                    concat(unhex("80E20000"), new byte[] {(byte) 0xA2}, cert, ReviewCard.CA.pub65);
            sw = RealCard.sw(card.transmit(perso));
            cell("a3 personalize", "9000", hexSw(sw), sw == 0x9000, ns);

            // b. OPEN in three select epochs plus one after a power cycle; each session signature
            // verified by ReviewSession (regression of F2).
            ReviewSession s = null;
            for (int i = 1; i <= 3; i++) {
                ns = System.nanoTime();
                sw = RealCard.sw(card.transmit(RealCard.SELECT));
                s = new ReviewSession(card::transmit, ReviewCard.CA.pub65);
                byte[] open = s.open();
                cell(
                        "b" + i + " open epoch " + i,
                        "select 9000, open 226B verified",
                        "select "
                                + hexSw(sw)
                                + ", "
                                + (open == null ? "FAIL: " + s.openFailure : open.length + "B"),
                        sw == 0x9000 && open != null,
                        ns);
            }
            ns = System.nanoTime();
            card.reset();
            sw = RealCard.sw(card.transmit(RealCard.SELECT));
            s = new ReviewSession(card::transmit, ReviewCard.CA.pub65);
            byte[] open = s.open();
            cell(
                    "b4 open after power cycle",
                    "select 9000, open 226B verified",
                    "select "
                            + hexSw(sw)
                            + ", "
                            + (open == null ? "FAIL: " + s.openFailure : open.length + "B"),
                    sw == 0x9000 && open != null,
                    ns);

            // c. CREATE P1=01 with the TV2 seed; WalletInfo and PUBLIC_KEY against the official
            // vectors.
            ns = System.nanoTime();
            Inner st = s.cmd(INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
            cell(
                    "c1 status blank",
                    "9000 0100",
                    hexSw(st.sw) + " " + hex(st.data),
                    st.sw == 0x9000 && st.data.length == 2 && st.data[0] == 0x01 && st.data[1] == 0,
                    ns);

            ns = System.nanoTime();
            Inner cr = s.cmd(INS_CREATE, (byte) 1, (byte) 0, concat(H0, SEED));
            byte[] winfo = cr.data;
            cell(
                    "c2 create import",
                    "9000, WalletInfo 51B",
                    hexSw(cr.sw) + " " + winfo.length + "B",
                    cr.sw == 0x9000 && winfo.length == 51,
                    ns);

            ns = System.nanoTime();
            byte[] xm = b58check(TV2[0][1]);
            byte[] mpk = slice(xm, 45, 33);
            boolean infoOk =
                    winfo.length == 51
                            && ReviewCard.eq(slice(winfo, 0, 33), mpk)
                            && winfo[33] == 0x02
                            && winfo[34] == 0x01
                            && ReviewCard.eq(slice(winfo, 35, 16), slice(sha256(a33), 0, 16));
            cell(
                    "c3 walletinfo",
                    "mpk == TV2 m pub, origin 02, c 1, ID(A)",
                    infoOk
                            ? "match"
                            : "mpk="
                                    + hex(slice(winfo, 0, 33))
                                    + " exp="
                                    + hex(mpk)
                                    + " origin="
                                    + String.format("%02X", winfo[33])
                                    + " c="
                                    + String.format("%02X", winfo[34])
                                    + " id="
                                    + hex(slice(winfo, 35, 16)),
                    infoOk,
                    ns);

            for (int ni = 1; ni < TV2.length; ni++) {
                String[] node = TV2[ni];
                ns = System.nanoTime();
                byte[] xp = b58check(node[1]);
                byte[] want = concat(slice(xp, 45, 33), slice(xp, 13, 32));
                Inner r = s.cmd(INS_PUBLIC_KEY, (byte) 0, (byte) 0, pathBytes(parsePath(node[0])));
                boolean ok = r.sw == 0x9000 && r.data.length == 65 && ReviewCard.eq(r.data, want);
                cell(
                        "c4 pubkey " + node[0],
                        "9000, pub‖cc == xpub",
                        hexSw(r.sw)
                                + " "
                                + (ok ? "match" : "got " + hex(r.data) + " exp " + hex(want)),
                        ok,
                        ns);
            }

            for (int ni = 1; ni < TV2ED.length; ni++) {
                String[] node = TV2ED[ni];
                ns = System.nanoTime();
                Inner r = s.cmd(INS_PUBLIC_KEY, (byte) 1, (byte) 0, pathBytes(parsePath(node[0])));
                byte[] got = r.data.length == 64 ? weiToEdwards(r.data) : r.data;
                boolean ok = r.sw == 0x9000 && ReviewCard.eq(got, unhex(node[1]));
                cell(
                        "c5 pubkey-ed " + node[0],
                        "9000, Edwards(W(A)) == official pub",
                        hexSw(r.sw) + " " + (ok ? "match" : "got " + hex(got) + " exp " + node[1]),
                        ok,
                        ns);
            }

            // d. Signatures on one leaf each, every one verified against the host-derived key.
            long[] pSecp = {HP, HP};
            byte[] pubSecp = compr(G.multiply(bip32Leaf(SEED, pSecp)));
            Map<String, Integer> seen = new HashMap<>();
            int verified = 0, failed = 0;
            ns = System.nanoTime();
            for (int i = 0; i < 200; i++) {
                byte[] dg = rand(32);
                Inner r = s.cmd(INS_SIGN_ECDSA, (byte) 0, (byte) 0, concat(dg, pathBytes(pSecp)));
                if (r.sw != 0x9000
                        || r.data.length != 64
                        || !ecdsaVerifyHash(pubSecp, dg, r.data)) {
                    failed++;
                    continue;
                }
                verified++;
                seen.merge(hex(slice(r.data, 0, 32)), 1, Integer::sum);
            }
            int dup = seen.values().stream().mapToInt(v -> v - 1).sum();
            cell(
                    "d1 sign ecdsa x200",
                    "200 verified, 0 duplicate r",
                    verified + " verified, " + failed + " failed, " + dup + " dup r",
                    failed == 0 && dup == 0,
                    ns);

            seen.clear();
            verified = failed = 0;
            int untweaked = 0;
            ns = System.nanoTime();
            for (int i = 0; i < 200; i++) {
                byte[] m = rand(32);
                byte[] tw = i < 100 ? new byte[32] : rand(32);
                if (i < 100) {
                    untweaked++;
                }
                Inner r =
                        s.cmd(INS_SIGN_BIP340, (byte) 0, (byte) 0, concat(m, tw, pathBytes(pSecp)));
                if (r.sw != 0x9000 || r.data.length != 64) {
                    failed++;
                    continue;
                }
                byte[] qx =
                        i2b(
                                taprootQ(bip32Leaf(SEED, pSecp), b2i(tw))
                                        .getAffineXCoord()
                                        .toBigInteger(),
                                32);
                if (!bip340Verify(qx, m, r.data)) {
                    failed++;
                    continue;
                }
                verified++;
                seen.merge(hex(slice(r.data, 0, 32)), 1, Integer::sum);
            }
            dup = seen.values().stream().mapToInt(v -> v - 1).sum();
            cell(
                    "d2 sign bip340 x200 (100 untweaked)",
                    "200 verified under P_even resp. Q = P_even + t·G, 0 duplicate R",
                    verified
                            + " verified ("
                            + untweaked
                            + " untw), "
                            + failed
                            + " failed, "
                            + dup
                            + " dup R",
                    failed == 0 && dup == 0,
                    ns);

            long[] pEd = {HP, HP + 1};
            byte[] encA = edPublic(slip10Leaf(SEED, pEd));
            seen.clear();
            verified = failed = 0;
            ns = System.nanoTime();
            for (int i = 0; i < 200; i++) {
                Inner bgn = s.cmd(INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(pEd));
                if (bgn.sw != 0x9000 || bgn.data.length != 64) {
                    failed++;
                    continue;
                }
                byte[] encR = weiToEdwards(bgn.data);
                byte[] msg = rand(64);
                byte[] stream = concat(encR, encA, msg);
                Inner upd = s.cmd(INS_SIGN_ED25519, (byte) 1, (byte) 0, slice(stream, 0, 64));
                Inner fin =
                        upd.sw == 0x9000
                                ? s.cmd(INS_SIGN_ED25519, (byte) 2, (byte) 0, slice(stream, 64, 64))
                                : upd;
                if (fin.sw != 0x9000
                        || fin.data.length != 32
                        || !edVerify(encA, msg, concat(encR, fin.data))) {
                    failed++;
                    continue;
                }
                verified++;
                seen.merge(hex(encR), 1, Integer::sum);
            }
            dup = seen.values().stream().mapToInt(v -> v - 1).sum();
            cell(
                    "d3 sign ed25519 x200",
                    "200 verified (begin/update/finish, 64B msg), 0 duplicate R",
                    verified + " verified, " + failed + " failed, " + dup + " dup R",
                    failed == 0 && dup == 0,
                    ns);

            // e. Gates.
            ns = System.nanoTime();
            sw = RealCard.sw(card.transmit(RealCard.SELECT));
            ReviewSession s2 = new ReviewSession(card::transmit, ReviewCard.CA.pub65);
            byte[] open2 = s2.open();
            Inner pk =
                    open2 == null
                            ? null
                            : s2.cmd(INS_PUBLIC_KEY, (byte) 0, (byte) 0, pathBytes(pSecp));
            cell(
                    "e1 pubkey unverified",
                    "6982",
                    "open "
                            + (open2 == null ? "FAIL: " + s2.openFailure : "ok")
                            + ", pk "
                            + (pk == null ? "-" : hexSw(pk.sw)),
                    open2 != null && pk != null && pk.sw == 0x6982,
                    ns);

            ns = System.nanoTime();
            int[] vws = new int[3];
            for (int i = 0; i < 3; i++) {
                vws[i] = s2.cmd(INS_VERIFY, (byte) 0, (byte) 0, H_WRONG).sw;
            }
            cell(
                    "e2 verify wrong x3",
                    "63C9 63C8 63C7 (spec A1, F=3)",
                    hexSw(vws[0]) + " " + hexSw(vws[1]) + " " + hexSw(vws[2]),
                    vws[0] == 0x63C9 && vws[1] == 0x63C8 && vws[2] == 0x63C7,
                    ns);

            ns = System.nanoTime();
            int vw4 = s2.cmd(INS_VERIFY, (byte) 0, (byte) 0, H_WRONG).sw;
            cell("e3 verify wrong 4th", "6986 (waited < W)", hexSw(vw4), vw4 == 0x6986, ns);

            ns = System.nanoTime();
            int waitBad = 0;
            for (int i = 0; i < 15; i++) {
                if (s2.cmd(INS_WAIT, (byte) 0, (byte) 0, new byte[0]).sw != 0x9000) {
                    waitBad++;
                }
            }
            cell(
                    "e4 wait x15",
                    "15x 9000 (§7.3 W=15)",
                    (15 - waitBad) + "x 9000, " + waitBad + " other",
                    waitBad == 0,
                    ns);

            ns = System.nanoTime();
            Inner vr = s2.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
            cell("e5 verify right after waits", "9000", hexSw(vr.sw), vr.sw == 0x9000, ns);

            ns = System.nanoTime();
            st = s2.cmd(INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
            cell(
                    "e6 status loaded tries 10",
                    "9000 020A",
                    hexSw(st.sw) + " " + hex(st.data),
                    st.sw == 0x9000
                            && st.data.length == 2
                            && st.data[0] == 0x02
                            && st.data[1] == 0x0A,
                    ns);

            ns = System.nanoTime();
            Inner bgn = s2.cmd(INS_SIGN_ED25519, (byte) 0, (byte) 0, pathBytes(pEd));
            Inner fin0 = s2.cmd(INS_SIGN_ED25519, (byte) 2, (byte) 0, new byte[0]);
            cell(
                    "e7 ed25519 finish 0B after begin",
                    "6700 (A2: stream needs 128B)",
                    "begin " + hexSw(bgn.sw) + ", finish " + hexSw(fin0.sw),
                    bgn.sw == 0x9000 && fin0.sw == 0x6700,
                    ns);

            ns = System.nanoTime();
            Inner er = s2.cmd(INS_ERASE, (byte) 0, (byte) 0, new byte[0]);
            cell("e8 erase", "9000", hexSw(er.sw), er.sw == 0x9000, ns);

            ns = System.nanoTime();
            st = s2.cmd(INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
            cell(
                    "e9 status blank after erase",
                    "9000 0100",
                    hexSw(st.sw) + " " + hex(st.data),
                    st.sw == 0x9000 && st.data.length == 2 && st.data[0] == 0x01 && st.data[1] == 0,
                    ns);
        } finally {
            writeEvidence();
        }
        long diverges = ROWS.stream().filter(r -> r[3].equals("DIVERGE")).count();
        if (diverges > 0 || !ReviewSession.checkViolations.isEmpty()) {
            // rows are the evidence; the test itself fails on any DIVERGE or record violation
            org.junit.jupiter.api.Assertions.fail(
                    diverges
                            + " DIVERGE cells, "
                            + ReviewSession.checkViolations.size()
                            + " record-check violations "
                            + ReviewSession.checkViolations);
        }
    }

    private static void writeEvidence() throws Exception {
        Path csv = Fixture.out().resolve("review-realcard.csv");
        StringBuilder sb = new StringBuilder("cell,expected,observed,verdict,ms\n");
        for (String[] r : ROWS) {
            sb.append(String.join(",", r)).append('\n');
        }
        Files.writeString(csv, sb.toString());
        StringBuilder md = new StringBuilder("# review realcard — card A\n\n");
        for (String n : NOTES) {
            md.append("- ").append(n).append('\n');
        }
        md.append('\n');
        md.append("| cell | expected | observed | verdict | ms |\n|---|---|---|---|---|\n");
        for (String[] r : ROWS) {
            md.append("| ").append(String.join(" | ", r)).append(" |\n");
        }
        Files.writeString(Fixture.out().resolve("review-realcard-summary.md"), md.toString());
    }

    @AfterAll
    static void cleanup() throws Exception {
        Fixture.cleanupCard();
    }
}
