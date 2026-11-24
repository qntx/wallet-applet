// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review;

import static org.qntx.card.review.ReviewHost.*;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.qntx.card.sim.Fault;
import org.qntx.card.sim.Rng;

/**
 * Source-mutant attack scenarios (matrix pass b of the mutant list in {@code
 * $A/review/mutants.md}): for each mutant id in {@code QNTX_MUTANT}, run the hostile action against
 * the mutant applet and record REFUSED (the card rejects or the effect does not happen) or RELEASED
 * (the effect happens: output in an unverified session, recovered seed, persistent state change, an
 * uncounted comparison). Prints one {@code MUTANT_RESULT} line per run for the driver to scrape.
 */
@EnabledIfEnvironmentVariable(named = "QNTX_MUTANT", matches = ".*")
final class MutantScenarioTest {

    private static final byte INS_STATUS = 0x20,
            INS_CREATE = 0x21,
            INS_VERIFY = 0x22,
            INS_CHANGE = 0x23,
            INS_ERASE = 0x24,
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
    private static final byte[] S1 =
            unhex(
                    "101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"
                            + "303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F");
    private static final byte[] H0 = sha256(utf8("mutant access hash H0"));
    private static final byte[] H1 = sha256(utf8("mutant access hash H1"));
    private static final byte[] H3 = sha256(utf8("mutant access hash H3"));
    private static final byte[] HT = sha256(utf8("mutant access hash HT"));
    private static final byte[] H9 = sha256(utf8("mutant wrong code"));
    private static final byte[] DG = sha256(utf8("mutant-scenario digest"));

    private static byte[] utf8(String s) {
        return s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String hx(int sw) {
        return String.format("%04X", sw < 0 ? -sw : sw & 0xFFFF);
    }

    private static int faultN(int dflt) {
        String v = System.getenv("QNTX_FAULT_N");
        return v == null ? dflt : Integer.parseInt(v);
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

    /** Inner SW, or {@code -outer} when the outer record failed. */
    private static ReviewSession.Inner cmd(ReviewSession s, byte ins, byte p1, byte[] data) {
        return s.cmd(ins, p1, (byte) 0, data);
    }

    /** BLANK card. */
    private static ReviewCard blankCard() {
        ReviewCard c = ReviewCard.uninitialised();
        c.blank();
        return c;
    }

    /** LOADED(S0,H0) card, c = 1. */
    private static ReviewCard loadedCard() {
        ReviewCard c = blankCard();
        c.create(S0, H0);
        return c;
    }

    /** L2 rig: LOADED(S0,H0) card with members [X, M]; session verified if {@code v}. */
    private static Object[] rigL2(boolean v) {
        ReviewCard c = blankCard();
        FakeMember m = new FakeMember(ReviewCard.CA);
        ReviewSession s = c.create(S0, H0, m.cardId);
        if (!v) {
            s = c.open();
        } else {
            s = c.open();
            s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
        }
        return new Object[] {c, m, s};
    }

    /** BLANK card, session open; BLANK cannot VERIFY so the session stays unverified. */
    private static Object[] rigBlank() {
        ReviewCard c = blankCard();
        FakeMember m = new FakeMember(ReviewCard.CA);
        ReviewSession s = c.open();
        return new Object[] {c, m, s};
    }

    /** Decrypts an EXPORT P1=01 payload as the target holding link private key l. */
    private static boolean recoveredSeed(byte[] z, byte[] exportM, byte[] record) {
        byte[] pl = FakeMember.unsealRecord(z, exportM, record);
        return pl != null && ReviewCard.eq(slice(pl, 1, 64), S0);
    }

    @Test
    void run() {
        String id = System.getenv("QNTX_MUTANT");
        String out;
        try {
            out = scenario(id);
        } catch (Throwable t) {
            out = "ERROR " + t.getClass().getSimpleName() + " " + t.getMessage();
        }
        System.out.println("MUTANT_RESULT " + id + " | " + out);
    }

    private static String scenario(String id) {
        switch (id) {
            case "M01":
                return m01();
            case "M02":
                return m02();
            case "M03":
            case "M06":
            case "M08":
            case "M09":
            case "M13":
                return unverifiedCmd(id);
            case "M04":
            case "M05":
                return ecdsaFlip();
            case "M07":
                return bip340Fault();
            case "M10":
                return edFault();
            case "M11":
            case "M12":
                return edNonce();
            case "M14":
                return m14();
            case "M15":
                return m15();
            case "M16":
            case "M17":
            case "M18":
            case "M19":
            case "M20":
            case "M21":
            case "M22":
            case "M23":
                return verifyScenario(id);
            case "M24":
                return m24();
            case "M25":
                return m25();
            case "M26":
                return m26();
            case "M27":
                return m27();
            case "M28":
                return m28();
            case "M29":
                return m29();
            case "M30":
                return m30();
            case "M31":
                return m31();
            case "M32":
                return m32();
            case "M33":
            case "M35":
            case "M36":
                return importPayload(id);
            case "M34":
                return m34();
            case "M37":
            case "M38":
            case "M39":
                return personalize(id);
            case "M40":
                return recordTamper(true);
            case "M41":
                return recordTamper(false);
            case "M42":
                return m42();
            case "M43":
                return "control[" + m24() + " || " + m01() + "]";
            case "M44":
                return m44();
            default:
                return "SKIP unknown " + id;
        }
    }

    /** M01: every verified-only command in an unverified session. */
    private static String m01() {
        ReviewCard c = loadedCard();
        ReviewSession s = c.open();
        StringBuilder b = new StringBuilder();
        ReviewSession.Inner p0 = cmd(s, INS_PUBLIC_KEY, (byte) 0, pathBytes(0));
        ReviewSession.Inner p1 = cmd(s, INS_PUBLIC_KEY, (byte) 1, pathBytes(0x80000000L));
        ReviewSession.Inner ec = cmd(s, INS_SIGN_ECDSA, (byte) 0, concat(DG, pathBytes(0)));
        ReviewSession.Inner bp =
                cmd(s, INS_SIGN_BIP340, (byte) 0, concat(DG, new byte[32], pathBytes(0)));
        ReviewSession.Inner e0 = cmd(s, INS_SIGN_ED25519, (byte) 0, pathBytes(0x80000000L));
        ReviewSession.Inner e2 = cmd(s, INS_SIGN_ED25519, (byte) 2, concat(u16(1), utf8("m")));
        b.append("pub0=")
                .append(hx(p0.sw))
                .append(" pub1=")
                .append(hx(p1.sw))
                .append(" ecdsa=")
                .append(hx(ec.sw))
                .append(" b340=")
                .append(hx(bp.sw))
                .append(" ed0=")
                .append(hx(e0.sw))
                .append(" ed2=")
                .append(hx(e2.sw));
        boolean any =
                p0.sw == 0x9000
                        || p1.sw == 0x9000
                        || ec.sw == 0x9000
                        || bp.sw == 0x9000
                        || e0.sw == 0x9000
                        || e2.sw == 0x9000;
        // unverified EXPORT chain on a fresh L2 card
        Object[] r = rigL2(false);
        ReviewSession s2 = (ReviewSession) r[2];
        FakeMember m = (FakeMember) r[1];
        ReviewSession.Inner x0 = cmd(s2, INS_EXPORT, (byte) 0, m.exportRequest());
        ReviewSession.Inner x1 = cmd(s2, INS_EXPORT, (byte) 1, HT);
        b.append(" exp0=").append(hx(x0.sw)).append(" exp1=").append(hx(x1.sw));
        boolean seed = false;
        if (x0.sw == 0x9000 && x1.sw == 0x9000) {
            byte[] e = slice(x0.data, 0, 65);
            byte[] zm = m.z(e);
            byte[] em = concat(LABEL_EXPORT, s2.cardA, m.a, m.lk, e);
            seed = recoveredSeed(zm, em, x1.data);
        }
        return (any || seed ? "RELEASED" : "REFUSED") + " " + b + (seed ? " seed=S0" : "");
    }

    /** M02: life gate off — CREATE on LOADED, ERASE/VERIFY on BLANK. */
    private static String m02() {
        ReviewCard c1 = loadedCard();
        ReviewSession s1 = c1.open();
        ReviewSession.Inner cr = cmd(s1, INS_CREATE, (byte) 1, concat(H3, S1, cardId(s1.cardA)));
        ReviewSession.Inner v3 = cmd(s1, INS_VERIFY, (byte) 0, H3);
        ReviewCard c2 = blankCard();
        ReviewSession s2 = c2.open();
        ReviewSession.Inner er = cmd(s2, INS_ERASE, (byte) 0, new byte[0]);
        ReviewSession.Inner st = cmd(s2, INS_STATUS, (byte) 0, new byte[0]);
        ReviewSession.Inner vf = cmd(s2, INS_VERIFY, (byte) 0, H0);
        boolean rel = v3.sw == 0x9000;
        return (rel ? "RELEASED" : "REFUSED")
                + " loadedCreate="
                + hx(cr.sw)
                + " verifyH3="
                + hx(v3.sw)
                + " | blank: erase="
                + hx(er.sw)
                + " status="
                + hx(st.sw)
                + " verify="
                + hx(vf.sw);
    }

    /** M03/M06/M08/M09/M13: one verified-only command in an unverified session. */
    private static String unverifiedCmd(String id) {
        ReviewCard c = loadedCard();
        ReviewSession s = c.open();
        switch (id) {
            case "M03":
                {
                    ReviewSession.Inner r =
                            cmd(s, INS_SIGN_ECDSA, (byte) 0, concat(DG, pathBytes(0)));
                    return (r.sw == 0x9000 ? "RELEASED" : "REFUSED") + " ecdsa=" + hx(r.sw);
                }
            case "M06":
                {
                    ReviewSession.Inner r =
                            cmd(
                                    s,
                                    INS_SIGN_BIP340,
                                    (byte) 0,
                                    concat(DG, new byte[32], pathBytes(0)));
                    return (r.sw == 0x9000 ? "RELEASED" : "REFUSED") + " b340=" + hx(r.sw);
                }
            case "M08":
                {
                    ReviewSession.Inner r =
                            cmd(s, INS_SIGN_ED25519, (byte) 0, pathBytes(0x80000000L));
                    return (r.sw == 0x9000 ? "RELEASED" : "REFUSED") + " ed0=" + hx(r.sw);
                }
            case "M09":
                {
                    ReviewSession.Inner r0 =
                            cmd(s, INS_SIGN_ED25519, (byte) 0, pathBytes(0x80000000L));
                    ReviewSession.Inner r2 =
                            cmd(s, INS_SIGN_ED25519, (byte) 2, concat(u16(1), utf8("m")));
                    return (r2.sw == 0x9000 ? "RELEASED" : "REFUSED")
                            + " ed0="
                            + hx(r0.sw)
                            + " ed2="
                            + hx(r2.sw);
                }
            default:
                { // M13
                    ReviewSession.Inner r0 = cmd(s, INS_PUBLIC_KEY, (byte) 0, pathBytes(0));
                    ReviewSession.Inner r1 =
                            cmd(s, INS_PUBLIC_KEY, (byte) 1, pathBytes(0x80000000L));
                    boolean rel = r0.sw == 0x9000 || r1.sw == 0x9000;
                    return (rel ? "RELEASED" : "REFUSED")
                            + " pub0="
                            + hx(r0.sw)
                            + " pub1="
                            + hx(r1.sw);
                }
        }
    }

    /** M04/M05: armEcdsaFlip on the signing call; RELEASED if an invalid signature is output. */
    private static String ecdsaFlip() {
        ReviewCard c = loadedCard();
        ReviewSession s = c.open();
        s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
        Fault.armEcdsaFlip(1);
        ReviewSession.Inner r = cmd(s, INS_SIGN_ECDSA, (byte) 0, concat(DG, pathBytes(0)));
        Fault.reset();
        if (r.sw != 0x9000) {
            return "REFUSED self-verify caught flip: sw=" + hx(r.sw);
        }
        BigInteger d = bip32Leaf(S0, path(0));
        boolean ok = ecdsaVerifyHash(compr(g().multiply(d)), DG, r.data);
        return (ok ? "REFUSED sig still valid" : "RELEASED invalid signature output") + " sw=9000";
    }

    /** M07: corrupt the BIP-340 nonce domain-sep; RELEASED if an invalid signature is output. */
    private static String bip340Fault() {
        ReviewCard c = loadedCard();
        ReviewSession s = c.open();
        s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
        Fault.armSkip("ModArith.mulMasked", faultN(1)); // corrupts s = ((k+e·d1)+e·d2) mod n
        ReviewSession.Inner r =
                cmd(s, INS_SIGN_BIP340, (byte) 0, concat(DG, new byte[32], pathBytes(0)));
        Fault.reset();
        if (r.sw != 0x9000) {
            return "REFUSED self-verify caught it: sw=" + hx(r.sw);
        }
        BigInteger d = bip32Leaf(S0, path(0));
        byte[] q = i2b(g().multiply(d).normalize().getXCoord().toBigInteger(), 32);
        boolean ok = bip340Verify(q, DG, r.data);
        return (ok ? "REFUSED sig still valid" : "RELEASED invalid signature output");
    }

    /** M10: corrupt S via mulMasked-skip; RELEASED if an invalid signature is output. */
    private static String edFault() {
        ReviewCard c = loadedCard();
        ReviewSession s = c.open();
        s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
        long[] p = path(0x80000000L);
        ReviewSession.Inner r0 = cmd(s, INS_SIGN_ED25519, (byte) 0, pathBytes(p[0]));
        if (r0.sw != 0x9000) {
            return "REFUSED begin=" + hx(r0.sw);
        }
        Fault.armSkip("ModArith.mulMasked", faultN(1));
        ReviewSession.Inner r2 = cmd(s, INS_SIGN_ED25519, (byte) 2, concat(u16(1), utf8("m")));
        Fault.reset();
        if (r2.sw != 0x9000) {
            return "REFUSED self-verify caught it: sw=" + hx(r2.sw);
        }
        byte[] aEd = edPublic(slip10Leaf(S0, p));
        byte[] sig = concat(slice(r0.data, 0, 32), r2.data); // R ‖ le32(S)
        boolean ok = edVerify(aEd, utf8("m"), sig);
        return (ok ? "REFUSED sig still valid" : "RELEASED invalid signature output");
    }

    /** M11/M12: Rng.fix constant → two begins on one path; RELEASED if the nonces match. */
    private static String edNonce() {
        ReviewCard c = loadedCard();
        ReviewSession s = c.open();
        s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
        long c0 = c.readEdCounter();
        Rng.fix(new byte[64]);
        ReviewSession.Inner r0 = cmd(s, INS_SIGN_ED25519, (byte) 0, pathBytes(0x80000000L));
        ReviewSession.Inner r1 = cmd(s, INS_SIGN_ED25519, (byte) 0, pathBytes(0x80000000L));
        Rng.reset();
        long c1 = c.readEdCounter();
        boolean reuse = r0.sw == 0x9000 && r1.sw == 0x9000 && ReviewCard.eq(r0.data, r1.data);
        return (reuse ? "RELEASED nonce reuse" : "REFUSED")
                + " r0="
                + hx(r0.sw)
                + " r1="
                + hx(r1.sw)
                + " edCounter "
                + c0
                + "->"
                + c1;
    }

    /** M14: unverified CHANGE — RELEASED if H1 then verifies. */
    private static String m14() {
        ReviewCard c = loadedCard();
        ReviewSession s = c.open();
        ReviewSession.Inner ch = cmd(s, INS_CHANGE, (byte) 0, H1);
        ReviewSession.Inner v1 = cmd(s, INS_VERIFY, (byte) 0, H1);
        ReviewSession.Inner v0 = cmd(s, INS_VERIFY, (byte) 0, H0);
        boolean rel = v1.sw == 0x9000;
        return (rel ? "RELEASED" : "REFUSED")
                + " change="
                + hx(ch.sw)
                + " verifyH1="
                + hx(v1.sw)
                + " verifyH0="
                + hx(v0.sw);
    }

    /** M15: unverified ERASE — RELEASED if the card is BLANK afterwards. */
    private static String m15() {
        ReviewCard c = loadedCard();
        ReviewSession s = c.open();
        ReviewSession.Inner er = cmd(s, INS_ERASE, (byte) 0, new byte[0]);
        ReviewSession s2 = c.open();
        ReviewSession.Inner st = cmd(s2, INS_STATUS, (byte) 0, new byte[0]);
        boolean blank = st.sw == 0x9000 && st.data[0] == 0x01;
        return (blank ? "RELEASED" : "REFUSED")
                + " erase="
                + hx(er.sw)
                + " status="
                + hx(st.sw)
                + " "
                + (st.sw == 0x9000 ? hex(st.data) : "");
    }

    /** M16–M23: VERIFY-path mutants. */
    private static String verifyScenario(String id) {
        ReviewCard c = loadedCard();
        ReviewSession s = c.open();
        switch (id) {
            case "M16":
            case "M17":
                {
                    ReviewSession.Inner v = cmd(s, INS_VERIFY, (byte) 0, H9);
                    ReviewSession.Inner st = cmd(s, INS_STATUS, (byte) 0, new byte[0]);
                    int tries = st.sw == 0x9000 ? st.data[1] & 0xFF : -1;
                    boolean rel = tries == 10 && v.sw != 0x9000; // uncounted comparison
                    return (rel ? "RELEASED" : "REFUSED")
                            + " verifyWrong="
                            + hx(v.sw)
                            + " tries="
                            + tries;
                }
            case "M18":
            case "M19":
            case "M20":
                {
                    ReviewSession.Inner v = cmd(s, INS_VERIFY, (byte) 0, H9);
                    ReviewSession.Inner pk = cmd(s, INS_PUBLIC_KEY, (byte) 0, pathBytes(0));
                    boolean rel = v.sw == 0x9000 || pk.sw == 0x9000;
                    return (rel ? "RELEASED" : "REFUSED")
                            + " verifyWrong="
                            + hx(v.sw)
                            + " publicKey="
                            + hx(pk.sw);
                }
            case "M21":
                {
                    c.injectFails(10);
                    ReviewSession.Inner v = cmd(s, INS_VERIFY, (byte) 0, H0);
                    ReviewSession.Inner st = cmd(s, INS_STATUS, (byte) 0, new byte[0]);
                    return (v.sw == 0x9000 ? "RELEASED" : "REFUSED")
                            + " f=10 verifyRight="
                            + hx(v.sw)
                            + " status="
                            + hx(st.sw)
                            + (st.sw == 0x9000 ? " " + hex(st.data) : "");
                }
            case "M22":
                {
                    c.injectFails(3);
                    ReviewSession.Inner v = cmd(s, INS_VERIFY, (byte) 0, H9); // no WAIT
                    boolean rel = (v.sw & 0xFFF0) == 0x63C0;
                    return (rel ? "RELEASED" : "REFUSED") + " f=3 noWait verifyWrong=" + hx(v.sw);
                }
            default:
                { // M23
                    c.injectFails(1);
                    ReviewSession.Inner v = cmd(s, INS_VERIFY, (byte) 0, H0);
                    ReviewSession.Inner st = cmd(s, INS_STATUS, (byte) 0, new byte[0]);
                    int tries = st.sw == 0x9000 ? st.data[1] & 0xFF : -1;
                    if (v.sw == 0x9000 && tries != 10) {
                        return "FAIL-SAFE (counter not reset; functional defect,"
                                + " no security release) verify="
                                + hx(v.sw)
                                + " tries="
                                + tries;
                    }
                    return "REFUSED verify=" + hx(v.sw) + " tries=" + tries;
                }
        }
    }

    /** M24: forged offer — genuine cert_M, attacker LK_T, 64 garbage bytes as sig_T. */
    private static String m24() {
        Object[] r = rigL2(true);
        ReviewSession s = (ReviewSession) r[2];
        FakeMember m = (FakeMember) r[1];
        BigInteger atk = randomScalar();
        byte[] lkT = uncomp(g().multiply(atk));
        ReviewSession.Inner e0 = cmd(s, INS_EXPORT, (byte) 0, concat(m.cert, lkT, new byte[64]));
        if (e0.sw != 0x9000) {
            return "REFUSED exp0=" + hx(e0.sw);
        }
        ReviewSession.Inner e1 = cmd(s, INS_EXPORT, (byte) 1, HT);
        if (e1.sw != 0x9000) {
            return "REFUSED exp0=9000 exp1=" + hx(e1.sw);
        }
        byte[] e = slice(e0.data, 0, 65);
        byte[] z = ecdhX(atk, e);
        byte[] em = concat(LABEL_EXPORT, s.cardA, m.a, lkT, e);
        return recoveredSeed(z, em, e1.data)
                ? "RELEASED forged offer accepted, S0 recovered under attacker link key"
                : "REFUSED payload unreadable";
    }

    /** M25: cert_T signed by a different CA; offer signature still valid under cert's A. */
    private static String m25() {
        Object[] r = rigL2(true);
        ReviewSession s = (ReviewSession) r[2];
        FakeMember m = (FakeMember) r[1];
        byte[] cert2 = cert(i2b(randomScalar(), 32), m.a);
        ReviewSession.Inner e0 = cmd(s, INS_EXPORT, (byte) 0, concat(cert2, m.lk, m.offerSig()));
        if (e0.sw != 0x9000) {
            return "REFUSED exp0=" + hx(e0.sw);
        }
        ReviewSession.Inner e1 = cmd(s, INS_EXPORT, (byte) 1, HT);
        if (e1.sw != 0x9000) {
            return "REFUSED exp0=9000 exp1=" + hx(e1.sw);
        }
        byte[] e = slice(e0.data, 0, 65);
        byte[] em = concat(LABEL_EXPORT, s.cardA, m.a, m.lk, e);
        return recoveredSeed(m.z(e), em, e1.data)
                ? "RELEASED foreign-CA cert accepted, S0 recovered"
                : "REFUSED payload unreadable";
    }

    /** M26: export to self — cert_T the card's own cert, LK_T‖sig_T its own OFFER. */
    private static String m26() {
        Object[] r = rigL2(true);
        ReviewSession s = (ReviewSession) r[2];
        ReviewSession.Inner of = cmd(s, INS_OFFER, (byte) 0, new byte[0]);
        ReviewSession.Inner e0 = cmd(s, INS_EXPORT, (byte) 0, concat(s.cert, of.data));
        ReviewSession.Inner e1 = e0.sw == 0x9000 ? cmd(s, INS_EXPORT, (byte) 1, HT) : null;
        return (e0.sw == 0x9000 ? "RELEASED self-export accepted" : "REFUSED")
                + " offer="
                + hx(of.sw)
                + " exp0="
                + hx(e0.sw)
                + (e1 != null ? " exp1=" + hx(e1.sw) : "");
    }

    /** M27: export to a certified non-member. */
    private static String m27() {
        Object[] r = rigL2(true);
        ReviewSession s = (ReviewSession) r[2];
        FakeMember n = new FakeMember(ReviewCard.CA); // certified but not a member
        ReviewSession.Inner e0 = cmd(s, INS_EXPORT, (byte) 0, n.exportRequest());
        return (e0.sw == 0x9000 ? "RELEASED non-member export accepted" : "REFUSED")
                + " exp0="
                + hx(e0.sw);
    }

    /** M28: compressed LK_T (02‖x) with a valid sig_T by M over that encoding. */
    private static String m28() {
        Object[] r = rigL2(true);
        ReviewSession s = (ReviewSession) r[2];
        FakeMember m = (FakeMember) r[1];
        byte[] lk33 = compr(g().multiply(m.link));
        byte[] sig = ecdsaSign(m.id, concat(LABEL_OFFER, lk33));
        ReviewSession.Inner e0 = cmd(s, INS_EXPORT, (byte) 0, concat(m.cert, lk33, sig));
        return (e0.sw == 0x9000 ? "RELEASED compressed LK_T accepted" : "REFUSED")
                + " exp0="
                + hx(e0.sw);
    }

    /** M29: verified EXPORT P1=00, VERIFY wrong (verified cleared), then EXPORT P1=01. */
    private static String m29() {
        Object[] r = rigL2(true);
        ReviewSession s = (ReviewSession) r[2];
        FakeMember m = (FakeMember) r[1];
        ReviewSession.Inner e0 = cmd(s, INS_EXPORT, (byte) 0, m.exportRequest());
        if (e0.sw != 0x9000) {
            return "REFUSED exp0=" + hx(e0.sw);
        }
        ReviewSession.Inner v = cmd(s, INS_VERIFY, (byte) 0, H9);
        ReviewSession.Inner e1 = cmd(s, INS_EXPORT, (byte) 1, HT);
        if (e1.sw != 0x9000) {
            return "REFUSED verifyWrong=" + hx(v.sw) + " exp1=" + hx(e1.sw);
        }
        byte[] e = slice(e0.data, 0, 65);
        byte[] em = concat(LABEL_EXPORT, s.cardA, m.a, m.lk, e);
        return recoveredSeed(m.z(e), em, e1.data)
                ? "RELEASED seed out after VERIFY failure"
                : "REFUSED payload unreadable verify=" + hx(v.sw);
    }

    /** M30: EXPORT P1=01 in a verified session with no pending export; payload under zero keys. */
    private static String m30() {
        Object[] r = rigL2(true);
        ReviewSession s = (ReviewSession) r[2];
        ReviewSession.Inner e1 = cmd(s, INS_EXPORT, (byte) 1, HT);
        if (e1.sw != 0x9000) {
            return "REFUSED exp1=" + hx(e1.sw);
        }
        byte[] rec = e1.data;
        byte[] ct = slice(rec, 0, rec.length - 16);
        byte[] tag = slice(rec, rec.length - 16, 16);
        byte[] zero = new byte[16];
        if (!ReviewCard.eq(cmac(zero, ct), tag)) {
            return "REFUSED CMAC under zero key failed";
        }
        byte[] pl = unM2(cbcInv(zero, zero, ct));
        boolean got = pl != null && pl.length == 130 && ReviewCard.eq(slice(pl, 1, 64), S0);
        return got ? "RELEASED seed under zero keys" : "REFUSED plaintext not S0";
    }

    /** M31: IMPORT P1=00 with a genuine cert_M but garbage sig_S. */
    private static String m31() {
        StringBuilder b = new StringBuilder();
        boolean rel = false;
        // LOADED L2 target, re-seal payload carrying a different seed
        Object[] r = rigL2(true);
        ReviewSession s = (ReviewSession) r[2];
        FakeMember m = (FakeMember) r[1];
        ReviewSession.Inner of = cmd(s, INS_OFFER, (byte) 0, new byte[0]);
        byte[] lkT = slice(of.data, 0, 65);
        byte[][] eo = m.exportOffer(s.cardA, lkT);
        byte[] reqBad = concat(slice(eo[0], 0, 162), new byte[64]);
        ReviewSession.Inner i0 = cmd(s, INS_IMPORT, (byte) 0, reqBad);
        b.append("loaded imp0=").append(hx(i0.sw));
        if (i0.sw == 0x9000) {
            byte[] z = ecdhX(b2i(eo[1]), lkT);
            byte[] em = concat(LABEL_EXPORT, m.a, s.cardA, lkT, slice(eo[0], 97, 65));
            byte[] payload =
                    concat(new byte[] {2}, S1, H3, new byte[] {2}, cardId(s.cardA), m.cardId);
            ReviewSession.Inner i1 =
                    cmd(s, INS_IMPORT, (byte) 1, FakeMember.sealRecord(z, em, payload)[0]);
            b.append(" imp1=").append(hx(i1.sw));
            rel |= i1.sw == 0x9000;
        }
        // BLANK target, install payload
        Object[] rb = rigBlank();
        ReviewSession sb = (ReviewSession) rb[2];
        FakeMember mb = (FakeMember) rb[1];
        ReviewSession.Inner ofb = cmd(sb, INS_OFFER, (byte) 0, new byte[0]);
        byte[] lkTb = slice(ofb.data, 0, 65);
        byte[][] eob = mb.exportOffer(sb.cardA, lkTb);
        byte[] reqBadB = concat(slice(eob[0], 0, 162), new byte[64]);
        ReviewSession.Inner ib0 = cmd(sb, INS_IMPORT, (byte) 0, reqBadB);
        b.append(" | blank imp0=").append(hx(ib0.sw));
        if (ib0.sw == 0x9000) {
            byte[] z = ecdhX(b2i(eob[1]), lkTb);
            byte[] em = concat(LABEL_EXPORT, mb.a, sb.cardA, lkTb, slice(eob[0], 97, 65));
            byte[] payload =
                    concat(new byte[] {2}, S0, H0, new byte[] {2}, cardId(sb.cardA), mb.cardId);
            ReviewSession.Inner ib1 =
                    cmd(sb, INS_IMPORT, (byte) 1, FakeMember.sealRecord(z, em, payload)[0]);
            ReviewSession.Inner st = cmd(sb, INS_STATUS, (byte) 0, new byte[0]);
            b.append(" imp1=")
                    .append(hx(ib1.sw))
                    .append(" status=")
                    .append(st.sw == 0x9000 ? hex(st.data) : hx(st.sw));
            rel |= ib1.sw == 0x9000 && st.sw == 0x9000 && st.data[0] == 0x02;
        }
        return (rel ? "RELEASED" : "REFUSED") + " " + b;
    }

    /** M32: IMPORT P1=00 with an off-curve E signed validly by M. */
    private static String m32() {
        Object[] r = rigBlank();
        ReviewSession s = (ReviewSession) r[2];
        FakeMember m = (FakeMember) r[1];
        ReviewSession.Inner of = cmd(s, INS_OFFER, (byte) 0, new byte[0]);
        byte[] lkT = slice(of.data, 0, 65);
        byte[] badE = concat(new byte[] {4}, unhex("01".repeat(32)), unhex("02".repeat(32)));
        byte[] em = concat(LABEL_EXPORT, m.a, s.cardA, lkT, badE);
        byte[] sig = ecdsaSign(m.id, em);
        ReviewSession.Inner i0 = cmd(s, INS_IMPORT, (byte) 0, concat(m.cert, badE, sig));
        return (i0.sw == 0x9000 ? "RELEASED off-curve E accepted" : "REFUSED")
                + " imp0="
                + hx(i0.sw);
    }

    /** M33–M36: tampered/member-mutated payloads on a BLANK target. */
    private static String importPayload(String id) {
        Object[] r = rigBlank();
        ReviewSession s = (ReviewSession) r[2];
        FakeMember m = (FakeMember) r[1];
        ReviewSession.Inner of = cmd(s, INS_OFFER, (byte) 0, new byte[0]);
        byte[] lkT = slice(of.data, 0, 65);
        byte[][] eo = m.exportOffer(s.cardA, lkT);
        ReviewSession.Inner i0 = cmd(s, INS_IMPORT, (byte) 0, eo[0]);
        if (i0.sw != 0x9000) {
            return "REFUSED imp0=" + hx(i0.sw);
        }
        byte[] z = ecdhX(b2i(eo[1]), lkT);
        byte[] em = concat(LABEL_EXPORT, m.a, s.cardA, lkT, slice(eo[0], 97, 65));
        byte[] payload;
        switch (id) {
            case "M35": // sender's ID absent
                payload = concat(new byte[] {2}, S0, H0, new byte[] {1}, cardId(s.cardA));
                break;
            case "M36": // own ID absent
                payload = concat(new byte[] {2}, S0, H0, new byte[] {1}, m.cardId);
                break;
            default:
                payload = concat(new byte[] {2}, S0, H0, new byte[] {2}, cardId(s.cardA), m.cardId);
        }
        byte[] rec = FakeMember.sealRecord(z, em, payload)[0];
        if (id.equals("M33")) {
            rec = rec.clone();
            rec[rec.length - 1] ^= 1; // tampered CMAC
        }
        ReviewSession.Inner i1 = cmd(s, INS_IMPORT, (byte) 1, rec);
        ReviewSession.Inner st = cmd(s, INS_STATUS, (byte) 0, new byte[0]);
        boolean inst = st.sw == 0x9000 && st.data[0] == 0x02;
        return (inst ? "RELEASED" : "REFUSED")
                + " imp1="
                + hx(i1.sw)
                + " status="
                + (st.sw == 0x9000 ? hex(st.data) : hx(st.sw));
    }

    /**
     * M34: re-seal variants on a LOADED L2 target (IMPORT needs no verified session, §16.1 item 7):
     * (a) different seed S1, same members/origin; (b) same seed, a third member; (c) same seed, the
     * other origin byte. Each on a fresh card, valid sender head. RELEASED iff IMPORT P1=01 answers
     * 9000 — expected refused by the second-level checks.
     */
    private static String m34() {
        StringBuilder b = new StringBuilder();
        boolean rel = false;
        for (int v = 0; v < 3; v++) {
            Object[] r = rigL2(false);
            ReviewSession s = (ReviewSession) r[2];
            FakeMember m = (FakeMember) r[1];
            ReviewSession.Inner of = cmd(s, INS_OFFER, (byte) 0, new byte[0]);
            byte[] lkT = slice(of.data, 0, 65);
            byte[][] eo = m.exportOffer(s.cardA, lkT);
            ReviewSession.Inner i0 = cmd(s, INS_IMPORT, (byte) 0, eo[0]);
            if (i0.sw != 0x9000) {
                b.append("v").append(v).append(" imp0=").append(hx(i0.sw)).append(' ');
                continue;
            }
            byte[] z = ecdhX(b2i(eo[1]), lkT);
            byte[] em = concat(LABEL_EXPORT, m.a, s.cardA, lkT, slice(eo[0], 97, 65));
            byte[] payload;
            switch (v) {
                case 0: // different seed, same members and origin
                    payload =
                            concat(
                                    new byte[] {2},
                                    S1,
                                    H3,
                                    new byte[] {2},
                                    cardId(s.cardA),
                                    m.cardId);
                    break;
                case 1:
                    { // same seed, c=3 members (stored c=2)
                        FakeMember m2 = new FakeMember(ReviewCard.CA);
                        payload =
                                concat(
                                        new byte[] {2},
                                        S0,
                                        H3,
                                        new byte[] {3},
                                        cardId(s.cardA),
                                        m.cardId,
                                        m2.cardId);
                        break;
                    }
                default: // same seed, other origin byte (generated, stored imported)
                    payload =
                            concat(
                                    new byte[] {1},
                                    S0,
                                    H3,
                                    new byte[] {2},
                                    cardId(s.cardA),
                                    m.cardId);
            }
            ReviewSession.Inner i1 =
                    cmd(s, INS_IMPORT, (byte) 1, FakeMember.sealRecord(z, em, payload)[0]);
            b.append("v").append(v).append(" imp1=").append(hx(i1.sw)).append(' ');
            rel |= i1.sw == 0x9000;
        }
        return (rel ? "RELEASED" : "REFUSED") + " " + b;
    }

    /** M37–M39: PERSONALIZE variants on a FACTORY card. */
    private static String personalize(String id) {
        ReviewCard c = ReviewCard.uninitialised();
        // drive init to FACTORY and capture A (setup only)
        c.transmit(ReviewHost.SELECT_WALLET);
        byte[] a = null;
        for (int i = 0; i < 20; i++) {
            byte[] resp = c.transmit(unhex("80E0000000"));
            if (sw(resp) == 0x9000) {
                a = respData(resp);
                break;
            }
        }
        if (a == null) {
            return "ERROR init did not reach FACTORY";
        }
        byte[] data;
        switch (id) {
            case "M37": // cert for another key
                data =
                        concat(
                                ReviewCard.CA.issue(compr(g().multiply(randomScalar()))),
                                ReviewCard.CA.pub65);
                break;
            case "M38": // caKey off-curve
                data =
                        concat(
                                ReviewCard.CA.issue(a),
                                concat(
                                        new byte[] {4},
                                        unhex("AA".repeat(32)),
                                        unhex("BB".repeat(32))));
                break;
            default: // M39: cert signed by a different CA
                data = concat(cert(i2b(randomScalar(), 32), a), ReviewCard.CA.pub65);
        }
        byte[] resp =
                c.transmit(
                        concat(
                                unhex("80E20000"),
                                new byte[] {(byte) data.length},
                                data,
                                new byte[] {0x00}));
        int perso = sw(resp);
        if (id.equals("M37") && perso == 0x9000) {
            // factory-only defect: the stored cert names another key while the card keeps
            // signing with its own, so the independent host's OPEN must fail — the card is
            // unusable but no secret is released
            ReviewSession probe = new ReviewSession(c.card::transmit, ReviewCard.CA.pub65);
            String open =
                    probe.open() == null ? "open refused: " + probe.openFailure : "OPEN ACCEPTED";
            return "FAIL-SAFE factory-only: PERSONALIZE accepts a cert for another key"
                    + " (card then unusable: "
                    + open
                    + ") — no secret released"
                    + " personalize="
                    + hx(perso);
        }
        return (perso == 0x9000 ? "RELEASED" : "REFUSED") + " personalize=" + hx(perso);
    }

    /** M40: record with a flipped tag; M41: valid tag over unpadded plaintext. */
    private static String recordTamper(boolean tagFlip) {
        ReviewCard c = loadedCard();
        ReviewSession s = c.open();
        s.cmd(INS_VERIFY, (byte) 0, (byte) 0, H0);
        byte[] rec;
        if (tagFlip) {
            rec = s.record(INS_STATUS, (byte) 0, (byte) 0, new byte[0]);
            rec[rec.length - 1] ^= 1;
        } else {
            // no M2 trailer: 13 zero bytes after the header — plen < 0 under a strict unM2
            byte[] plain = concat(new byte[] {INS_STATUS, 0, 0}, new byte[13]);
            byte[] iv = aesBlock(s.kce, concat(new byte[] {1}, new byte[13], u16(0)));
            byte[] ct = cbc(s.kce, iv, plain);
            rec = concat(ct, slice(cmac(s.kcm, u16(0), ct), 0, 8));
        }
        ReviewSession.Raw rr = s.raw(s.recordApdu((byte) 0, (byte) 0, rec));
        boolean released = rr.outer == 0x9000 && rr.inner != null && rr.inner.sw == 0x9000;
        return (released ? "RELEASED inner executed" : "REFUSED")
                + " outer="
                + hx(rr.outer)
                + (rr.inner != null ? " inner=" + hx(rr.inner.sw) : "");
    }

    /** M42: armEcdsaFlip on OPEN's identity signature. */
    private static String m42() {
        ReviewCard c = blankCard();
        Fault.armEcdsaFlip(1);
        try {
            c.open();
            Fault.reset();
            return "REFUSED OPEN signature verified";
        } catch (IllegalStateException t) {
            Fault.reset();
            return "RELEASED OPEN signature unverifiable: " + t.getMessage();
        }
    }

    /** M44: the G10 re-seal flow (same wallet under H3). */
    private static String m44() {
        Object[] r = rigL2(false);
        ReviewSession s = (ReviewSession) r[2];
        FakeMember m = (FakeMember) r[1];
        ReviewSession.Inner of = cmd(s, INS_OFFER, (byte) 0, new byte[0]);
        byte[] lkT = slice(of.data, 0, 65);
        byte[][] eo = m.exportOffer(s.cardA, lkT);
        ReviewSession.Inner i0 = cmd(s, INS_IMPORT, (byte) 0, eo[0]);
        byte[] z = ecdhX(b2i(eo[1]), lkT);
        byte[] em = concat(LABEL_EXPORT, m.a, s.cardA, lkT, slice(eo[0], 97, 65));
        byte[] payload = concat(new byte[] {2}, S0, H3, new byte[] {2}, cardId(s.cardA), m.cardId);
        ReviewSession.Inner i1 =
                cmd(s, INS_IMPORT, (byte) 1, FakeMember.sealRecord(z, em, payload)[0]);
        ReviewSession.Inner st = cmd(s, INS_STATUS, (byte) 0, new byte[0]);
        ReviewSession s2 = ((ReviewCard) r[0]).open();
        ReviewSession.Inner v3 = cmd(s2, INS_VERIFY, (byte) 0, H3);
        return "OBSERVED"
                + " imp0="
                + hx(i0.sw)
                + " imp1="
                + hx(i1.sw)
                + " status="
                + (st.sw == 0x9000 ? hex(st.data) : hx(st.sw))
                + " verifyH3="
                + hx(v3.sw);
    }
}
