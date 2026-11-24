// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.review;

import static org.qntx.card.review.ReviewCard.inner;
import static org.qntx.card.review.ReviewHost.*;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.qntx.card.sim.Fault;

/**
 * Reflective residue scanner: after each listed command, every byte[]/short[] reachable from the
 * WalletApplet instance, the APDU buffer, and every reachable transient key's material is searched
 * for 16-byte windows of every host-known secret.
 */
@EnabledIfEnvironmentVariable(named = "QNTX_REVIEW", matches = "full")
final class ResidueTest {

    private static final Path DIR =
            Paths.get(System.getenv().getOrDefault("QNTX_REVIEW_OUT", "build/review"));

    private static final byte[] S0 = sha512("residue S0".getBytes());
    private static final byte[] H0 = sha256("residue H0".getBytes());
    private static final byte[] H1 = sha256("residue H1".getBytes());
    private static final byte[] HE = sha256("residue host entropy".getBytes());
    private static final byte[] HT = sha256("residue HT".getBytes());
    private static final long[] SP = {0x8000002cL, 0x80000000L};
    private static final long[] EP = {0x80000000L, 0x80000001L};

    private static final List<String[]> ROWS = new ArrayList<>();
    private static int violations;

    private static byte[] pathBytes(long... idx) {
        byte[] out = new byte[1 + 4 * idx.length];
        out[0] = (byte) idx.length;
        for (int i = 0; i < idx.length; i++) {
            byte[] b = u32(idx[i]);
            System.arraycopy(b, 0, out, 1 + 4 * i, 4);
        }
        return out;
    }

    // reflection snapshot

    /** All byte[]/short[] buffers and transient key material reachable from the applet. */
    private static Map<String, byte[]> snapshot(ReviewCard c) {
        Map<String, byte[]> out = new HashMap<>();
        Object ap = c.card.applet(AID_WALLET);
        if (ap != null) {
            walk(ap, "applet", out, new IdentityHashMap<>(), 0);
        }
        try {
            out.put("APDU", c.card.apduBuffer().clone());
        } catch (Throwable t) {
            // no APDU buffer available
        }
        return out;
    }

    private static void walk(
            Object o,
            String path,
            Map<String, byte[]> out,
            IdentityHashMap<Object, Boolean> seen,
            int depth) {
        if (o == null || depth > 8 || seen.containsKey(o)) {
            return;
        }
        seen.put(o, Boolean.TRUE);
        Class<?> cl = o.getClass();
        if (o instanceof byte[]) {
            out.put(path, ((byte[]) o).clone());
            return;
        }
        if (o instanceof short[]) {
            short[] s = (short[]) o;
            byte[] b = new byte[s.length * 2];
            for (int i = 0; i < s.length; i++) {
                b[2 * i] = (byte) (s[i] >> 8);
                b[2 * i + 1] = (byte) s[i];
            }
            out.put(path, b);
            return;
        }
        if (o instanceof AESKey || o instanceof ECPrivateKey) {
            byte[] b = new byte[64];
            try {
                int n =
                        o instanceof AESKey
                                ? ((AESKey) o).getKey(b, (short) 0)
                                : ((ECPrivateKey) o).getS(b, (short) 0);
                if (n > 0) {
                    out.put(path + ":key", java.util.Arrays.copyOf(b, n));
                }
            } catch (Throwable t) {
                // cleared or unreadable key
            }
            return; // don't descend into javacard internals
        }
        if (o instanceof Object[]) {
            Object[] arr = (Object[]) o;
            for (int i = 0; i < arr.length; i++) {
                walk(arr[i], path + "[" + i + "]", out, seen, depth + 1);
            }
            return;
        }
        if (!cl.getName().startsWith("org.qntx.card")) {
            return;
        }
        for (Class<?> c = cl; c != null && c != Object.class; c = c.getSuperclass()) {
            for (Field f : c.getDeclaredFields()) {
                if (Modifier.isStatic(f.getModifiers()) || f.isSynthetic()) {
                    continue;
                }
                try {
                    f.setAccessible(true);
                    walk(f.get(o), path + "." + f.getName(), out, seen, depth + 1);
                } catch (Throwable t) {
                    // inaccessible field
                }
            }
        }
    }

    // secret windows

    private static final Map<String, String> WINDOWS = new HashMap<>();

    private static void addSecret(String name, byte[] s) {
        if (s == null || s.length < 16) {
            return;
        }
        for (int i = 0; i + 16 <= s.length; i++) {
            WINDOWS.putIfAbsent(hex(java.util.Arrays.copyOfRange(s, i, i + 16)), name);
        }
    }

    private static void scan(ReviewCard c, String phase, String after) {
        Map<String, Integer> firstOff = new HashMap<>();
        Map<String, Integer> lastOff = new HashMap<>();
        for (Map.Entry<String, byte[]> e : snapshot(c).entrySet()) {
            byte[] b = e.getValue();
            for (int i = 0; i + 16 <= b.length; i++) {
                String sec = WINDOWS.get(hex(java.util.Arrays.copyOfRange(b, i, i + 16)));
                if (sec != null) {
                    String k = e.getKey() + "|" + sec;
                    firstOff.putIfAbsent(k, i);
                    lastOff.put(k, i);
                }
            }
        }
        if (firstOff.isEmpty()) {
            ROWS.add(new String[] {after, "-", "-", "-", phase, "CLEAN"});
        }
        for (Map.Entry<String, Integer> e : firstOff.entrySet()) {
            String[] ks = e.getKey().split("[|]", 2);
            boolean ok = allowed(phase, ks[1], ks[0]);
            ROWS.add(
                    new String[] {
                        after,
                        ks[0],
                        e.getValue() + "-" + lastOff.get(e.getKey()),
                        ks[1],
                        phase,
                        ok ? "ALLOWED" : "VIOLATION"
                    });
            if (!ok) {
                violations++;
            }
        }
    }

    /**
     * Allowed residue: seed + derived-key caches during a verified session; stream content during
     * an active stream; kTe/kTm + sender during a pending export/import; session keys while the
     * session is open. Scratch buffers and the APDU buffer must never hold secrets.
     */
    private static boolean allowed(String phase, String secret, String buffer) {
        String bl = buffer.toLowerCase();
        if (bl.contains("apdu") || bl.matches(".*[.](p|w|h|n)$")) {
            return false; // scratch and the APDU buffer must always be clean
        }
        if (secret.startsWith("K_")) {
            // session keys are allowed for as long as the session is open
            return !phase.equals("CLOSED");
        }
        switch (phase) {
            case "VERIFIED":
            case "STREAM":
            case "PENDING":
                return true;
            default:
                return false;
        }
    }

    private static void secretsFor(byte[] seed, byte[] h, ReviewSession s) {
        byte[][] m32 = bip32Node(seed, new long[0]);
        addSecret("seed", seed);
        addSecret("kM", m32[0]);
        addSecret("cM", m32[1]);
        byte[][] ed = slip10Master(seed);
        addSecret("kE", ed[0]);
        addSecret("cE", ed[1]);
        byte[][] lp = bip32Node(seed, SP);
        addSecret("secp leaf k", lp[0]);
        addSecret("secp leaf c", lp[1]);
        byte[] el = slip10Leaf(seed, EP);
        addSecret("ed leaf", el);
        byte[] eh = sha512(el);
        addSecret("ed a", slice(eh, 0, 32));
        addSecret("ed prefix", slice(eh, 32, 32));
        addSecret("accessHash", h);
        addSecret("accessHash_T", HT);
        if (s != null) {
            sessionSecrets(s);
        }
    }

    private static void sessionSecrets(ReviewSession s) {
        addSecret("K_ce", s.kce);
        addSecret("K_cm", s.kcm);
        addSecret("K_re", s.kre);
        addSecret("K_rm", s.krm);
    }

    private static String hx(int sw) {
        return String.format("%04X", sw < 0 ? -sw : sw & 0xFFFF);
    }

    /** Reads the session seed out of the simulator's applet instance ({@code mem.seed}, 64 B). */
    private static byte[] sessionSeed(ReviewCard c) {
        try {
            Object ap = c.card.applet(AID_WALLET);
            Field mf = ap.getClass().getDeclaredField("mem");
            mf.setAccessible(true);
            Object mem = mf.get(ap);
            Field sf = mem.getClass().getDeclaredField("seed");
            sf.setAccessible(true);
            return ((byte[]) sf.get(mem)).clone();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("mem.seed reflection failed", e);
        }
    }

    // the run

    @Test
    void run() throws IOException {
        FakeMember m = new FakeMember(ReviewCard.CA);

        // scenario A: CREATE P1=01 → verify → every command → EXPORT → ERASE
        ReviewCard c = ReviewCard.uninitialised();
        c.blank();
        c.transmit(SELECT_WALLET);
        secretsFor(S0, H0, null);
        scan(c, "CLOSED", "SELECT wallet");
        ReviewSession s = c.open();
        sessionSecrets(s);
        scan(c, "UNVERIFIED", "OPEN");
        // CREATE leaves the seed in the session and verified set (§9.4)
        s = c.create(S0, H0, m.cardId);
        sessionSecrets(s);
        scan(c, "VERIFIED", "CREATE P1=01");
        ReviewSession.Inner vw = s.cmd((byte) 0x22, (byte) 0, (byte) 0, H1);
        if ((vw.sw & 0xFFF0) != 0x63C0) {
            throw new IllegalStateException("VERIFY wrong expected 63Cx got " + hx(vw.sw));
        }
        scan(c, "UNVERIFIED", "VERIFY wrong");
        inner(s, (byte) 0x22, (byte) 0, (byte) 0, H0, 0x9000);
        scan(c, "VERIFIED", "VERIFY right");
        inner(s, (byte) 0x30, (byte) 0, (byte) 0, pathBytes(SP), 0x9000);
        scan(c, "VERIFIED", "PUBLIC_KEY secp");
        inner(s, (byte) 0x30, (byte) 1, (byte) 0, pathBytes(EP), 0x9000);
        scan(c, "VERIFIED", "PUBLIC_KEY ed");
        inner(
                s,
                (byte) 0x31,
                (byte) 0,
                (byte) 0,
                concat(sha256("m".getBytes()), pathBytes(SP)),
                0x9000);
        scan(c, "VERIFIED", "SIGN_ECDSA");
        inner(
                s,
                (byte) 0x32,
                (byte) 0,
                (byte) 0,
                concat(sha256("m".getBytes()), new byte[32], pathBytes(SP)),
                0x9000);
        scan(c, "VERIFIED", "SIGN_BIP340");
        ReviewSession.Inner beg = inner(s, (byte) 0x33, (byte) 0, (byte) 0, pathBytes(EP), 0x9000);
        scan(c, "STREAM", "SIGN_ED25519 begin");
        byte[] encR = weiToEdwards(beg.data);
        byte[] encA = edPublic(slip10Leaf(S0, EP));
        byte[] stream = concat(encR, encA, "residue msg".getBytes());
        int half = stream.length / 2;
        inner(s, (byte) 0x33, (byte) 1, (byte) 0, slice(stream, 0, half), 0x9000);
        scan(c, "STREAM", "SIGN_ED25519 update");
        inner(
                s,
                (byte) 0x33,
                (byte) 2,
                (byte) 0,
                slice(stream, half, stream.length - half),
                0x9000);
        scan(c, "VERIFIED", "SIGN_ED25519 finish");
        // CHANGE is INS 0x23, data the new accessHash (§9.6); the session stays verified
        inner(s, (byte) 0x23, (byte) 0, (byte) 0, H1, 0x9000);
        addSecret("accessHash_new", H1);
        scan(c, "VERIFIED", "CHANGE");
        inner(s, (byte) 0x40, (byte) 0, (byte) 0, new byte[0], 0x9000);
        scan(c, "VERIFIED", "OFFER");
        ReviewSession.Inner e0 =
                inner(s, (byte) 0x41, (byte) 0, (byte) 0, m.exportRequest(), 0x9000);
        scan(c, "PENDING", "EXPORT P1=00 sw=" + hx(e0.sw));
        byte[] eph = slice(e0.data, 0, 65);
        byte[] z = m.z(eph);
        byte[] exportM = concat(LABEL_EXPORT, s.cardA, m.a, m.lk, eph);
        byte[][] tk = FakeMember.transferKeys(z, exportM);
        addSecret("kTe", tk[0]);
        addSecret("kTm", tk[1]);
        addSecret("sender", cardId(s.cardA));
        ReviewSession.Inner e1 = inner(s, (byte) 0x41, (byte) 1, (byte) 0, HT, 0x9000);
        // the pending export ended with the response: kTe/kTm and sender must be gone
        scan(c, "VERIFIED", "EXPORT P1=01 sw=" + hx(e1.sw));
        // ERASE is INS 0x24 with empty data (§9.7): the session stays open, unverified
        inner(s, (byte) 0x24, (byte) 0, (byte) 0, new byte[0], 0x9000);
        scan(c, "UNVERIFIED", "ERASE");

        // scenario B: IMPORT from fake source into a BLANK card
        ReviewCard c2 = ReviewCard.uninitialised();
        c2.blank();
        ReviewSession s2 = c2.open();
        sessionSecrets(s2);
        addSecret("accessHash_T", H1);
        scan(c2, "UNVERIFIED", "OPEN");
        ReviewSession.Inner of2 = inner(s2, (byte) 0x40, (byte) 0, (byte) 0, new byte[0], 0x9000);
        byte[] lkT2 = slice(of2.data, 0, 65);
        byte[][] eo2 = m.exportOffer(s2.cardA, lkT2);
        byte[] z2 = ecdhX(b2i(eo2[1]), lkT2);
        byte[] exportM2 = concat(LABEL_EXPORT, m.a, s2.cardA, lkT2, slice(eo2[0], 97, 65));
        byte[][] tk2 = FakeMember.transferKeys(z2, exportM2);
        addSecret("kTe", tk2[0]);
        addSecret("kTm", tk2[1]);
        ReviewSession.Inner i0 = inner(s2, (byte) 0x42, (byte) 0, (byte) 0, eo2[0], 0x9000);
        scan(c2, "PENDING", "IMPORT P1=00 sw=" + hx(i0.sw));
        byte[] payload =
                concat(new byte[] {0x01}, S0, H1, new byte[] {0x02}, m.cardId, cardId(s2.cardA));
        byte[][] seal = FakeMember.sealRecord(z2, exportM2, payload);
        ReviewSession.Inner i1 = inner(s2, (byte) 0x42, (byte) 1, (byte) 0, seal[0], 0x9000);
        // IMPORT P1=01 clears verified and ends the pending import (§9.14)
        scan(c2, "UNVERIFIED", "IMPORT P1=01 sw=" + hx(i1.sw));

        // scenario C: CREATE P1=00 (generate) + a real inner 6F00 + selects + power cycle
        ReviewCard c3 = ReviewCard.uninitialised();
        c3.blank();
        ReviewSession s3 = c3.open();
        sessionSecrets(s3);
        scan(c3, "UNVERIFIED", "OPEN");
        // CREATE P1=00 data is accessHash ‖ hostEntropy (§9.4); the generated seed is
        // unknown to the host and the session is left verified
        inner(s3, (byte) 0x21, (byte) 0, (byte) 0, concat(H0, HE), 0x9000);
        scan(c3, "VERIFIED", "CREATE P1=00");
        inner(s3, (byte) 0x22, (byte) 0, (byte) 0, H0, 0x9000);
        scan(c3, "VERIFIED", "VERIFY right");
        // register the generated seed and its derived secrets as search windows — this
        // only tells the scanner what to look for, it is not an oracle
        byte[] genSeed = sessionSeed(c3);
        secretsFor(genSeed, H0, s3);
        // one corrupted ECDSA output must fail the self-verify (§16.2 item 5): an inner
        // 6F00 tears the session down after its response record (§8.5)
        Fault.armEcdsaFlip(1);
        ReviewSession.Inner sig =
                s3.cmd(
                        (byte) 0x31,
                        (byte) 0,
                        (byte) 0,
                        concat(sha256("m".getBytes()), pathBytes(SP)));
        Fault.reset();
        if (sig.sw != 0x6F00) {
            throw new IllegalStateException(
                    "flipped SIGN_ECDSA expected inner 6F00 got " + hx(sig.sw));
        }
        scan(c3, "CLOSED", "inner 6F00");
        ReviewSession.Raw after = s3.send((byte) 0x20, (byte) 0, (byte) 0, new byte[0]);
        ROWS.add(
                new String[] {
                    "post-6F00 record",
                    "-",
                    "-",
                    "outer sw=" + hx(after.outer),
                    "CLOSED",
                    after.outer == 0x6985 ? "INFO" : "VIOLATION"
                });
        if (after.outer != 0x6985) {
            violations++;
        }
        c3.transmit(SELECT_NDEF);
        scan(c3, "CLOSED", "SELECT NDEF");
        c3.transmit(SELECT_WALLET);
        scan(c3, "CLOSED", "SELECT wallet again");
        c3.card.powerCycle();
        scan(c3, "CLOSED", "power cycle");

        write();
        if (violations > 0) {
            throw new AssertionError(violations + " residue violations; see residue.csv");
        }
    }

    private static void write() throws IOException {
        Files.createDirectories(DIR);
        StringBuilder csv = new StringBuilder("after,buffer,offset,secret,phase,verdict\n");
        for (String[] r : ROWS) {
            csv.append(String.join(",", r)).append('\n');
        }
        Files.writeString(DIR.resolve("residue.csv"), csv.toString());
        StringBuilder md = new StringBuilder("# Residue scan summary\n\n");
        md.append("Findings: ")
                .append(ROWS.size())
                .append(", violations: ")
                .append(violations)
                .append("\n\n");
        for (String[] r : ROWS) {
            if (r[5].equals("VIOLATION")) {
                md.append("- VIOLATION after `")
                        .append(r[0])
                        .append("`: secret `")
                        .append(r[3])
                        .append("` at ")
                        .append(r[1])
                        .append("+")
                        .append(r[2])
                        .append(" (phase ")
                        .append(r[4])
                        .append(")\n");
            }
        }
        Files.writeString(DIR.resolve("residue-summary.md"), md.toString());
    }
}
