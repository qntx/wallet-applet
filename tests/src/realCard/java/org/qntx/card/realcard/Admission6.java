// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.ToDoubleFunction;
import org.junit.jupiter.api.Test;

/**
 * Admission 6 (protocol §3 item 6): the NIST SP 800-22 Rev. 1a §4.2 decision rule over 10 MB of
 * {@code ALG_KEYGENERATION} output, and the first 32 output bytes after each of 100 power-ups
 * pairwise distinct.
 *
 * <p>The stream is split into {@code m = 80} sequences of 125&nbsp;000 bytes (10⁶ bits), the size
 * every statistic of the subset recommends: block frequency {@code M = 128} gives {@code N = 7812 ≥
 * 100} blocks (§2.3.7), longest run uses {@code M = 10 000} because {@code n ≥ 750 000} (§2.4.7),
 * and cumulative sums accepts {@code n ≥ 100} (§2.6.7). Each statistic produces one p-value per
 * sequence and is accepted only under both §4.2 checks: the §4.2.1 proportion of sequences with
 * {@code p ≥ 0.01} must be {@code ≥ p̂ − 3·sqrt(p̂(1−p̂)/m)} with {@code p̂ = 0.99} — 76.53, i.e. ≥
 * 77 of 80 — and the §4.2.2 uniformity of the 80 p-values over 10 equal bins must give {@code
 * P-value_T = igamc(9/2, χ²/2) ≥ 0.0001}.
 */
final class Admission6 extends Suite {
    private static final int SEQUENCES = 80;
    private static final int SEQ_BYTES = 125_000;
    private static final long SEQ_BITS = 8L * SEQ_BYTES;
    private static final int BYTES = SEQUENCES * SEQ_BYTES;
    private static final double PHAT = 0.99;
    private static final double UNIFORM_ALPHA = 0.0001;
    private static final int POWER_UPS = 100;

    @Test
    void nistSubsetOnTenMegabytes() {
        Probe probe = Suite.prepareProbe();
        ByteArrayOutputStream buf = new ByteArrayOutputStream(BYTES);
        while (buf.size() < BYTES) {
            buf.writeBytes(probe.rnd(Math.min(255, BYTES - buf.size())));
        }
        byte[] stream = buf.toByteArray();

        boolean ok =
                nist("frequency", pValues(stream, s -> Sp80022.frequency(s, SEQ_BITS)))
                        & nist(
                                "blockFrequency M=128",
                                pValues(stream, s -> Sp80022.blockFrequency(s, SEQ_BITS, 128)))
                        & nist("runs", pValues(stream, s -> Sp80022.runs(s, SEQ_BITS)))
                        & nist(
                                "longestRun M=10000",
                                pValues(stream, s -> Sp80022.longestRun(s, SEQ_BITS)))
                        & nist(
                                "cumulativeSums",
                                pValues(stream, s -> Sp80022.cumulativeSums(s, SEQ_BITS)));
        assertTrue(ok, "SP 800-22 §4.2 decision failed");
        Results.row("Admission 6", "nist subset", "pass", "five statistics pass §4.2");
    }

    @Test
    void firstOutputDistinctAcrossPowerUps() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < POWER_UPS; i++) {
            reader.powerCycle();
            Probe probe = Suite.prepareProbe();
            Probe.Rsp first = probe.first();
            assertEquals(0x9000, first.sw(), "first() after power-up");
            assertEquals(32, first.data().length);
            assertEquals(0x6985, probe.first().sw(), "second first() must return 6985");
            assertTrue(seen.add(Apdu.hex(first.data())), "first output repeated at power-up " + i);
        }
        Results.row(
                "Admission 6",
                "first outputs",
                "pass",
                POWER_UPS + " distinct first 32-byte outputs");
    }

    /** One p-value of {@code stat} per contiguous 125 000-byte sequence of {@code stream}. */
    private static double[] pValues(byte[] stream, ToDoubleFunction<byte[]> stat) {
        double[] p = new double[SEQUENCES];
        for (int i = 0; i < SEQUENCES; i++) {
            p[i] =
                    stat.applyAsDouble(
                            Arrays.copyOfRange(stream, i * SEQ_BYTES, (i + 1) * SEQ_BYTES));
        }
        return p;
    }

    /**
     * SP 800-22 Rev. 1a §4.2 decision on {@code m = 80} p-values: the §4.2.1 passing proportion
     * must reach {@code p̂ − 3·sqrt(p̂(1−p̂)/m)} (77 of 80 at {@code p̂ = 0.99}) and the §4.2.2
     * chi-square over 10 equal bins must yield {@code P-value_T ≥ 0.0001}.
     */
    private static boolean nist(String name, double[] p) {
        int pass = 0;
        int[] bins = new int[10];
        for (double v : p) {
            if (v >= Sp80022.ALPHA) {
                pass++;
            }
            bins[Math.min(9, (int) (v * 10))]++;
        }
        int need =
                (int) Math.ceil(SEQUENCES * (PHAT - 3 * Math.sqrt(PHAT * (1 - PHAT) / SEQUENCES)));
        double chi2 = 0;
        for (int bin : bins) {
            double d = bin - SEQUENCES / 10.0;
            chi2 += d * d / (SEQUENCES / 10.0);
        }
        double pUniform = Sp80022.igamc(9.0 / 2, chi2 / 2);
        boolean ok = pass >= need && pUniform >= UNIFORM_ALPHA;
        Results.row(
                "Admission 6",
                "SP800-22 " + name,
                ok ? "pass" : "fail",
                "proportion "
                        + pass
                        + "/"
                        + SEQUENCES
                        + " (>= "
                        + need
                        + "), P-value_T="
                        + pUniform);
        return ok;
    }
}
