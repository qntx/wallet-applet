// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.real;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The NIST SP 800-22 subset of admission item 6 (protocol.md §3, architecture.md §10): frequency,
 * block frequency (M = 128), runs, longest run of ones (M = 10⁴), cumulative sums forward and
 * backward, approximate entropy (m = 10) and the serial test (m = 16). Every returned p-value must
 * be ≥ 0.01.
 */
public final class RngStats {
    private RngStats() {}

    private static int bit(byte[] data, long i) {
        return (data[(int) (i >> 3)] >> (7 - (i & 7))) & 1;
    }

    /** {@code erfc(x)} — NIST p-value formulas need ~1e-7 absolute accuracy. */
    static double erfc(double x) {
        // Abramowitz–Stegun 7.1.26
        double t = 1.0 / (1.0 + 0.5 * Math.abs(x));
        double tau =
                t
                        * Math.exp(
                                -x * x
                                        - 1.26551223
                                        + t
                                                * (1.00002368
                                                        + t
                                                                * (0.37409196
                                                                        + t
                                                                                * (0.09678418
                                                                                        + t
                                                                                                * (-0.18628806
                                                                                                        + t
                                                                                                                * (0.27886807
                                                                                                                        + t
                                                                                                                                * (-1.13520398
                                                                                                                                        + t
                                                                                                                                                * (1.48851587
                                                                                                                                                        + t
                                                                                                                                                                * (-0.82215223
                                                                                                                                                                        + t
                                                                                                                                                                                * 0.17087277)))))))));
        return x >= 0 ? tau : 2 - tau;
    }

    /** The standard normal CDF via {@link #erfc}. */
    static double phi(double x) {
        return 0.5 * erfc(-x / Math.sqrt(2));
    }

    /** Regularized upper incomplete gamma Q(a, x) = Γ(a, x)/Γ(a) — Numerical Recipes gser/gcf. */
    static double gammaQ(double a, double x) {
        if (x < 0 || a <= 0) {
            throw new IllegalArgumentException();
        }
        if (x == 0) {
            return 1.0;
        }
        if (x < a + 1) {
            // series for P(a, x), return 1 − P
            double ap = a;
            double sum = 1.0 / a;
            double del = sum;
            for (int n = 1; n < 1000; n++) {
                ap += 1;
                del *= x / ap;
                sum += del;
                if (Math.abs(del) < Math.abs(sum) * 1e-14) {
                    break;
                }
            }
            return 1.0 - sum * Math.exp(-x + a * Math.log(x) - lgamma(a));
        }
        // continued fraction for Q(a, x)
        double b = x + 1 - a;
        double c = 1e300;
        double d = 1 / b;
        double h = d;
        for (int i = 1; i < 1000; i++) {
            double an = -i * (i - a);
            b += 2;
            d = an * d + b;
            if (Math.abs(d) < 1e-300) {
                d = 1e-300;
            }
            c = b + an / c;
            if (Math.abs(c) < 1e-300) {
                c = 1e-300;
            }
            d = 1 / d;
            double del = d * c;
            h *= del;
            if (Math.abs(del - 1.0) < 1e-14) {
                break;
            }
        }
        return h * Math.exp(-x + a * Math.log(x) - lgamma(a));
    }

    private static double lgamma(double x) {
        // Lanczos approximation, g = 7
        double[] p = {
            0.99999999999980993, 676.5203681218851, -1259.1392167224028,
            771.32342877765313, -176.61502916214059, 12.507343278686905,
            -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7
        };
        if (x < 0.5) {
            return Math.log(Math.PI / Math.sin(Math.PI * x)) - lgamma(1 - x);
        }
        x -= 1;
        double acc = p[0];
        for (int i = 1; i < p.length; i++) {
            acc += p[i] / (x + i);
        }
        double t = x + 7.5;
        return 0.5 * Math.log(2 * Math.PI) + (x + 0.5) * Math.log(t) - t + Math.log(acc);
    }

    /** Runs every test over the first {@code n} bits of {@code data}; name → p-value. */
    public static Map<String, Double> all(byte[] data) {
        Map<String, Double> p = new LinkedHashMap<>();
        long n = (long) data.length * 8;
        p.put("frequency", frequency(data, n));
        p.put("blockFrequency-128", blockFrequency(data, n, 128));
        p.put("runs", runs(data, n));
        p.put("longestRun-10000", longestRun(data, n, 10000));
        p.put("cusum-forward", cusum(data, n, true));
        p.put("cusum-backward", cusum(data, n, false));
        p.put("approxEntropy-10", approxEntropy(data, n, 10));
        double[] serial = serial(data, n, 16);
        p.put("serial-16-a", serial[0]);
        p.put("serial-16-b", serial[1]);
        return p;
    }

    static double frequency(byte[] data, long n) {
        long s = 0;
        for (long i = 0; i < n; i++) {
            s += 2 * bit(data, i) - 1;
        }
        return erfc(Math.abs(s) / Math.sqrt(n) / Math.sqrt(2));
    }

    static double blockFrequency(byte[] data, long n, int m) {
        long blocks = n / m;
        double chi2 = 0;
        for (long b = 0; b < blocks; b++) {
            int ones = 0;
            for (int i = 0; i < m; i++) {
                ones += bit(data, b * m + i);
            }
            double pi = (double) ones / m;
            chi2 += (pi - 0.5) * (pi - 0.5);
        }
        chi2 *= 4.0 * m;
        return gammaQ(blocks / 2.0, chi2 / 2);
    }

    static double runs(byte[] data, long n) {
        long ones = 0;
        for (long i = 0; i < n; i++) {
            ones += bit(data, i);
        }
        double pi = (double) ones / n;
        if (Math.abs(pi - 0.5) >= 2.0 / Math.sqrt(n)) {
            return 0.0; // the run-count statistic is meaningless off-balance
        }
        long v = 1;
        for (long i = 1; i < n; i++) {
            if (bit(data, i) != bit(data, i - 1)) {
                v++;
            }
        }
        double denom = 2 * Math.sqrt(2 * n) * pi * (1 - pi);
        return erfc(Math.abs(v - 2 * n * pi * (1 - pi)) / denom);
    }

    static double longestRun(byte[] data, long n, int m) {
        long blocks = n / m;
        // NIST table for M = 10⁴: bins for the longest run of ones per block
        double[] probs = {0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727};
        int[] v = new int[probs.length];
        for (long b = 0; b < blocks; b++) {
            int longest = 0;
            int cur = 0;
            for (int i = 0; i < m; i++) {
                if (bit(data, b * m + i) == 1) {
                    cur++;
                    if (cur > longest) {
                        longest = cur;
                    }
                } else {
                    cur = 0;
                }
            }
            int bin;
            if (longest <= 10) {
                bin = 0;
            } else if (longest >= 16) {
                bin = 6;
            } else {
                bin = longest - 10;
            }
            v[bin]++;
        }
        double chi2 = 0;
        for (int i = 0; i < probs.length; i++) {
            double e = blocks * probs[i];
            chi2 += (v[i] - e) * (v[i] - e) / e;
        }
        return gammaQ(3.0, chi2 / 2);
    }

    static double cusum(byte[] data, long n, boolean forward) {
        long max = 0;
        long s = 0;
        for (long i = 0; i < n; i++) {
            s += 2 * bit(data, forward ? i : n - 1 - i) - 1;
            if (Math.abs(s) > max) {
                max = Math.abs(s);
            }
        }
        double z = max;
        double sqrtN = Math.sqrt(n);
        double sum1 = 0;
        long k1 = (long) Math.floor((-n / z + 1) / 4.0);
        long k2 = (long) Math.floor((n / z - 1) / 4.0);
        for (long k = k1; k <= k2; k++) {
            sum1 += phi((4 * k + 1) * z / sqrtN) - phi((4 * k - 1) * z / sqrtN);
        }
        double sum2 = 0;
        k1 = (long) Math.floor((-n / z - 3) / 4.0);
        for (long k = k1; k <= k2; k++) {
            sum2 += phi((4 * k + 3) * z / sqrtN) - phi((4 * k + 1) * z / sqrtN);
        }
        return 1.0 - sum1 + sum2;
    }

    /** Cyclic count of each m-bit pattern over the first n bits. */
    private static long[] patternCounts(byte[] data, long n, int m) {
        long[] counts = new long[1 << m];
        int mask = (1 << m) - 1;
        int window = 0;
        for (int i = 0; i < m - 1; i++) {
            window = (window << 1) | bit(data, i);
        }
        for (long i = 0; i < n; i++) {
            window = ((window << 1) | bit(data, (i + m - 1) % n)) & mask;
            counts[window]++;
        }
        return counts;
    }

    static double approxEntropy(byte[] data, long n, int m) {
        double apen = phiEntropy(data, n, m) - phiEntropy(data, n, m + 1);
        double chi2 = 2 * n * (Math.log(2) - apen);
        return gammaQ(Math.pow(2, m - 1), chi2 / 2);
    }

    private static double phiEntropy(byte[] data, long n, int m) {
        long[] counts = patternCounts(data, n, m);
        double sum = 0;
        for (long c : counts) {
            if (c > 0) {
                double p = (double) c / n;
                sum += p * Math.log(p);
            }
        }
        return sum;
    }

    static double[] serial(byte[] data, long n, int m) {
        double psiM = psi2(data, n, m);
        double psiM1 = psi2(data, n, m - 1);
        double psiM2 = psi2(data, n, m - 2);
        double d1 = psiM - psiM1;
        double d2 = psiM - 2 * psiM1 + psiM2;
        return new double[] {
            gammaQ(Math.pow(2, m - 2), d1 / 2), gammaQ(Math.pow(2, m - 3), d2 / 2)
        };
    }

    private static double psi2(byte[] data, long n, int m) {
        long[] counts = patternCounts(data, n, m);
        double sum = 0;
        for (long c : counts) {
            sum += (double) c * c;
        }
        return sum * Math.pow(2, m) / n - n;
    }
}
