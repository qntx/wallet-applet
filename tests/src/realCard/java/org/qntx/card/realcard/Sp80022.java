// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

/**
 * The NIST SP 800-22 subset of Admission 6 (rev 1a §2.1, §2.3, §2.4, §2.6): frequency, block
 * frequency with {@code M = 128}, runs, longest run of ones in a block, and cumulative sums.
 * Special functions follow the cited approximations: {@link #igamc} is the regularized upper
 * incomplete gamma of Numerical Recipes 3rd ed. §6.2 (series + continued fraction), {@link #erfc}
 * derives from it as {@code Q(1/2, x²)} (A&S 6.5.31).
 */
final class Sp80022 {
    static final double ALPHA = 0.01;

    private Sp80022() {}

    static int bit(byte[] data, long i) {
        return (data[(int) (i >>> 3)] >>> (7 - (i & 7))) & 1;
    }

    /** SP 800-22 §2.1: the monobit frequency test p-value. */
    static double frequency(byte[] data, long n) {
        long s = 0;
        for (long i = 0; i < n; i++) {
            s += 2 * bit(data, i) - 1;
        }
        return erfc(Math.abs(s) / Math.sqrt(2.0 * n));
    }

    /** SP 800-22 §2.2: frequency within {@code m}-bit blocks. */
    static double blockFrequency(byte[] data, long n, int m) {
        long blocks = n / m;
        double chi2 = 0;
        for (long b = 0; b < blocks; b++) {
            int ones = 0;
            for (int i = 0; i < m; i++) {
                ones += bit(data, b * m + i);
            }
            double pi = (double) ones / m - 0.5;
            chi2 += pi * pi;
        }
        chi2 *= 4.0 * m;
        return igamc(blocks / 2.0, chi2 / 2.0);
    }

    /** SP 800-22 §2.3: the runs test; p is forced 0 when the π pretest fails. */
    static double runs(byte[] data, long n) {
        long ones = 0;
        for (long i = 0; i < n; i++) {
            ones += bit(data, i);
        }
        double pi = (double) ones / n;
        if (Math.abs(pi - 0.5) >= 2.0 / Math.sqrt(n)) {
            return 0;
        }
        long v = 1;
        for (long i = 0; i + 1 < n; i++) {
            if (bit(data, i) != bit(data, i + 1)) {
                v++;
            }
        }
        double arg = pi * (1 - pi);
        return erfc(Math.abs(v - 2 * n * arg) / (2 * arg * Math.sqrt(2.0 * n)));
    }

    /**
     * SP 800-22 §2.4: longest run of ones in a block, the {@code n ≥ 750000} parameters {@code M =
     * 10 000, K = 6} and the NIST class probabilities.
     */
    static double longestRun(byte[] data, long n) {
        int m = 10000;
        double[] pi = {0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727};
        long blocks = n / m;
        long[] v = new long[7];
        for (long b = 0; b < blocks; b++) {
            int run = 0;
            int longest = 0;
            for (int i = 0; i < m; i++) {
                if (bit(data, b * m + i) == 1) {
                    run++;
                    longest = Math.max(longest, run);
                } else {
                    run = 0;
                }
            }
            if (longest <= 10) {
                v[0]++;
            } else if (longest >= 16) {
                v[6]++;
            } else {
                v[longest - 10]++;
            }
        }
        double chi2 = 0;
        for (int i = 0; i < 7; i++) {
            double d = v[i] - blocks * pi[i];
            chi2 += d * d / (blocks * pi[i]);
        }
        return igamc(6 / 2.0, chi2 / 2.0);
    }

    /** SP 800-22 §2.6: cumulative sums (forward). */
    static double cumulativeSums(byte[] data, long n) {
        long s = 0;
        long z = 0;
        for (long i = 0; i < n; i++) {
            s += 2 * bit(data, i) - 1;
            z = Math.max(z, Math.abs(s));
        }
        double sqrtN = Math.sqrt(n);
        long start1 = (long) Math.ceil((-n / (double) z + 1) / 4);
        long end1 = (long) Math.floor((n / (double) z - 1) / 4);
        double sum1 = 0;
        for (long k = start1; k <= end1; k++) {
            sum1 += phi((4 * k + 1) * z / sqrtN) - phi((4 * k - 1) * z / sqrtN);
        }
        long start2 = (long) Math.ceil((-n / (double) z - 3) / 4);
        long end2 = (long) Math.floor((n / (double) z - 1) / 4);
        double sum2 = 0;
        for (long k = start2; k <= end2; k++) {
            sum2 += phi((4 * k + 3) * z / sqrtN) - phi((4 * k + 1) * z / sqrtN);
        }
        return 1.0 - sum1 + sum2;
    }

    static double phi(double x) {
        return 0.5 * erfc(-x / Math.sqrt(2));
    }

    /** Complementary error function via {@code Q(1/2, x²)} (A&S 6.5.31). */
    static double erfc(double x) {
        double q = igamc(0.5, x * x);
        return x >= 0 ? q : 2 - q;
    }

    /**
     * Regularized upper incomplete gamma {@code Q(a, x)} = {@code Γ(a, x) / Γ(a)}: the series
     * representation below {@code x < a + 1} and the continued fraction above it (Numerical Recipes
     * 3rd ed. §6.2).
     */
    static double igamc(double a, double x) {
        if (x < 0 || a <= 0) {
            throw new IllegalArgumentException("igamc domain");
        }
        if (x == 0) {
            return 1;
        }
        if (x < a + 1) {
            return 1 - gser(a, x);
        }
        return gcf(a, x);
    }

    private static double gser(double a, double x) {
        double sum = 1 / a;
        double term = sum;
        for (int i = 1; i < 1000; i++) {
            term *= x / (a + i);
            sum += term;
            if (Math.abs(term) < Math.abs(sum) * 3e-15) {
                break;
            }
        }
        return sum * Math.exp(-x + a * Math.log(x) - gammLn(a));
    }

    private static double gcf(double a, double x) {
        double tiny = 1e-300;
        double b = x + 1 - a;
        double c = 1 / tiny;
        double d = 1 / b;
        double h = d;
        for (int i = 1; i < 1000; i++) {
            double an = -i * (i - a);
            b += 2;
            d = an * d + b;
            if (Math.abs(d) < tiny) {
                d = tiny;
            }
            c = b + an / c;
            if (Math.abs(c) < tiny) {
                c = tiny;
            }
            d = 1 / d;
            double del = d * c;
            h *= del;
            if (Math.abs(del - 1) < 3e-15) {
                break;
            }
        }
        return h * Math.exp(-x + a * Math.log(x) - gammLn(a));
    }

    /** Lanczos log-gamma (Numerical Recipes 3rd ed. §6.1). */
    static double gammLn(double x) {
        double[] cof = {
            57.1562356658629235,
            -59.5979603554754912,
            14.1360979747417471,
            -0.491913816097620199,
            0.339946499848118887e-4,
            0.465236289270485756e-4,
            -0.983744753048795646e-4,
            0.158088703224912494e-3,
            -0.210264441724104883e-3,
            0.217439618115212643e-3,
            -0.164318106536763890e-3,
            0.844182239838527433e-4,
            -0.261908384015814087e-4,
            0.368991826595316234e-5
        };
        double y = x;
        double t = x + 5.24218750000000000;
        t = (x + 0.5) * Math.log(t) - t;
        double ser = 0.999999999999997092;
        for (double c : cof) {
            ser += c / ++y;
        }
        return t + Math.log(2.5066282746310005 * ser / x);
    }
}
