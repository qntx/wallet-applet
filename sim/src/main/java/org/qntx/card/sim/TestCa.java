// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import java.math.BigInteger;
import org.qntx.card.host.TestAnchors;

/**
 * The {@code ca1} test CA of {@code spec/vectors/cert.json}, pinned as a constant so {@link Server}
 * can personalise simulated cards without reading the vector file. Test material only — never a
 * production anchor (protocol.md §14.3).
 */
public final class TestCa {
    /** cert.json {@code cas[0].private}. */
    public static final BigInteger PRIVATE =
            new BigInteger("a76d852de566723ec4e6414f49b80dd3899ef7661b9afc4e6dac489adcba69a7", 16);

    /** cert.json {@code cas[0].public}, uncompressed — the ca1 entry of {@link TestAnchors}. */
    public static final byte[] PUBLIC = TestAnchors.CA1;

    private TestCa() {}
}
