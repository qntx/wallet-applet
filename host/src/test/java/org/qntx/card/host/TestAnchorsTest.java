// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The pinned test anchors equal {@code cert.json}'s {@code cas}. */
final class TestAnchorsTest {
    @Test
    void anchorsAreCertJsonCas() {
        List<Map<String, Object>> cas = Vectors.list(Vectors.load("cert.json"), "cas");
        assertArrayEquals(Vectors.hex(cas.get(0), "public"), TestAnchors.CA1, "ca1");
        assertArrayEquals(Vectors.hex(cas.get(1), "public"), TestAnchors.CA2, "ca2");
        assertTrue(TestAnchors.isTest(TestAnchors.CA1));
        assertTrue(TestAnchors.isTest(TestAnchors.CA2));
        assertFalse(TestAnchors.isTest(new byte[65]));
        assertFalse(TestAnchors.isTest(new byte[0]));
    }
}
