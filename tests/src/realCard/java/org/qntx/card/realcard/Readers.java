// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

/** Builds the {@link Reader} named by a {@code -PrealCard*} property. */
final class Readers {
    private Readers() {}

    /**
     * {@code sim} for the in-process simulator self-check, otherwise the PC/SC terminal whose name
     * equals or contains {@code spec}.
     */
    static Reader create(String spec) {
        if ("sim".equals(spec)) {
            return new SimReader();
        }
        return new PcscReader(spec);
    }
}
