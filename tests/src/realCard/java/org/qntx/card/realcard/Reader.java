// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

/**
 * One card under test of the real-card suite: full command-response pairs including the status
 * word, a power cycle, and whatever facts the transport can report about itself.
 */
public interface Reader extends AutoCloseable {
    /** One command APDU to one response APDU (data ‖ SW). */
    byte[] transmit(byte[] command);

    /** Power off and on; every card object and session is gone afterwards. */
    void powerCycle();

    /** Transport description for results.jsonl ({@code pcsc:<terminal>} or {@code sim}). */
    String describe();

    /**
     * {@code Boolean.TRUE} on a contactless interface, {@code FALSE} on contact, {@code null} when
     * undeterminable.
     */
    Boolean contactless();

    /** The 42-byte CPLC of the card, or {@code null} when the transport provides none. */
    byte[] cplc();

    /** Whether this reader is the in-process simulator self-check (never hardware evidence). */
    default boolean isSim() {
        return false;
    }

    @Override
    default void close() {}
}
