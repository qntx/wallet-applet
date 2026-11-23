// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import java.util.List;
import java.util.stream.Collectors;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.TerminalFactory;

/**
 * A card on a PC/SC terminal via {@code javax.smartcardio}. {@link #powerCycle} disconnects with
 * reset and reconnects; the CPLC is read with GET DATA on the default-selected card manager right
 * after connect, before any applet SELECT.
 */
final class PcscReader implements Reader {
    private static final byte[] GET_CPLC = {0x00, (byte) 0xCA, (byte) 0x9F, 0x7F, 0x00};

    private final CardTerminal terminal;
    private Card card;
    private byte[] cplc;

    PcscReader(String name) {
        try {
            List<CardTerminal> terminals = TerminalFactory.getDefault().terminals().list();
            terminal =
                    terminals.stream()
                            .filter(
                                    t ->
                                            t.getName().equalsIgnoreCase(name)
                                                    || t.getName().contains(name))
                            .findFirst()
                            .orElseThrow(
                                    () ->
                                            new IllegalStateException(
                                                    "no PC/SC terminal matching '"
                                                            + name
                                                            + "'; present: "
                                                            + terminals.stream()
                                                                    .map(CardTerminal::getName)
                                                                    .collect(
                                                                            Collectors.joining(
                                                                                    ", "))));
            connect();
        } catch (CardException e) {
            throw new IllegalStateException("PC/SC open failed: " + e.getMessage(), e);
        }
    }

    private void connect() throws CardException {
        card = terminal.connect("*");
        cplc = null;
        try {
            byte[] r = card.getBasicChannel().transmit(new CommandAPDU(GET_CPLC)).getBytes();
            if (r.length == 47 && r[0] == (byte) 0x9F && r[1] == 0x7F && r[2] == 0x2A) {
                cplc = new byte[42];
                System.arraycopy(r, 3, cplc, 0, 42);
            }
        } catch (CardException e) {
            // a non-GP card leaves cplc null; the suite reports it
        }
    }

    @Override
    public byte[] transmit(byte[] command) {
        try {
            return card.getBasicChannel().transmit(new CommandAPDU(command)).getBytes();
        } catch (CardException e) {
            throw new IllegalStateException("transmit failed on " + describe(), e);
        }
    }

    @Override
    public void powerCycle() {
        try {
            card.disconnect(true);
            connect();
        } catch (CardException e) {
            throw new IllegalStateException("power cycle failed on " + describe(), e);
        }
    }

    @Override
    public String describe() {
        return "pcsc:" + terminal.getName();
    }

    @Override
    public Boolean contactless() {
        String protocol = card.getProtocol();
        return "T=CL".equalsIgnoreCase(protocol);
    }

    @Override
    public byte[] cplc() {
        return cplc;
    }

    @Override
    public void close() {
        try {
            card.disconnect(false);
        } catch (CardException e) {
            // closing is best-effort
        }
    }
}
