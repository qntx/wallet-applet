// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tools;

import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.TerminalFactory;
import picocli.CommandLine.Option;

/**
 * Transport options shared by every subcommand: exactly one of {@code --sim host:port} (a card-sim
 * TCP port speaking the README "Framing" protocol) or {@code --reader name} (a PC/SC terminal).
 */
final class Transport implements AutoCloseable {

    @Option(names = "--sim", description = "card-sim TCP endpoint host:port")
    String sim;

    @Option(names = "--reader", description = "PC/SC terminal name")
    String reader;

    private BIBO bibo;

    BIBO open() throws IOException {
        if (sim == null && reader == null) {
            throw new IOException("one of --sim or --reader is required");
        }
        if (sim != null && reader != null) {
            throw new IOException("--sim and --reader are mutually exclusive");
        }
        if (sim != null) {
            int colon = sim.lastIndexOf(':');
            if (colon <= 0 || colon == sim.length() - 1) {
                throw new IOException("--sim expects host:port, got " + sim);
            }
            int port;
            try {
                port = Integer.parseInt(sim.substring(colon + 1));
            } catch (NumberFormatException e) {
                throw new IOException("--sim port is not a number", e);
            }
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(sim.substring(0, colon), port), 10_000);
            socket.setSoTimeout(30_000);
            bibo = new Vpcd(socket);
        } else {
            try {
                for (CardTerminal terminal : TerminalFactory.getDefault().terminals().list()) {
                    if (terminal.getName().equals(reader) && terminal.isCardPresent()) {
                        Card card = terminal.connect("T=1");
                        bibo = new Pcsc(card);
                        return bibo;
                    }
                }
            } catch (CardException e) {
                throw new IOException("PC/SC access failed: " + e.getMessage(), e);
            }
            throw new IOException("no PC/SC terminal '" + reader + "' with a card present");
        }
        return bibo;
    }

    @Override
    public void close() throws IOException {
        if (bibo instanceof Vpcd vpcd) {
            vpcd.socket().close();
        } else if (bibo instanceof Pcsc pcsc) {
            try {
                pcsc.card().disconnect(true);
            } catch (CardException ignored) {
                // the socket/card is gone either way
            }
        }
    }

    /**
     * The vpcd-style TCP transport of the README "Framing" table: {@code u16(len) ‖ APDU} frames;
     * an empty frame (a torn card) answers as an empty response.
     */
    private record Vpcd(Socket socket) implements BIBO {
        @Override
        public byte[] transceive(byte[] command) throws BIBOException {
            try {
                OutputStream out = socket.getOutputStream();
                out.write((command.length >>> 8) & 0xFF);
                out.write(command.length & 0xFF);
                out.write(command);
                out.flush();
                InputStream in = socket.getInputStream();
                int hi = in.read();
                int lo = in.read();
                if (hi < 0 || lo < 0) {
                    throw new IOException("card-sim closed the connection");
                }
                int len = (hi << 8) | lo;
                byte[] response = in.readNBytes(len);
                if (response.length != len) {
                    throw new IOException("short response frame from card-sim");
                }
                return response;
            } catch (IOException e) {
                throw new BIBOException("card-sim transport failed", e);
            }
        }
    }

    /** A PC/SC card channel as a {@link BIBO}. */
    private record Pcsc(Card card) implements BIBO {
        @Override
        public byte[] transceive(byte[] command) throws BIBOException {
            try {
                return card.getBasicChannel().transmit(new CommandAPDU(command)).getBytes();
            } catch (CardException e) {
                throw new BIBOException("PC/SC transmit failed", e);
            }
        }
    }
}
