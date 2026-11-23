// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.qntx.card.NdefApplet;
import org.qntx.card.WalletApplet;
import org.qntx.card.host.Certificates;
import org.qntx.card.host.Ids;

/**
 * TCP front end of the simulator (architecture.md §8 "Server"): one port per simulated card, the
 * vsmartcard vpcd framing of {@code u16(len) ‖ payload}, power and tear controls. The qntx/wallet
 * CI is the consumer; the framing is documented in README "Simulator (card-sim.jar)".
 *
 * <p>Every {@link Card} operation — install, personalisation, transmits, tear arming, power cycles
 * — runs on a single executor thread because jcardsim and {@link Fault} hold static and
 * thread-bound state. Connection threads only do frame I/O: a card accepts one connection at a time
 * and a second connection waits until the first closes.
 */
public final class Server {
    private static final int DEFAULT_CARDS = 3;
    private static final int MAX_CARDS = 16;
    private static final int DEFAULT_PORT = 35963;

    private static final byte[] WALLET_AID = {(byte) 0xF0, 0x71, 0x6E, 0x74, 0x78, 0x01, 0x01};
    private static final byte[] NDEF_AID = {(byte) 0xD2, 0x76, 0x00, 0x00, (byte) 0x85, 0x01, 0x01};

    /** The NDEF Text record "qntx card" (protocol.md §15 message). */
    private static final byte[] NDEF_MESSAGE =
            HexFormat.of().parseHex("D1010C5402656E716E74782063617264");

    private static final byte[] SELECT_WALLET = {
        0x00, (byte) 0xA4, 0x04, 0x00, 0x07, (byte) 0xF0, 0x71, 0x6E, 0x74, 0x78, 0x01, 0x01, 0x00
    };
    private static final byte[] GET_IDENTITY = {(byte) 0x80, (byte) 0xE0, 0x00, 0x00, 0x00};

    private static final int CTRL_POWER_OFF = 0x00;
    private static final int CTRL_POWER_ON = 0x01;
    private static final int CTRL_RESET = 0x02;
    private static final int CTRL_GET_ATR = 0x04;
    private static final int CTRL_TEAR = 0x10;
    private static final byte[] EMPTY = new byte[0];

    private Server() {}

    enum State {
        EMPTY,
        FACTORY,
        BLANK
    }

    private record Options(int cards, int port, State state) {}

    /** One simulated card: its card manager, card and listen socket. */
    private record SimCard(Isd isd, ServerSocket socket) {}

    public static void main(String[] args) throws Exception {
        Options options = options(args);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        List<SimCard> cards = new ArrayList<>(options.cards());
        HexFormat hex = HexFormat.of();
        for (int i = 0; i < options.cards(); i++) {
            Card card = new Card();
            Isd isd = new Isd(card, i, options.state() != State.EMPTY);
            ServerSocket socket =
                    new ServerSocket(options.port() == 0 ? 0 : options.port() + i, 16, loopback);
            if (options.state() == State.EMPTY) {
                System.out.println("card " + i + " port " + socket.getLocalPort());
            } else {
                byte[] a = prepare(executor, isd, options.state());
                System.out.println(
                        "card "
                                + i
                                + " port "
                                + socket.getLocalPort()
                                + " id "
                                + hex.formatHex(Ids.cardId(a))
                                + " short "
                                + Ids.shortId(a));
            }
            cards.add(new SimCard(isd, socket));
        }
        if (options.state() == State.BLANK) {
            System.out.println("anchor " + hex.formatHex(TestCa.PUBLIC));
        }
        System.out.println("ready");
        for (SimCard sim : cards) {
            Thread acceptor = new Thread(() -> accept(executor, sim), "card-acceptor");
            acceptor.start();
        }
    }

    /**
     * Installs both applets and reads {@code A}; in the {@code blank} state it also runs the §14
     * personalisation against the {@link TestCa} anchor. All on the card thread; the {@link Isd}
     * registry mirrors each install.
     */
    private static byte[] prepare(ExecutorService executor, Isd isd, State state) {
        Card card = isd.card();
        return call(
                executor,
                () -> {
                    card.install(WALLET_AID, WalletApplet.class);
                    isd.registerApp(WALLET_AID);
                    card.install(NDEF_AID, NdefApplet.class, NDEF_MESSAGE);
                    isd.registerApp(NDEF_AID);
                    expectOk(isd.transmit(SELECT_WALLET), "SELECT");
                    byte[] rapdu = isd.transmit(GET_IDENTITY);
                    expectOk(rapdu, "GET_IDENTITY");
                    byte[] a = Arrays.copyOf(rapdu, rapdu.length - 2);
                    if (state == State.FACTORY) {
                        return a;
                    }
                    byte[] cert = Certificates.issue(TestCa.PRIVATE, a);
                    byte[] personalize = new byte[5 + 162];
                    personalize[0] = (byte) 0x80;
                    personalize[1] = (byte) 0xE2;
                    personalize[4] = (byte) 162;
                    System.arraycopy(cert, 0, personalize, 5, 97);
                    System.arraycopy(TestCa.PUBLIC, 0, personalize, 102, 65);
                    expectOk(isd.transmit(personalize), "PERSONALIZE");
                    return a;
                });
    }

    private static void expectOk(byte[] rapdu, String what) {
        if (rapdu.length < 2
                || ((rapdu[rapdu.length - 2] & 0xFF) << 8 | rapdu[rapdu.length - 1] & 0xFF)
                        != 0x9000) {
            throw new IllegalStateException(what + " failed during card setup");
        }
    }

    /**
     * Accept loop of one card: connections are served one at a time, so a second connection waits
     * until the first closes. A new connection powers the card on with a power cycle; closing it
     * powers the card off. Persistent state lives as long as the server process.
     */
    private static void accept(ExecutorService executor, SimCard sim) {
        try {
            while (true) {
                Socket conn = sim.socket().accept();
                try {
                    serve(executor, sim.isd(), conn);
                } catch (IOException | RuntimeException e) {
                    // a framing error, malformed APDU or client disconnect ends the session
                } finally {
                    try {
                        conn.close();
                    } catch (IOException e) {
                        // the socket is gone either way
                    }
                    call(
                            executor,
                            () -> {
                                powerCycle(sim.isd());
                                return null;
                            });
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("accept failed on " + sim.socket(), e);
        }
    }

    /**
     * The vpcd frame loop of one connection: {@code len ≥ 4} is a command APDU answered with its
     * R-APDU, {@code len = 1} a power/reset/ATR control, {@code len = 3} beginning with {@code
     * 0x10} the tear arm. An APDU on an unpowered card or one that hit the armed tear is answered
     * with the empty frame {@code 00 00}.
     */
    private static void serve(ExecutorService executor, Isd isd, Socket conn) throws IOException {
        DataInputStream in = new DataInputStream(conn.getInputStream());
        OutputStream out = conn.getOutputStream();
        call(
                executor,
                () -> {
                    powerCycle(isd);
                    return null;
                });
        boolean powered = true;
        while (true) {
            int len;
            try {
                len = in.readUnsignedShort();
            } catch (EOFException e) {
                return;
            }
            byte[] payload = in.readNBytes(len);
            if (payload.length < len) {
                return;
            }
            if (len >= 4) {
                if (!powered) {
                    frame(out, EMPTY);
                } else {
                    try {
                        frame(out, call(executor, () -> isd.transmit(payload)));
                    } catch (TornException torn) {
                        // the field was lost mid-command; the card is unpowered until a
                        // power-on or reset control
                        powered = false;
                        frame(out, EMPTY);
                    }
                }
            } else if (len == 1) {
                switch (payload[0] & 0xFF) {
                    case CTRL_POWER_OFF -> {
                        call(executor, () -> powerCycle(isd));
                        powered = false;
                    }
                    case CTRL_POWER_ON -> {
                        if (!powered) {
                            call(executor, () -> powerCycle(isd));
                            powered = true;
                        }
                    }
                    case CTRL_RESET -> {
                        call(executor, () -> powerCycle(isd));
                        powered = true;
                    }
                    case CTRL_GET_ATR -> frame(out, call(executor, () -> isd.card().atr()));
                    default -> {
                        return;
                    }
                }
            } else if (len == 3 && (payload[0] & 0xFF) == CTRL_TEAR) {
                int n = ((payload[1] & 0xFF) << 8) | (payload[2] & 0xFF);
                if (n < 1) {
                    return;
                }
                int armed = n;
                call(
                        executor,
                        () -> {
                            isd.card().tearAt(armed);
                            return null;
                        });
            } else {
                // len 0 or 2, a different 3-byte control: framing error, close
                return;
            }
        }
    }

    private static Void powerCycle(Isd isd) {
        isd.card().powerCycle();
        isd.reset();
        return null;
    }

    /** {@code u16(len) ‖ payload} on the wire. */
    private static void frame(OutputStream out, byte[] payload) throws IOException {
        out.write((payload.length >> 8) & 0xFF);
        out.write(payload.length & 0xFF);
        out.write(payload);
        out.flush();
    }

    private static <T> T call(ExecutorService executor, Callable<T> task) {
        try {
            return executor.submit(task).get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted on the card thread", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException r) {
                throw r;
            }
            if (cause instanceof Error err) {
                throw err;
            }
            throw new IllegalStateException(cause);
        }
    }

    private static Options options(String[] args) {
        int cards = DEFAULT_CARDS;
        int port = DEFAULT_PORT;
        State parsedState = State.BLANK;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--help" -> {
                    usage(System.out);
                    System.exit(0);
                }
                case "--cards" -> cards = number(args, ++i, "--cards");
                case "--port" -> port = number(args, ++i, "--port");
                case "--state" -> {
                    String state = value(args, ++i, "--state");
                    try {
                        parsedState = State.valueOf(state.toUpperCase(Locale.ROOT));
                    } catch (IllegalArgumentException e) {
                        badArguments();
                    }
                }
                default -> badArguments();
            }
        }
        if (cards < 1 || cards > MAX_CARDS || port < 0 || port > 0xFFFF) {
            badArguments();
        }
        return new Options(cards, port, parsedState);
    }

    private static String value(String[] args, int i, String option) {
        if (i >= args.length) {
            badArguments();
        }
        return args[i];
    }

    private static int number(String[] args, int i, String option) {
        try {
            return Integer.parseInt(value(args, i, option));
        } catch (NumberFormatException e) {
            badArguments();
            return -1;
        }
    }

    private static void badArguments() {
        usage(System.err);
        System.exit(2);
    }

    private static void usage(PrintStream out) {
        out.println(
                "usage: card-sim [--cards N] [--port P] [--state empty|factory|blank]\n"
                        + "  --cards N           simulated cards, 1.."
                        + MAX_CARDS
                        + " (default "
                        + DEFAULT_CARDS
                        + ")\n"
                        + "  --port P            first TCP port, card i listens on 127.0.0.1:P+i;\n"
                        + "                      0 gives every card an ephemeral port (default "
                        + DEFAULT_PORT
                        + ")\n"
                        + "  --state empty       only the issuer security domain; no package,\n"
                        + "                      no applets\n"
                        + "  --state factory     applets installed, life FACTORY\n"
                        + "  --state blank       also personalise under the test CA (default)");
    }
}
