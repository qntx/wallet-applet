// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tools;

import apdu4j.core.BIBO;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import org.qntx.card.host.AccessCode;
import org.qntx.card.host.CardNotGenuineException;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Open;
import org.qntx.card.host.Session;
import org.qntx.card.host.SessionBrokenException;
import org.qntx.card.host.TestAnchors;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

/**
 * {@code qntx-card shell}: the debug REPL of architecture.md §11 — open a session, send inner
 * commands or raw outer APDUs, print decoded responses. It never accepts or prints seeds or session
 * keys: {@code inner 21 01 …} (CREATE importing a seed) is refused locally without a transmission.
 * A malformed line is an error printout, not a crash — the REPL continues.
 */
@Command(name = "shell", description = "Debug REPL over the session protocol of §8.")
final class ShellCmd implements Callable<Integer> {

    private final Ctx ctx;

    ShellCmd(Ctx ctx) {
        this.ctx = ctx;
    }

    @Mixin Transport transport;

    @Option(
            names = "--anchor",
            arity = "0..*",
            description = "trusted CA anchor, 65 bytes hex; repeatable")
    List<String> anchors = new ArrayList<>();

    @Option(names = "--test-anchors", description = "trust the ca1/ca2 test anchors")
    boolean testAnchors;

    @Override
    public Integer call() {
        try {
            return run();
        } catch (Exception e) {
            return ctx.fail("shell: " + RegistryCmd.message(e));
        }
    }

    private int run() throws Exception {
        List<byte[]> trust = new ArrayList<>();
        for (String anchor : anchors) {
            byte[] bytes = Apdu.parseHex(anchor.trim());
            if (bytes == null || bytes.length != 65) {
                return ctx.fail("shell: --anchor must be 65 bytes hex");
            }
            trust.add(bytes);
        }
        if (testAnchors) {
            trust.add(TestAnchors.CA1);
            trust.add(TestAnchors.CA2);
        }
        if (trust.isEmpty()) {
            return ctx.fail("shell: no trusted anchor (pass --anchor or --test-anchors)");
        }
        try (Transport t = transport) {
            var bibo = transport.open();
            var lines = new BufferedReader(new InputStreamReader(ctx.in(), StandardCharsets.UTF_8));
            Session session = null;
            String line;
            while ((line = lines.readLine()) != null) {
                String verb = line.trim().split("\\s+", 2)[0];
                if (verb.isEmpty()) {
                    continue;
                }
                try {
                    if (verb.equals("quit")) {
                        return 0;
                    }
                    session = dispatch(bibo, session, trust, line.trim(), verb);
                } catch (IllegalArgumentException | SessionBrokenException e) {
                    ctx.out().println("error: " + e.getMessage());
                }
            }
            return 0;
        }
    }

    /** One REPL line; returns the (possibly new) session. */
    private Session dispatch(
            BIBO bibo, Session session, List<byte[]> trust, String line, String verb)
            throws Exception {
        switch (verb) {
            case "open" -> {
                byte[] select = bibo.transceive(Apdu.SELECT_WALLET);
                if (Apdu.sw(select) != 0x9000) {
                    ctx.out().println("select <- " + Apdu.status(select));
                    return session;
                }
                var request = Open.request(new SecureRandom());
                try {
                    Session opened =
                            Open.response(
                                    request.secret(),
                                    request.apdu(),
                                    bibo.transceive(request.apdu()),
                                    trust);
                    ctx.out()
                            .println(
                                    "open <- 9000 id "
                                            + Apdu.hex(Ids.cardId(opened.identity()))
                                            + " short "
                                            + Ids.shortId(opened.identity()));
                    return opened;
                } catch (CardNotGenuineException e) {
                    ctx.out().println("open <- failed: " + e.getMessage());
                    return session;
                }
            }
            case "verify" -> {
                if (session == null) {
                    ctx.out().println("verify <- no open session");
                } else if (!line.startsWith("verify ")) {
                    ctx.out().println("usage: verify <code>");
                } else {
                    // the rest of the line is the code: printable ASCII 0x20–0x7E, spaces
                    // included (protocol.md §7.1); AccessCode.hash validates the range
                    byte[] hash =
                            AccessCode.hash(
                                    line.substring("verify ".length()),
                                    Ids.cardId(session.identity()));
                    inner(bibo, session, 0x22, 0, 0, hash);
                }
            }
            case "inner" -> {
                if (session == null) {
                    ctx.out().println("inner <- no open session");
                    return session;
                }
                String[] parts = line.split("\\s+");
                if (parts.length < 4 || parts.length > 5) {
                    ctx.out().println("usage: inner <ins> <p1> <p2> [hex]");
                    return session;
                }
                int ins = Integer.parseInt(parts[1], 16);
                int p1 = Integer.parseInt(parts[2], 16);
                int p2 = Integer.parseInt(parts[3], 16);
                // CREATE with an imported seed is refused locally: the tool never accepts seed
                // material on its command line
                if (ins == 0x21 && p1 == 0x01) {
                    ctx.out().println("inner <- refused: CREATE with a seed");
                    return session;
                }
                byte[] data = Apdu.parseHex(parts.length == 5 ? parts[4] : "");
                if (data == null) {
                    ctx.out().println("inner: data is not hex");
                    return session;
                }
                inner(bibo, session, ins, p1, p2, data);
            }
            case "apdu" -> {
                String[] parts = line.split("\\s+");
                if (parts.length != 2) {
                    ctx.out().println("usage: apdu <hex>");
                    return session;
                }
                byte[] command = Apdu.parseHex(parts[1]);
                if (command == null || command.length < 4) {
                    ctx.out().println("apdu: not a hex APDU");
                    return session;
                }
                print(bibo.transceive(command));
            }
            case "help" ->
                    ctx.out()
                            .println(
                                    "open | verify <code> | inner <ins> <p1> <p2> [hex]"
                                            + " | apdu <hex> | quit");
            default -> ctx.out().println("unknown command: " + verb);
        }
        return session;
    }

    private void inner(BIBO bibo, Session session, int ins, int p1, int p2, byte[] data)
            throws Exception {
        byte[] rapdu = bibo.transceive(session.wrap(ins, p1, p2, data));
        var response = session.unwrap(rapdu);
        ctx.out()
                .println(
                        "<- "
                                + String.format("%04X", response.sw())
                                + (response.data().length == 0
                                        ? ""
                                        : " " + Apdu.hex(response.data())));
    }

    private void print(byte[] response) {
        if (response.length < 2) {
            ctx.out().println("<- no response");
            return;
        }
        ctx.out()
                .println(
                        "<- "
                                + Apdu.status(response)
                                + (response.length == 2
                                        ? ""
                                        : " "
                                                + Apdu.hex(
                                                        Arrays.copyOf(
                                                                response, response.length - 2))));
    }
}
