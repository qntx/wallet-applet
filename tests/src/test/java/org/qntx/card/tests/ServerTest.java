// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Ed25519;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Open;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Transfer;
import org.qntx.card.host.WalletInfo;
import org.qntx.card.host.Wei25519Map;
import org.qntx.card.sim.TestCa;

/**
 * {@code card-sim.jar} end to end (architecture.md §14.7 R2): the real jar runs as a subprocess on
 * ephemeral ports and is driven over TCP with a client written here from the documented framing —
 * nothing is shared with the server classes. Covers framing, power and tear controls, and a
 * three-card creation, transfer and Ed25519 signature through the {@code host} codecs.
 */
final class ServerTest {
    private static final String JAR = System.getProperty("qntx.simJar");
    private static final long READY_TIMEOUT_MS = 120_000;

    private static Process process;
    private static final List<String> stdout = new CopyOnWriteArrayList<>();
    private static final List<String> stderr = new CopyOnWriteArrayList<>();
    private static final int[] ports = new int[4];

    /**
     * The wire client, written from the framing table alone: every message is {@code u16(len) ‖
     * payload}; a reply is the same frame. An empty {@code 00 00} frame means no response (power
     * off or a fired tear).
     */
    private static final class Link implements Closeable {
        private final Socket socket;
        private final DataInputStream in;
        private final DataOutputStream out;

        Link(int port) throws IOException {
            socket = new Socket("127.0.0.1", port);
            socket.setSoTimeout(60_000);
            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());
        }

        /** A command APDU frame; returns the R-APDU or an empty array on {@code 00 00}. */
        byte[] transmit(byte[] apdu) throws IOException {
            send(apdu);
            return receive();
        }

        byte[] atr() throws IOException {
            send(new byte[] {0x04});
            return receive();
        }

        void powerOff() throws IOException {
            send(new byte[] {0x00});
        }

        void powerOn() throws IOException {
            send(new byte[] {0x01});
        }

        void reset() throws IOException {
            send(new byte[] {0x02});
        }

        void armTear(int n) throws IOException {
            send(new byte[] {0x10, (byte) (n >> 8), (byte) n});
        }

        private void send(byte[] payload) throws IOException {
            out.writeShort(payload.length);
            out.write(payload);
            out.flush();
        }

        private byte[] receive() throws IOException {
            int len = in.readUnsignedShort();
            return in.readNBytes(len);
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    private static int sw(byte[] rapdu) {
        return ((rapdu[rapdu.length - 2] & 0xFF) << 8) | (rapdu[rapdu.length - 1] & 0xFF);
    }

    /** An inner command inside the session: wrap, transmit, unwrap (§8.3–8.4). */
    private static Response inner(Link link, Session session, int ins, int p1, byte[] data)
            throws Exception {
        return session.unwrap(link.transmit(session.wrap(ins, p1, 0, data)));
    }

    /** SELECT then OPEN; the session is verified against the ca1 anchor. */
    private static Session open(Link link) throws Exception {
        byte[] rapdu = link.transmit(Spec.SELECT);
        assertEquals(0x9000, sw(rapdu), "SELECT wallet");
        Open.Request req = Open.request(Vecs.RND);
        rapdu = link.transmit(req.apdu());
        return Open.response(req.secret(), req.apdu(), rapdu, List.of(TestCa.PUBLIC));
    }

    @BeforeAll
    static void start() throws Exception {
        process = spawn("--port", "0", "--cards", "4");
        Thread out = drain(process.getInputStream(), stdout);
        Thread err = drain(process.getErrorStream(), stderr);
        long deadline = System.currentTimeMillis() + READY_TIMEOUT_MS;
        while (!stdout.contains("ready") && System.currentTimeMillis() < deadline) {
            assertTrue(process.isAlive(), "server died early: " + stderr);
            Thread.sleep(50);
        }
        assertTrue(stdout.contains("ready"), "no ready line within " + READY_TIMEOUT_MS + "ms");
        for (String line : stdout) {
            if (line.startsWith("card ")) {
                String[] parts = line.split(" ");
                int i = Integer.parseInt(parts[1]);
                ports[i] = Integer.parseInt(parts[3]);
            }
        }
        assertEquals(4, stdout.stream().filter(l -> l.startsWith("card ")).count());
        assertEquals(1, stdout.stream().filter(l -> l.startsWith("anchor ")).count());
        int lastCard =
                stdout.lastIndexOf(
                        stdout.stream()
                                .filter(l -> l.startsWith("card "))
                                .reduce((a, b) -> b)
                                .get());
        int anchor =
                stdout.indexOf(
                        stdout.stream().filter(l -> l.startsWith("anchor ")).findFirst().get());
        assertTrue(
                lastCard < anchor && anchor < stdout.indexOf("ready"), "anchor once before ready");
        out.join(10_000);
        err.join(10_000);
    }

    @AfterAll
    static void stop() throws Exception {
        if (process != null) {
            process.destroy();
            process.waitFor(30, TimeUnit.SECONDS);
            process.destroyForcibly();
        }
    }

    private static Process spawn(String... args) throws IOException {
        String java = ProcessHandle.current().info().command().orElseThrow().toString();
        String[] command = new String[args.length + 3];
        command[0] = java;
        command[1] = "-jar";
        command[2] = JAR;
        System.arraycopy(args, 0, command, 3, args.length);
        return new ProcessBuilder(command).start();
    }

    private static Thread drain(java.io.InputStream in, List<String> into) {
        Thread t =
                new Thread(
                        () -> {
                            try (var reader =
                                    new java.io.BufferedReader(
                                            new java.io.InputStreamReader(
                                                    in, StandardCharsets.UTF_8))) {
                                String line;
                                while ((line = reader.readLine()) != null) {
                                    into.add(line);
                                }
                            } catch (IOException e) {
                                // the process is gone; the waiter sees what was collected
                            }
                        },
                        "server-test-drain");
        t.setDaemon(true);
        t.start();
        return t;
    }

    @Test
    void framingAndPowerControls() throws Exception {
        try (Link link = new Link(ports[0])) {
            // get ATR returns the jcardsim ATR
            byte[] atr = link.atr();
            assertTrue(atr.length > 10 && atr[0] == 0x3B, "ATR");
            Session session = open(link);
            assertEquals(0x9000, inner(link, session, 0x20, 0, new byte[0]).sw(), "STATUS record");
            // power off: an APDU gets the empty frame; power on: SELECT works again
            link.powerOff();
            assertEquals(0, link.transmit(Spec.SELECT).length, "unpowered APDU");
            link.powerOn();
            assertEquals(0x9000, sw(link.transmit(Spec.SELECT)), "SELECT after power on");
            // reset ends an open session: the old session's next record is rejected
            session = open(link);
            assertEquals(0x9000, inner(link, session, 0x20, 0, new byte[0]).sw());
            link.reset();
            assertEquals(0x9000, sw(link.transmit(Spec.SELECT)));
            byte[] record = session.wrap(0x20, 0, 0, new byte[0]);
            assertEquals(0x6985, sw(link.transmit(record)), "§13.1: no open session");
            // a malformed frame closes the connection; a new connection works
            link.out.writeShort(2);
            link.out.write(new byte[] {0x55, 0x55});
            link.out.flush();
            assertEquals(-1, link.in.read(), "malformed frame closes the connection");
        }
        try (Link link = new Link(ports[0])) {
            assertEquals(0x9000, sw(link.transmit(Spec.SELECT)), "new connection");
        }
    }

    @Test
    void tornVerifyCountsNoFailure() throws Exception {
        // card 3: create a self-only LOADED wallet, then tear at the first write of a wrong VERIFY
        try (Link link = new Link(ports[3])) {
            Session session = open(link);
            byte[] data = new byte[96];
            System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
            System.arraycopy(Vecs.seed(), 0, data, 32, 64);
            assertEquals(0x9000, inner(link, session, 0x21, 1, data).sw(), "CREATE");
            session = open(link);
            int tries = inner(link, session, 0x20, 0, new byte[0]).data()[1] & 0xFF;
            assertEquals(10, tries, "free of failures");
            link.armTear(1);
            // §9.5: the first persistent write is T-FAIL; tearing it leaves the count untouched
            assertEquals(
                    0,
                    link.transmit(session.wrap(0x22, 0, 0, Vecs.accessHashWrong())).length,
                    "torn VERIFY");
            link.powerOn();
            session = open(link);
            assertEquals(
                    tries,
                    inner(link, session, 0x20, 0, new byte[0]).data()[1] & 0xFF,
                    "the torn T-FAIL was rolled back");
            assertEquals(
                    0x9000,
                    inner(link, session, 0x22, 0, Vecs.accessHash()).sw(),
                    "the right code still verifies");
        }
    }

    @Test
    void threeCardCreationTransferAndSignature() throws Exception {
        try (Link l0 = new Link(ports[0]);
                Link l1 = new Link(ports[1]);
                Link l2 = new Link(ports[2])) {
            Session s0 = open(l0);
            Session s1 = open(l1);
            Session s2 = open(l2);
            byte[] id1 = Ids.cardId(s1.identity());
            byte[] id2 = Ids.cardId(s2.identity());
            // CREATE P1 = 00 on card 0 naming cards 1 and 2 as the other members
            byte[] hostEntropy = new byte[32];
            Vecs.RND.nextBytes(hostEntropy);
            byte[] data = new byte[96];
            System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
            System.arraycopy(hostEntropy, 0, data, 32, 32);
            System.arraycopy(id1, 0, data, 64, 16);
            System.arraycopy(id2, 0, data, 80, 16);
            Response create = inner(l0, s0, 0x21, 0, data);
            assertEquals(0x9000, create.sw(), "CREATE");
            byte[] info = create.data();
            // transfers 0 -> 1 and 0 -> 2 through the host Transfer codecs
            byte[] info1 = receiveFrom(l1, s1, l0, s0, s0.cert(), s1.cert(), Vecs.accessHashNew());
            byte[] info2 = receiveFrom(l2, s2, l0, s0, s0.cert(), s2.cert(), Vecs.accessHashNew());
            assertArrayEquals(info, info1, "card 1 WalletInfo");
            assertArrayEquals(info, info2, "card 2 WalletInfo");
            assertEquals(3, WalletInfo.parse(info).members().size(), "member count");
            // card 2 signs a message larger than one 236-byte record chunk
            assertEquals(
                    0x9000, inner(l2, s2, 0x22, 0, Vecs.accessHashNew()).sw(), "VERIFY on card 2");
            byte[] path = Vecs.pathEdSolana();
            Response pk = inner(l2, s2, 0x30, 1, path);
            assertEquals(0x9000, pk.sw(), "PUBLIC_KEY ed25519");
            byte[] encodedA = Wei25519Map.encode(pk.data());
            Response begin = inner(l2, s2, 0x33, 0, path);
            assertEquals(0x9000, begin.sw(), "begin");
            byte[] encodedR = Wei25519Map.encode(begin.data());
            byte[] message = new byte[500];
            Vecs.RND.nextBytes(message);
            byte[] stream = Ed25519.stream(encodedR, encodedA, message);
            int off = 0;
            while (stream.length - off > 236) {
                byte[] chunk = Arrays.copyOfRange(stream, off, off + 236);
                assertEquals(0x9000, inner(l2, s2, 0x33, 1, chunk).sw(), "update");
                off += 236;
            }
            Response fin = inner(l2, s2, 0x33, 2, Arrays.copyOfRange(stream, off, stream.length));
            assertEquals(0x9000, fin.sw(), "finish");
            byte[] signature = Ed25519.signature(encodedR, fin.data());
            // the independent oracle: BouncyCastle Ed25519Signer over the RFC 8032 key
            Ed25519Signer signer = new Ed25519Signer();
            signer.init(false, new Ed25519PublicKeyParameters(encodedA, 0));
            signer.update(message, 0, message.length);
            assertTrue(signer.verifySignature(signature), "signature verifies");
        }
    }

    /**
     * The §11.2 transfer through the {@link Transfer} codecs: OFFER on the target, VERIFY and
     * EXPORT on the source, IMPORT on the target; the decoders verify the card signatures.
     */
    private static byte[] receiveFrom(
            Link target,
            Session targetSession,
            Link source,
            Session sourceSession,
            byte[] sourceCert,
            byte[] targetCert,
            byte[] accessHashT)
            throws Exception {
        Response offer = inner(target, targetSession, 0x40, 0, new byte[0]);
        assertEquals(0x9000, offer.sw(), "OFFER");
        Transfer.Offer o = Transfer.decodeOffer(offer.data(), targetCert);
        assertEquals(
                0x9000,
                inner(source, sourceSession, 0x22, 0, Vecs.accessHash()).sw(),
                "source VERIFY");
        byte[] export0 = Transfer.export0(targetCert, concat(o.lk(), o.sig()));
        Response head = inner(source, sourceSession, 0x41, 0, export0);
        assertEquals(0x9000, head.sw(), "EXPORT0");
        Transfer.ExportHead h =
                Transfer.decodeExportHead(head.data(), sourceCert, targetCert, o.lk());
        Response payload = inner(source, sourceSession, 0x41, 1, Transfer.export1(accessHashT));
        assertEquals(0x9000, payload.sw(), "EXPORT1");
        Transfer.ExportPayload p = Transfer.decodeExportPayload(payload.data());
        Response i0 =
                inner(
                        target,
                        targetSession,
                        0x42,
                        0,
                        Transfer.import0(sourceCert, concat(h.e(), h.sig())));
        assertEquals(0x9000, i0.sw(), "IMPORT0");
        Response i1 =
                inner(target, targetSession, 0x42, 1, Transfer.import1(concat(p.ct(), p.tag())));
        assertEquals(0x9000, i1.sw(), "IMPORT1");
        return i1.data();
    }

    @Test
    void factoryStateHasNoAnchorAndIdentityIsAvailable() throws Exception {
        List<String> lines = new CopyOnWriteArrayList<>();
        Process factory = spawn("--port", "0", "--cards", "1", "--state", "factory");
        drain(factory.getInputStream(), lines);
        List<String> errors = new CopyOnWriteArrayList<>();
        drain(factory.getErrorStream(), errors);
        try {
            long deadline = System.currentTimeMillis() + READY_TIMEOUT_MS;
            while (!lines.contains("ready") && System.currentTimeMillis() < deadline) {
                assertTrue(factory.isAlive(), "factory server died: " + errors);
                Thread.sleep(50);
            }
            assertTrue(lines.contains("ready"));
            assertFalse(
                    lines.stream().anyMatch(l -> l.startsWith("anchor")),
                    "no anchor line in factory state");
            String cardLine = lines.stream().filter(l -> l.startsWith("card ")).findFirst().get();
            int port = Integer.parseInt(cardLine.split(" ")[3]);
            try (Link link = new Link(port)) {
                assertEquals(0x9000, sw(link.transmit(Spec.SELECT)));
                byte[] rapdu = link.transmit(Spec.hex("80E0000000"));
                assertEquals(35, rapdu.length, "A(33) ‖ 9000");
                assertEquals(0x9000, sw(rapdu));
            }
        } finally {
            factory.destroy();
            factory.waitFor(30, TimeUnit.SECONDS);
            factory.destroyForcibly();
        }
    }

    @Test
    void badArgumentsExitWithUsage() throws Exception {
        Process noCards = spawn("--cards", "0");
        assertTrue(noCards.waitFor(60, TimeUnit.SECONDS));
        assertEquals(2, noCards.exitValue(), "--cards 0");
        Process unknown = spawn("--frobnicate");
        assertTrue(unknown.waitFor(60, TimeUnit.SECONDS));
        assertEquals(2, unknown.exitValue(), "unknown option");
        Process help = spawn("--help");
        assertTrue(help.waitFor(60, TimeUnit.SECONDS));
        assertEquals(0, help.exitValue(), "--help");
    }

    @Test
    void testCaIsCertJsonCa1() {
        Map<String, Object> cert = Vecs.load("cert.json");
        Map<String, Object> ca1 = Vecs.list(cert, "cas").get(0);
        assertEquals(new BigInteger(1, Vecs.hex(ca1, "private")), TestCa.PRIVATE, "ca1 private");
        assertArrayEquals(Vecs.hex(ca1, "public"), TestCa.PUBLIC, "ca1 public");
    }

    private static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] part : parts) {
            len += part.length;
        }
        byte[] out = new byte[len];
        int off = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, off, part.length);
            off += part.length;
        }
        return out;
    }
}
