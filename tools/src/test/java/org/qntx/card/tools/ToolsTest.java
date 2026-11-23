// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.qntx.card.host.Certificates;
import org.qntx.card.host.Open;
import org.qntx.card.host.TestAnchors;

/**
 * {@code qntx-card} against the real {@code card-sim.jar} (architecture.md §11, brief R3): the CLI
 * runs in-process with an environment seam and piped streams; the card is a real simulator
 * subprocess reached over the vpcd-framing transport — the same path production uses.
 */
class ToolsTest {

    private static final String JAR = System.getProperty("qntx.simJar");
    private static final Path CAP = Path.of(System.getProperty("qntx.cap"));
    private static final Path VECTORS = Path.of(System.getProperty("qntx.vectors"));
    private static final HexFormat HEX = HexFormat.of();
    private static final String ISD_KEY = "404142434445464748494A4B4C4D4E4F";
    private static final byte[] NDEF = HEX.parseHex("D1010C5402656E716E74782063617264");
    private static final Pattern SHORT_ID = Pattern.compile("[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}");

    private static final Map<String, String> ENV = Map.of(Gp.ISD_KEY_ENV, ISD_KEY);

    @TempDir Path dir;

    private record Run(int exit, String out, String err) {}

    /** A {@code card-sim.jar} subprocess; {@link #close} kills it. */
    private static final class Sim implements AutoCloseable {
        private final Process process;
        final int port;

        Sim(String state) throws IOException {
            String java = ProcessHandle.current().info().command().orElseThrow().toString();
            process =
                    new ProcessBuilder(
                                    java, "-jar", JAR, "--state", state, "--cards", "1", "--port",
                                    "0")
                            .start();
            try {
                var reader =
                        new BufferedReader(
                                new InputStreamReader(
                                        process.getInputStream(), StandardCharsets.UTF_8));
                String line;
                int found = -1;
                long deadline = System.currentTimeMillis() + 30_000;
                while (System.currentTimeMillis() < deadline) {
                    line = reader.readLine();
                    if (line == null) {
                        break;
                    }
                    if (line.startsWith("card ") && line.contains(" port ")) {
                        String[] words = line.split(" ");
                        for (int i = 0; i + 1 < words.length; i++) {
                            if (words[i].equals("port")) {
                                found = Integer.parseInt(words[i + 1]);
                            }
                        }
                    }
                    if (line.equals("ready")) {
                        break;
                    }
                }
                if (found < 0) {
                    throw new IOException("card-sim printed no port");
                }
                port = found;
            } catch (IOException | RuntimeException e) {
                process.destroyForcibly();
                throw e;
            }
        }

        String sim() {
            return "127.0.0.1:" + port;
        }

        @Override
        public void close() {
            process.destroy();
            try {
                process.waitFor(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            process.destroyForcibly();
        }
    }

    private Run cli(Map<String, String> env, String stdin, String... args) {
        var out = new ByteArrayOutputStream();
        var err = new ByteArrayOutputStream();
        int code =
                Main.run(
                        args,
                        env::get,
                        new ByteArrayInputStream(stdin.getBytes(StandardCharsets.UTF_8)),
                        new PrintStream(out),
                        new PrintStream(err));
        return new Run(
                code, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }

    /**
     * CLI with piped streams: every line the tool prints goes through {@code responder}; a non-null
     * return value is written to the tool's stdin. Used for the §14.3 step-7 short-ID read-back,
     * which can only be typed after the tool prints it.
     */
    private Run cliRespond(
            Map<String, String> env, Function<String, String> responder, String... args)
            throws Exception {
        var stdin = new PipedInputStream();
        var stdinWrite = new PipedOutputStream(stdin);
        var stdout = new PipedInputStream();
        var stdoutWrite =
                new PrintStream(new PipedOutputStream(stdout), true, StandardCharsets.UTF_8);
        var stderr = new ByteArrayOutputStream();
        var code = new AtomicInteger(-1);
        Thread thread =
                new Thread(
                        () -> {
                            try {
                                code.set(
                                        Main.run(
                                                args,
                                                env::get,
                                                stdin,
                                                stdoutWrite,
                                                new PrintStream(stderr)));
                            } finally {
                                stdoutWrite.close();
                            }
                        },
                        "cli");
        thread.start();
        var out = new StringBuilder();
        var reader = new BufferedReader(new InputStreamReader(stdout, StandardCharsets.UTF_8));
        String line;
        while ((line = reader.readLine()) != null) {
            out.append(line).append('\n');
            String reply = responder.apply(line);
            if (reply != null) {
                stdinWrite.write((reply + "\n").getBytes(StandardCharsets.UTF_8));
                stdinWrite.flush();
            }
        }
        thread.join(30_000);
        return new Run(code.get(), out.toString(), stderr.toString(StandardCharsets.UTF_8));
    }

    private Path baseline(Sim sim) throws IOException {
        Run r = cli(ENV, "", "registry", "--sim", sim.sim(), "--scp", "03");
        assertEquals(0, r.exit(), r.err());
        Path file = dir.resolve("baseline.txt");
        Files.writeString(file, r.out());
        return file;
    }

    private Path keyFile(String privateHex) throws IOException {
        Path file = dir.resolve("ca.hex");
        Files.writeString(file, privateHex);
        return file;
    }

    private static String caPrivate(int index) throws IOException {
        String text = Files.readString(VECTORS.resolve("cert.json"));
        List<String> privates = new ArrayList<>();
        for (String line : text.split("\"")) {
            if (line.matches("[0-9a-f]{64}") && !privates.contains(line)) {
                privates.add(line);
            }
        }
        return privates.get(index);
    }

    private String capHash() throws Exception {
        return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(CAP)));
    }

    private int install(Sim sim, Path baselineFile) {
        return cli(
                        ENV,
                        "",
                        "install",
                        "--sim",
                        sim.sim(),
                        "--cap",
                        CAP.toString(),
                        "--cap-sha256",
                        uncheckedCapHash(),
                        "--scp",
                        "03",
                        "--baseline",
                        baselineFile.toString(),
                        "--ndef",
                        HEX.formatHex(NDEF))
                .exit();
    }

    private String uncheckedCapHash() {
        try {
            return capHash();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Exchange a chain of raw APDUs over the vpcd framing and return the last response; the wallet
     * applet is selected first.
     */
    private static byte[] apdu(String sim, byte[]... commands) throws IOException {
        byte[] wallet = {
            0x00,
            (byte) 0xA4,
            0x04,
            0x00,
            0x07,
            (byte) 0xF0,
            0x71,
            0x6E,
            0x74,
            0x78,
            0x01,
            0x01,
            0x00
        };
        byte[][] chain = new byte[commands.length + 1][];
        chain[0] = wallet;
        System.arraycopy(commands, 0, chain, 1, commands.length);
        try (Socket socket = new Socket()) {
            socket.connect(
                    new java.net.InetSocketAddress(
                            sim.split(":")[0], Integer.parseInt(sim.split(":")[1])),
                    10_000);
            var out = socket.getOutputStream();
            var in = socket.getInputStream();
            byte[] response = null;
            for (byte[] c : chain) {
                out.write((c.length >>> 8) & 0xFF);
                out.write(c.length & 0xFF);
                out.write(c);
                out.flush();
                int hi = in.read();
                int lo = in.read();
                int len = (hi << 8) | lo;
                response = in.readNBytes(len);
            }
            return response;
        }
    }

    private static int sw(byte[] response) {
        return (response[response.length - 2] & 0xFF) << 8 | response[response.length - 1] & 0xFF;
    }

    @Test
    void registryOnEmptyShowsIsdOnly() throws Exception {
        try (Sim sim = new Sim("empty")) {
            Run r = cli(ENV, "", "registry", "--sim", sim.sim(), "--scp", "03");
            assertEquals(0, r.exit(), r.err());
            assertEquals("ISD A000000151000000 01\n", r.out());
        }
    }

    @Test
    void installThenRegistryIsBaselinePlusThree() throws Exception {
        try (Sim sim = new Sim("empty")) {
            Path b = baseline(sim);
            assertEquals(0, install(sim, b));
            Run r = cli(ENV, "", "registry", "--sim", sim.sim(), "--scp", "03");
            assertEquals(
                    "APP D2760000850101 07\n"
                            + "APP F0716E74780101 07\n"
                            + "ISD A000000151000000 01\n"
                            + "PKG F0716E747800 01\n",
                    r.out());
        }
    }

    @Test
    void installRefusals() throws Exception {
        try (Sim sim = new Sim("empty")) {
            Path b = baseline(sim);
            // wrong --cap-sha256 is refused before any card contact
            Run r =
                    cli(
                            ENV,
                            "",
                            "install",
                            "--sim",
                            sim.sim(),
                            "--cap",
                            CAP.toString(),
                            "--cap-sha256",
                            "00".repeat(32),
                            "--scp",
                            "03",
                            "--baseline",
                            b.toString(),
                            "--ndef",
                            HEX.formatHex(NDEF));
            assertNotEquals(0, r.exit());
            // NDEF 0 and 101 bytes
            r =
                    cli(
                            ENV,
                            "",
                            "install",
                            "--sim",
                            sim.sim(),
                            "--cap",
                            CAP.toString(),
                            "--cap-sha256",
                            capHash(),
                            "--scp",
                            "03",
                            "--baseline",
                            b.toString(),
                            "--ndef",
                            "");
            assertNotEquals(0, r.exit());
            r =
                    cli(
                            ENV,
                            "",
                            "install",
                            "--sim",
                            sim.sim(),
                            "--cap",
                            CAP.toString(),
                            "--cap-sha256",
                            capHash(),
                            "--scp",
                            "03",
                            "--baseline",
                            b.toString(),
                            "--ndef",
                            "AA".repeat(101));
            assertNotEquals(0, r.exit());
            // SCP02 against the SCP03-only sim
            r =
                    cli(
                            ENV,
                            "",
                            "install",
                            "--sim",
                            sim.sim(),
                            "--cap",
                            CAP.toString(),
                            "--cap-sha256",
                            capHash(),
                            "--scp",
                            "02-55",
                            "--baseline",
                            b.toString(),
                            "--ndef",
                            HEX.formatHex(NDEF));
            assertNotEquals(0, r.exit());
            // wrong ISD key
            var wrongKey = new TreeMap<>(ENV);
            wrongKey.put(Gp.ISD_KEY_ENV, "41".repeat(16));
            r =
                    cli(
                            wrongKey,
                            "",
                            "install",
                            "--sim",
                            sim.sim(),
                            "--cap",
                            CAP.toString(),
                            "--cap-sha256",
                            capHash(),
                            "--scp",
                            "03",
                            "--baseline",
                            b.toString(),
                            "--ndef",
                            HEX.formatHex(NDEF));
            assertNotEquals(0, r.exit());
        }
    }

    @Test
    void tlvLookingNdefIsDeliveredWhole() throws Exception {
        // an NDEF message that itself parses as TLV with a C9 tag must still be wrapped: without
        // the explicit C9 encoding the card would see only AA (the C9 content)
        try (Sim sim = new Sim("empty")) {
            Path b = baseline(sim);
            Run r =
                    cli(
                            ENV,
                            "",
                            "install",
                            "--sim",
                            sim.sim(),
                            "--cap",
                            CAP.toString(),
                            "--cap-sha256",
                            capHash(),
                            "--scp",
                            "03",
                            "--baseline",
                            b.toString(),
                            "--ndef",
                            "C901AA");
            assertEquals(0, r.exit(), r.err());
            byte[] selectNdef = HEX.parseHex("00A4040007D276000085010100");
            byte[] selectFile = HEX.parseHex("00A4000C02E104");
            byte[] readBinary = HEX.parseHex("00B0000005");
            byte[] response = apdu(sim.sim(), selectNdef, selectFile, readBinary);
            assertEquals("0003c901aa", HEX.formatHex(Arrays.copyOf(response, response.length - 2)));
            assertEquals(0x9000, sw(response));
        }
    }

    @Test
    void duplicateInstallLeavesRegistryUnchanged() throws Exception {
        try (Sim sim = new Sim("empty")) {
            Path b = baseline(sim);
            assertEquals(0, install(sim, b));
            Run r =
                    cli(
                            ENV,
                            "",
                            "install",
                            "--sim",
                            sim.sim(),
                            "--cap",
                            CAP.toString(),
                            "--cap-sha256",
                            capHash(),
                            "--scp",
                            "03",
                            "--baseline",
                            b.toString(),
                            "--ndef",
                            HEX.formatHex(NDEF));
            assertNotEquals(0, r.exit());
            assertEquals(
                    "APP D2760000850101 07\n"
                            + "APP F0716E74780101 07\n"
                            + "ISD A000000151000000 01\n"
                            + "PKG F0716E747800 01\n",
                    cli(ENV, "", "registry", "--sim", sim.sim(), "--scp", "03").out());
        }
    }

    @Test
    void personaliseTestCaEndToEnd() throws Exception {
        try (Sim sim = new Sim("empty")) {
            Path b = baseline(sim);
            assertEquals(0, install(sim, b));
            Path record = dir.resolve("batch.jsonl");
            Run r =
                    cliRespond(
                            ENV,
                            line -> SHORT_ID.matcher(line).matches() ? line : null,
                            "personalise",
                            "--sim",
                            sim.sim(),
                            "--scp",
                            "03",
                            "--baseline",
                            b.toString(),
                            "--cap-sha256",
                            capHash(),
                            "--anchor",
                            HEX.formatHex(TestAnchors.CA1),
                            "--batch-record",
                            record.toString(),
                            "--test-ca",
                            keyFile(caPrivate(0)).toString());
            assertEquals(0, r.exit(), r.err() + r.out());
            String json = Files.readString(record).trim();
            byte[] cardId = HEX.parseHex(field(json, "cardId"));
            assertEquals(16, cardId.length);
            assertTrue(SHORT_ID.matcher(field(json, "shortId")).matches());
            byte[] cplc = HEX.parseHex(field(json, "cplc"));
            assertEquals(42, cplc.length);
            byte[] cert = HEX.parseHex(field(json, "cert"));
            assertTrue(Certificates.verify(TestAnchors.CA1, cert), "cert under ca1");
            assertEquals(capHash(), field(json, "loadFileHash"));
            // A of the cert corresponds to the recorded card ID
            assertEquals(
                    HEX.formatHex(cardId),
                    HEX.formatHex(org.qntx.card.host.Ids.cardId(Arrays.copyOf(cert, 33))));
            // afterwards GET_IDENTITY is refused (life ≥ BLANK)
            byte[] identity = apdu(sim.sim(), HEX.parseHex("80E0000000"));
            assertEquals(0x6985, sw(identity));
            // OPEN works under ca1
            var request = Open.request(new java.security.SecureRandom());
            byte[] open = apdu(sim.sim(), request.apdu());
            var session =
                    Open.response(request.secret(), request.apdu(), open, List.of(TestAnchors.CA1));
            assertTrue(Arrays.equals(session.identity(), Arrays.copyOf(cert, 33)));
            // the ISD key was replaced: the old one no longer opens a channel
            Run r2 = cli(ENV, "", "registry", "--sim", sim.sim(), "--scp", "03");
            assertNotEquals(0, r2.exit());
        }
    }

    @Test
    void personaliseRefusalsBeforeCardContact() throws Exception {
        try (Sim sim = new Sim("empty")) {
            Path b = baseline(sim);
            assertEquals(0, install(sim, b));
            Path record = dir.resolve("batch.jsonl");
            // --test-ca with a key that is not a test CA
            Run r =
                    cli(
                            ENV,
                            "",
                            "personalise",
                            "--sim",
                            sim.sim(),
                            "--scp",
                            "03",
                            "--baseline",
                            b.toString(),
                            "--cap-sha256",
                            capHash(),
                            "--anchor",
                            HEX.formatHex(TestAnchors.CA1),
                            "--batch-record",
                            record.toString(),
                            "--test-ca",
                            keyFile("42".repeat(32)).toString());
            assertNotEquals(0, r.exit());
            // --test-ca ca1 with --anchor ca2
            r =
                    cli(
                            ENV,
                            "",
                            "personalise",
                            "--sim",
                            sim.sim(),
                            "--scp",
                            "03",
                            "--baseline",
                            b.toString(),
                            "--cap-sha256",
                            capHash(),
                            "--anchor",
                            HEX.formatHex(TestAnchors.CA2),
                            "--batch-record",
                            record.toString(),
                            "--test-ca",
                            keyFile(caPrivate(0)).toString());
            assertNotEquals(0, r.exit());
            // production mode (HSM source) with a test anchor
            r =
                    cli(
                            ENV,
                            "",
                            "personalise",
                            "--sim",
                            sim.sim(),
                            "--scp",
                            "03",
                            "--baseline",
                            b.toString(),
                            "--cap-sha256",
                            capHash(),
                            "--anchor",
                            HEX.formatHex(TestAnchors.CA1),
                            "--batch-record",
                            record.toString(),
                            "--hsm-config",
                            dir.resolve("nohsm.cfg").toString(),
                            "--hsm-key",
                            "ca");
            assertNotEquals(0, r.exit());
        }
    }

    @Test
    void wrongShortIdAbortsBeforeKeyRotation() throws Exception {
        try (Sim sim = new Sim("empty")) {
            Path b = baseline(sim);
            assertEquals(0, install(sim, b));
            Path record = dir.resolve("batch.jsonl");
            Run r =
                    cliRespond(
                            ENV,
                            line -> SHORT_ID.matcher(line).matches() ? "FFFF-FFFF" : null,
                            "personalise",
                            "--sim",
                            sim.sim(),
                            "--scp",
                            "03",
                            "--baseline",
                            b.toString(),
                            "--cap-sha256",
                            capHash(),
                            "--anchor",
                            HEX.formatHex(TestAnchors.CA1),
                            "--batch-record",
                            record.toString(),
                            "--test-ca",
                            keyFile(caPrivate(0)).toString());
            assertNotEquals(0, r.exit());
            // step 8 was not reached: the old ISD key still opens the channel
            Run r2 = cli(ENV, "", "registry", "--sim", sim.sim(), "--scp", "03");
            assertEquals(0, r2.exit(), r2.err());
        }
    }

    @Test
    void alreadyPersonalisedRefused() throws Exception {
        try (Sim sim = new Sim("blank")) {
            Path record = dir.resolve("batch.jsonl");
            Run r =
                    cli(
                            ENV,
                            "",
                            "personalise",
                            "--sim",
                            sim.sim(),
                            "--scp",
                            "03",
                            "--baseline",
                            dir.resolve("b.txt").toString(),
                            "--cap-sha256",
                            capHash(),
                            "--anchor",
                            HEX.formatHex(TestAnchors.CA1),
                            "--batch-record",
                            record.toString(),
                            "--test-ca",
                            keyFile(caPrivate(0)).toString());
            assertNotEquals(0, r.exit());
        }
    }

    @Test
    void shellSessionAndLocalRefusals() throws Exception {
        try (Sim sim = new Sim("blank")) {
            String script = "open\ninner 20 00 zz\ninner 20 00 00\ninner 21 01 00 41\nquit\n";
            Run r = cli(ENV, script, "shell", "--sim", sim.sim(), "--test-anchors");
            assertEquals(0, r.exit(), r.err());
            assertTrue(r.out().contains("open <- 9000 id "), r.out());
            assertTrue(r.out().contains("error: "), r.out());
            assertTrue(r.out().contains("<- 9000"), r.out());
            assertTrue(r.out().contains("inner <- refused: CREATE with a seed"), r.out());
        }
    }

    @Test
    void hsmPersonalise() throws Exception {
        String lib = System.getenv("QNTX_SOFTHSM_LIB");
        assumeTrue(
                lib != null && Files.exists(Path.of(lib)),
                "SoftHSM library not provisioned (QNTX_SOFTHSM_LIB)");
        assumeTrue(
                onPath("softhsm2-util") && onPath("openssl"), "softhsm2-util/openssl not on PATH");
        // provision a token + secp256k1 keypair + self-signed cert via the default config
        String label = "qntx-hsm-test-" + ProcessHandle.current().pid();
        try (Sim sim = new Sim("empty")) {
            Path keyPem = dir.resolve("hsm-key.pem");
            Path certPem = dir.resolve("hsm-cert.pem");
            run0(
                    "softhsm2-util",
                    "--init-token",
                    "--free",
                    "--label",
                    label,
                    "--pin",
                    "1234",
                    "--so-pin",
                    "5678");
            run0(
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "EC",
                    "-pkeyopt",
                    "ec_paramgen_curve:secp256k1",
                    "-out",
                    keyPem.toString());
            run0(
                    "openssl",
                    "pkcs8",
                    "-topk8",
                    "-nocrypt",
                    "-in",
                    keyPem.toString(),
                    "-out",
                    keyPem.toString() + ".p8");
            run0(
                    "softhsm2-util",
                    "--import",
                    keyPem + ".p8",
                    "--token",
                    label,
                    "--label",
                    "ca",
                    "--id",
                    "01",
                    "--pin",
                    "1234");
            run0(
                    "openssl",
                    "req",
                    "-x509",
                    "-new",
                    "-key",
                    keyPem.toString(),
                    "-subj",
                    "/CN=qntx-hsm-test",
                    "-days",
                    "1",
                    "-out",
                    certPem.toString());
            run0(
                    "softhsm2-util",
                    "--import",
                    certPem.toString(),
                    "--import-type",
                    "cert",
                    "--token",
                    label,
                    "--label",
                    "ca",
                    "--id",
                    "01",
                    "--pin",
                    "1234");
            int slot = hsmSlot(label);
            Path cfg = dir.resolve("sunpkcs11.cfg");
            Files.writeString(
                    cfg, "name = SoftHSM\nlibrary = " + lib + "\nslotListIndex = " + slot + "\n");
            byte[] anchor = hsmAnchor(certPem);
            Map<String, String> env = Map.of(Gp.ISD_KEY_ENV, ISD_KEY, "QNTX_HSM_PIN", "1234");
            try {
                Path b = baseline(sim);
                assertEquals(0, install(sim, b));
                Path record = dir.resolve("batch.jsonl");
                Run r =
                        cliRespond(
                                env,
                                line -> SHORT_ID.matcher(line).matches() ? line : null,
                                "personalise",
                                "--sim",
                                sim.sim(),
                                "--scp",
                                "03",
                                "--baseline",
                                b.toString(),
                                "--cap-sha256",
                                capHash(),
                                "--anchor",
                                HEX.formatHex(anchor),
                                "--batch-record",
                                record.toString(),
                                "--hsm-config",
                                cfg.toString(),
                                "--hsm-key",
                                "ca");
                assertEquals(0, r.exit(), r.err() + r.out());
            } finally {
                runQuiet("softhsm2-util", "--delete-token", "--token", label);
            }
        }
    }

    /** Index of the token labelled {@code label} in {@code --show-slots} order. */
    private int hsmSlot(String label) throws Exception {
        var out = new StringBuilder();
        run0(out, "softhsm2-util", "--show-slots");
        int index = 0;
        for (String line : out.toString().lines().toList()) {
            if (line.startsWith("Slot ")) {
                index++;
            } else if (line.contains("Label:") && line.contains(label)) {
                return index - 1;
            }
        }
        throw new IllegalStateException("token " + label + " not found in --show-slots");
    }

    private byte[] hsmAnchor(Path certPem) throws Exception {
        // the CA public key, uncompressed: openssl writes it in the cert we just made
        var out = new StringBuilder();
        run0(out, "openssl", "x509", "-in", certPem.toString(), "-pubkey", "-noout");
        Path pubPem = dir.resolve("pub.pem");
        Path pubDer = dir.resolve("pub.der");
        Files.writeString(pubPem, out.toString());
        run0(
                "openssl",
                "pkey",
                "-pubin",
                "-pubout",
                "-outform",
                "DER",
                "-in",
                pubPem.toString(),
                "-out",
                pubDer.toString());
        byte[] der = Files.readAllBytes(pubDer);
        // SPKI for secp256k1 ends with the 65-byte uncompressed point
        return Arrays.copyOfRange(der, der.length - 65, der.length);
    }

    private static String field(String json, String name) {
        int i = json.indexOf("\"" + name + "\":\"");
        if (i < 0) {
            throw new IllegalStateException(name + " missing in " + json);
        }
        int start = i + name.length() + 4;
        return json.substring(start, json.indexOf('"', start));
    }

    private static boolean onPath(String tool) {
        return Arrays.stream(System.getenv("PATH").split(":"))
                .anyMatch(d -> Files.isExecutable(Path.of(d, tool)));
    }

    private static void run0(String... cmd) throws Exception {
        run0(new StringBuilder(), cmd);
    }

    private static void run0(StringBuilder out, String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String text = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (p.waitFor() != 0) {
            throw new IllegalStateException(String.join(" ", cmd) + " -> " + text);
        }
        out.append(text);
    }

    private static void runQuiet(String... cmd) {
        runQuiet(new StringBuilder(), cmd);
    }

    private static void runQuiet(StringBuilder out, String... cmd) {
        try {
            run0(out, cmd);
        } catch (Exception ignored) {
        }
    }
}
