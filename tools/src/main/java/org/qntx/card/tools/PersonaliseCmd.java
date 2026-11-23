// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tools;

import apdu4j.core.BIBO;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.qntx.card.host.Certificates;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Open;
import org.qntx.card.host.TestAnchors;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import pro.javacard.gp.keys.PlaintextKeys;

/**
 * {@code qntx-card personalise}: protocol.md §14.3 steps 4–10 — initialisation drive and identity
 * read, CA-issued certificate, PERSONALIZE, OPEN verification, registry check, operator short-ID
 * check, ISD key replacement and the batch record. The CA is either a test key file or an HSM key
 * (PKCS#11); secrets never leave their store and are never printed.
 */
@Command(name = "personalise", description = "Personalise a card end to end (§14.3 steps 4-10).")
final class PersonaliseCmd implements Callable<Integer> {

    private static final byte[] GET_CPLC = {
        (byte) 0x80, (byte) 0xCA, (byte) 0x9F, (byte) 0x7F, 0x00
    };

    /**
     * The KVN the replacement keys are stored under in step 8: one above the factory/test KVN 0x30
     * the sim and the batch baseline ship with, so a card still holding 0x30 keys is visibly
     * un-personalised.
     */
    private static final int REPLACED_KEY_VERSION = 0x31;

    private final Ctx ctx;

    PersonaliseCmd(Ctx ctx) {
        this.ctx = ctx;
    }

    @Mixin Transport transport;

    @Option(names = "--scp", required = true, description = "03 or 02-55")
    String scp;

    @Option(names = "--baseline", required = true, description = "admission registry baseline")
    Path baseline;

    @Option(
            names = "--cap-sha256",
            required = true,
            description = "SHA-256 of the CAP the card was loaded with, hex")
    String capSha256;

    @Option(
            names = "--anchor",
            required = true,
            description = "batch CA anchor, uncompressed secp256k1 public key, 65 bytes hex")
    String anchor;

    @Option(
            names = "--batch-record",
            required = true,
            description = "file the JSON batch record is appended to")
    Path batchRecord;

    @ArgGroup(exclusive = true, multiplicity = "1")
    CaSource ca;

    static final class CaSource {
        @Option(
                names = "--test-ca",
                description = "test CA private key file (hex); refuses production anchors")
        Path testCa;

        @ArgGroup(exclusive = false)
        Hsm hsm;
    }

    static final class Hsm {
        @Option(
                names = "--hsm-config",
                required = true,
                description = "SunPKCS11 configuration file")
        Path config;

        @Option(names = "--hsm-key", required = true, description = "key label on the token")
        String key;
    }

    /** The PKCS#11 provider and the labelled private key handle it exposes. */
    private record HsmKey(Provider provider, PrivateKey key) {}

    @Override
    public Integer call() {
        try {
            return run();
        } catch (Exception e) {
            return ctx.fail("personalise: " + RegistryCmd.message(e));
        }
    }

    private int run() throws Exception {
        byte[] anchorBytes;
        try {
            anchorBytes = HexFormat.of().parseHex(anchor.trim());
        } catch (IllegalArgumentException e) {
            return ctx.fail("personalise: --anchor is not hex");
        }
        if (anchorBytes.length != 65) {
            return ctx.fail("personalise: --anchor must be 65 bytes");
        }
        try {
            if (HexFormat.of().parseHex(capSha256.trim()).length != 32) {
                return ctx.fail("personalise: --cap-sha256 must be a SHA-256 hex string");
            }
        } catch (IllegalArgumentException e) {
            return ctx.fail("personalise: --cap-sha256 is not hex");
        }
        // CA checks happen before any card contact (R3): a test key must be a known test CA and
        // match the anchor; production refuses test anchors outright
        BigInteger testKey = null;
        HsmKey hsm = null;
        if (ca.testCa != null) {
            try {
                testKey =
                        new BigInteger(
                                1, HexFormat.of().parseHex(Files.readString(ca.testCa).trim()));
            } catch (IOException | IllegalArgumentException e) {
                return ctx.fail("personalise: cannot read --test-ca key file");
            }
            byte[] caPublic = Crypto.publicKey(testKey);
            if (!TestAnchors.isTest(caPublic)) {
                return ctx.fail("personalise: --test-ca key is not a test CA");
            }
            if (!Arrays.equals(caPublic, anchorBytes)) {
                return ctx.fail("personalise: --anchor does not match the --test-ca key");
            }
        } else {
            if (TestAnchors.isTest(anchorBytes)) {
                return ctx.fail("personalise: production refuses test anchors");
            }
            try {
                hsm = loadHsm(ca.hsm.config, ca.hsm.key);
            } catch (Exception e) {
                return ctx.fail("personalise: HSM setup failed: " + RegistryCmd.message(e));
            }
            if (hsm == null) {
                return ctx.fail(
                        "personalise: no private key labelled '" + ca.hsm.key + "' on the token");
            }
        }

        var baselineLines = RegistryText.read(baseline);
        try (Transport t = transport) {
            var bibo = transport.open();
            // step 4: CPLC of the ISD — explicitly selected, not just the power-up default —
            // then the wallet's identity
            byte[] selectIsd = bibo.transceive(Apdu.SELECT_ISD);
            if (Apdu.sw(selectIsd) != 0x9000) {
                return ctx.fail("personalise: SELECT ISD failed: " + Apdu.status(selectIsd));
            }
            byte[] cplc = getData(bibo.transceive(GET_CPLC));
            if (cplc == null) {
                return ctx.fail("personalise: GET DATA CPLC failed");
            }
            byte[] select = bibo.transceive(Apdu.SELECT_WALLET);
            if (Apdu.sw(select) != 0x9000) {
                return ctx.fail("personalise: SELECT wallet failed: " + Apdu.status(select));
            }
            // step 4 accepts an uninitialised card: the §4.3 drive finishes it before A is read
            byte[] identity;
            try {
                identity = Init.drive(bibo, null);
            } catch (Exception e) {
                return ctx.fail("personalise: initialisation failed: " + RegistryCmd.message(e));
            }
            if (identity.length != 35) {
                return ctx.fail("personalise: GET_IDENTITY refused: " + Apdu.status(identity));
            }
            byte[] a = Arrays.copyOf(identity, 33);
            byte[] cert =
                    ca.testCa != null
                            ? Certificates.issue(testKey, a)
                            : hsmIssue(hsm.provider(), hsm.key(), a);
            // the tool verifies the certificate against the anchor before the card ever sees it
            if (!Certificates.verify(anchorBytes, cert)) {
                return ctx.fail("personalise: issued certificate does not verify under --anchor");
            }

            // step 5 — everything below happens on a personalised card
            byte[] personalize = new byte[5 + 97 + 65];
            personalize[0] = (byte) 0x80;
            personalize[1] = (byte) 0xE2;
            personalize[4] = (byte) 162;
            System.arraycopy(cert, 0, personalize, 5, 97);
            System.arraycopy(anchorBytes, 0, personalize, 102, 65);
            byte[] response = bibo.transceive(personalize);
            if (Apdu.sw(response) != 0x9000) {
                return ctx.fail("personalise: PERSONALIZE failed: " + Apdu.status(response));
            }
            try {
                return finish(bibo, a, anchorBytes, cplc, cert, baselineLines);
            } catch (Exception e) {
                ctx.err()
                        .println("personalise: card is personalised but not finished - quarantine");
                return ctx.fail("personalise: " + RegistryCmd.message(e));
            }
        }
    }

    /**
     * Steps 5 (OPEN) through 9 (batch record). Any failure here leaves a personalised, unfinished
     * card and the caller prints the quarantine line.
     */
    private int finish(
            BIBO bibo,
            byte[] a,
            byte[] anchor,
            byte[] cplc,
            byte[] cert,
            List<String> baselineLines)
            throws Exception {
        byte[] select = bibo.transceive(Apdu.SELECT_WALLET);
        if (Apdu.sw(select) != 0x9000) {
            throw new IllegalStateException("SELECT wallet failed: " + Apdu.status(select));
        }
        var request = Open.request(new SecureRandom());
        byte[] rapdu = bibo.transceive(request.apdu());
        var session = Open.response(request.secret(), request.apdu(), rapdu, List.of(anchor));
        if (!Arrays.equals(Arrays.copyOf(session.cert(), 33), a)) {
            throw new IllegalStateException("OPEN certificate identity differs from GET_IDENTITY");
        }

        // step 6: channel; registry must be the baseline plus exactly the CAP entries
        var gp = Gp.open(bibo, Gp.isdKeys(ctx.env().apply(Gp.ISD_KEY_ENV)), Gp.scp(scp));
        if (!RegistryText.lines(gp.getRegistry()).equals(RegistryText.plusCap(baselineLines))) {
            throw new IllegalStateException("registry is not the baseline plus the CAP");
        }

        // step 7: the operator reads the short ID off the card face; a mismatch stops the run
        // before step 8, so the old ISD keys keep working
        String shortId = Ids.shortId(a);
        ctx.out().println(shortId);
        String typed =
                new BufferedReader(new InputStreamReader(ctx.in(), StandardCharsets.UTF_8))
                        .readLine();
        if (typed == null || !typed.trim().equalsIgnoreCase(shortId)) {
            throw new IllegalStateException("short ID does not match");
        }

        // step 8: three independent fresh keys replace ENC/MAC/DEK at the post-personalisation
        // KVN; the card checks the KCVs. The bytes live only until putKeys returns, never
        // stored or printed.
        byte[] enc = new byte[16];
        byte[] mac = new byte[16];
        byte[] dek = new byte[16];
        try {
            var random = new SecureRandom();
            random.nextBytes(enc);
            random.nextBytes(mac);
            random.nextBytes(dek);
            gp.putKeys(
                    PlaintextKeys.fromBytes(enc, mac, dek, null, null, null, REPLACED_KEY_VERSION)
                            .orElseThrow(),
                    true);
        } finally {
            Arrays.fill(enc, (byte) 0);
            Arrays.fill(mac, (byte) 0);
            Arrays.fill(dek, (byte) 0);
        }

        // step 9: one JSON record line
        String record =
                "{\"cardId\":\""
                        + HexFormat.of().formatHex(Ids.cardId(a))
                        + "\",\"shortId\":\""
                        + shortId
                        + "\",\"cplc\":\""
                        + HexFormat.of().formatHex(cplc)
                        + "\",\"cert\":\""
                        + HexFormat.of().formatHex(cert)
                        + "\",\"loadFileHash\":\""
                        + capSha256.trim().toLowerCase(Locale.ROOT)
                        + "\"}";
        Files.writeString(
                batchRecord,
                record + "\n",
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND);
        ctx.out().println("recorded " + shortId);
        return 0;
    }

    /**
     * {@code r ‖ s} over {@code "qntx-card/v1/cert" ‖ A} signed by the token's key: SunPKCS11
     * cannot multi-part-sign ECDSA (measured, evidence/pkcs11-secp256k1.txt), so the SHA-256 digest
     * is produced in software and sent through {@code NONEwithECDSA}.
     */
    private static byte[] hsmIssue(Provider p11, PrivateKey key, byte[] a) throws Exception {
        byte[] digest = Crypto.sha256(Certificates.LABEL_CERT, a);
        Signature signer = Signature.getInstance("NONEwithECDSA", p11);
        signer.initSign(key);
        signer.update(digest);
        ASN1Sequence seq = ASN1Sequence.getInstance(signer.sign());
        byte[] r = fixed32(ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
        byte[] s = fixed32(ASN1Integer.getInstance(seq.getObjectAt(1)).getValue());
        byte[] cert = new byte[97];
        System.arraycopy(a, 0, cert, 0, 33);
        System.arraycopy(r, 0, cert, 33, 32);
        System.arraycopy(s, 0, cert, 65, 32);
        return cert;
    }

    /**
     * Open the configured token and fetch the labelled private key; PIN comes from {@code
     * QNTX_HSM_PIN}. Returns {@code null} when the label resolves to no private key;
     * provider/keystore failures propagate so the caller can report the reason.
     */
    private HsmKey loadHsm(Path config, String label) throws Exception {
        String pin = ctx.env().apply("QNTX_HSM_PIN");
        Provider p11 = Security.getProvider("SunPKCS11").configure(config.toString());
        Security.addProvider(p11);
        KeyStore store = KeyStore.getInstance("PKCS11", p11);
        store.load(null, pin == null ? new char[0] : pin.toCharArray());
        return store.getKey(label, null) instanceof PrivateKey key ? new HsmKey(p11, key) : null;
    }

    private static byte[] fixed32(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        System.arraycopy(
                raw,
                Math.max(0, raw.length - 32),
                out,
                Math.max(0, 32 - raw.length),
                Math.min(raw.length, 32));
        return out;
    }

    /** {@code 9F7F 2A ‖ 42 bytes ‖ 9000} exactly, or {@code null}. */
    private static byte[] getData(byte[] response) {
        if (response == null
                || response.length != 3 + 42 + 2
                || Apdu.sw(response) != 0x9000
                || (response[0] & 0xFF) != 0x9F
                || (response[1] & 0xFF) != 0x7F
                || (response[2] & 0xFF) != 0x2A) {
            return null;
        }
        return Arrays.copyOfRange(response, 3, 45);
    }
}
