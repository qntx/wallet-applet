// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * {@link Transfer} command encoders and response decoders against BouncyCastle-made cards: the
 * identities, link keys and signatures are produced with {@link Crypto}, never by the applet.
 */
final class TransferTest {
    private static final SecureRandom RND = new SecureRandom();

    private static BigInteger scalar() {
        BigInteger s;
        do {
            s = new BigInteger(256, RND);
        } while (s.signum() == 0 || s.compareTo(Crypto.N) >= 0);
        return s;
    }

    /** A made-up card: identity scalar, compressed {@code A} and certificate. */
    private static BigInteger idPrivate = scalar();

    private static final byte[] A = Crypto.compress(Crypto.publicKey(idPrivate));
    private static final byte[] CERT = Certificates.issue(new BigInteger("7"), A);

    private static byte[] offerResponse(BigInteger linkPrivate) {
        byte[] lk = Crypto.publicKey(linkPrivate);
        byte[] sig = Crypto.sign(idPrivate, Crypto.sha256(concat(Transfer.LABEL_OFFER, lk)));
        return concat(lk, sig);
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    @Test
    void encodersProduceTheSpecLayout() {
        assertEquals(0, Transfer.offer().length);
        byte[] cert = new byte[97];
        byte[] offer = new byte[129];
        byte[] head = new byte[129];
        byte[] data = Transfer.export0(cert, offer);
        assertEquals(226, data.length);
        assertArrayEquals(cert, Arrays.copyOf(data, 97));
        assertArrayEquals(offer, Arrays.copyOfRange(data, 97, 226));
        data = Transfer.import0(cert, head);
        assertEquals(226, data.length);
        assertArrayEquals(head, Arrays.copyOfRange(data, 97, 226));
        byte[] h = new byte[32];
        assertArrayEquals(h, Transfer.export1(h));
        byte[] payload = new byte[176];
        assertArrayEquals(payload, Transfer.import1(payload));
        assertThrows(IllegalArgumentException.class, () -> Transfer.import1(new byte[159]));
        assertThrows(IllegalArgumentException.class, () -> Transfer.export1(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> Transfer.export0(new byte[96], offer));
    }

    @Test
    void decodeOfferVerifiesTheSignature() throws Exception {
        byte[] resp = offerResponse(scalar());
        Transfer.Offer o = Transfer.decodeOffer(resp, CERT);
        assertArrayEquals(Arrays.copyOf(resp, 65), o.lk());
        assertArrayEquals(Arrays.copyOfRange(resp, 65, 129), o.sig());
    }

    @Test
    void decodeOfferRejectsTampering() {
        byte[] resp = offerResponse(scalar());
        byte[] bad = resp.clone();
        bad[128] ^= 1;
        assertThrows(CardNotGenuineException.class, () -> Transfer.decodeOffer(bad, CERT));
        byte[] shortResp = Arrays.copyOf(resp, 128);
        assertThrows(CardNotGenuineException.class, () -> Transfer.decodeOffer(shortResp, CERT));
        // a signature under another identity
        byte[] lk = Crypto.publicKey(scalar());
        byte[] foreignSig = Crypto.sign(scalar(), Crypto.sha256(concat(Transfer.LABEL_OFFER, lk)));
        assertThrows(
                CardNotGenuineException.class,
                () -> Transfer.decodeOffer(concat(lk, foreignSig), CERT));
    }

    @Test
    void decodeExportHeadVerifiesTheTranscript() throws Exception {
        byte[] e = Crypto.publicKey(scalar());
        byte[] lkT = Crypto.publicKey(scalar());
        byte[] m = concat(Transfer.LABEL_EXPORT, A, Arrays.copyOf(CERT, 33), lkT, e);
        byte[] sig = Crypto.sign(idPrivate, Crypto.sha256(m));
        Transfer.ExportHead head = Transfer.decodeExportHead(concat(e, sig), CERT, CERT, lkT);
        assertArrayEquals(e, head.e());
        assertArrayEquals(sig, head.sig());
    }

    @Test
    void decodeExportHeadRejectsAWrongMessage() {
        byte[] e = Crypto.publicKey(scalar());
        byte[] lkT = Crypto.publicKey(scalar());
        byte[] otherLk = Crypto.publicKey(scalar());
        // signed for a different link key than the one presented
        byte[] m = concat(Transfer.LABEL_EXPORT, A, Arrays.copyOf(CERT, 33), otherLk, e);
        byte[] sig = Crypto.sign(idPrivate, Crypto.sha256(m));
        assertThrows(
                CardNotGenuineException.class,
                () -> Transfer.decodeExportHead(concat(e, sig), CERT, CERT, lkT));
    }

    /**
     * {@code spec/vectors/transfer.json} (§18): every {@code transfers} row decodes under the
     * cards' certificates and re-encodes to the §9.13–9.14 inner data bytes, and the check-5
     * rejection rows whose certificate is the transfer's own target/source fail the signature check
     * of {@link Transfer#decodeOffer}/{@link Transfer#decodeExportHead}.
     */
    @Test
    void transferVectorRowsDecodeEncodeAndReject() throws Exception {
        Map<String, Object> doc = Vectors.load("transfer.json");
        Map<String, byte[]> certs = new HashMap<>();
        for (Map<String, Object> c : Vectors.list(doc, "cards")) {
            certs.put((String) c.get("name"), Vectors.hex(c, "cert"));
        }
        Map<String, Map<String, Object>> transfers = new HashMap<>();
        for (Map<String, Object> t : Vectors.list(doc, "transfers")) {
            String name = (String) t.get("name");
            transfers.put(name, t);
            byte[] certS = certs.get(t.get("source"));
            byte[] certT = certs.get(t.get("target"));
            byte[] lk = Vectors.hex(t, "LK");
            byte[] offer = concat(lk, Vectors.hex(t, "offerSignature"));
            byte[] head = concat(Vectors.hex(t, "E"), Vectors.hex(t, "exportSignature"));
            byte[] payload = concat(Vectors.hex(t, "ct"), Vectors.hex(t, "tag"));

            Transfer.Offer o = Transfer.decodeOffer(offer, certT);
            assertArrayEquals(lk, o.lk(), name + ": OFFER link point");
            Transfer.ExportHead h = Transfer.decodeExportHead(head, certS, certT, lk);
            assertArrayEquals(Vectors.hex(t, "E"), h.e(), name + ": EXPORT head E");
            Transfer.ExportPayload p = Transfer.decodeExportPayload(payload);
            assertArrayEquals(Vectors.hex(t, "ct"), p.ct(), name + ": payload ct");
            assertArrayEquals(Vectors.hex(t, "tag"), p.tag(), name + ": payload tag");

            assertArrayEquals(concat(certT, offer), Transfer.export0(certT, offer), name);
            assertArrayEquals(
                    Vectors.hex(t, "accessHashT"),
                    Transfer.export1(Vectors.hex(t, "accessHashT")),
                    name);
            assertArrayEquals(concat(certS, head), Transfer.import0(certS, head), name);
            assertArrayEquals(payload, Transfer.import1(payload), name);
        }

        for (Map<String, Object> r : Vectors.list(doc, "rejectedOffers")) {
            Map<String, Object> t = transfers.get(r.get("transfer"));
            byte[] cert = Vectors.hex(r, "cert");
            if (((Number) r.get("check")).intValue() != 5
                    || !Arrays.equals(cert, certs.get(t.get("target")))) {
                continue;
            }
            byte[] resp = concat(Vectors.hex(r, "LK"), Vectors.hex(r, "signature"));
            assertThrows(
                    CardNotGenuineException.class,
                    () -> Transfer.decodeOffer(resp, cert),
                    (String) r.get("name"));
        }
        for (Map<String, Object> r : Vectors.list(doc, "rejectedExports")) {
            Map<String, Object> t = transfers.get(r.get("transfer"));
            byte[] cert = Vectors.hex(r, "cert");
            if (((Number) r.get("check")).intValue() != 5
                    || !Arrays.equals(cert, certs.get(t.get("source")))) {
                continue;
            }
            byte[] resp = concat(Vectors.hex(r, "E"), Vectors.hex(r, "signature"));
            assertThrows(
                    CardNotGenuineException.class,
                    () ->
                            Transfer.decodeExportHead(
                                    resp, cert, certs.get(t.get("target")), Vectors.hex(t, "LK")),
                    (String) r.get("name"));
        }
    }

    @Test
    void decodeExportPayloadChecksLength() throws Exception {
        byte[] resp = new byte[176];
        RND.nextBytes(resp);
        Transfer.ExportPayload p = Transfer.decodeExportPayload(resp);
        assertArrayEquals(Arrays.copyOf(resp, 160), p.ct());
        assertArrayEquals(Arrays.copyOfRange(resp, 160, 176), p.tag());
        assertEquals(144, Transfer.decodeExportPayload(new byte[160]).ct().length);
        assertThrows(
                CardNotGenuineException.class, () -> Transfer.decodeExportPayload(new byte[159]));
        assertThrows(
                CardNotGenuineException.class, () -> Transfer.decodeExportPayload(new byte[177]));
    }
}
