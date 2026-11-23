// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.util.Map;
import javacard.framework.Applet;
import org.junit.jupiter.api.Test;
import org.qntx.card.TransferVecs.Side;
import org.qntx.card.host.Certificates;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Response;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * Architecture §14.6 T5 — {@link Secp256k1#decompress} against {@code transfer.json}'s {@code
 * decompress} table and BouncyCastle: every vector row, {@code -Dqntx.decompress.randoms} random
 * keys in both parities, and the same bad points through the EXPORT/IMPORT certificate check
 * (§9.13/§9.14 check 4 → {@code 6A80}).
 */
final class DecompressTest {
    private static final int RANDOMS = Integer.getInteger("qntx.decompress.randoms", 200);

    private static Secp256k1 secp(Applet applet) {
        return Internals.secp(applet);
    }

    @Test
    void vectorRowsMatch() {
        Applet applet = Vecs.factory().applet(Spec.WALLET_AID);
        byte[] out = new byte[65];
        for (Map<String, Object> row : Vecs.list(TransferVecs.DOC, "decompress")) {
            byte[] compressed = Vecs.hex(row, "compressed");
            boolean valid = (Boolean) row.get("valid");
            short r = secp(applet).decompress(compressed, (short) 0, out, (short) 0);
            if (valid) {
                assertEquals(Const.CHECK_OK, r, row.get("name") + " accepted");
                assertArrayEquals(Vecs.hex(row, "uncompressed"), out, (String) row.get("name"));
            } else {
                assertEquals(Const.CHECK_FAIL, r, row.get("name") + " (" + row.get("reason") + ")");
            }
        }
    }

    @Test
    void randomKeysMatchBouncyCastle() {
        Applet applet = Vecs.factory().applet(Spec.WALLET_AID);
        byte[] out = new byte[65];
        for (int i = 0; i < RANDOMS; i++) {
            BigInteger d;
            do {
                d = new BigInteger(256, Vecs.RND);
            } while (d.signum() == 0 || d.compareTo(Crypto.N) >= 0);
            byte[] expect = Crypto.publicKey(d);
            byte[] compressed = Crypto.compress(expect);
            assertEquals(
                    Const.CHECK_OK,
                    secp(applet).decompress(compressed, (short) 0, out, (short) 0),
                    "key " + i);
            assertArrayEquals(expect, out, "key " + i);
            // the other parity must give the negated point — also a valid curve point
            compressed[0] ^= 1;
            byte[] flipped = Crypto.DOMAIN.getCurve().decodePoint(compressed).getEncoded(false);
            assertEquals(
                    Const.CHECK_OK,
                    secp(applet).decompress(compressed, (short) 0, out, (short) 0),
                    "flipped " + i);
            assertArrayEquals(flipped, out, "flipped " + i);
        }
    }

    @Test
    void badPointCertsAreRefusedAtCheck4() throws Exception {
        // the vector's invalid compressed points as certificate identities: the cert
        // verifies under ca1 (the CA signs any bytes) but decompression must fail check 4
        Map<String, Object> t = TransferVecs.find("transfers", "imported-to-target");
        Side source = new Side("source");
        Side target = new Side("target");
        TransferVecs.createWallet(source, TransferVecs.wallet("imported"));
        byte[] offer = TransferVecs.offerWith(target, t);
        assertEquals(
                0x9000,
                TransferVecs.verify(
                                source,
                                Vecs.hex(
                                        Vecs.obj(TransferVecs.wallet("imported"), "create"),
                                        "accessHash"))
                        .sw(),
                "VERIFY");
        for (String row : new String[] {"non-residue-even", "x-is-p", "prefix-04"}) {
            byte[] bad = Vecs.hex(TransferVecs.find("decompress", row), "compressed");
            byte[] cert = Certificates.issue(Vecs.caPrivate(), bad);
            Response exp =
                    source.inner(TransferVecs.INS_EXPORT, 0, TransferVecs.concat(cert, offer));
            assertEquals(0x6A80, exp.sw(), "EXPORT0 with " + row);
            assertEquals(0, TransferVecs.pending(source.applet));
            Response imp =
                    target.inner(
                            TransferVecs.INS_IMPORT,
                            0,
                            TransferVecs.concat(
                                    cert, Vecs.hex(t, "E"), Vecs.hex(t, "exportSignature")));
            assertEquals(0x6A80, imp.sw(), "IMPORT0 with " + row);
            assertEquals(0, TransferVecs.pending(target.applet));
        }
    }

    @Test
    void decompressBoundaries() {
        Applet applet = Vecs.factory().applet(Spec.WALLET_AID);
        byte[] out = new byte[65];
        // x = p and x = p − 1 straddle the field bound; p itself must fail
        BigInteger fp = Crypto.DOMAIN.getCurve().getField().getCharacteristic();
        byte[] p = new byte[33];
        p[0] = 0x02;
        byte[] pb = fp.toByteArray();
        System.arraycopy(
                pb,
                Math.max(0, pb.length - 32),
                p,
                1 + Math.max(0, 32 - pb.length),
                Math.min(32, pb.length));
        assertEquals(
                Const.CHECK_FAIL, secp(applet).decompress(p, (short) 0, out, (short) 0), "x = p");
        p = new byte[33];
        p[0] = 0x02;
        pb = fp.subtract(BigInteger.ONE).toByteArray();
        System.arraycopy(
                pb,
                Math.max(0, pb.length - 32),
                p,
                1 + Math.max(0, 32 - pb.length),
                Math.min(32, pb.length));
        short r = secp(applet).decompress(p, (short) 0, out, (short) 0);
        // p − 1 is a syntactically valid x: residue decides; compare with BC
        byte[] expect;
        try {
            expect = Crypto.DOMAIN.getCurve().decodePoint(p).getEncoded(false);
            assertEquals(Const.CHECK_OK, r, "x = p − 1 accepted iff residue");
            assertArrayEquals(expect, out);
        } catch (IllegalArgumentException e) {
            assertEquals(Const.CHECK_FAIL, r, "x = p − 1 non-residue");
        }
    }
}
