// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javacard.framework.Applet;
import javacard.security.AESKey;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Transfer;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/** {@code transfer.json} fixtures shared by the transfer suites: deterministic vector cards. */
final class TransferVecs {
    static final Map<String, Object> DOC = Vecs.load("transfer.json");

    static final int INS_CREATE = 0x21;
    static final int INS_VERIFY = 0x22;
    static final int INS_STATUS = 0x20;
    static final int INS_OFFER = 0x40;
    static final int INS_EXPORT = 0x41;
    static final int INS_IMPORT = 0x42;

    private TransferVecs() {}

    /** A deterministic vector card: its identity set before PERSONALIZE under its own cert. */
    static final class Side {
        final Card card;
        final Applet applet;
        final Map<String, Object> row;
        Session session;

        Side(String name) throws Exception {
            row = find("cards", name);
            card = Vecs.factory();
            applet = card.applet(Spec.WALLET_AID);
            Internals.setIdentity(applet, new BigInteger(1, Vecs.hex(row, "private")));
            assertEquals(
                    0x9000, Vecs.sw(card.transmit(Vecs.personalizeApdu(Vecs.hex(row, "cert")))));
            session = Vecs.open(card);
        }

        Response inner(int ins, int p1, byte[] data) throws Exception {
            return Vecs.roundtrip(card, session, ins, p1, 0, data);
        }

        byte[] cert() {
            return Vecs.hex(row, "cert");
        }

        byte[] uncompressed() {
            return Vecs.hex(row, "uncompressed");
        }
    }

    static Map<String, Object> find(String list, String name) {
        for (Map<String, Object> o : Vecs.list(DOC, list)) {
            if (o.get("name").equals(name)) {
                return o;
            }
        }
        throw new IllegalStateException(list + " lacks " + name);
    }

    static Map<String, Object> wallet(String name) {
        return find("wallets", name);
    }

    static byte[] aes(Applet applet, String name) {
        byte[] out = new byte[16];
        ((AESKey) Internals.memField(applet, name)).getKey(out, (short) 0);
        return out;
    }

    /** The pending word of {@link Session} (words[6..7]): zero means no pending state. */
    static int pending(Applet applet) {
        byte[] w = Internals.words(applet);
        return ((w[6] & 0xFF) << 8) | (w[7] & 0xFF);
    }

    /** CREATE with the wallet row's {@code create} object (Rng.fix for P1 = 00's t). */
    static void createWallet(Side creator, Map<String, Object> wallet) throws Exception {
        Map<String, Object> create = Vecs.obj(wallet, "create");
        int p1 = create.get("p1").equals("00") ? 0 : 1;
        byte[] data;
        if (p1 == 1) {
            data = concat(Vecs.hex(create, "accessHash"), Vecs.hex(create, "seed"));
        } else {
            org.qntx.card.sim.Rng.fix(Vecs.hex(create, "t"));
            data = concat(Vecs.hex(create, "accessHash"), Vecs.hex(create, "hostEntropy"));
        }
        try {
            @SuppressWarnings("unchecked")
            List<String> others = (List<String>) create.get("others");
            for (String id : others) {
                data = concat(data, Vecs.unhex(id));
            }
            Response r = creator.inner(INS_CREATE, p1, data);
            assertEquals(0x9000, r.sw(), "CREATE " + wallet.get("name"));
        } finally {
            org.qntx.card.sim.Rng.reset();
        }
    }

    /**
     * OFFER until {@code offer = VALID}, the vector link key reflected in, then a final OFFER —
     * returns {@code LK ‖ sig} with the sig asserted against BouncyCastle.
     */
    static byte[] offerWith(Side target, Map<String, Object> t) throws Exception {
        Response r = target.inner(INS_OFFER, 0, new byte[0]);
        assertEquals(0x9000, r.sw(), "OFFER");
        Internals.setLinkKey(target.applet, Vecs.hex(t, "linkPrivate"), Vecs.hex(t, "LK"));
        r = target.inner(INS_OFFER, 0, new byte[0]);
        assertEquals(0x9000, r.sw(), "OFFER (fixed link)");
        assertArrayEquals(Vecs.hex(t, "LK"), Arrays.copyOf(r.data(), 65));
        assertTrue(
                Crypto.verify(
                        target.uncompressed(),
                        Crypto.sha256(Transfer.LABEL_OFFER, Vecs.hex(t, "LK")),
                        Arrays.copyOfRange(r.data(), 65, 129)),
                "OFFER signature");
        return r.data();
    }

    /** IMPORT0 of the vector head {@code cert ‖ e ‖ sig}. */
    static Response import0(Side target, Side source, Map<String, Object> t, byte[] e, byte[] sig)
            throws Exception {
        return target.inner(INS_IMPORT, 0, concat(source.cert(), e, sig));
    }

    static Response verify(Side s, byte[] accessHash) throws Exception {
        return s.inner(INS_VERIFY, 0, accessHash);
    }

    static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) {
            len += p.length;
        }
        byte[] out = new byte[len];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }
}
