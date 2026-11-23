// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Bip340;
import org.qntx.card.host.Certificates;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Ecdsa;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Open;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Wei25519Map;
import org.qntx.card.sim.Card;

/**
 * Replays every case of spec/vectors/apdu.json: the §9.1 outer commands, the §9.2 checking order
 * inside session records and the wallet commands of §9.3–9.15. {@code LOADED} cases run on a card
 * created with {@link Vecs#loadWallet}; {@code verified} sessions VERIFY the case vector's access
 * hash first. The transfer lives run a second card, {@code peer}: SOURCE exports to a BLANK peer
 * that answered OFFER, TARGET imports from a LOADED member peer, TARGET-LOADED imports first and
 * then re-seals.
 */
final class ApduTableTest {

    private static final int INS_STATUS = 0x20;
    private static final int INS_CREATE = 0x21;
    private static final int INS_VERIFY = 0x22;
    private static final int INS_ERASE = 0x24;
    private static final int INS_SIGN_ED25519 = 0x33;
    private static final int INS_OFFER = 0x40;
    private static final int INS_EXPORT = 0x41;
    private static final int INS_IMPORT = 0x42;

    private static final byte[] LABEL_OFFER = "qntx-card/v1/offer".getBytes();
    private static final byte[] LABEL_EXPORT = "qntx-card/v1/export".getBytes();

    /** The second card of the transfer lives: BLANK after an OFFER (SOURCE) or LOADED (TARGET). */
    private static final class Peer {
        final Card card;
        final byte[] a;
        Session session;
        byte[] offer;
        byte[] head;
        byte[] payload;

        private Peer(Card card, byte[] a) {
            this.card = card;
            this.a = a;
        }

        /** A BLANK peer that has answered OFFER. */
        static Peer blank() throws Exception {
            Card card = Vecs.factory();
            Peer p = new Peer(card, Vecs.cardA(card));
            Vecs.blankFor(card, p.a);
            p.session = Vecs.open(card);
            p.offer = offer(p.card, p.session);
            return p;
        }

        /** A LOADED peer whose wallet lists {@code targetId} as the second member. */
        static Peer member(byte[] targetId) throws Exception {
            Card card = Vecs.factory();
            Peer p = new Peer(card, Vecs.cardA(card));
            Vecs.blankFor(card, p.a);
            p.session = Vecs.open(card);
            byte[] data = new byte[112];
            System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
            System.arraycopy(Vecs.seed(), 0, data, 32, 64);
            System.arraycopy(targetId, 0, data, 96, 16);
            Response r = Vecs.roundtrip(card, p.session, INS_CREATE, 1, 0, data);
            if (r.sw() != 0x9000) {
                throw new IllegalStateException("peer CREATE: " + Integer.toHexString(r.sw()));
            }
            p.session = Vecs.open(card);
            verify(p.card, p.session, Vecs.accessHash());
            return p;
        }

        byte[] cert() {
            return Vecs.certFor(a);
        }

        byte[] id() {
            return Ids.cardId(a);
        }

        /** EXPORT P1 = 00 ‖ P1 = 01 to the target's certificate and OFFER response. */
        void exportTo(byte[] certTarget, byte[] offerTarget, byte[] accessHashTarget)
                throws Exception {
            byte[] data = new byte[226];
            System.arraycopy(certTarget, 0, data, 0, 97);
            System.arraycopy(offerTarget, 0, data, 97, 129);
            Response h = Vecs.roundtrip(card, session, INS_EXPORT, 0, 0, data);
            if (h.sw() != 0x9000 || h.data().length != 129) {
                throw new IllegalStateException("peer EXPORT0: " + Integer.toHexString(h.sw()));
            }
            head = h.data();
            Response p = Vecs.roundtrip(card, session, INS_EXPORT, 1, 0, accessHashTarget);
            if (p.sw() != 0x9000) {
                throw new IllegalStateException("peer EXPORT1: " + Integer.toHexString(p.sw()));
            }
            payload = p.data();
        }
    }

    /** Per-case state: the card under test, its session and — for the transfer lives — a peer. */
    private static final class Ctx {
        Card card;
        byte[] a;
        Session session;
        Peer peer;
        byte[] offer;
        byte[] exportHead;
    }

    @Test
    void everyTableCase() throws Exception {
        Map<String, Object> doc = Vecs.load("apdu.json");
        for (Map<String, Object> group : Vecs.list(doc, "commands")) {
            for (Map<String, Object> c : Vecs.list(group, "cases")) {
                run(group, c);
            }
        }
    }

    private static void run(Map<String, Object> group, Map<String, Object> c) throws Exception {
        String name = group.get("name") + "." + c.get("name");
        int expectedSw = Integer.parseInt((String) c.get("sw"), 16);
        Ctx ctx = setup(name, c);
        if (!(Boolean) c.get("inner")) {
            byte[] apdu = resolveApdu((String) c.get("apdu"), ctx);
            byte[] rapdu = ctx.card.transmit(apdu);
            assertEquals(expectedSw, Vecs.sw(rapdu), name);
            Object response = c.get("response");
            if (response != null) {
                checkResponse((String) response, rapdu, ctx, apdu, name);
            }
            return;
        }
        byte[] plain = resolveApdu((String) c.get("apdu"), ctx);
        byte[] data = Arrays.copyOfRange(plain, 3, plain.length);
        Response r =
                Vecs.roundtrip(
                        ctx.card,
                        ctx.session,
                        plain[0] & 0xFF,
                        plain[1] & 0xFF,
                        plain[2] & 0xFF,
                        data);
        assertEquals(expectedSw, r.sw(), name);
        Object response = c.get("response");
        if (response != null) {
            assertTemplate((String) response, r.data(), ctx, name);
        }
    }

    /** The life setup of apdu.json: UNINIT, FACTORY, BLANK, LOADED and the transfer states. */
    private static Ctx setup(String name, Map<String, Object> c) throws Exception {
        Ctx ctx = new Ctx();
        String life = (String) c.get("life");
        // UNINIT is install without the §14.3 drive; every other life is initialised
        ctx.card = life.equals("UNINIT") ? Vecs.installed() : Vecs.factory();
        ctx.a = tryA(ctx.card); // GET_IDENTITY works only in FACTORY, so read it first
        if (!life.equals("any") && !life.equals("UNINIT") && !life.equals("FACTORY")) {
            Vecs.blankFor(ctx.card, ctx.a);
        }
        switch (life) {
            case "LOADED" -> ctx.session = Vecs.loadWallet(ctx.card);
            case "SOURCE" -> {
                ctx.peer = Peer.blank();
                ctx.session = Vecs.open(ctx.card);
                byte[] data = new byte[128];
                System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
                System.arraycopy(Vecs.seed(), 0, data, 32, 64);
                System.arraycopy(ctx.peer.id(), 0, data, 96, 16);
                System.arraycopy(Ids.cardId(Vecs.badPointA()), 0, data, 112, 16);
                Response r = Vecs.roundtrip(ctx.card, ctx.session, INS_CREATE, 1, 0, data);
                if (r.sw() != 0x9000) {
                    throw new IllegalStateException(
                            name + ": setup CREATE " + Integer.toHexString(r.sw()));
                }
                ctx.session = Vecs.open(ctx.card);
            }
            case "TARGET" -> ctx.peer = Peer.member(Ids.cardId(ctx.a));
            case "TARGET-LOADED" -> {
                ctx.peer = Peer.member(Ids.cardId(ctx.a));
                ctx.session = Vecs.open(ctx.card);
                ctx.offer = offer(ctx.card, ctx.session);
                ctx.peer.exportTo(Vecs.certFor(ctx.a), ctx.offer, Vecs.accessHash());
                importOn(ctx, ctx.peer.cert(), ctx.peer.head, ctx.peer.payload);
                ctx.session = Vecs.open(ctx.card);
            }
            default -> {}
        }
        setupSession(name, c, ctx);
        return ctx;
    }

    private static void setupSession(String name, Map<String, Object> c, Ctx ctx) throws Exception {
        String session = (String) c.get("session");
        switch (session) {
            case "none" -> {
                return;
            }
            case "open" -> openIfNeeded(ctx);
            case "verified" -> {
                openIfNeeded(ctx);
                verify(ctx.card, ctx.session, Vecs.accessHash());
            }
            case "streaming" -> {
                openIfNeeded(ctx);
                verify(ctx.card, ctx.session, Vecs.accessHash());
                Response b =
                        Vecs.roundtrip(
                                ctx.card, ctx.session, INS_SIGN_ED25519, 0, 0, Vecs.pathEdSolana());
                assertEquals(0x9000, b.sw(), name + ": setup SIGN_ED25519 begin");
            }
            case "offered" -> {
                openIfNeeded(ctx);
                ctx.offer = offer(ctx.card, ctx.session);
                ctx.peer.exportTo(Vecs.certFor(ctx.a), ctx.offer, Vecs.accessHashNew());
            }
            case "importing" -> {
                openIfNeeded(ctx);
                ctx.offer = offer(ctx.card, ctx.session);
                ctx.peer.exportTo(Vecs.certFor(ctx.a), ctx.offer, Vecs.accessHashNew());
                byte[] data = new byte[226];
                System.arraycopy(ctx.peer.cert(), 0, data, 0, 97);
                System.arraycopy(ctx.peer.head, 0, data, 97, 129);
                Response r = Vecs.roundtrip(ctx.card, ctx.session, INS_IMPORT, 0, 0, data);
                assertEquals(0x9000, r.sw(), name + ": setup IMPORT P1=00");
            }
            case "exporting" -> {
                openIfNeeded(ctx);
                verify(ctx.card, ctx.session, Vecs.accessHash());
                byte[] data = new byte[226];
                System.arraycopy(ctx.peer.cert(), 0, data, 0, 97);
                System.arraycopy(ctx.peer.offer, 0, data, 97, 129);
                Response r = Vecs.roundtrip(ctx.card, ctx.session, INS_EXPORT, 0, 0, data);
                assertEquals(0x9000, r.sw(), name + ": setup EXPORT P1=00");
                ctx.exportHead = r.data();
            }
            default -> throw new IllegalArgumentException("unknown session " + session);
        }
    }

    private static void openIfNeeded(Ctx ctx) throws Exception {
        if (ctx.session == null) {
            ctx.session = Vecs.open(ctx.card);
        }
    }

    private static byte[] offer(Card card, Session session) throws Exception {
        Response r = Vecs.roundtrip(card, session, INS_OFFER, 0, 0, new byte[0]);
        if (r.sw() != 0x9000 || r.data().length != 129) {
            throw new IllegalStateException("OFFER: " + Integer.toHexString(r.sw()));
        }
        return r.data();
    }

    private static void verify(Card card, Session session, byte[] accessHash) throws Exception {
        Response r = Vecs.roundtrip(card, session, INS_VERIFY, 0, 0, accessHash);
        if (r.sw() != 0x9000) {
            throw new IllegalStateException("setup VERIFY: " + Integer.toHexString(r.sw()));
        }
    }

    /** IMPORT P1 = 00 ‖ P1 = 01 on the card under test; asserts 9000 on both. */
    private static void importOn(Ctx ctx, byte[] certSender, byte[] head, byte[] payload)
            throws Exception {
        byte[] data = new byte[226];
        System.arraycopy(certSender, 0, data, 0, 97);
        System.arraycopy(head, 0, data, 97, 129);
        Response h = Vecs.roundtrip(ctx.card, ctx.session, INS_IMPORT, 0, 0, data);
        if (h.sw() != 0x9000) {
            throw new IllegalStateException("setup IMPORT0: " + Integer.toHexString(h.sw()));
        }
        Response p = Vecs.roundtrip(ctx.card, ctx.session, INS_IMPORT, 1, 0, payload);
        if (p.sw() != 0x9000) {
            throw new IllegalStateException("setup IMPORT1: " + Integer.toHexString(p.sw()));
        }
    }

    private static byte[] tryA(Card card) {
        byte[] rapdu = card.transmit(Vecs.unhex("80E0000000"));
        return Vecs.sw(rapdu) == 0x9000 ? Arrays.copyOf(rapdu, 33) : new byte[33];
    }

    /** Symbol resolution: {@code peer.*} and the bad point come from the case context. */
    private static byte[] symbol(String name, Ctx ctx) {
        return switch (name) {
            case "peer.cert" -> ctx.peer.cert();
            case "peer.cert.otherCa" -> Certificates.issue(Vecs.ca2Private(), ctx.peer.a);
            case "peer.id" -> ctx.peer.id();
            case "peer.offer" -> ctx.peer.offer;
            case "peer.offer.badSig" -> mutateLast(ctx.peer.offer);
            case "peer.offer.prefix03" -> {
                byte[] offer = ctx.peer.offer.clone();
                offer[0] = 3;
                yield offer;
            }
            case "peer.exportHead" -> ctx.peer.head;
            case "peer.exportHead.badSig" -> mutateLast(ctx.peer.head);
            case "peer.exportPayload" -> ctx.peer.payload;
            case "peer.exportPayload.badTag" -> mutateLast(ctx.peer.payload);
            case "peer.exportPayload.badCt" -> {
                byte[] payload = ctx.peer.payload.clone();
                payload[0] ^= 1;
                yield payload;
            }
            case "cert.badPoint" -> Certificates.issue(Vecs.caPrivate(), Vecs.badPointA());
            case "id.badPoint" -> Ids.cardId(Vecs.badPointA());
            default -> Vecs.symbol(name, ctx.card, ctx.a);
        };
    }

    private static byte[] resolveApdu(String template, Ctx ctx) {
        StringBuilder out = new StringBuilder();
        int i = 0;
        while (i < template.length()) {
            if (template.charAt(i) == '{') {
                int close = template.indexOf('}', i);
                for (byte b : symbol(template.substring(i + 1, close), ctx)) {
                    out.append(String.format("%02x", b));
                }
                i = close + 1;
            } else {
                int next = template.indexOf('{', i);
                out.append(template, i, next < 0 ? template.length() : next);
                i = next < 0 ? template.length() : next;
            }
        }
        return Vecs.unhex(out.toString());
    }

    private static byte[] mutateLast(byte[] base) {
        byte[] out = base.clone();
        out[out.length - 1] ^= 1;
        return out;
    }

    private static void checkResponse(String sym, byte[] rapdu, Ctx ctx, byte[] apdu, String name)
            throws Exception {
        if (sym.equals("{A}")) {
            assertArrayEquals(ctx.a, Arrays.copyOf(rapdu, 33), name);
            return;
        }
        if (sym.equals("{openResponse}")) {
            // host-verifiable: the fixed session.json request against the ca1 anchor
            Map<String, Object> doc = Vecs.load("session.json");
            Session s =
                    Open.response(
                            Vecs.hex(doc, "hostPrivate"), apdu, rapdu, List.of(Vecs.caPublic()));
            assertEquals(0, s.counter(), name);
            return;
        }
        assertTemplate(sym, Arrays.copyOf(rapdu, rapdu.length - 2), ctx, name);
    }

    /**
     * Matches a response template of hex literals and {@code {symbols}} against the inner payload.
     * {@code {masterPublicKey.any}} accepts any 33-byte compressed secp256k1 point; the transfer
     * wildcards are checked against independent host cryptography (and, for {@code
     * {exportPayload.any}}, by completing the import on the peer card).
     */
    private static void assertTemplate(String template, byte[] actual, Ctx ctx, String name)
            throws Exception {
        int pos = 0;
        int i = 0;
        while (i < template.length()) {
            if (template.charAt(i) == '{') {
                int close = template.indexOf('}', i);
                String sym = template.substring(i + 1, close);
                if (sym.equals("masterPublicKey.any")) {
                    assertTrue(actual.length - pos >= 33, name + ": response too short");
                    byte[] pk = Arrays.copyOfRange(actual, pos, pos + 33);
                    assertTrue(pk[0] == 2 || pk[0] == 3, name + ": masterPublicKey.any prefix");
                    Crypto.decompress(pk); // throws unless x is on the curve
                    pos += 33;
                } else if (sym.equals("offer.any")) {
                    // LK ‖ sig: valid point, signature under the card's A of "offer" ‖ LK
                    assertTrue(actual.length - pos >= 129, name + ": response too short");
                    byte[] lk = Arrays.copyOfRange(actual, pos, pos + 65);
                    byte[] sig = Arrays.copyOfRange(actual, pos + 65, pos + 129);
                    assertEquals(4, lk[0], name + ": offer.any LK prefix");
                    assertTrue(
                            Crypto.DOMAIN.getCurve().decodePoint(lk).isValid(),
                            name + ": offer.any LK off curve");
                    byte[] m = concat(LABEL_OFFER, lk);
                    assertTrue(
                            Ecdsa.verify(Crypto.decompress(ctx.a), Crypto.sha256(m), sig),
                            name + ": offer.any signature");
                    pos += 129;
                } else if (sym.equals("exportHead.any")) {
                    // E ‖ sig_S of "export" ‖ A_S ‖ A_T ‖ LK_T ‖ E under the card's A
                    assertTrue(actual.length - pos >= 129, name + ": response too short");
                    byte[] e = Arrays.copyOfRange(actual, pos, pos + 65);
                    byte[] sig = Arrays.copyOfRange(actual, pos + 65, pos + 129);
                    assertEquals(4, e[0], name + ": exportHead.any E prefix");
                    assertTrue(
                            Crypto.DOMAIN.getCurve().decodePoint(e).isValid(),
                            name + ": exportHead.any E off curve");
                    byte[] m =
                            concat(
                                    LABEL_EXPORT,
                                    ctx.a,
                                    ctx.peer.a,
                                    Arrays.copyOf(ctx.peer.offer, 65),
                                    e);
                    assertTrue(
                            Ecdsa.verify(Crypto.decompress(ctx.a), Crypto.sha256(m), sig),
                            name + ": exportHead.any signature");
                    pos += 129;
                } else if (sym.equals("exportPayload.any")) {
                    // ct ‖ tag the peer accepts: IMPORT on the peer, then WalletInfo must match
                    int len = actual.length - pos;
                    assertTrue(len == 160 || len == 176, name + ": exportPayload.any length");
                    byte[] payload = Arrays.copyOfRange(actual, pos, pos + len);
                    byte[] data = new byte[226];
                    System.arraycopy(Vecs.certFor(ctx.a), 0, data, 0, 97);
                    System.arraycopy(ctx.exportHead, 0, data, 97, 129);
                    Response h =
                            Vecs.roundtrip(ctx.peer.card, ctx.peer.session, INS_IMPORT, 0, 0, data);
                    assertEquals(0x9000, h.sw(), name + ": exportPayload.any peer IMPORT0");
                    Response p =
                            Vecs.roundtrip(
                                    ctx.peer.card, ctx.peer.session, INS_IMPORT, 1, 0, payload);
                    assertEquals(0x9000, p.sw(), name + ": exportPayload.any peer IMPORT1");
                    // IMPORT P1 = 01's response is the WalletInfo of the imported wallet (§9.14)
                    byte[] want =
                            concat(
                                    Vecs.seedMasterPublicKey(),
                                    new byte[] {2, 3},
                                    Ids.cardId(ctx.a),
                                    ctx.peer.id(),
                                    Ids.cardId(Vecs.badPointA()));
                    assertArrayEquals(want, p.data(), name + ": exportPayload.any WalletInfo");
                    pos += len;
                } else if (sym.startsWith("sig.ecdsa.")) {
                    // 64 bytes r ‖ s, verified with the host helper under the template key
                    assertTrue(actual.length - pos >= 64, name + ": response too short");
                    byte[] sig = Arrays.copyOfRange(actual, pos, pos + 64);
                    String keyName =
                            switch (sym.substring("sig.ecdsa.".length())) {
                                case "bip84Account" -> "btc-bip84-account";
                                default -> sym.substring("sig.ecdsa.".length());
                            };
                    byte[] pk =
                            Crypto.decompress(Vecs.hex(Vecs.secpTemplate(keyName), "publicKey"));
                    assertTrue(
                            Ecdsa.verify(pk, Vecs.digest(), sig),
                            name + ": invalid ECDSA signature under " + keyName);
                    pos += 64;
                } else if (sym.startsWith("sig.bip340.")) {
                    // 64 bytes R_x ‖ s under the BIP-340 output key of the template
                    assertTrue(actual.length - pos >= 64, name + ": response too short");
                    byte[] sig = Arrays.copyOfRange(actual, pos, pos + 64);
                    byte[] pk = Vecs.hex(Vecs.secpTemplate("btc-bip86"), "publicKey");
                    byte[] internal = Arrays.copyOfRange(pk, 1, 33);
                    byte[] out =
                            sym.equals("sig.bip340.bip86")
                                    ? Bip340.outputKey(Crypto.decompress(pk), Vecs.tweakBip86())
                                    : internal;
                    assertTrue(
                            Bip340.verify(out, Vecs.message(), sig),
                            name + ": invalid BIP-340 signature under " + sym);
                    pos += 64;
                } else if (sym.equals("wei.any")) {
                    // 64 bytes X ‖ Y of a Wei25519 point other than the base point
                    assertTrue(actual.length - pos >= 64, name + ": response too short");
                    byte[] wei = Arrays.copyOfRange(actual, pos, pos + 64);
                    Wei25519Map.encode(wei); // throws unless X ‖ Y is on Wei25519
                    assertTrue(
                            !Arrays.equals(wei, Vecs.weiBase()),
                            name + ": wei.any must not be the base point");
                    pos += 64;
                } else if (sym.equals("ed25519.S.any")) {
                    // 32 bytes le32(S) with int_le(S) < l
                    assertTrue(actual.length - pos >= 32, name + ": response too short");
                    byte[] s = Arrays.copyOfRange(actual, pos, pos + 32);
                    byte[] be = new byte[32];
                    for (int j = 0; j < 32; j++) {
                        be[j] = s[31 - j];
                    }
                    assertTrue(
                            new java.math.BigInteger(1, be).compareTo(Vecs.ED25519_L) < 0,
                            name + ": S out of range");
                    pos += 32;
                } else {
                    byte[] want = symbol(sym, ctx);
                    assertSlice(want, actual, pos, name + ": {" + sym + "}");
                    pos += want.length;
                }
                i = close + 1;
            } else {
                int next = template.indexOf('{', i);
                String lit = next < 0 ? template.substring(i) : template.substring(i, next);
                byte[] want = Vecs.unhex(lit);
                assertSlice(want, actual, pos, name);
                pos += want.length;
                i = next < 0 ? template.length() : next;
            }
        }
        assertEquals(actual.length, pos, name + ": response length");
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

    private static void assertSlice(byte[] want, byte[] actual, int pos, String name) {
        assertTrue(actual.length - pos >= want.length, name + ": response too short");
        assertArrayEquals(want, Arrays.copyOfRange(actual, pos, pos + want.length), name);
    }
}
