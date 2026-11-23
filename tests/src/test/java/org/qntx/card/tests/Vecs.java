// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import com.fasterxml.jackson.jr.ob.JSON;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.qntx.card.WalletApplet;
import org.qntx.card.host.Bip340;
import org.qntx.card.host.Certificates;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Open;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Slip10;
import org.qntx.card.sim.Card;

/**
 * The committed vectors of spec/vectors plus the card/session plumbing the command tests share.
 * Test CA material comes from {@code cert.json} (ca1 personalizes the card under test).
 */
public final class Vecs {
    public static final SecureRandom RND = new SecureRandom();
    private static final Path DIR = Path.of(System.getProperty("qntx.vectors", "spec/vectors"));

    private Vecs() {}

    public static Map<String, Object> load(String name) {
        try {
            return JSON.std.mapFrom(Files.readAllBytes(DIR.resolve(name)));
        } catch (IOException e) {
            throw new IllegalStateException("cannot read vector file " + name, e);
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(Map<String, Object> doc, String key) {
        return (Map<String, Object>) doc.get(key);
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> list(Map<String, Object> doc, String key) {
        return (List<Map<String, Object>>) doc.get(key);
    }

    public static byte[] hex(Map<String, Object> obj, String key) {
        return HexFormat.of().parseHex((String) obj.get(key));
    }

    public static byte[] unhex(String s) {
        return HexFormat.of().parseHex(s);
    }

    public static int sw(byte[] rapdu) {
        return ((rapdu[rapdu.length - 2] & 0xFF) << 8) | (rapdu[rapdu.length - 1] & 0xFF);
    }

    /** cert.json's ca1 private scalar: the batch CA of every test card. */
    public static BigInteger caPrivate() {
        Map<String, Object> cert = load("cert.json");
        return new BigInteger(1, hex(list(cert, "cas").get(0), "private"));
    }

    public static BigInteger ca2Private() {
        Map<String, Object> cert = load("cert.json");
        return new BigInteger(1, hex(list(cert, "cas").get(1), "private"));
    }

    /** cert.json's ca1 public key, the anchor the test cards are personalized under. */
    public static byte[] caPublic() {
        return hex(list(load("cert.json"), "cas").get(0), "public");
    }

    public static byte[] ca2Public() {
        return hex(list(load("cert.json"), "cas").get(1), "public");
    }

    /** cert.json's card2 certificate: valid under ca1 for a different identity. */
    public static byte[] certOtherA() {
        for (Map<String, Object> v : list(load("cert.json"), "verify")) {
            if (v.get("name").equals("card2-under-ca1")) {
                return hex(v, "cert");
            }
        }
        throw new IllegalStateException("cert.json lacks card2-under-ca1");
    }

    /** A freshly installed, selected card in FACTORY. */
    public static Card factory() {
        Card card = new Card();
        card.install(Spec.WALLET_AID, WalletApplet.class);
        card.transmit(Spec.SELECT);
        return card;
    }

    /** The card's compressed identity key from GET_IDENTITY (FACTORY only). */
    public static byte[] cardA(Card card) {
        byte[] rapdu = card.transmit(unhex("80E0000000"));
        if (sw(rapdu) != 0x9000) {
            throw new IllegalStateException(
                    "GET_IDENTITY failed: " + Integer.toHexString(sw(rapdu)));
        }
        return Arrays.copyOf(rapdu, 33);
    }

    /** A card personalized under ca1 (BLANK); returns the card and its A/cert. */
    public static Card blank(byte[] cert) {
        Card card = factory();
        byte[] rapdu = card.transmit(personalizeApdu(cert));
        if (sw(rapdu) != 0x9000) {
            throw new IllegalStateException(
                    "PERSONALIZE failed: " + Integer.toHexString(sw(rapdu)));
        }
        return card;
    }

    /** The common case: a fresh card personalized with a cert for its own A under ca1. */
    public static Card blankSelf() {
        Card card = factory();
        return blankFor(card, cardA(card));
    }

    public static Card blankFor(Card card, byte[] a) {
        byte[] rapdu = card.transmit(personalizeApdu(certFor(a)));
        if (sw(rapdu) != 0x9000) {
            throw new IllegalStateException(
                    "PERSONALIZE failed: " + Integer.toHexString(sw(rapdu)));
        }
        return card;
    }

    /** cert = A ‖ Sign(ca1, "qntx-card/v1/cert" ‖ A) for the card's own A. */
    public static byte[] certFor(byte[] a) {
        return Certificates.issue(caPrivate(), a);
    }

    public static byte[] personalizeApdu(byte[] cert) {
        byte[] apdu = new byte[5 + 162];
        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0xE2;
        apdu[4] = (byte) 162;
        System.arraycopy(cert, 0, apdu, 5, 97);
        System.arraycopy(caPublic(), 0, apdu, 102, 65);
        return apdu;
    }

    /** OPEN on the card and host-verify the response; the shared session. */
    public static Session open(Card card) throws Exception {
        Open.Request req = Open.request(RND);
        byte[] rapdu = card.transmit(req.apdu());
        return Open.response(req.secret(), req.apdu(), rapdu, List.of(caPublic()));
    }

    /** A command record round trip: returns the inner {@link Response}. */
    public static Response roundtrip(
            Card card, Session session, int ins, int p1, int p2, byte[] data) throws Exception {
        byte[] rapdu = card.transmit(session.wrap(ins, p1, p2, data));
        return session.unwrap(rapdu);
    }

    /** The fixed access hash the LOADED test card was created with (access.json valid[0]). */
    public static byte[] accessHash() {
        return hex(list(load("access.json"), "valid").get(0), "accessHash");
    }

    /** An access hash different from {@link #accessHash} (access.json valid[1]). */
    public static byte[] accessHashWrong() {
        return hex(list(load("access.json"), "valid").get(1), "accessHash");
    }

    /** A third access hash, for CHANGE (access.json valid[2]). */
    public static byte[] accessHashNew() {
        return hex(list(load("access.json"), "valid").get(2), "accessHash");
    }

    /** The fixed CREATE {@code hostEntropy}: any value, constant across runs. */
    public static byte[] entropy() {
        return unhex("b1b2b3b4b5b6b7b8b9babbbcbdbebfb0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0");
    }

    /** apdu.json {@code {digest}}: the fixed SIGN_ECDSA digest (any value). */
    public static byte[] digest() {
        return unhex("827134c09e1f154d7d0239e5b8f74ebb638b420eabea552628efc21198f6ca64");
    }

    /** apdu.json {@code {message}}: the fixed SIGN_BIP340 message (any value). */
    public static byte[] message() {
        return unhex("f95466d086770e689964664219266fe5ed215c92ae20bab5c9d79addddedf8c0");
    }

    /** derivation.json's secp256k1 template {@code name}, or null. */
    public static Map<String, Object> secpTemplate(String name) {
        for (Map<String, Object> t : list(obj(load("derivation.json"), "templates"), "secp256k1")) {
            if (t.get("name").equals(name)) {
                return t;
            }
        }
        return null;
    }

    /**
     * apdu.json {@code {tweak.bip86}}: {@code TaggedHash("TapTweak", x(P))} of the btc-bip86
     * template key (BIP-341); cross-checked against bip340.json case {@code template-bip86}.
     */
    public static byte[] tweakBip86() {
        byte[] pk = hex(secpTemplate("btc-bip86"), "publicKey");
        return Bip340.taggedHash("TapTweak", Arrays.copyOfRange(pk, 1, 33));
    }

    /**
     * apdu.json {@code {tweak.zeroKey}}: {@code n − d₀'} where {@code d₀'} is the parity-normalized
     * btc-bip86 template private key, so {@code d₀' + t ≡ 0 (mod n)} (bip340.json {@code
     * invalidTweak[2]}).
     */
    public static byte[] tweakZeroKey() {
        BigInteger d = new BigInteger(1, hex(secpTemplate("btc-bip86"), "privateKey"));
        byte[] pub = Crypto.decompress(hex(secpTemplate("btc-bip86"), "publicKey"));
        if ((pub[64] & 1) == 1) {
            d = Crypto.N.subtract(d); // y(P) odd: BIP-340 signs with n − d
        }
        return Crypto.N.subtract(d).mod(Crypto.N).toByteArray();
    }

    /** {@code derivation.json templates.seed} — its BIP-32 master is valid. */
    public static byte[] seed() {
        return hex(obj(load("derivation.json"), "templates"), "seed");
    }

    /** {@code derivation.json templates.masterPublicKey}. */
    public static byte[] seedMasterPublicKey() {
        return hex(obj(load("derivation.json"), "templates"), "masterPublicKey");
    }

    /** {@code publicKey \u2016 chainCode} of the derivation.json evm template. */
    public static byte[] pkSecpEvm() {
        for (Map<String, Object> t : list(obj(load("derivation.json"), "templates"), "secp256k1")) {
            if (t.get("name").equals("evm")) {
                byte[] out = new byte[65];
                byte[] pub = hex(t, "publicKey");
                System.arraycopy(pub, 0, out, 0, 33);
                System.arraycopy(hex(t, "chainCode"), 0, out, 33, 32);
                return out;
            }
        }
        throw new IllegalStateException("derivation.json lacks secp256k1 evm template");
    }

    /** The edwards25519 subgroup order {@code l} of RFC 8032 (for {@code le32(S) < l}). */
    public static final java.math.BigInteger ED25519_L =
            new java.math.BigInteger(
                    "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16);

    /** {@code W(G_W)}, the Wei25519 base point as {@code X ‖ Y} — what {@code wei.any} excludes. */
    public static byte[] weiBase() {
        byte[] one = new byte[32];
        one[31] = 1;
        return Slip10.wei(one);
    }

    /** {@code W(A)} of the derivation.json solana template. */
    public static byte[] pkEdSolana() {
        for (Map<String, Object> t : list(obj(load("derivation.json"), "templates"), "ed25519")) {
            if (t.get("name").equals("solana")) {
                return hex(t, "wei");
            }
        }
        throw new IllegalStateException("derivation.json lacks ed25519 solana template");
    }

    /** Wire path {@code m/44'/60'/0'/0/0} (the secp256k1 evm template). */
    public static byte[] pathSecpEvm() {
        return unhex("058000002c8000003c800000000000000000000000");
    }

    /** Wire path {@code m/44'/501'/0'/0'} (the ed25519 solana template). */
    public static byte[] pathEdSolana() {
        return unhex("048000002c800001f58000000080000000");
    }

    /** The compressed point {@code 02 ‖ u256(5)}: a valid public key nobody knows a scalar for. */
    public static byte[] badPointA() {
        byte[] a = new byte[33];
        a[0] = 2;
        a[32] = 5;
        return a;
    }

    /** A card ID different from {@code ID(a)} ({@code marker} must differ per caller). */
    private static byte[] otherId(byte[] a, int marker) {
        byte[] id = Ids.cardId(a);
        id[0] ^= (byte) marker;
        return id;
    }

    /**
     * The {@code LOADED} setup of apdu.json: on a BLANK card, OPEN, {@code CREATE P1 = 01} with
     * {@code accessHash \u2016 seed} and no other members, then a new OPEN — whose session is
     * returned, open but not verified.
     */
    public static Session loadWallet(Card card) throws Exception {
        Session session = open(card);
        byte[] data = new byte[96];
        System.arraycopy(accessHash(), 0, data, 0, 32);
        System.arraycopy(seed(), 0, data, 32, 64);
        Response r = roundtrip(card, session, 0x21, 1, 0, data);
        if (r.sw() != 0x9000) {
            throw new IllegalStateException("CREATE failed: " + Integer.toHexString(r.sw()));
        }
        return open(card);
    }

    /**
     * Resolves an apdu.json {@code {symbol}} placeholder for the card under test. Symbols not
     * listed need no resolution in the cases that use them ({@code openResponse} is matched
     * structurally, {@code masterPublicKey.any} is a response-only wildcard).
     */
    public static byte[] symbol(String name, Card card, byte[] a) {
        return switch (name) {
            case "A" -> a;
            case "cert" -> certFor(a);
            case "cert.otherA" -> certOtherA();
            case "cert.otherCa" -> Certificates.issue(ca2Private(), a);
            case "caKey" -> caPublic();
            case "caKey.prefix03" -> mutate(caPublic(), 0, (byte) 0x03);
            case "caKey.xIsP" -> withCoord(caPublic(), 1);
            case "caKey.yIsP" -> withCoord(caPublic(), 33);
            case "caKey.offCurve" -> mutate(caPublic(), 64, (byte) (caPublic()[64] ^ 1));
            case "hostEph" -> hex(load("session.json"), "hostEph");
            case "hostEph.prefix02" -> mutate(hex(load("session.json"), "hostEph"), 0, (byte) 0x02);
            case "hostEph.offCurve" -> {
                byte[] e = hex(load("session.json"), "hostEph").clone();
                e[64] ^= 1;
                yield e;
            }
            case "record0" ->
                    Arrays.copyOfRange(
                            hex(list(load("record.json"), "commands").get(0), "apdu"), 5, 29);
            case "accessHash" -> accessHash();
            case "accessHash.wrong" -> accessHashWrong();
            case "accessHash.new" -> accessHashNew();
            case "entropy" -> entropy();
            case "seed" -> seed();
            case "digest" -> digest();
            case "message" -> message();
            case "tweak.bip86" -> left32(tweakBip86());
            case "tweak.zeroKey" -> left32(tweakZeroKey());
            case "seed.masterPublicKey" -> seedMasterPublicKey();
            case "pk.secp.evm" -> pkSecpEvm();
            case "pk.ed.solana" -> pkEdSolana();
            case "id.self" -> Ids.cardId(a);
            case "id.other1" -> otherId(a, 0x01);
            case "id.other2" -> otherId(a, 0x02);
            default -> throw new IllegalArgumentException("unknown symbol " + name);
        };
    }

    /** Substitutes {@code {name}} placeholders of an apdu.json APDU template. */
    public static byte[] resolveApdu(String template, Card card, byte[] a) {
        StringBuilder out = new StringBuilder();
        int i = 0;
        while (i < template.length()) {
            if (template.charAt(i) == '{') {
                int close = template.indexOf('}', i);
                String name = template.substring(i + 1, close);
                for (byte b : symbol(name, card, a)) {
                    out.append(String.format("%02x", b));
                }
                i = close + 1;
            } else {
                int next = template.indexOf('{', i);
                out.append(template, i, next < 0 ? template.length() : next);
                i = next < 0 ? template.length() : next;
            }
        }
        return unhex(out.toString());
    }

    /** The value as exactly 32 bytes, left-padded (a BigInteger export helper). */
    private static byte[] left32(byte[] v) {
        byte[] out = new byte[32];
        int skip = Math.max(0, v.length - 32);
        System.arraycopy(v, skip, out, Math.max(0, 32 - v.length), Math.min(32, v.length));
        return out;
    }

    public static String shortIdOf(byte[] a) {
        return Ids.shortId(a);
    }

    private static byte[] mutate(byte[] base, int off, byte v) {
        byte[] out = base.clone();
        out[off] = v;
        return out;
    }

    private static byte[] withCoord(byte[] base, int off) {
        byte[] out = base.clone();
        byte[] p = new byte[32];
        byte[] b = Crypto.DOMAIN.getCurve().getField().getCharacteristic().toByteArray();
        System.arraycopy(
                b,
                Math.max(0, b.length - 32),
                p,
                Math.max(0, 32 - b.length),
                Math.min(b.length, 32));
        System.arraycopy(p, 0, out, off, 32);
        return out;
    }
}
