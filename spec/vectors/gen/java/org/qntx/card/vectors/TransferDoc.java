// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * {@code transfer.json}: the multi-card wallet transfer vectors of spec/protocol.md §9.12–9.14 and
 * §11 — three deterministic cards, the decompress table of §10.5, two wallets (one imported, one
 * generated), five transfers, the rejected offer/export checks of §9.13–9.14 and the rejected
 * payload checks of §9.14 {@code P1 = 0x01}. Every claim is asserted against BouncyCastle while it
 * is written.
 */
final class TransferDoc {
    private static final byte[] LABEL_OFFER = Vec.ascii("qntx-card/v1/offer");
    private static final byte[] LABEL_EXPORT = Vec.ascii("qntx-card/v1/export");
    private static final byte[] LABEL_KDF = Vec.ascii("qntx-card/v1/kdf-transfer");
    private static final byte[] LABEL_SEED = Vec.ascii("qntx-card/v1/seed");

    private static final BigInteger P = Crypto.DOMAIN.getCurve().getField().getCharacteristic();
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger SEVEN = BigInteger.valueOf(7);
    private static final BigInteger LEGENDRE = P.subtract(BigInteger.ONE).shiftRight(1);
    private static final BigInteger SQRT = P.add(BigInteger.ONE).shiftRight(2);
    private static final byte[] ZEROS = new byte[16];

    /** A deterministic transfer card: identity scalar, keys, member ID and ca1 certificate. */
    private record Card(
            String name,
            BigInteger privateKey,
            byte[] a,
            byte[] uncompressed,
            byte[] id,
            byte[] cert) {
        static Card of(String name, boolean oddY, BigInteger ca1) {
            BigInteger d = Cards.identityPrivate("transfer/" + name, oddY);
            byte[] pub = Crypto.publicKey(d);
            byte[] a = Crypto.compress(pub);
            byte[] cert = Certificates.issue(ca1, a);
            assertTrue(Certificates.verify(Crypto.publicKey(ca1), cert), "card cert " + name);
            return new Card(name, d, a, pub, Ids.cardId(a), cert);
        }
    }

    /** A wallet as the creator's CREATE command sees it. */
    private record Wallet(
            String name,
            String creator,
            Object create,
            byte[] seed,
            int origin,
            byte[] memberIds,
            byte[] masterPublicKey) {

        /** {@code c ‖ IDs}, the stored members block. */
        byte[] members() {
            byte[] out = new byte[1 + memberIds.length];
            out[0] = (byte) (memberIds.length / 16);
            System.arraycopy(memberIds, 0, out, 1, memberIds.length);
            return out;
        }

        /** {@code masterPublicKey ‖ origin ‖ c ‖ IDs}, the WalletInfo of §9.2. */
        byte[] walletInfo() {
            byte[] members = members();
            byte[] out = new byte[33 + 1 + members.length];
            System.arraycopy(masterPublicKey, 0, out, 0, 33);
            out[33] = (byte) origin;
            System.arraycopy(members, 0, out, 34, members.length);
            return out;
        }
    }

    /** One transfer row's computed material plus its serialised form. */
    private record Transfer(
            String name,
            Wallet wallet,
            Card source,
            Card target,
            String targetLife,
            int slotOnSource,
            int slotOnTarget,
            BigInteger linkPrivate,
            byte[] lk,
            byte[] offerHash,
            byte[] offerSignature,
            BigInteger e,
            byte[] ep,
            byte[] z,
            byte[] m,
            byte[] th,
            byte[] exportSignature,
            byte[] kTe,
            byte[] kTm,
            byte[] accessHashT,
            byte[] payload,
            byte[] ct,
            byte[] tag,
            byte[] walletInfo) {

        static Transfer of(
                String name, Wallet wallet, Card source, Card target, String targetLife) {
            BigInteger linkPrivate = Cards.scalar("transfer/" + name + "/link");
            BigInteger e = Cards.scalar("transfer/" + name + "/e");
            byte[] accessHashT = Vec.det("transfer/" + name + "/accessHashT");

            byte[] lk = Crypto.publicKey(linkPrivate);
            byte[] offerHash = Crypto.sha256(LABEL_OFFER, lk);
            byte[] offerSignature = Crypto.sign(target.privateKey(), offerHash);
            assertTrue(
                    Crypto.verify(target.uncompressed(), offerHash, offerSignature),
                    name + " offerSignature");

            byte[] ep = Crypto.publicKey(e);
            assertTrue(decompressReason(Crypto.compress(ep)) == null, name + " E");
            byte[] z = Arrays.copyOfRange(Crypto.multiply(e, lk), 1, 33);
            byte[] z2 = Arrays.copyOfRange(Crypto.multiply(linkPrivate, ep), 1, 33);
            assertTrue(Arrays.equals(z, z2), name + " Z mismatch");
            byte[] m = concat(LABEL_EXPORT, source.a(), target.a(), lk, ep);
            assertTrue(m.length == 215, name + " M length");
            byte[] th = Crypto.sha256(m);
            byte[] exportSignature = Crypto.sign(source.privateKey(), th);
            assertTrue(
                    Crypto.verify(source.uncompressed(), th, exportSignature),
                    name + " exportSignature");

            byte[] keys = Crypto.kdf(z, LABEL_KDF, th, 32);
            byte[] kTe = Arrays.copyOf(keys, 16);
            byte[] kTm = Arrays.copyOfRange(keys, 16, 32);

            byte[] payload =
                    concat(
                            new byte[] {(byte) wallet.origin()},
                            wallet.seed(),
                            accessHashT,
                            wallet.members());
            byte[] ct = Crypto.aesCbc(kTe, ZEROS, Crypto.m2pad(payload), true);
            byte[] tag = Crypto.cmac(kTm, ct);

            return new Transfer(
                    name,
                    wallet,
                    source,
                    target,
                    targetLife,
                    slot(source, target, wallet, "LOADED"),
                    slot(target, source, wallet, targetLife),
                    linkPrivate,
                    lk,
                    offerHash,
                    offerSignature,
                    e,
                    ep,
                    z,
                    m,
                    th,
                    exportSignature,
                    kTe,
                    kTm,
                    accessHashT,
                    payload,
                    ct,
                    tag,
                    wallet.walletInfo());
        }

        Object row() {
            return Vec.object(
                    "name", name,
                    "wallet", wallet.name(),
                    "source", source.name(),
                    "target", target.name(),
                    "targetLife", targetLife,
                    "slotOnSource", slotOnSource,
                    "slotOnTarget", slotOnTarget,
                    "linkPrivate", Vec.hex(Vec.scalar(linkPrivate)),
                    "LK", Vec.hex(lk),
                    "offerHash", Vec.hex(offerHash),
                    "offerSignature", Vec.hex(offerSignature),
                    "e", Vec.hex(Vec.scalar(e)),
                    "E", Vec.hex(ep),
                    "Z", Vec.hex(z),
                    "M", Vec.hex(m),
                    "TH", Vec.hex(th),
                    "exportSignature", Vec.hex(exportSignature),
                    "kTe", Vec.hex(kTe),
                    "kTm", Vec.hex(kTm),
                    "accessHashT", Vec.hex(accessHashT),
                    "payload", Vec.hex(payload),
                    "ct", Vec.hex(ct),
                    "tag", Vec.hex(tag),
                    "walletInfo", Vec.hex(walletInfo));
        }
    }

    private TransferDoc() {}

    static Object document() {
        Card source = Card.of("source", false, CertDoc.CA1);
        Card target = Card.of("target", true, CertDoc.CA1);
        Card third = Card.of("third", false, CertDoc.CA1);
        List<Card> cards = List.of(source, target, third);

        Wallet imported = importedWallet(source, target);
        Wallet generated = generatedWallet(source, target, third);

        List<Transfer> transfers =
                List.of(
                        Transfer.of("imported-to-target", imported, source, target, "BLANK"),
                        Transfer.of("imported-reseal-target", imported, source, target, "LOADED"),
                        Transfer.of("generated-to-target", generated, source, target, "BLANK"),
                        Transfer.of("generated-to-third", generated, source, third, "BLANK"),
                        Transfer.of(
                                "generated-reseal-third-from-target",
                                generated,
                                target,
                                third,
                                "LOADED"));

        byte[] twist = twistPoint();
        byte[] invalidCurve = invalidCurvePoint();

        return Vec.object(
                "labels",
                        Vec.object(
                                "offer", Vec.hex(LABEL_OFFER),
                                "export", Vec.hex(LABEL_EXPORT),
                                "kdfTransfer", Vec.hex(LABEL_KDF)),
                "ca", Vec.hex(Crypto.publicKey(CertDoc.CA1)),
                "cards", List.of(cardRow(source), cardRow(target), cardRow(third)),
                "decompress", decompressRows(cards),
                "wallets", List.of(walletRow(imported), walletRow(generated)),
                "transfers",
                        List.of(
                                transfers.get(0).row(),
                                transfers.get(1).row(),
                                transfers.get(2).row(),
                                transfers.get(3).row(),
                                transfers.get(4).row()),
                "probes",
                        Vec.object(
                                "twist", Vec.hex(twist),
                                "invalidCurve", Vec.hex(invalidCurve)),
                "rejectedOffers", rejectedOffers(transfers.get(0), target, third, twist),
                "rejectedExports",
                        rejectedExports(
                                transfers.get(0),
                                transfers.get(1),
                                source,
                                target,
                                third,
                                twist,
                                invalidCurve),
                "rejectedPayloads", rejectedPayloads(transfers.get(0), transfers.get(1), third));
    }

    // ── cards / decompress ─────────────────────────────────────────────

    private static Object cardRow(Card c) {
        return Vec.object(
                "name", c.name(),
                "private", Vec.hex(Vec.scalar(c.privateKey())),
                "A", Vec.hex(c.a()),
                "uncompressed", Vec.hex(c.uncompressed()),
                "id", Vec.hex(c.id()),
                "cert", Vec.hex(c.cert()));
    }

    /** The card's own §10.5 check: {@code null} when the point decompresses, else the reason. */
    private static String decompressReason(byte[] compressed) {
        int prefix = compressed[0] & 0xFF;
        if (prefix != 0x02 && prefix != 0x03) {
            return "prefix not 02 or 03";
        }
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(compressed, 1, 33));
        if (x.compareTo(P) >= 0) {
            return "x >= p";
        }
        if (!isResidue(x.modPow(THREE, P).add(SEVEN).mod(P))) {
            return "x^3 + 7 is a quadratic non-residue";
        }
        return null;
    }

    private static List<Object> decompressRows(List<Card> cards) {
        List<Object> rows = new ArrayList<>();
        List<byte[]> randoms = new ArrayList<>();
        for (Card c : cards) {
            rows.add(decompressRow("card-" + c.name(), c.a()));
        }
        for (int i = 0; i < 16; i++) {
            BigInteger d = Cards.scalar("transfer/decompress/" + i);
            byte[] pub = Crypto.publicKey(d);
            randoms.add(pub);
            rows.add(decompressRow("random-" + i, Crypto.compress(pub)));
        }
        // the same x with the other prefix: a different, also-valid point with y' = p − y
        for (int i = 0; i < 2; i++) {
            byte[] flipped = new byte[33];
            flipped[0] = (byte) ((randoms.get(i)[64] & 1) == 0 ? 0x03 : 0x02);
            System.arraycopy(randoms.get(i), 1, flipped, 1, 32);
            rows.add(decompressRow("parity-flip-" + i, flipped));
        }
        // x = 5 is the smallest positive x whose x³ + 7 is a non-residue (asserted below)
        for (int x = 1; x < 5; x++) {
            BigInteger bx = BigInteger.valueOf(x);
            assertTrue(
                    isResidue(bx.modPow(THREE, P).add(SEVEN).mod(P)),
                    "x = " + x + " should be a residue");
        }
        assertTrue(!isResidue(BigInteger.valueOf(132)), "x = 5 should be a non-residue");
        byte[] even5 = new byte[33];
        even5[0] = 0x02;
        even5[32] = 0x05;
        byte[] odd5 = even5.clone();
        odd5[0] = 0x03;
        byte[] xIsP = new byte[33];
        xIsP[0] = 0x02;
        System.arraycopy(Vec.scalar(P), 0, xIsP, 1, 32);
        byte[] xMax = new byte[33];
        xMax[0] = 0x03;
        Arrays.fill(xMax, 1, 33, (byte) 0xFF);
        Card source = cards.get(0);
        byte[] prefix04 = new byte[33];
        prefix04[0] = 0x04;
        System.arraycopy(source.a(), 1, prefix04, 1, 32);
        byte[] prefix00 = new byte[33];
        System.arraycopy(source.a(), 1, prefix00, 1, 32);
        rows.add(invalidRow("non-residue-even", even5));
        rows.add(invalidRow("non-residue-odd", odd5));
        rows.add(invalidRow("x-is-p", xIsP));
        rows.add(invalidRow("x-max", xMax));
        rows.add(invalidRow("prefix-04", prefix04));
        rows.add(invalidRow("prefix-00", prefix00));
        return rows;
    }

    private static Object decompressRow(String name, byte[] compressed) {
        String reason = decompressReason(compressed);
        assertTrue(reason == null, name + " unexpectedly invalid: " + reason);
        byte[] uncompressed = Crypto.DOMAIN.getCurve().decodePoint(compressed).getEncoded(false);
        assertTrue(uncompressed.length == 65 && uncompressed[0] == 0x04, name);
        return Vec.object(
                "name",
                name,
                "compressed",
                Vec.hex(compressed),
                "valid",
                Boolean.TRUE,
                "uncompressed",
                Vec.hex(uncompressed));
    }

    private static Object invalidRow(String name, byte[] compressed) {
        String reason = decompressReason(compressed);
        assertTrue(reason != null, name + " unexpectedly valid");
        return Vec.object(
                "name",
                name,
                "compressed",
                Vec.hex(compressed),
                "valid",
                Boolean.FALSE,
                "reason",
                reason);
    }

    // ── wallets ────────────────────────────────────────────────────────

    private static Wallet importedWallet(Card source, Card target) {
        byte[] seed = Vec.det("transfer/imported/seed", 64);
        byte[] accessHash = Vec.det("transfer/imported/accessHash");
        byte[] memberIds = concat(source.id(), target.id());
        return new Wallet(
                "imported",
                source.name(),
                Vec.object(
                        "p1", "01",
                        "accessHash", Vec.hex(accessHash),
                        "seed", Vec.hex(seed),
                        "others", List.of(Vec.hex(target.id()))),
                seed,
                0x02,
                memberIds,
                masterPublicKey(seed));
    }

    private static Wallet generatedWallet(Card source, Card target, Card third) {
        BigInteger t = Cards.scalar("transfer/generated/t");
        byte[] hostEntropy = Vec.det("transfer/generated/hostEntropy");
        byte[] seed = Crypto.sha512(LABEL_SEED, Vec.scalar(t), hostEntropy);
        byte[] accessHash = Vec.det("transfer/generated/accessHash");
        byte[] memberIds = concat(source.id(), target.id(), third.id());
        return new Wallet(
                "generated",
                source.name(),
                Vec.object(
                        "p1", "00",
                        "accessHash", Vec.hex(accessHash),
                        "hostEntropy", Vec.hex(hostEntropy),
                        "t", Vec.hex(Vec.scalar(t)),
                        "others", List.of(Vec.hex(target.id()), Vec.hex(third.id()))),
                seed,
                0x01,
                memberIds,
                masterPublicKey(seed));
    }

    /** Compressed {@code kM·G} of the BIP-32 master; {@link Hd#bip32Master} asserts validity. */
    private static byte[] masterPublicKey(byte[] seed) {
        Hd.Node master = Hd.bip32Master(seed);
        return Crypto.compress(Crypto.publicKey(new BigInteger(1, master.privateKey())));
    }

    private static Object walletRow(Wallet w) {
        return Vec.object(
                "name", w.name(),
                "creator", w.creator(),
                "create", w.create(),
                "seed", Vec.hex(w.seed()),
                "origin", String.format("%02x", w.origin()),
                "members", Vec.hex(w.members()),
                "masterPublicKey", Vec.hex(w.masterPublicKey()));
    }

    /**
     * The peer-key slot of §16.1 item 1: the position of {@code peer} among the members other than
     * {@code card} itself, in {@code members} order; {@code BLANK} always slot 0.
     */
    private static int slot(Card card, Card peer, Wallet wallet, String life) {
        if (life.equals("BLANK")) {
            return 0;
        }
        byte[] members = wallet.members();
        int c = members[0] & 0xFF;
        int self = -1;
        int found = -1;
        for (int i = 0; i < c; i++) {
            byte[] id = Arrays.copyOfRange(members, 1 + 16 * i, 1 + 16 * (i + 1));
            if (Arrays.equals(id, card.id())) {
                self = i;
            }
            if (Arrays.equals(id, peer.id())) {
                found = i;
            }
        }
        assertTrue(self >= 0 && found >= 0 && self != found, "slot: peer not a member");
        return found - (found > self ? 1 : 0);
    }

    // ── probes ─────────────────────────────────────────────────────────

    /** The Legendre symbol of {@code v}: 1 residue, −1 non-residue, 0 zero. */
    private static int legendre(BigInteger v) {
        BigInteger l = v.modPow(LEGENDRE, P);
        return l.equals(BigInteger.ONE) ? 1 : l.equals(P.subtract(BigInteger.ONE)) ? -1 : 0;
    }

    private static boolean isResidue(BigInteger v) {
        return legendre(v) == 1;
    }

    /** The even square root of the residue {@code v} (p ≡ 3 mod 4). */
    private static BigInteger evenSqrt(BigInteger v) {
        BigInteger y = v.modPow(SQRT, P);
        if (y.testBit(0)) {
            y = P.subtract(y);
        }
        assertTrue(y.multiply(y).mod(P).equals(v), "sqrt");
        return y;
    }

    /**
     * {@code 04 ‖ x=5 ‖ y} with {@code y² = (5³ + 7)·d mod p} for the smallest non-residue {@code d
     * ≥ 2}: a point on a quadratic twist, off the curve.
     */
    private static byte[] twistPoint() {
        BigInteger d = BigInteger.TWO;
        while (isResidue(d)) {
            d = d.add(BigInteger.ONE);
        }
        BigInteger rhs = BigInteger.valueOf(132).multiply(d).mod(P);
        assertTrue(isResidue(rhs), "twist rhs should be a residue");
        return point(BigInteger.valueOf(5), evenSqrt(rhs));
    }

    /** {@code 04 ‖ 1 ‖ y} with {@code y² = 2 mod p}: on {@code y² = x³ + 1}, off this curve. */
    private static byte[] invalidCurvePoint() {
        assertTrue(isResidue(BigInteger.TWO), "2 should be a residue");
        return point(BigInteger.ONE, evenSqrt(BigInteger.TWO));
    }

    private static byte[] point(BigInteger x, BigInteger y) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(Vec.scalar(x), 0, out, 1, 32);
        System.arraycopy(Vec.scalar(y), 0, out, 33, 32);
        return out;
    }

    // ── rejected tables ────────────────────────────────────────────────

    private static byte[] signForOffer(Card target, byte[] lk) {
        byte[] hash = Crypto.sha256(LABEL_OFFER, lk);
        byte[] sig = Crypto.sign(target.privateKey(), hash);
        assertTrue(Crypto.verify(target.uncompressed(), hash, sig), "offer sign");
        return sig;
    }

    private static Object rejectedOffers(Transfer t, Card target, Card third, byte[] twist) {
        byte[] certOtherCa = Certificates.issue(CertDoc.CA2, target.a());
        byte[] sigByThird = Crypto.sign(third.privateKey(), Crypto.sha256(LABEL_OFFER, t.lk()));

        byte[] lk03 = t.lk().clone();
        lk03[0] = 0x03;
        byte[] lkOffCurve = t.lk().clone();
        lkOffCurve[64] ^= 0x01;
        byte[] lkXIsP = t.lk().clone();
        System.arraycopy(Vec.scalar(P), 0, lkXIsP, 1, 32);
        byte[] badSig = t.offerSignature().clone();
        badSig[63] ^= 0x01;

        return List.of(
                rejectedOffer(
                        "cert-other-ca",
                        certOtherCa,
                        t.lk(),
                        signForOffer(target, t.lk()),
                        1,
                        "certificate does not verify under caKey"),
                rejectedOffer(
                        "cert-own",
                        t.source().cert(),
                        t.lk(),
                        signForOffer(target, t.lk()),
                        2,
                        "target certificate is the own card"),
                rejectedOffer(
                        "cert-non-member",
                        third.cert(),
                        t.lk(),
                        sigByThird,
                        3,
                        "target is not a member"),
                rejectedOffer(
                        "offer-prefix-03",
                        target.cert(),
                        lk03,
                        signForOffer(target, lk03),
                        5,
                        "LK_T[0] is not 0x04"),
                rejectedOffer(
                        "offer-bad-signature",
                        target.cert(),
                        t.lk(),
                        badSig,
                        5,
                        "sig_T does not verify under A_T"),
                rejectedOffer(
                        "offer-wrong-key",
                        target.cert(),
                        t.lk(),
                        sigByThird,
                        5,
                        "sig_T does not verify under A_T"),
                rejectedOffer(
                        "lk-off-curve",
                        target.cert(),
                        lkOffCurve,
                        signForOffer(target, lkOffCurve),
                        6,
                        "LK_T is not a valid point"),
                rejectedOffer(
                        "lk-x-is-p",
                        target.cert(),
                        lkXIsP,
                        signForOffer(target, lkXIsP),
                        6,
                        "LK_T is not a valid point"),
                rejectedOffer(
                        "lk-twist",
                        target.cert(),
                        twist,
                        signForOffer(target, twist),
                        6,
                        "LK_T is not a valid point"));
    }

    private static Object rejectedOffer(
            String name, byte[] cert, byte[] lk, byte[] signature, int check, String reason) {
        return Vec.object(
                "name",
                name,
                "transfer",
                "imported-to-target",
                "cert",
                Vec.hex(cert),
                "LK",
                Vec.hex(lk),
                "signature",
                Vec.hex(signature),
                "check",
                check,
                "reason",
                reason);
    }

    private static Object rejectedExports(
            Transfer t,
            Transfer reseal,
            Card source,
            Card target,
            Card third,
            byte[] twist,
            byte[] invalidCurve) {
        byte[] certOtherCa = Certificates.issue(CertDoc.CA2, source.a());
        byte[] staleLk = Crypto.publicKey(Cards.scalar("transfer/stale/link"));
        byte[] tampered = t.ep().clone();
        tampered[64] ^= 0x01;

        List<Object> rows = new ArrayList<>();
        rows.add(
                export(
                        "cert-other-ca",
                        t.name(),
                        certOtherCa,
                        t.ep(),
                        t.exportSignature(),
                        1,
                        "certificate does not verify under caKey"));
        rows.add(
                export(
                        "cert-own",
                        t.name(),
                        target.cert(),
                        t.ep(),
                        t.exportSignature(),
                        2,
                        "sender certificate is the own card"));
        rows.add(
                export(
                        "cert-non-member-loaded",
                        reseal.name(),
                        third.cert(),
                        reseal.ep(),
                        reseal.exportSignature(),
                        3,
                        "sender is not a member"));
        rows.add(
                export(
                        "cert-not-sender-blank",
                        t.name(),
                        third.cert(),
                        t.ep(),
                        t.exportSignature(),
                        5,
                        "sig_S does not verify under A_S"));
        rows.add(
                export(
                        "tampered-e",
                        t.name(),
                        source.cert(),
                        tampered,
                        t.exportSignature(),
                        5,
                        "sig_S does not cover this E"));
        // M' carries a different link key: sig_S verifies for M', not for the card's M
        byte[] staleM = concat(LABEL_EXPORT, source.a(), target.a(), staleLk, t.ep());
        byte[] staleSig = Crypto.sign(source.privateKey(), Crypto.sha256(staleM));
        rows.add(
                export(
                        "stale-lk",
                        t.name(),
                        source.cert(),
                        t.ep(),
                        staleSig,
                        5,
                        "sig_S covers a different LK"));

        String reason = "E is not a valid point";
        rows.add(badE("e-off-curve", t, tampered, 6, reason));
        byte[] xIsP = t.ep().clone();
        System.arraycopy(Vec.scalar(P), 0, xIsP, 1, 32);
        rows.add(badE("e-x-is-p", t, xIsP, 6, reason));
        byte[] prefix02 = t.ep().clone();
        prefix02[0] = 0x02;
        rows.add(badE("e-prefix-02", t, prefix02, 6, reason));
        rows.add(badE("e-zero", t, new byte[65], 6, reason));
        rows.add(badE("e-twist", t, twist, 6, reason));
        rows.add(badE("e-invalid-curve", t, invalidCurve, 6, reason));
        return rows;
    }

    /** A check-6 row: signed by the source over M built with the bad E and the transfer's LK. */
    private static Object badE(String name, Transfer t, byte[] e, int check, String reason) {
        byte[] m = concat(LABEL_EXPORT, t.source().a(), t.target().a(), t.lk(), e);
        byte[] sig = Crypto.sign(t.source().privateKey(), Crypto.sha256(m));
        return export(name, t.name(), t.source().cert(), e, sig, check, reason);
    }

    private static Object export(
            String name,
            String transfer,
            byte[] cert,
            byte[] e,
            byte[] signature,
            int check,
            String reason) {
        return Vec.object(
                "name", name,
                "transfer", transfer,
                "cert", Vec.hex(cert),
                "E", Vec.hex(e),
                "signature", Vec.hex(signature),
                "check", check,
                "reason", reason);
    }

    private static Object rejectedPayloads(Transfer t, Transfer reseal, Card third) {
        List<Object> rows = new ArrayList<>();

        byte[] badTag = t.tag().clone();
        badTag[15] ^= 0x01;
        byte[] badCt = t.ct().clone();
        badCt[0] ^= 0x01;
        byte[] padded = Crypto.m2pad(t.payload());
        byte[] noPad = padded.clone();
        noPad[t.payload().length] = 0x00;
        byte[] noPadCt = encrypt(t.kTe(), noPad);

        rows.add(
                payload(
                        "tag-flipped",
                        t.name(),
                        padded,
                        t.ct(),
                        badTag,
                        1,
                        "tag does not match ct"));
        rows.add(
                payload(
                        "ct-flipped",
                        t.name(),
                        padded,
                        badCt,
                        t.tag(),
                        1,
                        "tag does not match ct"));
        rows.add(
                payload(
                        "bad-padding",
                        t.name(),
                        noPad,
                        noPadCt,
                        Crypto.cmac(t.kTm(), noPadCt),
                        2,
                        "M2 unpadding fails"));

        byte[] countMismatch = t.payload().clone();
        countMismatch[97] = 0x03;
        byte[] countOne = t.payload().clone();
        countOne[97] = 0x01;
        byte[] origin00 = t.payload().clone();
        origin00[0] = 0x00;
        byte[] origin03 = t.payload().clone();
        origin03[0] = 0x03;

        rows.add(
                payloadRow(
                        "count-mismatch", t, countMismatch, 2, "payload length does not match c"));
        rows.add(payloadRow("count-one", t, countOne, 2, "payload length does not match c"));
        rows.add(payloadRow("origin-00", t, origin00, 3, "origin is not 0x01 or 0x02"));
        rows.add(payloadRow("origin-03", t, origin03, 3, "origin is not 0x01 or 0x02"));

        // ids-duplicate: source ‖ source; not-listing-target: source ‖ third;
        // not-listing-source: third ‖ target
        rows.add(
                idsRow(
                        "ids-duplicate",
                        t,
                        ids(t.source().id(), t.source().id()),
                        3,
                        "member IDs are not pairwise distinct"));
        rows.add(
                idsRow(
                        "not-listing-target",
                        t,
                        ids(t.source().id(), third.id()),
                        3,
                        "the importing card is not among the members"));
        rows.add(
                idsRow(
                        "not-listing-source",
                        t,
                        ids(third.id(), t.target().id()),
                        3,
                        "the sender is not among the members"));

        // the LOADED re-seal rows of imported-reseal-target: check 5
        byte[] otherSeed = reseal.payload().clone();
        byte[] newSeed = Vec.det("transfer/other/seed", 64);
        System.arraycopy(newSeed, 0, otherSeed, 1, 64);
        Hd.bip32Master(newSeed); // check 4 must pass for the row to reach check 5
        rows.add(
                payloadRow(
                        "reseal-other-seed",
                        reseal,
                        otherSeed,
                        5,
                        "fingerprint does not equal the stored fp"));

        byte[] otherOrigin = reseal.payload().clone();
        otherOrigin[0] = 0x01;
        rows.add(
                payloadRow(
                        "reseal-other-origin",
                        reseal,
                        otherOrigin,
                        5,
                        "origin does not equal the stored origin"));

        byte[] swapped = reseal.payload().clone();
        System.arraycopy(reseal.payload(), 98 + 16, swapped, 98, 16);
        System.arraycopy(reseal.payload(), 98, swapped, 98 + 16, 16);
        rows.add(
                payloadRow(
                        "reseal-other-members",
                        reseal,
                        swapped,
                        5,
                        "members do not equal the stored members"));

        byte[] three = new byte[146];
        System.arraycopy(reseal.payload(), 0, three, 0, 97);
        three[97] = 0x03;
        System.arraycopy(reseal.payload(), 98, three, 98, 32);
        System.arraycopy(third.id(), 0, three, 130, 16);
        rows.add(
                payloadRow(
                        "reseal-other-members-three",
                        reseal,
                        three,
                        5,
                        "members do not equal the stored members"));
        return rows;
    }

    private static byte[] encrypt(byte[] kTe, byte[] plaintext) {
        return Crypto.aesCbc(kTe, ZEROS, plaintext, true);
    }

    private static Object payloadRow(
            String name, Transfer t, byte[] payload, int check, String reason) {
        byte[] padded = Crypto.m2pad(payload);
        byte[] ct = encrypt(t.kTe(), padded);
        return payload(name, t.name(), padded, ct, Crypto.cmac(t.kTm(), ct), check, reason);
    }

    /** A row whose member IDs are replaced while the rest of the payload is kept. */
    private static Object idsRow(String name, Transfer t, byte[] ids, int check, String reason) {
        byte[] p = t.payload().clone();
        p[97] = (byte) (ids.length / 16);
        byte[] out = new byte[98 + ids.length];
        System.arraycopy(p, 0, out, 0, 97);
        out[97] = (byte) (ids.length / 16);
        System.arraycopy(ids, 0, out, 98, ids.length);
        return payloadRow(name, t, out, check, reason);
    }

    private static byte[] ids(byte[]... parts) {
        return concat(parts);
    }

    private static Object payload(
            String name,
            String transfer,
            byte[] plaintext,
            byte[] ct,
            byte[] tag,
            int check,
            String reason) {
        return Vec.object(
                "name", name,
                "transfer", transfer,
                "plaintext", Vec.hex(plaintext),
                "ct", Vec.hex(ct),
                "tag", Vec.hex(tag),
                "check", check,
                "reason", reason);
    }

    private static byte[] concat(byte[]... parts) {
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

    private static void assertTrue(boolean cond, String what) {
        if (!cond) {
            throw new IllegalStateException("transfer.json assertion failed: " + what);
        }
    }
}
