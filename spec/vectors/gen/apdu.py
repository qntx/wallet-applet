#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 QuantX
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Generates spec/vectors/apdu.json from the protocol tables (spec/protocol.md §18).

Transcribes the checks of §8.1 (OPEN), §8.3 (SESSION, outer only — the record-level cases
live in record.json), §9.2 (checking order and the unknown-INS case), §9.3–9.11 and §9.15
(STATUS, CREATE, VERIFY, CHANGE, ERASE, PUBLIC_KEY, SIGN_ECDSA, SIGN_BIP340, SIGN_ED25519,
WAIT), §9.12–9.14 (OFFER, EXPORT, IMPORT) and §14.1–14.2 (GET_IDENTITY, PERSONALIZE). Preconditions that need a prepared failure
count (the WAIT gate of §9.5) are in verify-sequence.json; data checks that no fixed input can
reach (an invalid BIP-32 master or child, probability about 2^-127) are tested by fault
injection, and the exhausted Ed25519 counter (edCounter = 0xFFFFFFFF after 2^32 - 1
signatures) by a prepared persistent state, not listed here. An update chunk of more than 236
bytes cannot be carried by a command record (§8.3), so its length case is not listed either.
Transfer data checks that only a forged peer can reach — an offer or export whose identity
signature is valid over an invalid point (EXPORT LK_T, IMPORT E) and IMPORT P1 = 01 payloads with
a valid MAC but invalid content — need the peer's private keys and are in transfer.json; the
OFFER/IMPORT sequences of §18 are in verify-sequence.json. Transfer cases run against a second
genuine card, {peer}, whose role each life value describes (STATES).
APDUs are templates with {symbol} placeholders;
this script computes each Lc byte from the symbol lengths. In every command, case k violates
check k and every later check that can be violated at the same time, and expects check k's
status word; the last case is the success case. Stdlib only; output is canonical
(json.dumps(obj, indent=2) + "\\n", ASCII).

Usage: python3 apdu.py [out.json]
"""
import json
import sys

# Placeholder byte lengths. {record0} is the ct‖tag part of record.json commands[0].
SYMBOL_LEN = {
    "A": 33,
    "cert": 97,
    "cert.otherA": 97,
    "cert.otherCa": 97,
    "caKey": 65,
    "caKey.prefix03": 65,
    "caKey.xIsP": 65,
    "caKey.yIsP": 65,
    "caKey.offCurve": 65,
    "hostEph": 65,
    "hostEph.prefix02": 65,
    "hostEph.offCurve": 65,
    "openResponse": 226,
    "record0": 24,
    "accessHash": 32,
    "accessHash.wrong": 32,
    "accessHash.new": 32,
    "entropy": 32,
    "seed": 64,
    "id.self": 16,
    "id.other1": 16,
    "id.other2": 16,
    "digest": 32,
    "message": 32,
    "tweak.bip86": 32,
    "tweak.zeroKey": 32,
    "peer.cert": 97,
    "peer.cert.otherCa": 97,
    "peer.id": 16,
    "peer.offer": 129,
    "peer.offer.badSig": 129,
    "peer.offer.prefix03": 129,
    "peer.exportHead": 129,
    "peer.exportHead.badSig": 129,
    "peer.exportPayload": 160,
    "peer.exportPayload.badTag": 160,
    "peer.exportPayload.badCt": 160,
    "cert.badPoint": 97,
    "id.badPoint": 16,
}

SYMBOLS = {
    "A": "33 bytes: the compressed identity key of the card under test, cert[0..33) — cert.json's card1",
    "cert": "97 bytes: cert = A ‖ r ‖ s of the card under test under ca1 — cert.json's card1 certificate",
    "cert.otherA": "97 bytes: a certificate under ca1 for a different identity key — cert.json's card2 certificate",
    "cert.otherCa": "97 bytes: the certificate of this card's A issued under ca2 — cert.json identity card1 signed by ca2",
    "caKey": "65 bytes: the uncompressed public key of ca1 — cert.json cas[0].public",
    "caKey.prefix03": "65 bytes: caKey with the first byte changed to 0x03 (not an uncompressed point)",
    "caKey.xIsP": "65 bytes: caKey with x replaced by the field prime p",
    "caKey.yIsP": "65 bytes: caKey with y replaced by the field prime p",
    "caKey.offCurve": "65 bytes: caKey with y flipped so y^2 != x^3 + 7 (mod p)",
    "hostEph": "65 bytes: a valid uncompressed host ephemeral public key — session.json hostEph",
    "hostEph.prefix02": "65 bytes: hostEph with the first byte changed to 0x02",
    "hostEph.offCurve": "65 bytes: hostEph with y flipped so the point is off the curve",
    "openResponse": "226 bytes: cardEph ‖ sig ‖ cert plus SW 9000; verified through Open.response (session.json)",
    "record0": "24 bytes: ct ‖ tag of record.json commands[0].apdu — a well-formed record",
    "accessHash": "32 bytes: the access hash the LOADED card under test was created with (any fixed value; the card never sees the code)",
    "accessHash.wrong": "32 bytes: an access hash different from {accessHash}",
    "accessHash.new": "32 bytes: an access hash different from {accessHash} and {accessHash.wrong}, used by CHANGE",
    "entropy": "32 bytes: host entropy for CREATE P1 = 00 (any value)",
    "seed": "64 bytes: derivation.json templates.seed (its BIP-32 master key is valid)",
    "id.self": "16 bytes: ID(A) of the card under test",
    "id.other1": "16 bytes: a card ID different from {id.self}",
    "id.other2": "16 bytes: a card ID different from {id.self} and {id.other1}",
    "seed.masterPublicKey": "response only, 33 bytes: compressed BIP-32 master public key of {seed} (derivation.json templates.masterPublicKey)",
    "masterPublicKey.any": "response only, 33 bytes: a compressed secp256k1 point (prefix 02 or 03, x on the curve); the value is random",
    "pk.secp.evm": "response only, 65 bytes: publicKey(33) ‖ chainCode(32) of m/44'/60'/0'/0/0 under {seed} (derivation.json templates)",
    "pk.ed.solana": "response only, 64 bytes: W(A) of m/44'/501'/0'/0' under {seed} (derivation.json templates)",
    "digest": "32 bytes: a fixed SIGN_ECDSA digest (any value)",
    "message": "32 bytes: a fixed SIGN_BIP340 message (any value)",
    "tweak.bip86": "32 bytes: TaggedHash(\"TapTweak\", x(P)) (BIP-341) where P is the public key of m/86'/0'/0'/0/0 under {seed} (derivation.json templates btc-bip86)",
    "tweak.zeroKey": "32 bytes: n - d0' where d0' is the private key of m/86'/0'/0'/0/0 under {seed}, replaced by n - d0 when its public key has odd y (§12.2); the tweaked key d0' + t is 0 mod n",
    "sig.ecdsa.evm": "response only, 64 bytes: r ‖ s with r, s in [1, n-1], a valid ECDSA signature (§12.1, e = int({digest})) under the public key of m/44'/60'/0'/0/0 under {seed} (derivation.json templates evm); random nonce",
    "sig.ecdsa.bip84Account": "response only, 64 bytes: r ‖ s with r, s in [1, n-1], a valid ECDSA signature of {digest} under the public key of m/84'/0'/0' under {seed} (derivation.json templates btc-bip84-account); random nonce",
    "sig.bip340.bip86": "response only, 64 bytes: R_x ‖ s, a valid BIP-340 signature of {message} under the x-only output key x(P_even + int({tweak.bip86})·G) of m/86'/0'/0'/0/0 under {seed}; random aux",
    "sig.bip340.untweaked": "response only, 64 bytes: R_x ‖ s, a valid BIP-340 signature of {message} under x(P) where P is the public key of m/86'/0'/0'/0/0 under {seed}; random aux",
    "wei.any": "response only, 64 bytes: X ‖ Y of a point on Wei25519 (§10.4) other than the base point; the nonce is random",
    "ed25519.S.any": "response only, 32 bytes: le32(S) with int_le(S) < l; S depends on the random nonce of the stream's begin",
    "peer.cert": "97 bytes: the certificate of {peer}, a second card personalized under ca1 (cert = A_peer ‖ Sign(ca1, \"qntx-card/v1/cert\" ‖ A_peer))",
    "peer.cert.otherCa": "97 bytes: the certificate of {peer}'s identity key A_peer issued under ca2",
    "peer.id": "16 bytes: ID(A_peer) of {peer}",
    "peer.offer": "129 bytes: LK ‖ sig, the OFFER response of {peer} (life SOURCE: {peer} is BLANK and answered one OFFER)",
    "peer.offer.badSig": "129 bytes: {peer.offer} with its last byte xored with 0x01",
    "peer.offer.prefix03": "129 bytes: {peer.offer} with its first byte changed to 0x03",
    "peer.exportHead": "129 bytes: E ‖ sig_S, the response of {peer} (the source of life TARGET and TARGET-LOADED, verified) to EXPORT P1 = 00 with {cert} ‖ the OFFER response of the card under test in the case's session",
    "peer.exportHead.badSig": "129 bytes: {peer.exportHead} with its last byte xored with 0x01",
    "peer.exportPayload": "160 bytes: ct(144) ‖ tag(16), the response of {peer} to EXPORT P1 = 01 with {accessHash.new}, sent right after the EXPORT P1 = 00 that produced {peer.exportHead}",
    "peer.exportPayload.badTag": "160 bytes: {peer.exportPayload} with its last byte (in tag) xored with 0x01",
    "peer.exportPayload.badCt": "160 bytes: {peer.exportPayload} with its first byte (in ct) xored with 0x01",
    "cert.badPoint": "97 bytes: a certificate under ca1 for A' = 0x02 ‖ u256(5); x = 5 is the smallest positive x for which x^3 + 7 is a quadratic non-residue mod p, so A' does not decompress (§10.5)",
    "id.badPoint": "16 bytes: ID(A') of the A' of {cert.badPoint}",
    "offer.any": "response only, 129 bytes: LK ‖ sig where LK is a valid uncompressed secp256k1 point and sig a valid signature under {A} of \"qntx-card/v1/offer\" ‖ LK (§9.12); LK is random",
    "exportHead.any": "response only, 129 bytes: E ‖ sig_S where E is a valid uncompressed secp256k1 point and sig_S a valid signature under {A} of \"qntx-card/v1/export\" ‖ {A} ‖ A_peer ‖ LK ‖ E, with A_peer from {peer.cert} and LK from {peer.offer} (§9.13); E is random",
    "exportPayload.any": "response only, 176 bytes: ct(160) ‖ tag(16) that {peer} accepts: IMPORT P1 = 00 with {cert} ‖ the E ‖ sig_S of the session's EXPORT P1 = 00, then IMPORT P1 = 01 with these 176 bytes, both on {peer} in one session, return 9000 and WalletInfo {seed.masterPublicKey} 02 03 {id.self} {peer.id} {id.badPoint}",
}

# Setup of each life/session combination named by the cases.
STATES = {
    "FACTORY": "a freshly installed card",
    "BLANK": "FACTORY, then PERSONALIZE with {cert} and {caKey}",
    "LOADED": "BLANK, then OPEN and CREATE P1 = 01 with {accessHash} ‖ {seed} (no other members), then a new OPEN",
    "session none": "no OPEN after the setup",
    "session open": "the last OPEN of the setup (OPEN once for BLANK); not verified",
    "session verified": "session open, then VERIFY {accessHash} returned 9000",
    "session streaming": "session verified, then SIGN_ED25519 begin (P1 = 00) with path m/44'/501'/0'/0' returned 9000",
    "SOURCE": "BLANK, then OPEN and CREATE P1 = 01 with {accessHash} ‖ {seed} ‖ {peer.id} ‖ {id.badPoint} (members = self, peer, badPoint), then a new OPEN. {peer} is a second card personalized under ca1, BLANK, that answered one OFFER ({peer.offer})",
    "TARGET": "BLANK. {peer} is a second card personalized under ca1 and LOADED by OPEN and CREATE P1 = 01 with {accessHash} ‖ {seed} ‖ {id.self} (members = peer, self); its session stays verified",
    "TARGET-LOADED": "TARGET, then the card under test receives the wallet: OPEN, OFFER; {peer} EXPORT P1 = 00 with {cert} ‖ that OFFER response and EXPORT P1 = 01 with {accessHash}; the card under test IMPORT P1 = 00 with {peer.cert} ‖ E ‖ sig_S and IMPORT P1 = 01 with ct ‖ tag (LOADED, members = peer, self, f = 0); then a new OPEN on the card under test",
    "session offered": "session open, then OFFER returned 9000 on the card under test",
    "session importing": "session offered, then IMPORT P1 = 00 with {peer.cert} ‖ {peer.exportHead} returned 9000",
    "session exporting": "session verified, then EXPORT P1 = 00 with {peer.cert} ‖ {peer.offer} returned 9000",
}


def apdu(head, *data, lc=None, le=None):
    """Build the hex-string APDU `head ‖ Lc ‖ data ‖ Le`.

    `head` is the four header bytes; `data` tokens are hex or {symbol} placeholders; `lc`
    overrides the computed Lc (used by the intentional length violations); `le` appends a
    trailing Le byte.
    """
    dl = sum(
        SYMBOL_LEN[t[1:-1]] if t.startswith("{") else len(bytes.fromhex(t)) for t in data
    )
    declared = dl if lc is None else lc
    assert 0 <= declared <= 0xFF
    out = head
    if data or lc is not None:
        out += f"{declared:02x}" + "".join(data)
    if le is not None:
        out += le
    return out


def case(name, life, session, apdu_hex, inner, sw, response=None):
    c = {
        "name": name,
        "life": life,
        "session": session,
        "apdu": apdu_hex,
        "inner": inner,
        "sw": sw,
    }
    if response is not None:
        c["response"] = response
    return c


# §9.2 paths: depth(1) ‖ u32(index)…; i' = i + 2^31.
PATH_EVM = "05" + "8000002c" + "8000003c" + "80000000" + "00000000" + "00000000"  # m/44'/60'/0'/0/0
PATH_SOLANA = "04" + "8000002c" + "800001f5" + "80000000" + "80000000"  # m/44'/501'/0'/0'
PATH_SOLANA_SOFT = "04" + "8000002c" + "800001f5" + "80000000" + "00000000"  # m/44'/501'/0'/0
PATH_BIP84_ACCOUNT = "03" + "80000054" + "80000000" + "80000000"  # m/84'/0'/0'
PATH_BIP86 = "05" + "80000056" + "80000000" + "80000000" + "00000000" + "00000000"  # m/86'/0'/0'/0/0
DEPTH_ELEVEN = "0b" + "80000000" * 11
# secp256k1 group order n and the largest 32-byte value, both rejected as tweaks (§12.2)
ORDER_N = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
MAX_32 = "ff" * 32

# life values: FACTORY, BLANK, LOADED (§4.1), "any", or the transfer setups SOURCE, TARGET and
# TARGET-LOADED (§9.12–9.14, see STATES).
# session: "none", "open", "verified", "streaming", "offered", "importing" or "exporting".
COMMANDS = [
    {
        "name": "DISPATCH",
        "section": "9.1",
        "cases": [
            case("wrong-cla", "any", "none", apdu("00e00000", le="00"), False, "6e00"),
            case("unknown-ins", "any", "none", apdu("807f0000", le="00"), False, "6d00"),
        ],
    },
    {
        "name": "GET_IDENTITY",
        "section": "14.1",
        "cases": [
            # life checked first: P1/P2 and Lc are also wrong here
            case("life-blank", "BLANK", "none", apdu("80e00100", "00"), False, "6985"),
            # P1/P2 checked before length: Lc is also wrong here
            case("p1p2", "FACTORY", "none", apdu("80e00100", "00"), False, "6a86"),
            case("length", "FACTORY", "none", apdu("80e00000", "00"), False, "6700"),
            case(
                "success",
                "FACTORY",
                "none",
                apdu("80e00000", le="00"),
                False,
                "9000",
                "{A}",
            ),
        ],
    },
    {
        "name": "PERSONALIZE",
        "section": "14.2",
        "cases": [
            case(
                "life-blank",
                "BLANK",
                "none",
                apdu("80e20100", "{cert}", "{caKey}", lc=0xA1),
                False,
                "6985",
            ),
            case(
                "p1p2",
                "FACTORY",
                "none",
                apdu("80e20100", "{cert}", "{caKey}", lc=0xA1),
                False,
                "6a86",
            ),
            # declared Lc = 161, one short of 162; the trailing byte parses as Le
            case(
                "length",
                "FACTORY",
                "none",
                apdu("80e20000", "{cert}", "{caKey}", lc=0xA1),
                False,
                "6700",
            ),
            case(
                "cert-not-this-card",
                "FACTORY",
                "none",
                apdu("80e20000", "{cert.otherA}", "{caKey}"),
                False,
                "6a80",
            ),
            case(
                "cakey-prefix03",
                "FACTORY",
                "none",
                apdu("80e20000", "{cert}", "{caKey.prefix03}"),
                False,
                "6a80",
            ),
            case(
                "cakey-x-is-p",
                "FACTORY",
                "none",
                apdu("80e20000", "{cert}", "{caKey.xIsP}"),
                False,
                "6a80",
            ),
            case(
                "cakey-y-is-p",
                "FACTORY",
                "none",
                apdu("80e20000", "{cert}", "{caKey.yIsP}"),
                False,
                "6a80",
            ),
            case(
                "cakey-off-curve",
                "FACTORY",
                "none",
                apdu("80e20000", "{cert}", "{caKey.offCurve}"),
                False,
                "6a80",
            ),
            case(
                "cert-under-other-ca",
                "FACTORY",
                "none",
                apdu("80e20000", "{cert.otherCa}", "{caKey}"),
                False,
                "6a80",
            ),
            case(
                "success",
                "FACTORY",
                "none",
                apdu("80e20000", "{cert}", "{caKey}"),
                False,
                "9000",
            ),
        ],
    },
    {
        "name": "OPEN",
        "section": "8.1",
        "cases": [
            case("life-factory", "FACTORY", "none", apdu("80100100", "00"), False, "6985"),
            case("p1p2", "BLANK", "none", apdu("80100100", "00"), False, "6a86"),
            # declared Lc = 64: the 65th point byte parses as Le, incoming length 64 != 65
            case(
                "length",
                "BLANK",
                "none",
                apdu("80100000", "{hostEph}", lc=0x40),
                False,
                "6700",
            ),
            case(
                "hosteph-prefix02",
                "BLANK",
                "none",
                apdu("80100000", "{hostEph.prefix02}", le="00"),
                False,
                "6a80",
            ),
            case(
                "hosteph-off-curve",
                "BLANK",
                "none",
                apdu("80100000", "{hostEph.offCurve}", le="00"),
                False,
                "6a80",
            ),
            case(
                "success",
                "BLANK",
                "none",
                apdu("80100000", "{hostEph}", le="00"),
                False,
                "9000",
                "{openResponse}",
            ),
        ],
    },
    {
        "name": "SESSION",
        "section": "8.3",
        "cases": [
            # record-level rejections live in record.json rejectedCommands
            case(
                "no-session",
                "BLANK",
                "none",
                apdu("80120000", "{record0}", le="00"),
                False,
                "6985",
            ),
        ],
    },
    {
        "name": "INNER_DISPATCH",
        "section": "9.2",
        "cases": [
            # INS known is the first inner check; P1/P2 and data are also wrong here
            case("unknown-ins", "BLANK", "open", "7f0102ff", True, "6d00"),
        ],
    },
    {
        "name": "STATUS",
        "section": "9.3",
        "cases": [
            case("p1p2", "BLANK", "open", "20010200", True, "6a86"),
            case("length", "BLANK", "open", "20000001", True, "6700"),
            case("success-blank", "BLANK", "open", "200000", True, "9000", "0100"),
            case("success-loaded", "LOADED", "open", "200000", True, "9000", "020a"),
        ],
    },
    {
        "name": "CREATE",
        "section": "9.4",
        "cases": [
            # life first: P1 and length are also wrong here
            case("life-loaded", "LOADED", "open", "21020000", True, "6985"),
            case("p1", "BLANK", "open", "21020000", True, "6a86"),
            case("p2", "BLANK", "open", "210001{accessHash}{entropy}", True, "6a86"),
            case("length-generate-65", "BLANK", "open", "210000{accessHash}{entropy}00", True, "6700"),
            case("length-generate-112", "BLANK", "open", "210000{accessHash}{entropy}{id.other1}{id.other2}{id.other1}", True, "6700"),
            case("length-import-80", "BLANK", "open", "210100{accessHash}{entropy}{id.other1}", True, "6700"),
            case("others-duplicate", "BLANK", "open", "210000{accessHash}{entropy}{id.other1}{id.other1}", True, "6a80"),
            case("others-self", "BLANK", "open", "210000{accessHash}{entropy}{id.other1}{id.self}", True, "6a80"),
            case("import-others-self", "BLANK", "open", "210100{accessHash}{seed}{id.self}", True, "6a80"),
            case("success-generate", "BLANK", "open", "210000{accessHash}{entropy}", True, "9000", "{masterPublicKey.any}0101{id.self}"),
            case("success-generate-three", "BLANK", "open", "210000{accessHash}{entropy}{id.other1}{id.other2}", True, "9000", "{masterPublicKey.any}0103{id.self}{id.other1}{id.other2}"),
            case("success-import", "BLANK", "open", "210100{accessHash}{seed}{id.other1}", True, "9000", "{seed.masterPublicKey}0202{id.self}{id.other1}"),
        ],
    },
    {
        "name": "VERIFY",
        "section": "9.5",
        "cases": [
            case("life-blank", "BLANK", "open", "22010000", True, "6985"),
            case("p1p2", "LOADED", "open", "22010000", True, "6a86"),
            case("p2", "LOADED", "open", "220001{accessHash}", True, "6a86"),
            case("length", "LOADED", "open", "220000{accessHash}00", True, "6700"),
            case("wrong", "LOADED", "open", "220000{accessHash.wrong}", True, "63c9"),
            case("success", "LOADED", "open", "220000{accessHash}", True, "9000", "{seed.masterPublicKey}0201{id.self}"),
        ],
    },
    {
        "name": "CHANGE",
        "section": "9.6",
        "cases": [
            case("life-blank", "BLANK", "open", "23010000", True, "6985"),
            case("p1p2", "LOADED", "verified", "23010000", True, "6a86"),
            case("length", "LOADED", "verified", "230000{accessHash.new}00", True, "6700"),
            case("unverified", "LOADED", "open", "230000{accessHash.new}", True, "6982"),
            case("success", "LOADED", "verified", "230000{accessHash.new}", True, "9000", ""),
        ],
    },
    {
        "name": "ERASE",
        "section": "9.7",
        "cases": [
            case("life-blank", "BLANK", "open", "24010000", True, "6985"),
            case("p1p2", "LOADED", "verified", "24010000", True, "6a86"),
            case("length", "LOADED", "verified", "24000000", True, "6700"),
            case("unverified", "LOADED", "open", "240000", True, "6982"),
            case("success", "LOADED", "verified", "240000", True, "9000", ""),
        ],
    },
    {
        "name": "WAIT",
        "section": "9.15",
        "cases": [
            case("life-blank", "BLANK", "open", "25010000", True, "6985"),
            case("p1p2", "LOADED", "open", "25010000", True, "6a86"),
            case("length", "LOADED", "open", "25000000", True, "6700"),
            case("success", "LOADED", "open", "250000", True, "9000", ""),
        ],
    },
    {
        "name": "PUBLIC_KEY",
        "section": "9.8",
        "cases": [
            case("life-blank", "BLANK", "open", "30020000", True, "6985"),
            case("p1", "LOADED", "verified", "30020000", True, "6a86"),
            case("p2", "LOADED", "verified", "300001" + PATH_EVM, True, "6a86"),
            case("length-empty", "LOADED", "verified", "300000", True, "6700"),
            case("length-short", "LOADED", "verified", "300000" + PATH_EVM[:-8], True, "6700"),
            case("length-long", "LOADED", "verified", "300000" + PATH_EVM + "00", True, "6700"),
            case("unverified", "LOADED", "open", "300000" + PATH_EVM, True, "6982"),
            case("depth-zero", "LOADED", "verified", "30000000", True, "6a80"),
            case("depth-eleven", "LOADED", "verified", "3000000b" + "80000000" * 11, True, "6a80"),
            case("ed25519-depth-zero", "LOADED", "verified", "30010000", True, "6a80"),
            case("ed25519-not-hardened", "LOADED", "verified", "300100" + PATH_SOLANA_SOFT, True, "6a80"),
            case("success-secp256k1", "LOADED", "verified", "300000" + PATH_EVM, True, "9000", "{pk.secp.evm}"),
            case("success-ed25519", "LOADED", "verified", "300100" + PATH_SOLANA, True, "9000", "{pk.ed.solana}"),
        ],
    },
    {
        "name": "SIGN_ECDSA",
        "section": "9.9",
        "cases": [
            # life first: P1 and length are also wrong here
            case("life-blank", "BLANK", "open", "31010000", True, "6985"),
            case("p1", "LOADED", "verified", "31010000", True, "6a86"),
            case("p2", "LOADED", "verified", "310001{digest}" + PATH_EVM, True, "6a86"),
            case("length-empty", "LOADED", "verified", "310000", True, "6700"),
            # the depth byte is missing: 32 bytes is shorter than 33 + 4d for every d
            case("length-no-path", "LOADED", "verified", "310000{digest}", True, "6700"),
            case("length-short", "LOADED", "verified", "310000{digest}" + PATH_EVM[:-8], True, "6700"),
            case("length-long", "LOADED", "verified", "310000{digest}" + PATH_EVM + "00", True, "6700"),
            case("unverified", "LOADED", "open", "310000{digest}" + PATH_EVM, True, "6982"),
            case("depth-zero", "LOADED", "verified", "310000{digest}00", True, "6a80"),
            case("depth-eleven", "LOADED", "verified", "310000{digest}" + DEPTH_ELEVEN, True, "6a80"),
            # a non-hardened leaf (public derivation check) and a hardened leaf (k·G check)
            case("success-evm", "LOADED", "verified", "310000{digest}" + PATH_EVM, True, "9000", "{sig.ecdsa.evm}"),
            case("success-hardened-leaf", "LOADED", "verified", "310000{digest}" + PATH_BIP84_ACCOUNT, True, "9000", "{sig.ecdsa.bip84Account}"),
        ],
    },
    {
        "name": "SIGN_BIP340",
        "section": "9.10",
        "cases": [
            case("life-blank", "BLANK", "open", "32010000", True, "6985"),
            case("p1", "LOADED", "verified", "32010000", True, "6a86"),
            case("p2", "LOADED", "verified", "320001{message}{tweak.bip86}" + PATH_BIP86, True, "6a86"),
            case("length-empty", "LOADED", "verified", "320000", True, "6700"),
            # the depth byte is missing: 64 bytes is shorter than 65 + 4d for every d
            case("length-no-path", "LOADED", "verified", "320000{message}{tweak.bip86}", True, "6700"),
            case("length-short", "LOADED", "verified", "320000{message}{tweak.bip86}" + PATH_BIP86[:-8], True, "6700"),
            case("length-long", "LOADED", "verified", "320000{message}{tweak.bip86}" + PATH_BIP86 + "00", True, "6700"),
            case("unverified", "LOADED", "open", "320000{message}{tweak.bip86}" + PATH_BIP86, True, "6982"),
            # path before tweak: the tweak is also invalid here
            case("depth-zero", "LOADED", "verified", "320000{message}" + ORDER_N + "00", True, "6a80"),
            case("depth-eleven", "LOADED", "verified", "320000{message}{tweak.bip86}" + DEPTH_ELEVEN, True, "6a80"),
            case("tweak-n", "LOADED", "verified", "320000{message}" + ORDER_N + PATH_BIP86, True, "6a80"),
            case("tweak-max", "LOADED", "verified", "320000{message}" + MAX_32 + PATH_BIP86, True, "6a80"),
            case("tweaked-key-zero", "LOADED", "verified", "320000{message}{tweak.zeroKey}" + PATH_BIP86, True, "6a80"),
            case("success-bip86", "LOADED", "verified", "320000{message}{tweak.bip86}" + PATH_BIP86, True, "9000", "{sig.bip340.bip86}"),
            case("success-untweaked", "LOADED", "verified", "320000{message}" + "00" * 32 + PATH_BIP86, True, "9000", "{sig.bip340.untweaked}"),
        ],
    },
    {
        "name": "SIGN_ED25519",
        "section": "9.11",
        "cases": [
            case("life-blank", "BLANK", "open", "33030000", True, "6985"),
            case("p1", "LOADED", "verified", "33030000", True, "6a86"),
            case("p2", "LOADED", "verified", "330001" + PATH_SOLANA, True, "6a86"),
            case("begin-length-empty", "LOADED", "verified", "330000", True, "6700"),
            case("begin-length-short", "LOADED", "verified", "330000" + PATH_SOLANA[:-8], True, "6700"),
            case("begin-length-long", "LOADED", "verified", "330000" + PATH_SOLANA + "00", True, "6700"),
            # length before the stream precondition: no stream is active here either
            case("update-length-empty", "LOADED", "verified", "330100", True, "6700"),
            case("finish-length-empty", "LOADED", "verified", "330200", True, "6700"),
            case("begin-unverified", "LOADED", "open", "330000" + PATH_SOLANA, True, "6982"),
            case("update-unverified", "LOADED", "open", "330100aa", True, "6982"),
            case("finish-unverified", "LOADED", "open", "330200aa", True, "6982"),
            case("update-no-stream", "LOADED", "verified", "330100aa", True, "6985"),
            case("finish-no-stream", "LOADED", "verified", "330200aa", True, "6985"),
            case("begin-depth-zero", "LOADED", "verified", "33000000", True, "6a80"),
            case("begin-depth-eleven", "LOADED", "verified", "330000" + DEPTH_ELEVEN, True, "6a80"),
            case("begin-not-hardened", "LOADED", "verified", "330000" + PATH_SOLANA_SOFT, True, "6a80"),
            case("begin-success", "LOADED", "verified", "330000" + PATH_SOLANA, True, "9000", "{wei.any}"),
            case("update-success", "LOADED", "streaming", "330100" + "00112233", True, "9000", ""),
            case("finish-success", "LOADED", "streaming", "330200" + "44556677", True, "9000", "{ed25519.S.any}"),
        ],
    },
    {
        "name": "OFFER",
        "section": "9.12",
        "cases": [
            # BLANK and LOADED both allow OFFER: no life case is reachable inside a session
            case("p1p2", "BLANK", "open", "40010000", True, "6a86"),
            case("length", "BLANK", "open", "40000000", True, "6700"),
            case("success-blank", "BLANK", "open", "400000", True, "9000", "{offer.any}"),
            case("success-loaded", "LOADED", "open", "400000", True, "9000", "{offer.any}"),
        ],
    },
    {
        "name": "EXPORT",
        "section": "9.13",
        "cases": [
            # life first: P1 and length are also wrong here
            case("life-blank", "BLANK", "open", "41020000", True, "6985"),
            case("p1", "SOURCE", "verified", "41020000", True, "6a86"),
            case("p2", "SOURCE", "verified", "410001{peer.cert}{peer.offer}", True, "6a86"),
            case("length-0", "SOURCE", "verified", "410000{peer.cert}{peer.offer}00", True, "6700"),
            case("length-1", "SOURCE", "verified", "410100{accessHash.new}00", True, "6700"),
            case("unverified-0", "SOURCE", "open", "410000{peer.cert}{peer.offer}", True, "6982"),
            case("unverified-1", "SOURCE", "open", "410100{accessHash.new}", True, "6982"),
            case("no-pending-export", "SOURCE", "verified", "410100{accessHash.new}", True, "6985"),
            # data checks 1-5 of §9.13 in order; each case also fails no earlier check
            case("cert-other-ca", "SOURCE", "verified", "410000{peer.cert.otherCa}{peer.offer}", True, "6a80"),
            case("cert-own", "SOURCE", "verified", "410000{cert}{peer.offer}", True, "6a80"),
            case("cert-non-member", "SOURCE", "verified", "410000{cert.otherA}{peer.offer}", True, "6a80"),
            case("cert-no-decompression", "SOURCE", "verified", "410000{cert.badPoint}{peer.offer}", True, "6a80"),
            case("offer-prefix03", "SOURCE", "verified", "410000{peer.cert}{peer.offer.prefix03}", True, "6a80"),
            case("offer-bad-signature", "SOURCE", "verified", "410000{peer.cert}{peer.offer.badSig}", True, "6a80"),
            case("success-0", "SOURCE", "verified", "410000{peer.cert}{peer.offer}", True, "9000", "{exportHead.any}"),
            case("success-1", "SOURCE", "exporting", "410100{accessHash.new}", True, "9000", "{exportPayload.any}"),
        ],
    },
    {
        "name": "IMPORT",
        "section": "9.14",
        "cases": [
            # BLANK and LOADED both allow IMPORT: no life case is reachable inside a session
            case("p1", "TARGET", "open", "42020000", True, "6a86"),
            case("p2", "TARGET", "open", "420001" + "00" * 226, True, "6a86"),
            case("length-0", "TARGET", "offered", "420000" + "00" * 225, True, "6700"),
            case("length-1-short", "TARGET", "importing", "420100" + "00" * 161, True, "6700"),
            case("length-1-long", "TARGET", "importing", "420100" + "00" * 177, True, "6700"),
            case("no-offer-0", "TARGET", "open", "420000" + "00" * 226, True, "6985"),
            case("no-offer-1", "TARGET", "open", "420100" + "00" * 160, True, "6985"),
            case("no-pending-import", "TARGET", "offered", "420100" + "00" * 160, True, "6985"),
            # data checks 1-5 of §9.14 P1 = 00 in order; each case also fails no earlier check
            case("cert-other-ca", "TARGET", "offered", "420000{peer.cert.otherCa}{peer.exportHead}", True, "6a80"),
            case("cert-own", "TARGET", "offered", "420000{cert}{peer.exportHead}", True, "6a80"),
            case("cert-non-member-loaded", "TARGET-LOADED", "offered", "420000{cert.otherA}{peer.exportHead}", True, "6a80"),
            # BLANK has no membership check: a certified non-sender fails at the signature
            case("cert-not-sender-blank", "TARGET", "offered", "420000{cert.otherA}{peer.exportHead}", True, "6a80"),
            case("cert-no-decompression", "TARGET", "offered", "420000{cert.badPoint}{peer.exportHead}", True, "6a80"),
            case("export-bad-signature", "TARGET", "offered", "420000{peer.cert}{peer.exportHead.badSig}", True, "6a80"),
            case("success-0", "TARGET", "offered", "420000{peer.cert}{peer.exportHead}", True, "9000", ""),
            # data check 1 of §9.14 P1 = 01; checks 2-5 need a forged payload (transfer.json)
            case("bad-tag", "TARGET", "importing", "420100{peer.exportPayload.badTag}", True, "6a80"),
            case("bad-ct", "TARGET", "importing", "420100{peer.exportPayload.badCt}", True, "6a80"),
            case("success-1", "TARGET", "importing", "420100{peer.exportPayload}", True, "9000", "{seed.masterPublicKey}0202{peer.id}{id.self}"),
            case("reseal-success-0", "TARGET-LOADED", "offered", "420000{peer.cert}{peer.exportHead}", True, "9000", ""),
            case("reseal-success-1", "TARGET-LOADED", "importing", "420100{peer.exportPayload}", True, "9000", "{seed.masterPublicKey}0202{peer.id}{id.self}"),
        ],
    },
]


def main():
    doc = {"symbols": SYMBOLS, "states": STATES, "commands": COMMANDS}
    out = json.dumps(doc, indent=2, ensure_ascii=True) + "\n"
    if len(sys.argv) > 1:
        with open(sys.argv[1], "w", encoding="ascii", newline="\n") as f:
            f.write(out)
    else:
        sys.stdout.write(out)


if __name__ == "__main__":
    main()
