<!--
SPDX-FileCopyrightText: 2026 QuantX
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# qntx card protocol 1

The single normative specification of the qntx card: the wallet applet and the NDEF applet
running on the card, and the host side (implemented by the qntx/wallet kernel). An independent
team can implement an interoperable card or host from this document and the vector files of
§18 alone. The threat model is `docs/threat-model.md`; the applet's architecture and
implementation plan are `docs/architecture.md`.

A qntx card wallet is a *card set* of one to three cards holding the same 64-byte seed. No
command outputs a private key, the seed or the access code. The only way key material leaves a
card is the transfer of §11: encrypted for, and accepted only by, another genuine card that was
named as a member when the wallet was created.

## Contents

1. Conventions
2. Identifiers
3. Platform requirements
4. Lifecycle and persistent state
5. Identity and certificates
6. SELECT
7. Access code
8. Secure session
9. Command reference
10. Key storage and derivation
11. Multi-card operations
12. Signing
13. Status words
14. Personalisation
15. NDEF applet
16. Implementation requirements
17. Versioning and freeze
18. Test vectors

## 1. Conventions

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT are to be
interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all
capitals. This specification has no optional features: every requirement applies to every
implementation.

- `‖` is concatenation. `x[a..b)` is the half-open byte range of `x`. `x(n)` denotes an `n`-byte
  field. `0ⁿ` is `n` zero bytes.
- Integers on the wire are unsigned big-endian unless stated otherwise. `u8`, `u16`, `u32` are
  1-, 2- and 4-byte big-endian encodings. Ed25519 scalars and encodings are little-endian as in
  RFC 8032; `le32(x)` is the 32-byte little-endian encoding of `x`, `int_le(b)` the integer of
  little-endian bytes `b`. `int(b)` is the integer of big-endian bytes `b`.
- Quoted strings such as `"qntx-card/v1/cert"` stand for their ASCII bytes, without length
  prefix or terminator. Every label in this document is unique and no label is a prefix of
  another.
- `SHA-256`, `SHA-512` are FIPS 180-4. `HMAC-SHA512` is RFC 2104 with SHA-512.
  `AES(K, X)` encrypts one 16-byte block with AES-128 (FIPS 197). `CBC(K, IV, X)` is AES-128-CBC
  encryption (NIST SP 800-38A) of `X`, `|X|` a multiple of 16, without padding.
  `CMAC(K, M)` is AES-CMAC (NIST SP 800-38B) with a 128-bit key and the full 16-byte output.
- `M2(X)` is ISO/IEC 9797-1 padding method 2: `X ‖ 0x80 ‖ 0ᵏ` with the smallest `k ≥ 0` making
  the length a multiple of 16 (so `k ≤ 15`). `unM2(Y)` removes it and fails if `Y` is empty, not a
  multiple of 16, its last non-zero byte is not `0x80`, or more than 15 zero bytes follow that
  `0x80`.
- secp256k1 is the curve of SEC 2 v2 §2.4.1: field prime `p`, order `n`, generator `G`.
  Ed25519 is RFC 8032 §5.1: field prime `q = 2²⁵⁵ − 19`, group order `ℓ`, base point `B`.
- A secp256k1 point is encoded **uncompressed** (`0x04 ‖ x(32) ‖ y(32)`, 65 bytes) or
  **compressed** (`0x02|0x03 ‖ x(32)`, 33 bytes, SEC 1 §2.3.3) as each field states.
  `encode(P)` for an Ed25519 point is RFC 8032 §5.1.2 (32 bytes).
- `Sign(k, M)` is ECDSA over secp256k1 (SEC 1 §4.1.3) with private key `k` and message hash
  `e = SHA-256(M)`; its wire form is `r(32) ‖ s(32)`. Any `s ∈ [1, n−1]` is valid: the card
  outputs either half and verifiers MUST accept both.
  `Verify(A, M, sig)` is the corresponding verification with public key `A`; it fails if `r` or
  `s` is outside `[1, n−1]`.
- `ID(A) = SHA-256(A)[0..16)` where `A` is a compressed secp256k1 identity public key. `ID(A)` is
  the **card ID**. `short(A) = ID(A)[0..4)` written as 8 uppercase hexadecimal digits in two groups
  (`XXXX-XXXX`) is the **short ID**: it is printed on the card face (§14.3) and is what hosts show
  and ask the user to confirm.
- `KDF(Z, label, ctx, len)` is the one-step key derivation of NIST SP 800-56C Rev. 2 §4.1,
  option 1 (H = SHA-256), with FixedInfo = `label ‖ ctx`: the first `len` bytes of
  `SHA-256(u32(1) ‖ Z ‖ label ‖ ctx) ‖ SHA-256(u32(2) ‖ Z ‖ label ‖ ctx)`. `len ≤ 64`.
- `Argon2id(P, S, m, t, p, T)` is RFC 9106 Argon2id, version `0x13`, with no secret and no
  associated data; `m` in KiB.
- `KDF108(K, label, ctx)` is the counter-mode KDF of NIST SP 800-108r1 §4.1 with PRF = CMAC,
  `r = 8`, output length 256 bits: `CMAC(K, 0x01 ‖ label ‖ 0x00 ‖ ctx ‖ 0x0100) ‖ CMAC(K, 0x02 ‖ label ‖ 0x00
  ‖ ctx ‖ 0x0100)` (32 bytes).
- Constants of the access-code rules (§7.3): failure limit `L = 10`, free attempts `F = 3`, wait
  units per attempt `W = 15`; one wait unit is `I = 400` SHA-256 iterations (§9.15).
- An index `i'` denotes `i + 2³¹` (hardened).

## 2. Identifiers

| Item | Value |
| --- | --- |
| Load file (package) AID | `F0716E747800` |
| Wallet applet class AID and instance AID | `F0716E74780101` |
| NDEF applet class AID | `F0716E74780201` |
| NDEF applet instance AID | `D2760000850101` (NFC Forum Type 4 Tag application) |
| Proprietary class byte | `0x80` |

`F0716E7478` is `0xF0` (ISO/IEC 7816-5 proprietary, unregistered category) followed by ASCII
`qntx`. In the wallet instance AID, byte 6 (`0x01`) designates the wallet applet and byte 7
(`0x01`) is the protocol version (§17). iOS hosts MUST list `F0716E74780101` and
`D2760000850101` in `com.apple.developer.nfc.readersession.iso7816.select-identifiers`.

## 3. Platform requirements

The applet targets Java Card 3.0.5 Classic and uses only these standard APIs (baseline silicon:
NXP JCOP 4 P71, J3R180 class):

| API | Constants and methods | Use |
| --- | --- | --- |
| `javacard.framework` | `Applet`, `APDU`, `ISO7816`, `ISOException`, `Util`; `JCSystem.makeTransientByteArray(…, CLEAR_ON_DESELECT)`, `beginTransaction`, `commitTransaction`, `abortTransaction`, `getTransactionDepth` | Framework, transactions, transient memory |
| `javacard.security.KeyBuilder` | `TYPE_EC_FP_PRIVATE`, `TYPE_EC_FP_PUBLIC`, `TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT` (all `LENGTH_EC_FP_256`); `TYPE_AES` and `TYPE_AES_TRANSIENT_DESELECT` (`LENGTH_AES_128`); `TYPE_RSA_PRIVATE` (`LENGTH_RSA_512`) | Key objects |
| `javacard.security.KeyPair` | `ALG_EC_FP`, `genKeyPair` | Identity key, link key |
| `javacard.security.Signature` | `ALG_ECDSA_SHA_256`: `sign`, `verify`, `signPreComputedHash`, `verifyPreComputedHash`; `ALG_AES_CMAC_128`: `sign`, `verify` | Identity signatures, ECDSA, CMAC |
| `javacard.security.KeyAgreement` | `ALG_EC_SVDP_DH_PLAIN_XY`, `ALG_EC_PACE_GM` | Scalar multiplication, point addition |
| `javacard.security.MessageDigest` | `ALG_SHA_256`, `ALG_SHA_512` | Hashing, HMAC-SHA512 |
| `javacard.security.RandomData` | `ALG_KEYGENERATION` | Every random value |
| `javacardx.crypto.Cipher` | `ALG_AES_BLOCK_128_CBC_NOPAD`; `ALG_RSA_NOPAD` | Record layer, wrapping; modular arithmetic |

The silicon MUST additionally behave as follows. Each item is an admission test run on every
silicon batch before personalisation (`docs/architecture.md` §10). A batch that fails any item is
not used: there is no fallback implementation and no protocol variant. Items 1–5 and 7 passed on
the development card (JCOP 4 P71, CPLC IC type `D321`). For item 9 the iteration cost was
measured on the same card (2.37 ms per 32-byte SHA-256), which gives 965 ms per `WAIT`; the full
command is timed by the real-card suite.

1. `ALG_RSA_NOPAD` with a `LENGTH_RSA_512` private key accepts a 64-byte modulus whose value is
   below `2²⁵⁶` (leading zero bytes) with the private exponent `2` or a 32-byte exponent, computes
   `x^e mod m` for every 64-byte input `x < m`, and rejects `x ≥ m` with an exception.
2. `ALG_EC_PACE_GM` returns `s·G' + H` as a 65-byte uncompressed point, where `G'` is the
   generator of the private key's domain, and throws an exception when the result is the point at
   infinity.
3. `ALG_EC_SVDP_DH_PLAIN_XY` returns the 65-byte uncompressed product point and throws an
   exception for an input point that is not on the curve, has a coordinate `≥ p`, or is compressed.
4. `signPreComputedHash` and `verifyPreComputedHash` accept a 32-byte hash.
5. 256-bit EC keys, persistent and `TRANSIENT_DESELECT`, accept the secp256k1 domain parameters and
   the Wei25519 parameters of §10.4. The domain parameters of a `TRANSIENT_DESELECT` key need not
   survive a deselection or a reset (they do not on the baseline chip).
6. `RandomData.ALG_KEYGENERATION` passes the statistical tests of `docs/architecture.md` §10, and its
   first 32-byte outputs after 100 consecutive power-ups are pairwise distinct.
7. `setKey`, `setS`, `setW`, `setExponent` and `genKeyPair` on persistent key objects participate in
   an open transaction (JCRE 3.2 §9.3): an abort or power loss restores the previous key value.
8. Each named transaction of §4.3, executed on the card, consumes at most 50 % of
   `getMaxCommitCapacity`, and `install` of the wallet applet consumes at most 60 % (measured
   with `getUnusedCommitCapacity`; consumption is page-granular).
9. One `WAIT` (§9.15) takes at least 900 ms and at most 1100 ms on a contactless reader. The
   lower bound keeps destruction without the code slow (§7.3); the upper bound keeps `W` units and
   a `VERIFY` within one iOS NFC connection (about 20 s by the limit commonly assumed for iOS;
   Apple does not document it, and it is measured on reference phones before freeze).
10. The production load file installs (`INSTALL [for install and make selectable]` of the wallet
    and NDEF applets succeeds).

HMAC-SHA512 is computed in software over `ALG_SHA_512`. Ed25519 is computed through the
short-Weierstrass curve Wei25519 (§10.4); the card outputs Wei25519 points and the host encodes
them.

Transport: ISO/IEC 14443-4 or ISO/IEC 7816-3 T=1. Only short APDUs are used (`Lc ≤ 255`,
`Ne ≤ 256`). Hosts MUST send `Le = 0x00` on every command that returns data. The applet is not
multiselectable.

## 4. Lifecycle and persistent state

### 4.1 States

| State | Wire code (§9.3) | Meaning |
| --- | --- | --- |
| `FACTORY` | — | Installed, identity key generated, no certificate |
| `BLANK` | `0x01` | Certificate and CA key installed, no wallet |
| `LOADED` | `0x02` | Holds a wallet |

```text
FACTORY ──PERSONALIZE──▶ BLANK ──CREATE or IMPORT──▶ LOADED ──CHANGE or IMPORT (re-seal)──▶ LOADED
                           ▲                            │
                           └── ERASE (verified), the ───┘
                               L-th consecutive failed VERIFY, or a
                               counter fault detected by VERIFY
```

"A counter fault detected by `VERIFY`" is an inconsistent `fails` (§9.5 step 2) or a failed
read-back gate (§9.5 step 6); both perform T-ERASE and return `6F00`. There is no other
transition. A re-seal (`IMPORT` into `LOADED`, §9.14) replaces only the access
code of the same wallet.

Between install and the end of initialisation (§4.3) the applet is *uninitialised* — not a
`life` value: every command except `SELECT` and `GET_IDENTITY` returns `6283` (§4.3).

### 4.2 Persistent state

Every persistent change happens inside exactly one of the named transactions of §4.3. "Cleared"
means set to all zero bytes; key objects are never cleared but overwritten with fresh random
values inside the transaction (§16.1). `fails` is never cleared: `fails ← 0` writes the value
`0x0000` and its complement `0xFFFF` (§16.2 item 2). `f` is an unsigned 16-bit value: every
value ≥ `L`, including those ≥ `0x8000`, counts as `f ≥ L`.

| Field | Content | Size | Written by |
| --- | --- | --- | --- |
| `life` | `FACTORY`, `BLANK` or `LOADED` | 2 (coded, §16.2) | initialisation, T-PERSO, T-CREATE, T-INSTALL, T-ERASE |
| `idKey` | Identity key pair, secp256k1 (private 32, public 65) | key pair | initialisation |
| `cert` | Certificate (§5.2) | 97 | T-PERSO |
| `caKey` | CA public key, uncompressed | 65 (key object) | T-PERSO |
| `edCounter` | Ed25519 nonce counter `N` (§12.3), initially 0 | 4 | T-EDCTR |
| `wrapKey` | AES-128 key (§10.1) | 16 (key object) | T-CREATE, T-CHANGE, T-INSTALL, T-ERASE |
| `ct` | Encrypted seed (§10.1) | 64 | T-CREATE, T-CHANGE, T-INSTALL, T-ERASE |
| `tag` | Seed MAC (§10.1) | 16 | T-CREATE, T-CHANGE, T-INSTALL, T-ERASE |
| `fp` | Seed fingerprint `SHA-256("qntx-card/v1/fingerprint" ‖ seed)` (§10.1) | 32 | T-CREATE, T-INSTALL, T-ERASE |
| `origin` | `0x01` generated on a card, `0x02` imported (§9.4) | 2 (coded) | T-CREATE, T-INSTALL, T-ERASE |
| `members` | Count `c ∈ [1, 3]` and card IDs `ID₁ … ID_c` | 1 + 48 | T-CREATE, T-INSTALL, T-ERASE |
| `fails` | Consecutive failed `VERIFY` count `f` and its bitwise complement | 2 + 2 | initialisation, T-FAIL, T-OK, T-CREATE, T-INSTALL, T-ERASE |
| `linkKey` | Link key pair, secp256k1, public key `LK` (§11) | key pair | initialisation, T-OFFER, T-CREATE, T-INSTALL, T-ERASE |
| `offer` | `NONE` or `VALID` | 2 (coded) | T-OFFER, T-CREATE, T-INSTALL, T-ERASE |
| `init` | Next initialisation step or `INIT_DONE` (coded, §16.2) | 2 | install (0), initialisation |

In `BLANK`, `ct`, `tag`, `fp`, `origin` and `members` are cleared, `fails` holds 0 and `wrapKey`
holds a random key unrelated to any ciphertext. After T-CREATE, T-INSTALL and T-ERASE, `offer = NONE` and
the link private key is a random scalar unrelated to any published `LK`. `OFFER` may set
`offer = VALID` in `BLANK` and in `LOADED`. `idKey`, `cert`, `caKey` and `edCounter` survive every
transition. Every field of this table that is not a key object is kept in one persistent array
(`docs/architecture.md` §4), so that each named transaction writes that one array and its key objects
and nothing else (§3 item 8).

### 4.3 Transactions

| Name | Command | Persistent effect (all in one `beginTransaction` … `commitTransaction`) |
| --- | --- | --- |
| T-PERSO | `PERSONALIZE` | `cert`, `caKey`; `life ← BLANK` |
| T-CREATE | `CREATE` | `wrapKey` (fresh random), `ct`, `tag`, `fp`, `origin`, `members`; `fails ← 0`; link private key ← fresh random scalar; `offer ← NONE`; `life ← LOADED` |
| T-INSTALL | `IMPORT` (`P1 = 0x01`) | as T-CREATE, with the transferred values (in `LOADED`, `fp`, `origin` and `members` are rewritten with equal values) |
| T-FAIL | `VERIFY` | `fails ← f + 1` |
| T-OK | `VERIFY` | `fails ← 0` |
| T-CHANGE | `CHANGE` | `wrapKey` (fresh random), `ct`, `tag` |
| T-ERASE | `ERASE`, `VERIFY` | `life ← BLANK`; `wrapKey` ← fresh random; clear `ct`, `tag`, `fp`, `origin`, `members`; `fails ← 0`; link private key ← fresh random scalar; `offer ← NONE` |
| T-OFFER | `OFFER` with `offer = NONE` | new `linkKey` (`genKeyPair`); `offer ← VALID` |
| T-EDCTR | `SIGN_ED25519` (`P1 = 0x00`) | `edCounter ← N` |

`install` allocates every object and writes nothing else (on the baseline chip `install` runs
inside one platform transaction whose journal holds 5,120 B; install MUST consume at most 60 % of
`getMaxCommitCapacity`). Initialisation then loads the domain parameters and RSA moduli of §10
and `docs/architecture.md` §5.5 into the persistent key objects, generates `idKey` and an initial
`linkKey`, installs a random `wrapKey`, sets `fails ← 0`, `offer = NONE`, `life = FACTORY`
(`edCounter` is 0 from allocation) and finally writes `init ← INIT_DONE`. It runs outside any
transaction in steps, each driven by one `GET_IDENTITY` (§14.1) and each MUST complete within
500 ms on the baseline chip; every step is idempotent, `init` advances only after a step
completed, so a torn step is repeated whole. `init` is a coded value read twice like `life`
(§16.2 item 1). The number of steps is an implementation property, at most 16.

## 5. Identity and certificates

### 5.1 Identity key

`idKey` is a secp256k1 key pair generated on the card in the applet constructor. Its private
key never leaves the card and survives every transition. `A` denotes its compressed public key.
The identity key signs exactly three kinds of message, each starting with its own label:

| Message | Signed by | Section |
| --- | --- | --- |
| `"qntx-card/v1/session" ‖ hostEph(65) ‖ cardEph(65) ‖ A(33)` | card | 8.1 |
| `"qntx-card/v1/offer" ‖ LK(65)` | card | 9.12 |
| `"qntx-card/v1/export" ‖ A_S(33) ‖ A_T(33) ‖ LK_T(65) ‖ E(65)` | card | 9.13 |

The identity key is never used for key agreement.

### 5.2 Certificate

```text
cert(97) = A(33) ‖ r(32) ‖ s(32)
(r, s)   = Sign(caPrivate, "qntx-card/v1/cert" ‖ A)
```

Each production batch has its own CA key pair, so trust can be withdrawn per batch; `caKey` on
a card is the public key of its batch. A host verifies a certificate by
`Verify(anchor, "qntx-card/v1/cert" ‖ A, r ‖ s)` for each trusted anchor in turn and accepts it if
one succeeds. A card verifies a peer certificate with
its own `caKey`. Production hosts MUST NOT trust test anchors, and test cards MUST be issued
under test CAs only.

## 6. SELECT

```text
00 A4 04 00 07 F0716E74780101 00
```

Response: `9000`, no data. Selecting the wallet applet tears down any session (§8.5); it never
writes persistent memory.

## 7. Access code

### 7.1 Host derivation

The user chooses an access code: 6 to 64 characters of printable ASCII (`0x20`–`0x7E`). Hosts
reject any other character and any other length; no Unicode normalisation is applied. For the
card with identity key `A` the host computes

```text
accessHash = Argon2id(P = code, S = "qntx-card/v1/access" ‖ ID(A), m = 65536, t = 3, p = 4, T = 32)
```

The host learns `ID(A)` from the card's certificate in `OPEN` (for `EXPORT` `P1 = 0x01`, from the
target card's `OPEN`). The same code therefore gives a different `accessHash` on every card, and
each guess against a read-out card costs one Argon2id evaluation. The host overwrites the code
as soon as the hashes it needs are computed. The card never sees the code. Different cards of one
set can have different access codes.

### 7.2 Card verification

The card stores no `accessHash` and no value from which `accessHash` can be checked without
`wrapKey`. It verifies a candidate `h` by recomputing the seed MAC (§10.1):

```text
K_enc ‖ K_mac = KDF108(wrapKey, "qntx-card/v1/wrap", h)        (16 ‖ 16)
match         = CMAC(K_mac, ct) == tag                           (constant time)
```

On a match the seed is `CBC⁻¹(K_enc, 0¹⁶, ct)`. On a mismatch nothing is decrypted.

### 7.3 Failure limit and wait

`L = 10`, `F = 3`, `W = 15`. A candidate is compared only after the failure that it would
represent has been committed and read back (T-FAIL). A match resets the count (T-OK). When `f`
reaches `L` the wallet is erased (T-ERASE). The first `F` attempts after a success are immediate;
while `f ≥ F`, each attempt requires that `W` `WAIT` units (§9.15) have been completed in the same
session since the previous attempt; otherwise `VERIFY` returns `6986` without comparing. Waiting
is session state only: a power loss discards it and
never changes `f`. The exact order is in §9.5.

## 8. Secure session

All inner commands (§9.2) travel inside a session. A session authenticates the card to the
host, provides confidentiality, integrity, ordering and replay protection, and terminates in the
host's kernel. The host has no identity.

### 8.1 OPEN

```text
80 10 00 00 41 hostEph(65) 00
```

`hostEph` is a fresh host ephemeral secp256k1 public key, uncompressed.

Checks, in order: `life ∈ {BLANK, LOADED}` (else `6985`); `P1 = P2 = 0x00` (else `6A86`);
`Lc = 65` (else `6700`); `hostEph[0] = 0x04` (else `6A80`).

The card tears down any existing session (§8.5), then:

```text
x        = random 32 bytes, redrawn until 1 ≤ int(x) ≤ n − 1
cardEph  = uncompressed(x·G)                                            (65)
Z        = x-coordinate of x·hostEph                                    (32)
TH       = SHA-256("qntx-card/v1/session" ‖ hostEph ‖ cardEph ‖ A)
sig      = Sign(idKey, "qntx-card/v1/session" ‖ hostEph ‖ cardEph ‖ A)  (computed over TH)
K_ce ‖ K_cm ‖ K_re ‖ K_rm = KDF(Z, "qntx-card/v1/kdf-session", TH, 64)
ctr      = 0
```

If the multiplication throws because `hostEph` is not a valid point (§3 item 3), the card returns
`6A80`. The
card wipes `x` and `Z` before responding. The session is open and not verified.

Response (226 bytes): `cardEph(65) ‖ sig(64) ‖ cert(97)`, `9000`.

The host MUST, before sending any record: verify `cert` against its anchors (§5.2); take `A`
from `cert`; check `Verify(A, "qntx-card/v1/session" ‖ hostEph ‖ cardEph ‖ A, sig)`; and on any
failure abandon the card with no option to continue. It then computes `Z` with its ephemeral
private key and derives the same keys. Both sides wipe the ephemeral private keys and `Z`.

This is a one-sided signed Diffie–Hellman exchange (SIGMA with a single identity, Krawczyk 2003):
both ephemerals and the card's identity are covered by the card's signature and by the KDF, so a
holder of another certified key cannot make the host attribute this session to a different card.

### 8.2 Keys

`K_ce`, `K_cm` encrypt and authenticate host-to-card records; `K_re`, `K_rm` card-to-host
records. Each is a 16-byte AES-128 key. `ctr` is a 16-bit counter shared by a command and its
response.

### 8.3 Command record

```text
plain = INS(1) ‖ P1(1) ‖ P2(1) ‖ data          |data| ≤ 236
IV    = AES(K_ce, 0x01 ‖ 0¹³ ‖ u16(ctr))
ct    = CBC(K_ce, IV, M2(plain))
tag   = CMAC(K_cm, u16(ctr) ‖ ct)[0..8)
APDU  = 80 12 00 00 Lc ‖ ct ‖ tag ‖ 00          Lc = |ct| + 8
```

The card processes `SESSION` (`INS = 0x12`) in this order. Steps 2–5 tear the session down and
return the outer status in clear with no data.

1. No open session: `6985`.
2. `P1 ≠ 0x00` or `P2 ≠ 0x00`: `6982`.
3. `Lc < 24`, or `Lc − 8` not a multiple of 16: `6982`.
4. Recompute `tag` with the current `ctr` and compare in constant time; mismatch: `6982`.
5. Decrypt; `unM2` fails: `6982`.
6. `|plain| < 3`: inner status `6700`.
7. Dispatch the inner command (§9.2).

Outcomes of steps 6–7 are returned as a response record (§8.4) with outer status `9000`.

### 8.4 Response record

```text
plain = data ‖ SW1 ‖ SW2                         |data| ≤ 237
IV    = AES(K_re, 0x02 ‖ 0¹³ ‖ u16(ctr))
ct    = CBC(K_re, IV, M2(plain))
tag   = CMAC(K_rm, u16(ctr) ‖ ct)[0..8)
R-APDU = ct ‖ tag ‖ 90 00
```

After sending the response both sides set `ctr ← ctr + 1`. When the response just sent carried
`ctr = 0xFFFF`, the card tears the session down. The host MUST check the outer status, verify
`tag` in constant time before decrypting, check `unM2`, and abandon the session on any failure.
The inner status word is the result of the command.

### 8.5 Teardown

A session is torn down by: `SELECT` of the wallet applet; `OPEN`; a failure in §8.3 steps 2–5;
counter exhaustion; any inner `6F00` (after its response record is sent); card reset or loss of
the field. Teardown wipes, in this order: the `verified` flag, the decrypted seed, the
derivation caches, the Ed25519 stream, the pending export and import states, the `waited` count,
the session keys and `ctr`. All of these live in `CLEAR_ON_DESELECT` memory, and the applet wipes them explicitly
in `select()` and in `OPEN` without relying on deselection. The domain parameters of a transient
EC key object are cleared together with its value (on the development card on every deselection,
including a re-`SELECT` of the same applet, and on reset); the applet loads them in `select()`,
before any use.

## 9. Command reference

### 9.1 Outer commands

| Command | APDU | `life` | Section |
| --- | --- | --- | --- |
| `SELECT` | `00 A4 04 00 07 F0716E74780101 00` | any | 6 |
| `GET_IDENTITY` | `80 E0 00 00 00` | `FACTORY` | 14.1 |
| `PERSONALIZE` | `80 E2 00 00 A2 cert(97) ‖ caKey(65)` | `FACTORY` | 14.2 |
| `OPEN` | `80 10 00 00 41 hostEph 00` | `BLANK`, `LOADED` | 8.1 |
| `SESSION` | `80 12 00 00 Lc record 00` | open session | 8.3 |

Outer dispatch order: the `SELECT` that selected the applet returns `9000`; otherwise
`CLA ≠ 0x80` returns `6E00`; while uninitialised (§4.3), `GET_IDENTITY` performs one
initialisation step and every other `INS` — known or not — returns `6283`; an `INS` not in this
table returns `6D00`; then the command's own checks apply. (Non-normative: a command whose CLA
names a logical channel other than 0 is answered by the platform, `6881` on the baseline chip,
and never reaches the applet, which is not multiselectable.)

### 9.2 Inner commands

| `INS` | Command | `BLANK` | `LOADED` | Verified | Section |
| --- | --- | --- | --- | --- | --- |
| `0x20` | `STATUS` | yes | yes | — | 9.3 |
| `0x21` | `CREATE` | yes | — | — | 9.4 |
| `0x22` | `VERIFY` | — | yes | — | 9.5 |
| `0x23` | `CHANGE` | — | yes | required | 9.6 |
| `0x24` | `ERASE` | — | yes | required | 9.7 |
| `0x25` | `WAIT` | — | yes | — | 9.15 |
| `0x30` | `PUBLIC_KEY` | — | yes | required | 9.8 |
| `0x31` | `SIGN_ECDSA` | — | yes | required | 9.9 |
| `0x32` | `SIGN_BIP340` | — | yes | required | 9.10 |
| `0x33` | `SIGN_ED25519` | — | yes | required | 9.11 |
| `0x40` | `OFFER` | yes | yes | — | 9.12 |
| `0x41` | `EXPORT` | — | yes | required | 9.13 |
| `0x42` | `IMPORT` | yes | yes (re-seal) | — | 9.14 |

**Checking order.** Every inner command checks, in this order, returning the first failure:
`INS` known (else `6D00`); `life` allows the command (else `6985`); `P1`/`P2` (else `6A86`);
length (else `6700`); verified if required (else `6982`); other preconditions (`6985`; the wait
of `VERIFY`, §9.5 step 3: `6986`); data validity (`6A80`); then the effect. Unless stated
otherwise `P1 = P2 = 0x00` is required.

**Pending states.** Three multi-command operations keep state between commands: the Ed25519
stream (§9.11), the pending export (§9.13) and the pending import (§9.14). Before dispatching an
inner command the card ends (wipes) every pending state that the command does not continue. A
continuation command (`SIGN_ED25519` `P1 ∈ {0x01, 0x02}`, `EXPORT` `P1 = 0x01`, `IMPORT`
`P1 = 0x01`) ends its own pending state on every outcome except a successful `SIGN_ED25519`
`P1 = 0x01`.

**Verified.** The session flag `verified` is set only by a successful `VERIFY` and by `CREATE`,
and cleared by `VERIFY` (§9.5 step 1, reached only after the common checks pass), `ERASE`, a
successful `IMPORT` `P1 = 0x01` and teardown.

**Paths.** `path = depth(1) ‖ u32(index₁) ‖ … ‖ u32(index_depth)`. A command whose last field is
a path has a length that MUST equal the fixed part plus `1 + 4·depth`, where `depth` is the
first byte of the path (else `6700`); `depth ∉ [1, 10]` returns `6A80`; for ed25519 every index
MUST be hardened (else `6A80`).

**WalletInfo.** `CREATE`, `VERIFY` and `IMPORT` return

```text
WalletInfo = masterPublicKey(33) ‖ origin(1) ‖ c(1) ‖ ID₁(16) ‖ … ‖ ID_c(16)
```

`masterPublicKey` is the compressed BIP-32 master public key (§10.2), `origin` and `members` as
stored. Its length is `35 + 16·c` (≤ 83).

**Checks per command**, in the checking order above (`d` = path depth byte; a dash means no
check at that position). The command sections give the effects.

| Command | `life` (`6985`) | `P1`/`P2` (`6A86`) | `Lc` (`6700`) | Verified (`6982`) | Preconditions (`6985`) | Data checks in order (`6A80`) |
| --- | --- | --- | --- | --- | --- | --- |
| `STATUS` | `BLANK`, `LOADED` | `00 00` | 0 | — | — | — |
| `CREATE` | `BLANK` | `P1 ∈ {00, 01}`, `P2 = 00` | `P1 = 00`: 64, 80, 96; `P1 = 01`: 96, 112, 128 | — | — | `others` pairwise distinct; none equals `ID(A)`; (`P1 = 01`) BIP-32 master valid |
| `VERIFY` | `LOADED` | `00 00` | 32 | — | wait complete if `F ≤ f < L`, else `6986` (§9.5 steps 2–3: `f ≥ L` erases first) | — (outcome `9000`, `63Cx`, `6983` or `6F00` per §9.5) |
| `CHANGE` | `LOADED` | `00 00` | 32 | required | — | — |
| `ERASE` | `LOADED` | `00 00` | 0 | required | — | — |
| `WAIT` | `LOADED` | `00 00` | 0 | — | — | — |
| `PUBLIC_KEY` | `LOADED` | `P1 ∈ {00, 01}`, `P2 = 00` | `1 + 4d` | required | — | `d ∈ [1, 10]`; (ed25519) all indices hardened; every BIP-32 child valid |
| `SIGN_ECDSA` | `LOADED` | `00 00` | `33 + 4d` | required | — | `d ∈ [1, 10]`; every child valid |
| `SIGN_BIP340` | `LOADED` | `00 00` | `65 + 4d` | required | — | `d ∈ [1, 10]`; every child valid; `int(tweak) < n`; tweaked key ≠ 0 |
| `SIGN_ED25519` begin | `LOADED` | `P1 ∈ {00, 01, 02}`, `P2 = 00` | `1 + 4d` | required | `edCounter ≠ 0xFFFFFFFF` | `d ∈ [1, 10]`; all indices hardened |
| `SIGN_ED25519` update | `LOADED` | as above | 1–236 | required | active stream | — |
| `SIGN_ED25519` finish | `LOADED` | as above | 1–236 | required | active stream | — |
| `OFFER` | `BLANK`, `LOADED` | `00 00` | 0 | — | — | — |
| `EXPORT` `P1 = 00` | `LOADED` | `P1 ∈ {00, 01}`, `P2 = 00` | 226 | required | — | `cert_T` under `caKey`; `A_T ≠ A`; `ID(A_T)` in `members`; `A_T` decompresses; `LK_T[0] = 04` and `sig_T`; `LK_T` a valid point |
| `EXPORT` `P1 = 01` | `LOADED` | as above | 32 | required | pending export | — |
| `IMPORT` `P1 = 00` | `BLANK`, `LOADED` | `P1 ∈ {00, 01}`, `P2 = 00` | 226 | — | `offer = VALID` | `cert_S` under `caKey`; `A_S ≠ A`; (`LOADED`) `ID(A_S)` in `members`; `A_S` decompresses; `sig_S`; `E` on the curve |
| `IMPORT` `P1 = 01` | `BLANK`, `LOADED` | as above | 160, 176 | — | `offer = VALID`; pending import | `tag`; `unM2` and payload length; `origin`, `c`, IDs; BIP-32 master valid; (`LOADED`) `origin`, members and fingerprint equal to the stored ones |

A failed self-verification of a signature (§12) returns `6F00` after all checks above have passed.

### 9.3 STATUS (`0x20`)

Data: empty (`Lc = 0`, else `6700`). Response (2 bytes):

```text
life(1) ‖ tries(1)
```

`life` is `0x01` (`BLANK`) or `0x02` (`LOADED`). `tries` is `0x00` in `BLANK` and
`max(L − f, 0)` in `LOADED`. `STATUS` has no side effect.

### 9.4 CREATE (`0x21`)

| `P1` | Data | `Lc` |
| --- | --- | --- |
| `0x00` generate | `accessHash(32) ‖ hostEntropy(32) ‖ others` | `64 + 16m` |
| `0x01` import | `accessHash(32) ‖ seed(64) ‖ others` | `96 + 16m` |

`others` is `m ∈ {0, 1, 2}` card IDs of the other members (no count byte; `m` follows from
`Lc`). Checks after the common ones: `P1 ∈ {0x00, 0x01}` (else `6A86`); `Lc` matches the table
for some `m` (else `6700`); the IDs in `others` are pairwise distinct and none equals `ID(A)`
(else `6A80`).

Seed:

- `P1 = 0x00`: `seed = SHA-512("qntx-card/v1/seed" ‖ t ‖ hostEntropy)`, `t` 32 random bytes.
  If the BIP-32 master key of `seed` is invalid (§10.2) the card draws a new `t`. `origin = 0x01`.
- `P1 = 0x01`: `seed` as given (a BIP-39 seed computed by the host). An invalid BIP-32 master key
  returns `6A80`. `origin = 0x02`.

Effect: `members = (1 + m) ‖ ID(A) ‖ others` (own ID first, then `others` in the given order);
`wrapKey` fresh random; `ct`, `tag`, `fp` from `seed` and `accessHash` (§10.1); T-CREATE. In the
session: the seed is kept for derivation and `verified` is set.

Response: `WalletInfo`. With `P1 = 0x01` the host MUST compare `masterPublicKey` with its own
computation from the seed.

### 9.5 VERIFY (`0x22`)

Data: `accessHash(32)` (`Lc = 32`, else `6700`).

1. Clear `verified`, wipe the session seed and the derivation caches.
2. Read `fails` from persistent memory twice, independently, into `f_a` and `f_b`. If the
   complement of either read disagrees: T-ERASE, return `6F00`. If `f_a ≥ L` or `f_b ≥ L`:
   T-ERASE, return `6983`. Each test is thus evaluated twice, once per read (§16.2).
3. If `f_a ≥ F` and `waited < W`: return `6986`. Nothing is written and the candidate is not used.
4. `waited ← 0`.
5. T-FAIL: `fails ← f_a + 1` with its complement; commit.
6. Read-back gate, evaluated twice independently (§16.2), each on a fresh read `f₁` of `fails`:
   the transaction depth is 0; `f₁` and its complement agree; `f₁ = f_b + 1`; `f₁ ≤ L`. On any
   failure: if a transaction is open, `abortTransaction`; then T-ERASE and return `6F00`.
7. Compute `match` as in §7.2, twice, independently (§16.2).
8. Match: decrypt the seed into the session; compute `SHA-256("qntx-card/v1/fingerprint" ‖ seed)`
   and compare it with `fp` (constant time, twice); on a difference wipe the seed and return
   `6F00` (the failure stays counted). Otherwise T-OK; set `verified`; return `WalletInfo`.
9. Mismatch and `f₁ = L`: T-ERASE; return `6983`.
10. Mismatch and `f₁ < L`: return `63Cx` with `x = L − f₁` (`1 ≤ x ≤ 9`).

The candidate is first used in step 7, after T-FAIL is committed and read back. A power loss
before T-FAIL leaves no comparison performed; after it, the failure is counted. If `f₁ = L`
and power is lost before step 9 completes, the next `VERIFY` erases at step 2 without comparing.
A fault that skips the write or the commit of T-FAIL is caught at step 6 because the value must
equal `f_b + 1` and the transaction must be closed (JCRE 3.2 §7.2: an uncommitted update reads
back as its new value). The value written comes from `f_a` and the value expected from the
independent read `f_b`, so a single data fault that alters either local copy after its
complement check, or the value written, makes the gate fail; rolling the count back needs a
second, matching fault (T-L3). A forced match without the right code decrypts garbage, which
fails the fingerprint, so T-OK is not reached. A skipped wait gives one attempt without waiting;
the number of comparisons is still bounded by `L`. When the gate fails with a transaction still
open (a skipped `commitTransaction`), the abort restores `f_a` before T-ERASE begins its own
transaction (`beginTransaction` throws while one is open).

### 9.6 CHANGE (`0x23`)

Data: `newAccessHash(32)` (`Lc = 32`, else `6700`). Requires verified. Effect: new random
`wrapKey`; `ct`, `tag` recomputed from the session seed and `newAccessHash` (§10.1); T-CHANGE.
`fails` stays 0. The session stays verified. Response: empty. Other cards of the set are not
affected.

### 9.7 ERASE (`0x24`)

Data: empty (`Lc = 0`, else `6700`). Requires verified. Effect: T-ERASE; clear `verified`,
wipe the session seed and caches. The session stays open (so that `OFFER` can follow in the same
session). Response: empty. A card whose code is forgotten is not erased but re-sealed (§11.3).

### 9.8 PUBLIC_KEY (`0x30`)

`P1`: `0x00` secp256k1, `0x01` ed25519 (else `6A86`). Data: `path` (§9.2). Requires verified.

Response: secp256k1 `publicKey(33) ‖ chainCode(32)` (compressed public key and chain code of the
node at `path`, §10.3); ed25519 `W(A)(64)`, the Wei25519 point of the leaf public key (§10.4),
which the host encodes. An invalid BIP-32 child on the path returns `6A80`.

### 9.9 SIGN_ECDSA (`0x31`)

Data: `digest(32) ‖ path` (secp256k1). Requires verified. Response: `r(32) ‖ s(32)` (§12.1).

### 9.10 SIGN_BIP340 (`0x32`)

Data: `message(32) ‖ tweak(32) ‖ path` (secp256k1). Requires verified. `int(tweak) ≥ n` or a zero
tweaked key returns `6A80`. Response: `R_x(32) ‖ s(32)` (§12.2).

### 9.11 SIGN_ED25519 (`0x33`)

| `P1` | Step | Data | Response |
| --- | --- | --- | --- |
| `0x00` | begin | `path` (ed25519) | `W(R)(64)` |
| `0x01` | update | `chunk`, 1–236 bytes | empty |
| `0x02` | finish | `chunk`, 1–236 bytes | `le32(S)(32)` |

Requires verified. `P1 ∉ {0x00, 0x01, 0x02}` returns `6A86`. `update` and `finish` without an
active stream return `6985`. An empty `update` or `finish` returns `6700`; the stream is at
least 64 bytes long, so its last chunk is always sent with `finish`. `begin` with
`edCounter = 0xFFFFFFFF` returns `6985`. `begin` with
an active stream ends it and starts a new one. The chunks form the *stream*, the input of the
RFC 8032 challenge hash; hosts MUST send `encode(R) ‖ encode(A) ‖ M`, where `encode(R)` is the host's
encoding of the returned `W(R)` and `encode(A)` that of `PUBLIC_KEY` for `path` (§10.4). The card
does not parse the stream; any other stream yields a signature that is invalid under the card's
key (§12.3). The host forms the signature `encode(R) ‖ le32(S)`. The message has no length limit.
Note: chunks above 236 bytes cannot be carried by a command record (§8.3); the card checks the
bound anyway. Algorithm: §12.3.

### 9.12 OFFER (`0x40`)

Data: empty (`Lc = 0`, else `6700`). Allowed in `BLANK` and in `LOADED` (re-seal, §11.3). Effect:
with `offer = NONE`, T-OFFER (new link key pair with public key `LK`; `offer ← VALID`); with
`offer = VALID`, nothing is written and the stored `LK` is returned again. A link key is
therefore generated at most once per offer: `offer` returns to `NONE` only through T-CREATE,
T-INSTALL or T-ERASE. Each response carries a fresh identity signature. Response (129 bytes):

```text
LK(65) ‖ Sign(idKey, "qntx-card/v1/offer" ‖ LK)(64)
```

### 9.13 EXPORT (`0x41`)

**`P1 = 0x00`.** Data: `cert_T(97) ‖ LK_T(65) ‖ sig_T(64)` (`Lc = 226`, else `6700`). Requires
verified. Data checks, in order, each failing with `6A80`:

1. `cert_T` verifies under `caKey` (§5.2); let `A_T = cert_T[0..33)`.
2. `A_T ≠ A`.
3. `ID(A_T)` is in `members`.
4. `A_T` decompresses (§10.5).
5. `LK_T[0] = 0x04` and `Verify(A_T, "qntx-card/v1/offer" ‖ LK_T, sig_T)`.

Then:

```text
e      = random 32 bytes, redrawn until 1 ≤ int(e) ≤ n − 1
E      = uncompressed(e·G)
Z      = x-coordinate of e·LK_T                     (6A80 if LK_T is not a valid point)
M      = "qntx-card/v1/export" ‖ A ‖ A_T ‖ LK_T ‖ E
TH     = SHA-256(M)
sig_S  = Sign(idKey, M)                            (computed over TH)
K_te ‖ K_tm = KDF(Z, "qntx-card/v1/kdf-transfer", TH, 32)
```

The card wipes `e` and `Z`, keeps `K_te`, `K_tm` as the pending export, and responds
`E(65) ‖ sig_S(64)` (129 bytes).

**`P1 = 0x01`.** Data: `accessHash_T(32)` (`Lc = 32`, else `6700`). Requires verified and a
pending export (else `6985`).

```text
payload = origin(1) ‖ seed(64) ‖ accessHash_T(32) ‖ c(1) ‖ ID₁ ‖ … ‖ ID_c
ct      = CBC(K_te, 0¹⁶, M2(payload))              (144 or 160 bytes)
tag     = CMAC(K_tm, ct)
```

`origin`, `c` and the IDs are the stored values. The card ends the pending export and responds
`ct ‖ tag(16)` (160 or 176 bytes). `accessHash_T` becomes the access code of the target card.

### 9.14 IMPORT (`0x42`)

Allowed in `BLANK` (install) and in `LOADED` (re-seal of the same wallet with a new access code).

**`P1 = 0x00`.** Data: `cert_S(97) ‖ E(65) ‖ sig_S(64)` (`Lc = 226`, else `6700`). Precondition:
`offer = VALID` (else `6985`). Data checks, in order, each failing with `6A80`:

1. `cert_S` verifies under `caKey`; let `A_S = cert_S[0..33)`.
2. `A_S ≠ A`.
3. In `LOADED` only: `ID(A_S)` is in `members`.
4. `A_S` decompresses (§10.5).
5. `Verify(A_S, M, sig_S)` with `M = "qntx-card/v1/export" ‖ A_S ‖ A ‖ LK ‖ E`, `LK` the stored
   link public key, using the peer-key slot of §16.1 item 1.
6. `E` is a valid uncompressed secp256k1 point: `E[0] = 0x04`, both coordinates `< p`, and
   `y² ≡ x³ + 7 (mod p)` (§16.5).

Then `Z = x-coordinate of l·E` (`l` the link private key), `K_te ‖ K_tm = KDF(Z, "qntx-card/v1/kdf-transfer", SHA-256(M),
32)`; the card keeps `K_te`, `K_tm` and `ID(A_S)` as the pending import. Response: empty.

**`P1 = 0x01`.** Data: `ct ‖ tag(16)` with `|ct| ∈ {144, 160}` (`Lc ∈ {160, 176}`, else `6700`).
Precondition: `offer = VALID` and a pending import (else `6985`). Data checks, in order, each
failing with `6A80`:

1. `CMAC(K_tm, ct) = tag` (constant time).
2. `payload = unM2(CBC⁻¹(K_te, 0¹⁶, ct))` succeeds and `|payload| = 98 + 16c`.
3. `origin ∈ {0x01, 0x02}`; `c ∈ {2, 3}`; the IDs are pairwise distinct; `ID(A)` and the pending
   sender ID are among them.
4. The BIP-32 master key of `seed` is valid (§10.2).
5. In `LOADED` only: `origin` equals the stored `origin`; `c ‖ ID₁ ‖ … ‖ ID_c` equals the first `1 + 16c`
   bytes of the stored `members`; `SHA-256("qntx-card/v1/fingerprint" ‖ seed)` equals the stored `fp`.

Effect: `wrapKey` fresh random; `ct`, `tag`, `fp` from `seed` and `accessHash_T`; `origin`,
`members` from the payload; T-INSTALL. `verified` is cleared and any session seed wiped; the
session is **not** verified. Response: `WalletInfo`. The seed and payload are wiped before the
response is sent.

### 9.15 WAIT (`0x25`)

Data: empty (`Lc = 0`, else `6700`). Allowed in `LOADED`; no access code is required. Effect:
`w ← 0³²` in transient memory; `I = 400` times `w ← SHA-256(w)` (one compression block each);
`w` is discarded;
`waited ← min(waited + 1, W)`. No persistent write. Response: empty. `waited` is session state
(cleared by teardown, §8.5) and is consumed by `VERIFY` (§9.5 step 4). A host that sees
`tries ≤ L − F` in `STATUS` sends `W` `WAIT` commands before `VERIFY`; on the baseline chip one
`WAIT` takes about 1 s (965 ms on the development card, §16.6; §3 item 9 bounds it to
900–1100 ms), so such an attempt needs about 15 s of continuous contact.

## 10. Key storage and derivation

### 10.1 Seed storage

The seed is 64 bytes. It is stored only encrypted:

```text
K_enc ‖ K_mac = KDF108(wrapKey, "qntx-card/v1/wrap", accessHash)
ct            = CBC(K_enc, 0¹⁶, seed)                 (64)
tag           = CMAC(K_mac, ct)                       (16)
```

```text
fp            = SHA-256("qntx-card/v1/fingerprint" ‖ seed)  (32)
```

`wrapKey` is a fresh random AES-128 key for every T-CREATE, T-CHANGE and T-INSTALL, so each key
pair `(K_enc, K_mac)` encrypts exactly one plaintext. `fp` identifies the wallet to the card
(re-seal, §9.14) and confirms a decryption (§9.5); it is never output. To an actor who has read
`wrapKey` and `ct` out of the chip, `fp` is a verifier of the access code of the same cost as
`tag`; it adds no verifier beyond `tag`. The decrypted seed exists only in transient
memory of a verified session (or, during `CREATE` and `IMPORT`, of the command).

### 10.2 Master keys

```text
I = HMAC-SHA512(key = "Bitcoin seed", seed);  kM = int(I[0..32)), cM = I[32..64)
J = HMAC-SHA512(key = "ed25519 seed", seed);  kE = J[0..32),      cE = J[32..64)
masterPublicKey = compressed(kM·G)
```

The BIP-32 master key is **valid** if `1 ≤ kM ≤ n − 1`. The SLIP-10 ed25519 master is always
valid.

### 10.3 secp256k1 derivation

BIP-32 `CKDpriv` from `(kM, cM)` along `path`. For an index `i ≥ 2³¹`: `I = HMAC-SHA512(c_par,
0x00 ‖ k_par(32) ‖ u32(i))`; otherwise `I = HMAC-SHA512(c_par, compressed(k_par·G) ‖ u32(i))`.
`k = (int(I[0..32)) + k_par) mod n`, `c = I[32..64)`. If `int(I[0..32)) ≥ n` or `k = 0` the child
is invalid and the command returns `6A80`.

### 10.4 ed25519 derivation

SLIP-10 for ed25519 from `(kE, cE)`: for each (hardened) index `i`,
`I = HMAC-SHA512(c_par, 0x00 ‖ k_par(32) ‖ u32(i))`, `k = I[0..32)`, `c = I[32..64)`. The leaf
`sk = k` is an RFC 8032 private key: `h = SHA-512(sk)`, `a = clamp(h[0..32))` (RFC 8032 §5.1.5),
`prefix = h[32..64)`, `A = a·B`.

The card computes Ed25519 points on **Wei25519**, the short-Weierstrass curve
`Y² = X³ + a_W·X + b_W` over `q` that is isomorphic to edwards25519 (draft-ietf-lwig-curve-representations):

```text
a_W = 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144
b_W = 0x7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864
G_W = (0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a,
       0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9)     order ℓ
```

`G_W` corresponds to `B`; scalar multiples are taken with the scalar reduced mod `ℓ`
(`A = (a mod ℓ)·G_W`). The card's Wei25519 key objects are loaded with cofactor `K = 1`
(`setK(1)`); scalars are reduced mod `ℓ` before use, so the engine never applies a cofactor. On
the wire a point is `W(P) = X(32) ‖ Y(32)`, its affine coordinates
big-endian. The host maps it to edwards25519 and encodes it:

```text
u      = X − A₃ (mod q)          A₃ = 486662/3 mod q = 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad2451
y      = (u − 1)·(u + 1)⁻¹ (mod q)
x      = c·u·Y⁻¹ (mod q)         c = 0x70d9120b9f5ff9442d84f723fc03b0813a5e2c2eb482e57d3391fb5500ba81e7
encode = le32(y) with bit 255 set to x mod 2                  (RFC 8032 §5.1.2)
```

`c` is the square root of `−486664 mod q` that maps `G_W` to the RFC 8032 base point (the other
root maps it to `−B`). Worked example: for the RFC 8032 §7.1
TEST 1 key, `W(A)` is `5961a13b…96b48329 ‖ 53373f33…2aca8de5` and maps to the TEST 1 public key
`d75a9801…f707511a`.

### 10.5 Identity key decompression

Certificates carry the compressed identity key (§5.2). To verify a peer's signature the card
decompresses it: with `x = int(A[1..33))`, require `x < p` and `A[0] ∈ {0x02, 0x03}`; compute
`z = x³ + 7 mod p` and `y = z^((p+1)/4) mod p`; require `y² ≡ z (mod p)`; if `y mod 2 ≠ A[0] mod 2`,
`y ← p − y`. Any failure is `6A80`. The result `0x04 ‖ x ‖ y` is loaded into the sender's or target's peer-key slot (§16.1 item 1).

## 11. Multi-card operations

### 11.1 Card-set model

A card set is fixed when the wallet is created: `CREATE` on the first card names up to two other
cards by card ID, and the resulting `members` list (own ID first) is copied unchanged to every
card that receives the wallet. A card holding the wallet can transfer it to a member card at any
time, provided its own access code is verified in the session; the receiving card MUST be
`BLANK`, or `LOADED` with the same wallet (same `fp`, `origin` and `members`), in which case only
its access code is replaced (re-seal). No card outside `members` can ever receive the wallet,
`members` can never grow, and no transfer can replace one wallet by another on a `LOADED` card.
Membership is named by the creator and proves no possession: anyone holding a genuine card can
name any card ID in a `CREATE` of their own and install that foreign wallet into a `BLANK` card
they hold in the field; hosts detect it by `masterPublicKey` and the short ID.

### 11.2 Transfer

Source S (`LOADED`, verified) and target T (`BLANK`, or `LOADED` for a re-seal) take part; the host relays every message
inside two separate sessions and never sees `payload`:

```text
T: OFFER                           → LK_T, sig_T          (T-OFFER)
S: EXPORT P1=0 (cert_T, LK_T, sig_T) → E, sig_S
S: EXPORT P1=1 (accessHash_T)       → ct, tag
T: IMPORT P1=0 (cert_S, E, sig_S)   → —
T: IMPORT P1=1 (ct, tag)            → WalletInfo          (T-INSTALL)
```

Properties (proved or argued in `docs/threat-model.md` §5): S releases `payload` only to a certified
member that holds the private key of `LK_T`; T installs only a payload produced by a certified
card that signed `LK_T` and its own identity into `M`; `payload` is fresh for each export; an
export relayed to another card, or made for an earlier offer, fails at T because `M` binds `A_T`
and `LK_T`. Every export made for the current offer stays importable until the offer ends
(T-INSTALL or T-ERASE), so a host keeps one `accessHash_T` per target for the whole operation.
The host MUST compare the `masterPublicKey` returned by `IMPORT` with the source card's.

The host obtains `cert_T` from T's `OPEN` response and `cert_S` from S's. T keeps `linkKey`
across power loss, so the steps can span separate taps; `IMPORT` `P1 = 0x00` can be repeated with
the same export as long as `offer = VALID`.

### 11.3 Flows built from transfer

- **Create a set of k cards**: `OFFER` on each of the k − 1 targets; `CREATE` on the first card
  with their IDs; `EXPORT` to each target; `IMPORT` on each target.
- **Forgotten access code on card X (re-seal)**: `OFFER` on X, which stays `LOADED` (no code
  needed; an offer that is still valid returns the same `LK`); `EXPORT` from any member whose code is known, with X's new `accessHash_T`; `IMPORT` on
  X. Nothing on X is destroyed before the member has proved its code.
- **Card erased by the failure limit**: the same steps; X is `BLANK`.

## 12. Signing

Every signature is verified on the card, against a public key computed independently of the
signing computation, before it is output (§16.2). A failed self-verification returns `6F00` and
tears the session down.

### 12.1 ECDSA

`k_leaf` is the key at `path` (§10.3). The card signs `digest` as a pre-computed hash:
`e = int(digest)` (no hashing, no truncation since `n` has 256 bits), nonce from the platform
generator, per SEC 1 §4.1.3. Output `r(32) ‖ s(32)`; `s` is not normalised. Hosts compute the
recovery id from the known public key and normalise to low `s` where the chain requires it.

### 12.2 BIP-340 with a tweak

`d₀` is the key at `path`.

```text
P  = d₀·G;  if y(P) is odd: d₀ ← n − d₀            (BIP-341 taproot_tweak_seckey)
t  = int(tweak);  t ≥ n → 6A80
d  = (d₀ + t) mod n;  d = 0 → 6A80
aux = 32 random bytes
sig = BIP-340 Sign(d, message, aux)                (BIP-340 "Default Signing")
```

`Q = P_even + t·G` is computed independently of `d` (`PACE_GM`, or `Q = P_even` when `t = 0`, so
the engine is never given a zero scalar); its parity decides BIP-340's negation of `d`. A zero
nonce `k'` (probability about 2⁻²⁵⁶) returns `6F00`.

For a BIP-86 key-path spend the host sends `tweak = TaggedHash("TapTweak", x(P))`; for a script
tree `TaggedHash("TapTweak", x(P) ‖ merkleRoot)`; `tweak = 0³²` signs with the even-y internal key.
Output `R_x(32) ‖ s(32)`.

### 12.3 Ed25519, single-pass and hedged

`begin(path)`:

```text
sk, a, prefix, A    per §10.4 (A as a Wei25519 point)
N   = edCounter + 1;  T-EDCTR: edCounter ← N (committed before r is computed)
Zr  = 32 random bytes
r   = int_le(SHA-512("qntx-card/v1/ed25519-nonce" ‖ Zr ‖ prefix ‖ ID(A_card) ‖ u32(N))) mod ℓ
R   = r·G_W;  respond W(R)
H   = empty SHA-512 context
```

`ID(A_card)` is this card's card ID (§1), so member cards that share the seed and reach the same
`N` still derive different `r`. The hash input is 110 bytes, one SHA-512 block, with the random
`Zr` ahead of the secret `prefix`.

`update(chunk)`: `H.update(chunk)`. `finish(chunk)`: `H.update(chunk)`;
`k = int_le(H.final()) mod ℓ`; `S = (r + k·a) mod ℓ` computed per §16.2 item 6; check
`S·G_W = R + k·A`; output `le32(S)`; wipe `sk`, `h`, `a`, `prefix`, `r`, `k`, `S` and the stream.

With the stream `encode(R) ‖ encode(A) ‖ M` the signature `encode(R) ‖ le32(S)` verifies under
RFC 8032 §5.1.7 for `encode(A)` (a worked example built this way is accepted by OpenSSL and
libsodium). It is not deterministic. Whatever stream the host sends, `S = r + k'·a`
with a fresh secret `r`, so the outputs reveal nothing about `a`; a wrong stream only produces a
signature that is invalid under the card's key. `r` does not repeat even if the random generator
fails (counter and card ID), and is unpredictable even if the counter is faulted (secret `prefix`
and `Zr`). The message crosses the interface once and is never stored on the card.

## 13. Status words

### 13.1 Outer

This section and §13.2 cover the wallet applet; the NDEF applet's status words are defined in §15.

| SW | Meaning |
| --- | --- |
| `9000` | Success; for `SESSION` the result is the inner status in the response record |
| `6283` | Uninitialised (§4.3): repeat `GET_IDENTITY` until it returns another status word |
| `6700` | Wrong `Lc` |
| `6982` | Record failure (§8.3 steps 2–5); the session is torn down |
| `6985` | Wrong `life`, or `SESSION` with no open session |
| `6A80` | Invalid data (point, certificate, signature) |
| `6A86` | Wrong `P1`/`P2` |
| `6D00` | Unknown `INS` |
| `6E00` | Wrong `CLA` |
| `6F00` | Internal error |

### 13.2 Inner

| SW | Data | Meaning |
| --- | --- | --- |
| `9000` | per command | Success |
| `63Cx` | — | Wrong access code; `x ∈ [1, 9]` attempts remain before the wallet is erased |
| `6700` | — | Wrong data length, or record plaintext shorter than 3 bytes |
| `6982` | — | Access code not verified in this session |
| `6983` | — | The failure limit was reached; the wallet on this card has been erased |
| `6985` | — | Wrong `life`; no offer; no pending stream, export or import; Ed25519 counter exhausted |
| `6986` | — | `VERIFY` while `F ≤ f < L` without `W` `WAIT` units completed in this session since the previous attempt (§7.3, §9.5 step 3); nothing was written |
| `6A80` | — | Invalid data: member IDs, seed, path, tweak, derived key, certificate, signature, point, MAC, padding, payload, re-seal of a different wallet |
| `6A86` | — | Wrong `P1`/`P2` |
| `6D00` | — | Unknown inner `INS` |
| `6F00` | — | Internal error or detected fault (including an inconsistent failure counter or a failed read-back or fingerprint check in `VERIFY`); the session is torn down after this response |

## 14. Personalisation

### 14.1 GET_IDENTITY (`80 E0 00 00 00`)

While uninitialised (§4.3) GET_IDENTITY performs the next initialisation step and returns `6283`
while steps remain; the call that completes the last step continues with the checks below and
returns `A`.

Checks: `life = FACTORY` (else `6985`); `P1 = P2 = 0x00` (else `6A86`); no data (else `6700`).
Response: `A(33)`.

### 14.2 PERSONALIZE (`80 E2 00 00 A2 cert(97) ‖ caKey(65)`)

Checks, in order: `life = FACTORY` (else `6985`); `P1 = P2 = 0x00` (else `6A86`); `Lc = 162`
(else `6700`); `cert[0..33) = A`; `caKey[0] = 0x04`, both coordinates `< p` and
`y² ≡ x³ + 7 (mod p)`, checked explicitly (`setW` does not check points); `cert` verifies under
`caKey` (each else `6A80`). Effect: T-PERSO. Response: empty.

### 14.3 Production procedure

Every production card MUST be prepared as follows:

1. Admission: the silicon batch passes the tests of §3 and `docs/architecture.md` §10.
2. Load the load file `F0716E747800` over the secure channel protocol recorded for the batch at
   admission (GlobalPlatform SCP03, or SCP02 `i = 55`), authenticated with the transport keys
   after the tool has verified the card cryptogram; the personalisation tool MUST check the load
   file hash against the reproducible release build.
3. Install the wallet applet (`F0716E74780101`, no install parameters) and the NDEF applet
   (`D2760000850101`, applet-specific install data = the NDEF message, §15).
4. Repeat `SELECT`, `GET_IDENTITY` until it returns `9000` (initialisation, §4.3); the tool
   bounds the repetitions at 16 and fails the card otherwise. The last response carries `A`.
5. The batch CA signs `"qntx-card/v1/cert" ‖ A` in its HSM.
6. `PERSONALIZE`; `SELECT`, `OPEN` with a fresh host key; verify the certificate and the session
   signature against the batch anchor.
7. GlobalPlatform `GET STATUS`: the registry MUST equal the batch's factory registry recorded at
   admission plus exactly the load file and the two instances above.
8. Print `short(A)` (§1) on the card face and read it back by the tool's camera or operator check
   against `short(A)` computed from the `A` returned by `GET_IDENTITY` in step 4, which MUST equal
   `cert[0..33)` from the `OPEN` of step 6 (`GET_IDENTITY` is not available after `PERSONALIZE`).
9. Replace the ISD keys with random keys generated inside the personalisation tool and never
   stored or output.
10. Record card ID, short ID, CPLC, certificate and load file hash in the batch record.

The CA private keys live only in an offline HSM under two-person control. Test and production
CAs are distinct.

## 15. NDEF applet

A read-only NFC Forum Type 4 Tag (mapping version 2.0). It holds no keys and no user data.

| File | ID | Content |
| --- | --- | --- |
| Capability container | `E103` | `000F ‖ 20 ‖ 00FF ‖ 00FF ‖ 04 06 ‖ E104 ‖ u16(2 + |msg|) ‖ 00 ‖ FF` (15 bytes) |
| NDEF file | `E104` | `u16(|msg|) ‖ msg` |

`msg` is the applet-specific install data, 1–100 bytes (installation fails otherwise). The
applet does not parse it.

Commands (`CLA = 0x00`, else `6E00`); the selected file is transient and reset by every
`SELECT` by AID:

| Command | APDU | Result |
| --- | --- | --- |
| SELECT by AID | `00 A4 04 00 07 D2760000850101 00` | `9000` |
| SELECT file | `00 A4 00 0C 02 fid` | `9000` for `E103`, `E104`; any other data (other `fid`, `Lc ≠ 2`) → `6A82` and the selection is unchanged; `P1`/`P2` other than `00 0C` → `6A86` |
| READ BINARY | `00 B0 off(2) Le` | No file selected → `6985`; `off > size` → `6B00`; else `min(Ne, size − off)` bytes from `off`, `9000` |
| UPDATE BINARY | `00 D6 …` | `6985` |
| other `INS` | — | `6D00` |

## 16. Implementation requirements

### 16.1 Atomicity and ordering

1. Every change of a field of §4.2 happens in the transaction §4.3 names for it, and in no other
   command. No transaction nests or spans commands. The only other persistent writes are
   `setW` on public-key objects that hold no state and no secret (the four rotating ECDSA
   verification keys of `SIGN_ECDSA`, and the two peer-key slots used to verify `sig_T` and
   `sig_S` in `EXPORT` and `IMPORT`); they happen outside any transaction, and a torn write only
   makes the current verification fail (`6F00` or `6A80`), never changes behaviour later. In
   `LOADED`, peer-key slot `k ∈ {0, 1}` holds the key of the `k`-th member other than this card,
   in `members` order; in `BLANK`, slot 0 is used. Before `setW` the card reads the slot
   (`getW`) and skips the write when it already holds the decompressed key.
2. T-FAIL is committed, the transaction depth checked to be 0 and `fails` read back and checked
   against the expected value, before the candidate access hash is used in any computation
   (§9.5). No response data is written to the APDU buffer while a transaction is open.
3. T-EDCTR is committed before `r` is computed (§12.3).
4. T-OFFER is committed before the offer is output.
5. Persistent arrays are never written with `arrayCopyNonAtomic`/`arrayFillNonAtomic` or other
   non-atomic writes inside a transaction.
6. No object is created after the constructor returns.
7. In a session that is not verified, a `LOADED` card performs no persistent write other than
   T-FAIL, T-ERASE and (with the right code) T-OK in `VERIFY`, T-OFFER when `offer = NONE`, the peer-key slot write of
   `IMPORT` `P1 = 0x00` when the slot does not hold the sender's key, and T-INSTALL in `IMPORT`
   `P1 = 0x01`, which needs an export from a member whose code was verified. Absent tearing, an actor
   without the code therefore causes at most `L` T-FAIL commits before the wallet is erased (or
   the user's next success resets the count), one T-OFFER per offer and one write per peer-key
   slot (`docs/threat-model.md` P19).

Key objects are overwritten with fresh random values inside the transactions (T-CREATE, T-INSTALL,
T-CHANGE, T-ERASE), never cleared after a commit, so a power loss leaves no residual key that
belongs to a past transfer or ciphertext (§3 item 7).

### 16.2 Fault resistance

1. `life`, `origin`, `offer`, `init`, the session flags `verified` and session-open, the
   pending-state
   flags, and the result of every signature, MAC, certificate and fingerprint verification are
   16-bit values from a code set whose members have pairwise Hamming distance ≥ 8 and differ from
   `0x0000` and `0xFFFF` (`docs/architecture.md` §6). A transient flag that reads `0x0000` is the state
   the platform leaves after clearing transient memory and means no session, not verified, no
   pending state. Any other value returns `6F00` and tears the session down.
2. `fails` is stored with its bitwise complement in every state, from the constructor on
   (`fails ← 0` writes `0x0000 ‖ 0xFFFF`). `STATUS` returns `6F00` when they disagree, in `BLANK`
   and in `LOADED`; `VERIFY` performs T-ERASE and returns `6F00` (§9.5 step 2).
3. The access-code comparison is computed twice with independent `KDF108` and CMAC computations.
   T-OK, decryption and `verified` are reachable only through two independent branches, each
   comparing a coded result with `CHECK_OK`, whose fall-through path is the failure path; T-OK
   additionally requires the fingerprint check of §9.5 step 8.
4. Each of the following checks is evaluated twice, with coded results, immediately before the
   effect it guards: the `life` check of `PERSONALIZE`, `CREATE`, `OFFER`, `IMPORT` and `ERASE`;
   `verified` before each signature, public key, `CHANGE` effect, `ERASE` effect and export
   payload; the certificate and membership checks of `EXPORT`; the equality checks of `IMPORT` in
   `LOADED`; the gates of `VERIFY` steps 2 and 6 (in step 2 the two evaluations use the two
   independent reads `f_a` and `f_b`). The wait check of `VERIFY` step 3 is evaluated
   once: skipping it saves one wait and cannot raise the number of comparisons above `L`.
5. Every signature is self-verified before output (§12): ECDSA with `verifyPreComputedHash`
   under the leaf public key computed by public derivation (`K_par + IL·G`) for a non-hardened
   leaf, or `k_leaf·G` for a hardened leaf; BIP-340 per BIP-340 `Verify` with
   `Q = P_even + t·G`; Ed25519 by `S·G_W = R + k·A`. Self-verification detects faults in the
   signing computation. For a hardened ECDSA leaf and for Ed25519 the verification key derives
   from the same private value, so a fault that rewrote that value before signing is not detected
   by the card; the host's verification against the public key it cached for that path rejects
   such a signature.
6. Secret products are computed on two additive shares re-drawn uniformly for every signature
   (`d = d₁ + d₂ mod n`, `a = a₁ + a₂ mod ℓ`) and recombined in this order:
   `s = ((k + e·d₁) mod n + e·d₂) mod n` and `S = ((r + k·a₁) mod ℓ + k·a₂) mod ℓ`. No intermediate
   value equals `e·d` or `k·a`.
7. Every input to `ALG_RSA_NOPAD` is reduced below the modulus in constant time before use (§3
   item 1): `a + b` by one conditional subtraction of `m`, `a − b` as `a − b + m`.
8. An exception from `PACE_GM` or `PLAIN_XY` caused by an infinite result during BIP-32 child
   derivation is an invalid child (`6A80`, §10.3); any other unexpected exception is `6F00`.

### 16.3 Secrets and wiping

1. Secrets on the card: `idKey`, `linkKey` and `wrapKey` private material (key objects); session
   keys (transient key objects); the decrypted seed, derived keys and chain codes, nonces,
   `prefix`, `Zr`, ephemeral scalars, shares, transfer payloads, candidate access hashes
   (transient arrays).
2. Every transient secret is wiped after its last use in the command and on teardown, on every
   path including exceptions.
3. After every `SESSION` the APDU buffer is overwritten where it held inner plaintext.
4. Unexpected exceptions map to `6F00`; native exception reason codes are never returned.

### 16.4 Constant time

Comparisons of MACs, tags, fingerprints and access-code results; modular addition, subtraction,
reduction and conditional negation; clamping; share recombination: no branch, loop bound or array
index depends on secret data.

### 16.5 Points

A private key used in more than one scalar multiplication with external input MUST only be
multiplied by points that were checked to be on the curve (`IMPORT` `P1 = 0x00` step 6).
Single-use private keys (`x` in `OPEN`, `e` in `EXPORT`) rely on `PLAIN_XY` rejecting invalid
points (§3 item 3). Public keys loaded with `setW` from external input are checked explicitly
first (`caKey` in `PERSONALIZE`, decompressed `A_T` and `A_S`, §10.5), because `setW` does not
check points. The identity key is never multiplied by any point. Wallet keys are multiplied only by
`G`, `G_W` or points the card computed itself.

### 16.6 Memory and time

All session state is `CLEAR_ON_DESELECT`. The domain parameters of a transient EC key object are
cleared together with its value (on the development card on every deselection, including a
re-`SELECT` of the same applet, and on reset); the applet loads them in `select()`, before any
use (§8.5). Each initialisation step of §4.3 completes within
500 ms; on the baseline chip every command MUST complete within
1500 ms. Hosts MUST set the reader transceive timeout to at least 5000 ms. Card times computed
from unit costs measured on the development card: `OPEN` 160 ms; `VERIFY` 124 ms; `WAIT` 965 ms;
`CREATE` 106 ms; `SIGN_ECDSA` 411 ms (cold, depth 5); `SIGN_BIP340` 724 ms (cold); `SIGN_ED25519`
begin 430 ms, update 21 ms, finish 486 ms; `PUBLIC_KEY` ed25519 217 ms; `OFFER` 137 ms (78 ms with
a valid offer); `EXPORT` `P1 = 0x00` 424 ms; `IMPORT` `P1 = 0x00` 471 ms. The longest command
(`WAIT`) has a margin of 1.55× to the limit (1.36× at the 1100 ms bound of §3 item 9), every
other command at least 2×. Full commands are timed by the real-card suite before
freeze.

### 16.7 Randomness

Every random value is drawn from `RandomData.ALG_KEYGENERATION` (§3 item 6). The applet does not
run its own health tests on the generator: they are part of the certified platform (S4 in
`docs/threat-model.md`), and the failure that matters for a contactless card, a generator that repeats
its output after every power-up, is tested at admission and detected by hosts through repeated
`cardEph` values (a host remembers recent `cardEph` values per card and stops using a card that
repeats one). ECDSA nonces are generated by the platform and are never made
deterministic: the same leaf key may also sign BIP-340, and BIP-340 ("Alternative Signing")
warns that nonces without randomness are unsafe when the same key is used in another context.

## 17. Versioning and freeze

The protocol version is the last byte of the wallet instance AID (`0x01`). There is no version
field and no negotiation. Until the first production batch, this document may change in place.
The production protocol is frozen after an external audit of the applet and this document,
including fault-injection and tearing evaluation; afterwards a change ships only as a new
protocol with a new instance AID on new cards, and hosts support every version still in use.
A card-generated seed can never move to a card of another protocol version or batch (§11.1), so
a defect found after freeze is handled by the host: it stops creating wallets on the affected
batch or version and guides the user to migrate the funds to a new card set.

## 18. Test vectors

`spec/vectors/` holds JSON files with lowercase hexadecimal strings, licensed
`MIT OR Apache-2.0`. Keys in them are public test keys and MUST NOT be used for funds. Every file
is generated by two independent generators (Java with BouncyCastle; TypeScript with noble) that
MUST agree, and is consumed by the card tests and by the qntx/wallet host. Randomised card
outputs are covered by verification-only cases; for unit tests that fix the random source the
files give exact bytes.

| File | Sections | Content | Independent oracle |
| --- | --- | --- | --- |
| `kdf.json` | 1, 8.1, 10.1 | `KDF` and `KDF108` inputs and outputs | NIST SP 800-38B CMAC examples; Python `cryptography` |
| `cert.json` | 5 | Test CA, identity keys, `ID`, certificates; wrong anchor, wrong key, bad signature, high-`s` | noble `secp256k1`; BouncyCastle |
| `session.json` | 8.1–8.2 | Fixed ephemerals → `TH` (including `A`), session signature check, `Z`, keys; a signature by another certified key over the same ephemerals is rejected | noble; Python `cryptography` |
| `record.json` | 1, 8.3–8.4 | Keys, counters → command and response records; tampered tag, padding (including a 32-byte padding block), counter, length | Python `cryptography` |
| `access.json` | 7.1 | Codes and card IDs → `accessHash`; the same code on two cards; rejected codes (5 and 65 characters, non-ASCII, control characters) | `argon2-cffi` (reference C); noble `argon2id` |
| `wrap.json` | 7.2, 10.1 | `wrapKey`, `accessHash`, seed → `K_enc`, `K_mac`, `ct`, `tag`, `fp` | Python `cryptography`, `hashlib` |
| `transfer.json` | 9.12–9.14, 10.5, 11 | Fixed link keys, `e`, identity keys → decompressed peer keys, `M`, `TH`, `Z`, keys, payload, `ct`, `tag`; tampered, non-member, non-residue `x` and wrong-parity cases; re-seal of the same wallet and refusal of a different `fp`, `origin` or member list | noble; Python `cryptography`; libsecp256k1 (`coincurve`) |
| `derivation.json` | 10.2–10.4 | BIP-32 test vectors 1–5, SLIP-10 ed25519 vectors 1–2, wallet template paths, invalid-child handling; Wei25519 points `W(A)` with their edwards25519 encodings (base point and 8 random points) | Official BIP-32 and SLIP-10 vectors; `@scure/bip32`; OpenSSL and libsodium Ed25519 public keys |
| `ecdsa.json` | 12.1 | Keys, digests, signatures for verification; recovery-id and low-`s` cases | noble `secp256k1`; BouncyCastle |
| `bip340.json` | 12.2 | BIP-340 official vectors; BIP-341/BIP-86 tweak cases; fixed-`aux` exact signatures | BIP-340 reference CSV; BIP-86 vectors; noble `schnorr` |
| `ed25519.json` | 10.4, 12.3 | RFC 8032 §7.1 vectors (verification); fixed `N`, `Zr`, card ID → exact `r`, `W(R)`, `S`; two card IDs with equal `N` and `Zr` give different `r`; a wrong stream gives an invalid signature | RFC 8032; noble `ed25519`; libsodium |
| `apdu.json` | 9, 13, 14 | Every command's encoding; for each command every precondition in checking order with its status word; the `UNINIT` setup and the `INIT` cases of §4.3 | Generated from this document's tables by `spec/vectors/gen/apdu.py` |
| `verify-sequence.json` | 7.3, 9.3, 9.5, 9.12, 9.14, 9.15 | Command sequences with the expected inner status word and `STATUS` after each step: wrong codes from `f = 0` to `L` (`63C9` … `63C7`, then `6986` until `W` `WAIT`s, `63C6` … `63C1`, `6983`); `waited` lost on a new `OPEN`; `WAIT` beyond `W`; a right code at every `f < L` resets; the `tries = 0` state (power loss after the `L`-th T-FAIL) where the next `VERIFY` returns `6983` without comparing; a re-seal of a `LOADED` card resets `fails`; `OFFER` repeated with a valid offer returns the same `LK`; `IMPORT` `P1 = 0x00` after a committed install returns `6985` | Generated from §9 by `spec/vectors/gen/sequence.py`; replayed by the card suite and by the qntx/wallet protocol client against the simulator |
| `ndef.json` | 15 | Capability container and NDEF file for sample messages; READ BINARY offsets | NFC Forum T4T 2.0 §5 by hand |
