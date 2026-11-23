<!--
SPDX-FileCopyrightText: 2026 QuantX
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# qntx/wallet-applet architecture and implementation plan

This document defines the rewritten `qntx/wallet-applet` repository: layout, classes, memory,
dispatch, countermeasure placement, build, simulator, tests, tools, CI and release, the
repository `AGENTS.md`, and the plan that splits the work into the six fixed stages. The
normative protocol is `protocol.md`; reasons are in `decisions.md` (D*n*). Numbers come from
`$A/resolve-2/evidence/budget_r2.out` (B2).

## 1. Repository layout

Everything on `origin/main` is deleted (`wallet`, `backup`, `ndef`, `shared`, `tools`, `tests`,
`notes`, `docs`; the `sdks` submodule is kept only for the JCDK kit). The new tree:

```text
wallet-applet/
├── applet/                    the one CAP: package org.qntx.card (Java 8 source, JC 3.0.5 API)
│   └── src/main/java/org/qntx/card/*.java
├── sim/                       card simulator: vendored jcardsim fork + transaction/tearing runtime + TCP server
│   ├── jcardsim/              licel/jcardsim at a pinned commit (Apache-2.0), patches as commits
│   └── src/main/java/org/qntx/card/sim/
├── host/                      reference host library written from protocol.md (Java, BouncyCastle)
│   └── src/main/java/org/qntx/card/host/
├── tests/                     JUnit 6: unit, simulator command tests, tearing, vectors, fuzz; admission probe; real-card suite
│   ├── src/test/java/
│   ├── src/admission/java/      test-only admission CAP (AID F0716E7478FF), §10 probes
│   └── src/realCard/java/
├── tools/                     qntx-card CLI: install, personalise, registry, debug shell (picocli, GlobalPlatformPro, apdu4j)
├── spec/
│   ├── protocol.md            normative specification (MIT OR Apache-2.0)
│   └── vectors/               *.json + gen/java (BouncyCastle) + gen/ts (noble) + gen/apdu.py
├── AGENTS.md README.md SECURITY.md CONTRIBUTING.md LICENSE LICENSES/ REUSE.toml
├── buildSrc/                  the CAP conversion shared by applet/ and the admission CAP
├── build.gradle.kts settings.gradle.kts gradle/libs.versions.toml gradle.properties
└── .github/workflows/{ci.yml,release.yml}
```

`settings.gradle.kts` includes exactly `applet`, `sim`, `host`, `tests`, `tools`. Copyright
`QuantX`; applet, sim patches, host, tests, tools AGPL-3.0-or-later; `spec/**`
`MIT OR Apache-2.0`; vendored jcardsim keeps Apache-2.0 (compatible with AGPL-3.0-or-later).

## 2. Package and classes

One CAP, one package `org.qntx.card`, package AID `F0716E747800`, two applet classes. Every
class has one responsibility. "Stage" is the implementation stage that creates the class and its
tests (§14); later stages may extend a class only as their acceptance tables state.

| Class | Responsibility | Spec | Stage |
| --- | --- | --- | --- |
| `WalletApplet` | `install`, `select`, `process`; outer dispatch; inner dispatch with the checking order, pending-state ending and `6F00` mapping of `protocol.md` §9.2 | §6, §9.1, §9.2 | scaffold |
| `Const` | Status words, INS codes, labels, coded constants (§6), sizes | §13 | core |
| `Mem` | Allocates every transient array and shared engine once; scratch ownership rules (§5.2) | §16.3 | core |
| `Bytes` | Constant-time compare, wipe, `u16`/`u32` codecs, M2 pad/unpad | §1, §16.4 | core |
| `Kdf` | `KDF` (SP 800-56C one-step, SHA-256) and `KDF108` (SP 800-108, CMAC) | §1 | core |
| `Secp256k1` | Domain parameters, `x·P` via `PLAIN_XY`, `s·G + H` via `PACE_GM`, compression, decompression of compressed identity keys (`y = (x³+7)^((p+1)/4)`, `y²` check, parity), explicit on-curve check, DER ⇄ `r ‖ s` | §1, §10.5, §16.5 | core |
| `Identity` | `idKey`, `cert`, `caKey`; `GET_IDENTITY`, `PERSONALIZE`; `Sign`/`Verify` with domain labels; peer certificate verification; `ID(A)` | §5, §14.1–14.2 | core |
| `Session` | `OPEN`, keys, counter, command/response records, teardown | §8 | core |
| `State` | The one persistent array `state` and its field offsets (§4); coded reads and writes of `life`, `origin`, `offer`, `fails`; every class writes its fields only through `State`, inside its named transaction | §4.2 | core |
| `Wallet` | Persistent wallet fields incl. the seed fingerprint `fp`, wrap/unwrap (§10.1), failure counter, `STATUS`, `CREATE`, `VERIFY` with the two independent counter reads and the read-back gate, `CHANGE`, `ERASE`, `WAIT`, `WalletInfo` | §4, §7, §9.3–9.7, §9.15, §10.1 | wallet |
| `Derivation` | HMAC-SHA512, BIP-32, SLIP-10, master keys, node caches, `PUBLIC_KEY` | §9.8, §10.2–10.4 | wallet |
| `ModArith` | Modular multiply/square through `ALG_RSA_NOPAD` (keys `(ℓ,2)`, `(n,2)`, `(p,2)`, `(p,(p+1)/4)`); constant-time 256-bit add, subtract, reduce, conditional negate; constant-time reduction of every RSA input below the modulus; share splitting | §16.2.6, §16.4 | wallet |
| `Wei25519` | Wei25519 domain, `x·B` (no Edwards encoding on the card; the map is host-side, §10.4) | §10.4 | wallet |
| `Ecdsa` | `SIGN_ECDSA`: sign, independent leaf public key, self-verify with rotating verify keys | §9.9, §12.1 | sign |
| `Bip340` | `SIGN_BIP340`: tweak, BIP-340 signing with masked `e·d`, self-verify | §9.10, §12.2 | sign |
| `Ed25519` | `SIGN_ED25519`: nonce, counter, stream, masked `k·a`, self-verify | §9.11, §12.3 | sign |
| `Transfer` | `OFFER` (idempotent while the offer is valid), `EXPORT`, `IMPORT` (incl. the membership check before decompression and the re-seal equality checks in `LOADED`), link key, the two peer-key slots, pending export/import | §9.12–9.14, §11 | sets |
| `NdefApplet` | Read-only Type 4 Tag | §15 | release |

## 3. Command dispatch

```text
process(apdu)
├─ selectingApplet()                → Session.teardown(); 9000                 (select() also tears down)
├─ CLA ≠ 0x80                       → 6E00
├─ INS 0xE0 GET_IDENTITY            → Identity
├─ INS 0xE2 PERSONALIZE             → Identity            (T-PERSO)
├─ INS 0x10 OPEN                    → Session.open
├─ INS 0x12 SESSION                 → Session.unwrap  ──fail──▶ teardown; 6982 / 6985 in clear
│                                        │ plain = INS P1 P2 data (in the APDU buffer)
│                                        ▼
│                                   WalletApplet.inner(ins, p1, p2, data)
│                                     1. endPendingExcept(ins, p1)                 (§9.2)
│                                     2. INS known?        else 6D00
│                                     3. life allows?      else 6985    (coded check, §6)
│                                     4. P1/P2             else 6A86
│                                     5. length            else 6700
│                                     6. verified?         else 6982    (coded check)
│                                     7. handler (Wallet | Derivation | Ecdsa | Bip340 | Ed25519 | Transfer)
│                                        preconditions 6985, data 6A80, effect, response into APDU buffer
│                                   Session.wrap(response, SW)  → R-APDU ct ‖ tag ‖ 9000
│                                   catch ISOException(sw)       → wrap(sw)
│                                   catch any other Throwable    → wrap(6F00); teardown after send
└─ otherwise                        → 6D00
```

Handlers write the response data to the start of the APDU buffer and return its length;
`Session.wrap` encrypts in place. The applet never calls `setOutgoing` before the record is
complete. Every handler runs in `try { … } finally { Mem.wipeScratch(); }`.

Command data are collected with `setIncomingAndReceive` followed by `receiveBytes` in a loop
until `Lc` bytes have arrived (audit-impl F-20); the record is then processed in place in the
APDU buffer.

A transient coded flag that reads `0x0000` is the platform-cleared state — no session, not
verified, no pending state (a failed `SELECT FILE` also clears `CLEAR_ON_DESELECT` without
calling `select()`); `0x0000` is the only accepted value outside the code set and selects the
safe branch rather than `6F00` (audit-impl F-19). The transient EC curve domains die with the
selection epoch regardless; `select()` re-loads them (§5.5).

A `PACE_GM`/`PLAIN_XY` `CryptoException` on an infinite result during BIP-32 child computation
maps to `6A80` (invalid child, §10.3), not `6F00` (audit-impl F-13). The `6F00` mapping is
otherwise unchanged.

## 4. Persistent state

Every field of `protocol.md` §4.2 that is not a key object lives in one persistent `byte[272]`
array `state`, allocated by `State` in the constructor:

| Offset | Length | Field | Representation | Owner |
| --- | --- | --- | --- | --- |
| 0 | 2 | `life` | coded `short` | `Wallet` (`Identity` writes `BLANK` in T-PERSO) |
| 2 | 4 | `fails` | `f ‖ ~f`; `fails ← 0` writes `0000 FFFF` (also in the constructor) | `Wallet` |
| 6 | 2 | `origin` | coded `short` | `Wallet` |
| 8 | 2 | `offer` | coded `short` | `Transfer` |
| 10 | 4 | `edCounter` | `u32` | `Ed25519` |
| 14 | 49 | `members` | count + 3 IDs | `Wallet` |
| 63 | 32 | `fp` | never output | `Wallet` |
| 95 | 64 | `ct` | | `Wallet` |
| 159 | 16 | `tag` | | `Wallet` |
| 175 | 97 | `cert` | | `Identity` |

Key objects:

| Field | Representation | Owner |
| --- | --- | --- |
| `idKey` | `KeyPair(ALG_EC_FP, 256)`, private `TYPE_EC_FP_PRIVATE` | `Identity` |
| `caKey` | `ECPublicKey` (secp256k1 domain) | `Identity` |
| `wrapKey` | `AESKey` `TYPE_AES`, 128; in `BLANK` it holds a random key unrelated to any ciphertext (T-ERASE installs it inside the transaction) | `Wallet` |
| `linkKey` | `KeyPair(ALG_EC_FP, 256)`; T-CREATE/T-INSTALL/T-ERASE overwrite the private key with a fresh random scalar (`setS`) inside the transaction | `Transfer` |
| peer-key slots 0, 1 | two `ECPublicKey` (secp256k1 domain), state-free (`protocol.md` §16.1 item 1) | `Transfer` |

One array for every non-key field is the simplest layout in which each named transaction touches a
single array: `life`, `fails`, `offer` and `members` are each written by several transactions
with different field sets (audit-final F-15). The array's physical page alignment is unknown, so
each transaction is charged two array pages: with card A's page-granular commit buffer (512 B
per array page and per `setKey`/`setS`, 1,024 B per `setW`/`genKeyPair`, audit-impl F-12) the
worst case is T-PERSO, T-CREATE, T-INSTALL, T-ERASE and T-OFFER at 2,048 B (40 %), T-CHANGE
at 1,536 B, T-FAIL, T-OK and T-EDCTR at 1,024 B (measured by `CommitCapacityTest`). There is no
`clearKey` anywhere (§16.1). The constructor generates `idKey` and an initial `linkKey`
(`genKeyPair`) and sets `fails ← 0`, `offer = NONE`, `life = FACTORY`. Each transaction of `protocol.md` §4.3 is one method
that begins, writes and commits, with no other persistent write inside or outside it.

## 5. Memory

### 5.1 Budget (J3R180)

Transient sizes measured in the simulator (sizes from card A); the persistent column stays an
estimate where nothing measures it.

| Class | Transient (`CLEAR_ON_DESELECT`) | Persistent (objects and arrays) |
| --- | --- | --- |
| `Session` | 4 AES transient keys 128; counter, `verified`, `waited`, stream/export/import state words 10 → **138** | key headers 160 |
| `State` | — | `state` 272 (§4) |
| `Wallet` | session seed 64; wrap keys `K_enc`, `K_mac` 2 × 32 (in `Mem`) → **128** | `wrapKey` 72 |
| `Derivation` | secp256k1 cache 170 (parent key uncompressed); ed25519 cache 105; working node 101; HMAC pad 192 → **568** | — |
| `ModArith` | scratch: 2 × 64 RSA in/out, 4 × 32 operands → **256** | 4 RSA-512 private keys `(ℓ,2)`, `(n,2)`, `(p,2)`, `(p,(p+1)/4)` → **736** |
| `Secp256k1` | transient EC private key 272; 2 × 65 point scratch 130; ECDSA `Signature` 112 → **514** | key header 84; constants 200 |
| `Wei25519` | transient EC private key 272 → **272** | key header 84; constants 220 |
| `Ed25519` | stream: `a` 32, `r` 32, `R`, `A` points 130 → **194** (in `Mem`, no encoding on the card) | — (`edCounter` in `state`) |
| `Transfer` | pending sender ID 16; 2 scratch AES keys 64 (in `Mem`) → **80** | `linkKey` 772; 2 peer-key slots 760; key headers 80 |
| `Identity` | — | `idKey` 772; `caKey` 380 |
| `Ecdsa` | — | 4 rotating verify keys 1,520 (§5.4) |
| `Mem` (shared engines) | AES-CBC 48; CMAC 32; SHA-256 128; SHA-512 208 → **416** | engine objects 400 |
| `NdefApplet` | selected file 2 | CC + message ≤ 117 |
| **Total** | **2,568** of 3,990 → margin 1,422 B (36 %) | **≈ 6.6 KB** + CAP 26,860 B load components (the `qntx-card.cap` file is 129,684 B) of 157,524 B |

Budget rule (acceptance): transient total ≤ 3,390 B (15 % margin on the 3,990 B JCAlgTest
pool) as reported by the simulator's memory accounting (§8) and, on real cards, by
`JCSystem.getAvailableMemory` after install (§10). The pool measured on card A is ≈ 4,130 B
(audit-impl §6). Commit capacity is consumed per page: 512 B per array page and per
`setKey`/`setS`, 1,024 B per `setW`/`genKeyPair` on card A (audit-impl F-12); every named
transaction MUST consume ≤ 50 % of `getMaxCommitCapacity`, and the single-array layout of §4
keeps every named transaction ≤ 2,048 B (40 %) at the worst-case alignment (measured by
`CommitCapacityTest`).

### 5.2 Scratch plan

Commands are sequential, so one command owns all scratch arrays (`Mem.W` 256 B arithmetic,
`Mem.P` 130 B points, `Mem.H` 192 B HMAC, `Mem.N` 101 B working node). Scratch content never
survives a command: `Mem.wipeScratch()` runs in `finally`. State that must survive between
commands lives only in dedicated arrays: session keys and counter (`Session`), `waited`
(`Wallet`), seed (`Wallet`), caches (`Derivation`), stream (`Ed25519`), pending sender ID and
transfer keys (`Transfer`).
Record plaintext is processed in place in the APDU buffer and overwritten after the response
(`protocol.md` §16.3).

### 5.3 Node caches

`Derivation` keeps one secp256k1 entry (path, private key, chain code, uncompressed public key of
the parent of the most recently derived leaf) and one ed25519 entry (path, key, chain code of
the parent). A request whose path minus its last index equals the cached path costs one
HMAC-SHA512. Caches live in `CLEAR_ON_DESELECT`, are wiped by `VERIFY` (step 1), `ERASE`,
a successful `IMPORT P1=1` and teardown, and never change outputs. Hosts that order PSBT inputs by path get
one HMAC per input (B2: warm cache, 222 ms per segwit input, 535 ms per taproot input).

### 5.4 NVM writes and wear

| Operation | Persistent writes |
| --- | --- |
| `VERIFY` | T-FAIL (4 B), T-OK (4 B) |
| `WAIT` | none |
| `SIGN_ECDSA` | one `setW` (65 B) on one of 4 verify keys, chosen uniformly at random by one random byte `& 3` (no state kept) |
| `SIGN_ED25519` begin | T-EDCTR (4 B) |
| `EXPORT` `P1=0`, `IMPORT` `P1=0` | one `setW` on the peer's slot, skipped when the slot already holds that key |
| `CREATE`, `IMPORT` `P1=1`, `ERASE` | one transaction each, incl. `setKey`/`setS` (T-ERASE installs a fresh random `wrapKey`; T-CREATE/T-INSTALL/T-ERASE overwrite the link private key inside the transaction) |
| `CHANGE`, `PERSONALIZE` | one transaction each |
| `OFFER` | one transaction (T-OFFER) only when `offer = NONE`; nothing while the offer is valid |
| `OPEN`, `STATUS`, `PUBLIC_KEY`, `SIGN_BIP340`, update/finish | none |

The session ephemeral is generated by `x·G` into the transient private key, never by
`genKeyPair` on persistent objects (RP §2.7, §4.1). Endurance is 200k–500k cycles per cell
(RP L26, M); NXP's figure for this silicon is UNVERIFIED. Estimates at the pessimistic 200k:

| Cell | Writes | Lifetime at 200k cycles |
| --- | --- | --- |
| Each of the 4 ECDSA verify keys (random choice) | 100 ECDSA signatures a day → ~9,100 a year per key | ~22 years |
| `fails` | 2 per tap; 20 taps a day → 14,600 a year | ~13.7 years (34 years at 500k) |
| `edCounter` | 1 per Ed25519 signature; 50 a day → 18,250 a year | ~11 years (27 years at 500k) |

**Writes without the access code** (audit-final F-3, `protocol.md` §16.1 item 7, P19). Every
unauthenticated persistent write path on a `LOADED` card and its bound, for an actor who does not
cut the field:

| Path | Bound |
| --- | --- |
| `VERIFY` T-FAIL | ≤ `L` commits, then T-ERASE (the wallet is gone); the count resets only by the user's own success |
| `OFFER` T-OFFER | one per offer; the offer stays valid until T-INSTALL or T-ERASE |
| `IMPORT` `P1=0` peer-key `setW` | one per slot (2 slots); the sender must be a member, checked before decompression |
| `IMPORT` `P1=1` T-INSTALL (re-seal) | only with an export made by a member whose code was verified in its own session |
| Every other command in an unverified session | none |

On a `BLANK` card (no wallet) `OFFER`/`IMPORT` writes are not bounded; an actor who tears every
write can force repeated writes but holds the card and can destroy it anyway (A47). The
sacrificial-card endurance test covers T-FAIL/T-OK, `setW` and T-OFFER.

The real-card suite measures write behaviour that cannot be simulated (§10). Endurance on this
silicon stays UNVERIFIED (audit-impl F-21); the sacrificial-card endurance test — never on
development card A — is mandatory before the protocol freeze. Rotating cells are prepared in
the implementation so that the result cannot affect the wire.

### 5.5 Constants

- secp256k1: SEC 2 v2 §2.4.1 (`p`, `a = 0`, `b = 7`, `G`, `n`, `h = 1`, `(p+1)/4` for
  decompression, §10.5).
- Wei25519: domain parameters and the host-side Edwards map are normative in `protocol.md`
  §10.4; the card keeps only the domain and `x·B` — no modular inversion, no mod-`q`
  arithmetic, no encoding. `PUBLIC_KEY`/`SIGN_ED25519` begin output the affine point
  `X(32) ‖ Y(32)`. `derivation.json` and `ed25519.json` include the base point and 8 random
  points to pin the domain and the host map.
- Clamped scalars are multiples of 8 and may exceed `ℓ`: `a·B` is computed as `(a mod ℓ)·B` with
  constant-time reduction.
- `2²⁵⁶ mod ℓ` for reducing 512-bit hashes: `h = hi·2²⁵⁶ + lo` → `(hi mod ℓ)·(2²⁵⁶ mod ℓ) + (lo mod
  ℓ)`, the inner reductions by four constant-time conditional subtractions of `8ℓ, 4ℓ, 2ℓ, ℓ`.
- RSA moduli `ℓ`, `n`, `p` as 64-byte values with leading zeros; exponents `2` and `(p+1)/4`
  (32 bytes). Multiplication: `ab = ((a + b)² − (a − b)²)/4 mod m` (two squarings, division by
  4 as two modular halvings). Every operand is reduced below `m` in constant time before
  `doFinal` (`a + b` conditional subtraction of `m`, `a − b + m`): card A rejects inputs ≥ `m`
  (audit-impl F-14).
- A transient EC key holds its domain parameters only for the selection epoch: deselection or
  reset clears value and domain (card A, `probe-transient-reselect`), so `select()` re-loads
  both domains every time — `setS` on a domainless key throws `CryptoException`
  `ILLEGAL_VALUE` (§8 patch 13).

## 6. Countermeasure placement

Coded constants (RM(1,4) codewords, pairwise Hamming distance ≥ 8, generated and checked by
`$A/design/evidence/coded.py`):

| Name | Value | Name | Value |
| --- | --- | --- | --- |
| `LIFE_FACTORY` | `0x0F0F` | `OFFER_VALID` | `0x5555` |
| `LIFE_BLANK` | `0x0FF0` | `VERIFIED_NO` | `0x55AA` |
| `LIFE_LOADED` | `0x3333` | `VERIFIED_YES` | `0x5A5A` |
| `ORIGIN_GENERATED` | `0x33CC` | `CHECK_FAIL` | `0x5AA5` |
| `ORIGIN_IMPORTED` | `0x3C3C` | `CHECK_OK` | `0x6666` |
| `OFFER_NONE` | `0x3CC3` | | |

| Countermeasure (`protocol.md`) | Where |
| --- | --- |
| Lifecycle check with coded value, evaluated twice for `PERSONALIZE`, `CREATE`, `OFFER`, `IMPORT`, `ERASE`; any non-member value → `6F00` (§16.2.1) | `WalletApplet.inner` step 3; `Identity`, `Wallet`, `Transfer` before every T-* transaction |
| `verified` check at dispatch and again before output (§16.2.4) | `WalletApplet.inner` step 6; `Derivation.publicKey`, `Ecdsa`, `Bip340`, `Ed25519.begin` (before T-EDCTR), `Ed25519.finish` (before `le32(S)`; `update` has no effect beyond hashing, the dispatch gate only), `Wallet.change`, `Wallet.erase` (before T-ERASE), `Transfer.export1` immediately before writing the response. In `Ecdsa`/`Bip340` the self-verification `setW` on a verify key precedes the second-level check: under a single fault that forced the dispatch gate in an unverified session the card may write one public, stateless verify key — absent faults no unverified write happens (§16.1 item 7) |
| `fails` read twice independently into `f_a`, `f_b` (two separate reads of the persistent array, each with its complement check); the `f ≥ L` re-entry erase evaluated once on each (coded) at `VERIFY` step 2 | `Wallet.verify` |
| T-FAIL writes `f_a + 1` and commits; then the read-back gate evaluated twice independently, each on a fresh read and each a coded result: `getTransactionDepth() = 0`, value/complement consistent, value `= f_b + 1`, value `≤ L`; any failure → `abortTransaction` if a transaction is open, then T-ERASE + `6F00`; the candidate is never used (§16.1.2, §16.2.2) | `Wallet.verify` |
| T-EDCTR read back (transaction closed, stored `edCounter = N`) before `r` is computed (§16.1 item 3) | `Ed25519.begin` |
| T-OFFER read back (transaction closed, stored `offer = VALID`) before `LK` is output (§16.1 item 4) | `Transfer.offer` |
| `WAIT` gate before the comparison once `f_a ≥ F` (§9.5): a single check — a skipped wait yields at most one unwaited attempt and the guess bound stays `L` | `Wallet.verify` |
| Two-branch structure for T-OK: two independent `KDF108` + CMAC computations; T-OK, seed decryption and `verified` are reachable only through two independent branches whose fall-through path is failure; each compares a coded result with `CHECK_OK` (§16.2.3) | `Wallet.verify` |
| Seed fingerprint: after a match, `fp'` recomputed and compared with the stored `fp` (constant time, twice) before T-OK (§9.5 step 8) | `Wallet.verify` |
| Every signature/MAC/certificate verification result as `CHECK_OK`/`CHECK_FAIL`, checked twice | `Identity.verify`, `Transfer`, `Session.unwrap` |
| Double coded checks on every check that guards a persistent write or a seed-derived output (§16.2): each certificate, signature and MAC verification is computed once and its coded result is compared at its checking-order position (`6A80`), then the guards are evaluated twice immediately before the effect (`6F00`): `EXPORT` `P1 = 0x00` — certificate and membership (recomputed) before the pending export and `E`; `IMPORT` `P1 = 0x00` — certificate and, when not `BLANK`, membership before the peer-slot `setW`; `IMPORT` `P1 = 0x01` — MAC and, when not `BLANK`, the three re-seal equality checks (recomputed) plus `life` equal to the value read at the start, before T-INSTALL; `OFFER` — `life` before T-OFFER; `EXPORT` `P1 = 0x01` — `verified` before the payload; the `LOADED`-only checks are written `if (life != BLANK)` so a skipped branch enters them | `Transfer` |
| Self-verification of every signature (§16.2.5): detects faults in the signing computation; for hardened ECDSA leaves and Ed25519 it does not detect a fault that rewrote the private key before signing — the host's check against the cached public key does; the result is computed once and evaluated twice, so a forced result needs a second, matching fault in the signing computation | `Ecdsa` (leaf public key via `PACE_GM(IL, K_par)` for non-hardened leaves), `Bip340` (`Q = P_even + t·G` via `PACE_GM`; check `s·G + (−e·Q) = R`), `Ed25519` (`S·B + (−k·A) = R`) |
| Share masking of secret products with the §16.2.6 order: `s = ((k + e·d₁) mod n + e·d₂) mod n`, `S = ((r + k·a₁) mod ℓ + k·a₂) mod ℓ`; `d₁`, `a₁` fresh uniform per signature; no intermediate equals `e·d` or `k·a` | `ModArith.mulMasked`, used by `Bip340` and `Ed25519` |
| Structural binding of the seed to the code (D6) | `Wallet.verify`/`unwrap` decrypt only after `CHECK_OK` |
| Constant time (§16.4); every RSA operand reduced below the modulus in constant time before `doFinal` | `Bytes.equal`, `ModArith` (fixed loop bounds, masks instead of branches) |
| Point rule (§16.5): explicit on-curve check; decompression `y = (x³+7)^((p+1)/4)` with `y²` check and parity (§10.5) | `Secp256k1.onCurve`/`decompress` used by `Transfer.export0`/`import0`; `Identity.personalize` checks `caKey` explicitly |
| Teardown wipe order (§8.5) | `Session.teardown` |

A failed re-evaluation behind a passed dispatch gate returns `6F00`.

## 7. Build system and toolchain

- Gradle 9.5.1, JDK 25 toolchain (foojay), Java 8 source/target for `applet` (JCDK converter).
- JCDK `jc320v26.0_kit` from the existing `sdks` submodule, `targetsdk 3.0.5`; CAP built with
  `ant-javacard` 26.05.15 invoked from Gradle (one `cap` task, package AID `F0716E747800`, two
  applets). The CAP build is reproducible: fixed timestamps, sorted inputs; CI builds twice and
  compares SHA-256.
- Spotless (google-java-format 1.35.0, ktlint 1.8.0), REUSE lint, CycloneDX 3.2.4 SBOM.
- Libraries: jcardsim fork (vendored, §8), BouncyCastle 1.84 (host, tests), JUnit 6.0.3,
  jackson-jr 2.19.1 (vectors), PIT (mutation, `tests`), Jazzer (fuzz, `tests`), picocli 4.7.7,
  apdu4j and GlobalPlatformPro 26.04.20.1 (`tools`; GlobalPlatformPro is also the test oracle of
  the simulated ISD in `sim` tests), Shadow 9.6.1 (`card-sim.jar`), slf4j 2.0.18 (`slf4j-nop` in
  `tools`). Versions pinned in
  `gradle/libs.versions.toml`; new versions at least 7 days old.
- Applet code rules: no allocation after install, no recursion, no `String`, `int`, floats or
  multi-dimensional arrays; exceptions only `ISOException` for control flow; every secret buffer
  transient and wiped on all paths.

## 8. Simulator

jcardsim (licel master `7cd4b51`, pinned commit) is vendored under `sim/jcardsim` because the
Maven Central build lacks what the applet needs and the needed fixes are not upstream (RP §7.1,
§7.3). Patches, each a separate commit whose test is derived from one row of audit-impl's F-6
deviation table:

1. `ALG_RSA_NOPAD`: accept any modulus (BouncyCastle rejects prime moduli, RP §7.3) — plain
   `BigInteger.modPow`.
2. Transactions: a journal of pre-images for every persistent write inside
   `beginTransaction`/`commitTransaction`, covering key-object internal state (`setKey`,
   `setS`, `setW`, `setExponent`, `genKeyPair`, `clearKey` in the jcardsim key classes), not
   only arrays; abort and power loss restore. Commit capacity is counted per page as on card A
   (audit-final F-19): each persistent array touched in the transaction is charged two 512 B
   pages (worst-case alignment) per started 512 B of touched span, `setKey`/`setS` 512 B,
   `setW`/`genKeyPair` 1,024 B, against 5,120 B with `TransactionException` beyond it; the
   test suite asserts every named transaction ≤ 2,560 B (`protocol.md` §3 item 8).
   `beginTransaction` with a transaction open throws `TransactionException` `IN_PROGRESS`.
   A persistent-write counter per command is exposed to the tests.
3. Auto-abort: when `process` returns with a transaction still open, the runtime aborts it and
   the response returns `6F00`; data already sent stays delivered (card A behaviour, JCRE 3.2
   §7.6.2).
4. `setW` and `KeyAgreement` (`PLAIN_XY`, `PACE_GM`) reject compressed points with
   `CryptoException` `ILLEGAL_VALUE` (card A); `PACE_GM` throws `CryptoException` on an
   infinite result (jcardsim returns 1 byte `00`).
5. Power-loss injection: a `java.lang.classfile` agent rewrites applet bytecode so that every
   store into a persistent array, every `Util.arrayCopy*`, and every key-object setter (patched
   in the jcardsim key classes) calls `Tear.point()`; the test sets "tear at write N", the call
   throws an uncatchable `PowerLoss` error, the runtime rolls back the open transaction and
   clears transient memory, and the test resumes with a new power-up.
6. Memory accounting: every `makeTransient*`, transient key and engine allocation is charged with
   the measured per-object sizes of §5.1; install fails above 3,990 B; the report is printed by
   the build.
7. `CLEAR_ON_DESELECT` per context (verified upstream behaviour, RP §7.3).
8. Call skipping and store faults: the agent guards every call from applet code to a void applet
   method and to `JCSystem.begin/commit/abortTransaction` with `Fault.skip`; a test arms the
   n-th call to be skipped. `Fault.armStore(n, v)` makes the n-th persistent `Util.setShort`
   store `v`.
9. `MessageDigest` operations are counted per algorithm per command (`Card.digests`), so tests
   can assert the `WAIT` iteration count (§14.4 W3) and HMAC counts of the node cache.
10. Fixed randomness: `Rng.fix(block)` makes every `RandomData` output of applet engines start
    at `block[0]` for each call (cyclic beyond its length) until `Rng.reset()`, so tests
    reproduce the exact signatures of `bip340.json` (fixed `aux`) and `ed25519.json` (fixed
    `Zr`).
11. ECDSA output fault: `Fault.armEcdsaFlip(n)` xors the last byte of the n-th ECDSA signature
    output of applet engines since arming (a fault inside the platform signing computation).
12. Key generation seeds: each `SecureRandomNullProvider` (behind `genKeyPair`) is seeded with 8
    bytes of OS randomness, so simulated cards have distinct identity and link keys.
13. Transient EC domains: `Memory.buildKey` registers every transient EC private key the applet
    builds, and `CardRuntime` clears them — value and domain — on applet deselection (the
    `TRANSIENT_DESELECT` keys) and on card reset (both transient kinds), matching card A
    (audit-impl `probe-transient-reselect`); `ECPrivateKeyImpl.setS` on a key without domain
    parameters throws `CryptoException` `ILLEGAL_VALUE`. The wallet applet re-loads both domains
    in `select()` (§5.5).

Server: `org.qntx.card.sim.Server` listens on TCP, one port per simulated card, framing as
vsmartcard vpcd (2-byte big-endian length, then the payload): length ≥ 4 is an APDU; length 1 is
a vpcd control (`00` off, `01` on, `02` reset, `04` ATR); length 3 `10 ‖ u16(N)` arms power loss
at the N-th persistent write of the next command that makes N writes. A torn APDU, or an APDU on
an unpowered card, is answered with an empty frame. `--state empty|factory|blank`; cards also
carry a simulated issuer security domain (SCP03 `i = 00`, GP test keys) so the tools run against
the simulator (README "Simulator"). Distribution: `card-sim.jar` (simulator + applet classes, one
fat jar), released with every tag with its SHA-256 and build provenance; the qntx/wallet CI pins a
version and checksum (`host.md` §8), so `card-sim.jar` inherits these semantics and wallet CI
never sees a divergence the real card would reject (audit-impl F-6).

What the simulator cannot show (RP §7.3): side channels, faults beyond the modelled tearing,
timing, chip algorithm availability and behaviour (`PACE_GM` format, zero-extended RSA, DER
details), RF behaviour, GlobalPlatform. These are the real-card suite (§10).

## 9. Test strategy

| Layer | What | Where |
| --- | --- | --- |
| Unit (JVM) | Pure logic classes run as plain Java: `Bytes`, `Kdf`, `ModArith`, `Wei25519` `x·B`, `Secp256k1` decompression, `Derivation` arithmetic, DER codec, against vectors and BouncyCastle | `tests` |
| Command | Every command through the simulator: success path, every status word it can return, every precondition in checking order (generated from `apdu.json`), every state × command cell of `protocol.md` §9.2; the sequences of `verify-sequence.json`; the persistent-write counter of every command in an unverified session on a `LOADED` card matches `protocol.md` §16.1 item 7 | `tests` |
| Tearing | For every command and every N from 1 to its number of persistent writes: tear at write N, power up, assert the post-state listed in the command's section (no lost failure, no uncounted comparison, no half-installed wallet, offer state consistent) | `tests` |
| Vectors | Every `spec/vectors/*.json` consumed through the real command interface where the input is controllable; generators in Java (BouncyCastle) and TypeScript (noble) must produce identical files (CI job) | `tests`, `spec/vectors/gen` |
| Differential | 10⁴ random signatures per scheme per CI run (10⁵ nightly) verified by BouncyCastle and by noble (via the TS generator in verify mode); random paths, tweaks, message lengths 0–8 KiB for Ed25519 | `tests` |
| Reference host | `host` module implements the host side from `protocol.md` only (no applet code imported); all command tests drive the card through it | `host`, `tests` |
| Fuzz | Jazzer on `Session.unwrap` + inner dispatch (random records with valid keys), on every parser (`path`, certificates, payload) | `tests` |
| Mutation | PIT on `applet` classes with the command and tearing suites; the gates of each stage (listed in §14) must have no surviving mutant; the report is attached to each PR | `tests` |
| Fault mutants | Hand-written fault mutants are the primary fault evidence (PIT mutates JVM bytecode, not CAP instruction skips): delete the T-FAIL call; delete `commitTransaction` (assert abort, T-ERASE, `6F00`, card `BLANK`, no comparison); overwrite `f_a` with a smaller value after its complement check; overwrite the value T-FAIL writes; skip the `f ≥ L` test with `f = L`; force one comparison branch to pass; force the fingerprint check; skip the `WAIT` gate (assert the comparison count still stays ≤ L); skip `ERASE`'s `verified` gate; skip each `IMPORT` equality check in `LOADED`. Each asserts no uncounted comparison, no T-OK and no output, per P2/P3 of `threat-model.md` | `tests` |
| Real card | §10, gated by `-PrealCard=<reader>`; never run in CI; reports "not run" | `tests/src/realCard` |

## 10. Real-card suite and silicon admission

Run on each silicon batch and before the protocol freeze; results recorded in the batch record.

| Test | Measures / asserts |
| --- | --- |
| Admission 1 | `ALG_RSA_NOPAD` with zero-extended 512-bit moduli and exponents `2` and a 32-byte exponent: results equal BigInteger for 1,000 random inputs per modulus; every input ≥ `m` is rejected |
| Admission 2 | `ALG_EC_PACE_GM` output is the 65-byte point `s·G' + H` (secp256k1 and Wei25519); an infinite result throws `CryptoException` |
| Admission 3 | `PLAIN_XY` 65-byte product; rejects off-curve, `x ≥ p` and compressed inputs — rejection is REQUIRED, the protocol relies on it (§3) |
| Admission 4 | `signPreComputedHash`, `verifyPreComputedHash` on 32-byte hashes |
| Admission 5 | Wei25519 and secp256k1 domains accepted by 256-bit keys and transient keys |
| Admission 6 | RandomData: NIST SP 800-22 subset on 10 MB from `ALG_KEYGENERATION` with the Rev. 1a §4.2 decision rule — 80 sequences of 10⁶ bits; per statistic at least 77 of 80 with p ≥ 0.01 (§4.2.1) and uniformity P-value_T ≥ 0.0001 (§4.2.2); statistics frequency, block frequency (M = 128), runs, longest run (M = 10⁴), cumulative sums; the first 32-byte output after each of 100 power-ups is pairwise distinct |
| Admission 7 | Persistent key objects `setKey`/`setS`/`setW`/`setExponent`/`genKeyPair` participate in transactions (abort restores the previous value) |
| Admission 8 | Every named transaction consumes ≤ 50 % of `getMaxCommitCapacity` — the wallet applet cannot report `getUnusedCommitCapacity` inside its own transactions, so the admission probe (test-only CAP `F0716E7478FF`) replays each named transaction's write set, one `byte[272]` at the §4 offsets plus the key-object setters of the same types, and reports `max − unused` before the commit; `getAvailableMemory(CLEAR_ON_DESELECT)` after install ≥ 15 % of the pool |
| Admission 9 | One `WAIT` unit takes 0.9–1.1 s on a contactless reader (median of 9; card A predicted 965 ms from the measured 2.370 ms per iteration) |
| Timing | Every command of `protocol.md` §16.6 on a contact and an NFC reader; assert ≤ 1,500 ms; record vs B2 |
| APDU | `Lc = 248` receive test (the `setIncomingAndReceive` + `receiveBytes` loop of §3) |
| Flows | The flows of B2 on iOS and Android with the wallet harness (taps, seconds); before freeze also: `WAIT` time on each reference phone at the weakest usable coupling, the iOS single-connection limit (15 `WAIT` + `VERIFY` must complete in one connection), the displayable length of the iOS `alertMessage` (`host.md` §3) and native Argon2id time on the slowest supported phone (`$A/spec/FROZEN.md`) |
| Tearing | Field cut at programmable instants during `VERIFY`, `CREATE`, `IMPORT`, `ERASE` (requires a programmable reader); assert post-states |
| NVM | Write time of the transactions; endurance after 10⁶ `setW` on one key object, 10⁶ T-FAIL/T-OK and 10⁵ T-OFFER, with all other transactions still committing afterwards (sacrificial card — never development card A; mandatory before freeze) |

Admission rows 1–9 are `protocol.md` §3 items 1–9. Audit-impl ran admission 1–5 and 7 on development card A (JCOP4 P71, CPLC IC type `D321`, batch
`2092`) and they passed (`$A/audit-impl/evidence/card/functional.out`); admission must be
repeated on each production batch. Multi-card flows are simulation-only while only one
development card exists.

## 11. Tools

`tools` builds `qntx-card` (picocli):

- `install` — load and install the CAP over SCP02 (`i = 55`) or SCP03 as recorded for the batch
  at admission (GlobalPlatformPro library), check the load-file hash against the release, and
  compare the registry with the admission baseline plus exactly the load file and the two
  instances (`protocol.md` §14.3 steps 2, 3, 6).
- `personalise` — `GET_IDENTITY`, obtain the certificate from the HSM interface (PKCS#11), send
  `PERSONALIZE`, verify `OPEN`, perform the step-6 registry check, replace ISD keys with
  discarded random keys, append the batch record (steps 4–8). It records and prints the short ID
  `short(A)` (8 hex) that is printed on the card face. A `--test-ca` mode uses a software test
  CA and refuses production anchors.
- `registry` — print the registry (one sorted line per entry: kind, AID, lifecycle); admission
  records it as the factory baseline of §14.3 step 6.
- `shell` — debug REPL over PC/SC or the simulator TCP port using the `host` library: open a
  session, run inner commands, print decoded records. It never accepts or prints seeds.

Transport keys (`QNTX_ISD_KEY`) and the HSM PIN (`QNTX_HSM_PIN`) are read only from the
environment. HSM signing uses SunPKCS11 `NONEwithECDSA` over a software SHA-256: SunPKCS11 on
JDK 25 with SoftHSM 2.7 fails `SHA256withECDSA` at `C_SignUpdate`
(`CKR_OPERATION_NOT_INITIALIZED`) for secp256k1, and SunPKCS11's KeyStore exposes a private key
only when a certificate with the same `CKA_ID` exists on the token; the production HSM's
behaviour is UNVERIFIED.

## 12. CI and release

- `ci.yml` (pull requests and `main`): REUSE lint, Spotless check, build CAP (twice, compare
  hash), unit + command + tearing + vector + fuzz-smoke tests, vector generator agreement (JDK 25
  and Bun), PIT on gate classes, memory report vs §5.1 budget, CAP size report. Actions pinned
  by commit SHA, `permissions: contents: read`.
- `release.yml` (tags `v*`): build from a clean checkout; upload `qntx-card.cap`,
  `card-sim.jar`, `vectors.zip`, `tools` distribution, CycloneDX SBOM, `SHA256SUMS`; build
  provenance via `actions/attest-build-provenance`; release notes list the protocol version and
  the CAP hash. Permissions: `contents: write`, `id-token: write`, `attestations: write`.
- Before any tag, the real-card gate of §10 — install the production CAP on card A, then `OPEN`
  across three select epochs and a power cycle (`InstallRealCardTest`) — MUST have passed on the
  tagged commit; CI cannot run it, so the result is recorded in the release notes.

## 13. Repository `AGENTS.md`

````markdown
# AGENTS.md — qntx/wallet-applet

The qntx card: a Java Card 3.0.5 applet (one CAP, package `org.qntx.card`) that holds an HD
wallet seed and signs for qntx/wallet. `spec/protocol.md` is the single normative specification;
code and spec change in the same pull request, and a disagreement between them is a bug in both.

## Invariants

1. No command outputs a private key, the seed or an access code. The only key-material output is
   the encrypted transfer to a member card (`spec/protocol.md` §11).
2. The seed is stored only encrypted under keys derived from the access code; it is decrypted
   only after a matching MAC and the stored fingerprint check, after the failure count was
   committed and read back.
3. Every persistent change is inside the transaction the spec names for it; commits precede the
   comparison, output or signature they guard.
4. `ERASE` requires a verified session. In an unverified session a `LOADED` card writes only
   what `spec/protocol.md` §16.1 item 7 allows.
5. Every signature is self-verified before output.
6. Security-relevant flags use the coded constants of `Const`; never `boolean` or `0/1`.
7. No allocation after install; no recursion; no `String`, `int`, floating point or
   multi-dimensional arrays in `applet`; every secret is in transient memory and wiped on all
   paths; comparisons of secrets are constant time.
8. Only standard Java Card 3.0.5 APIs listed in `spec/protocol.md` §3; no vendor APIs.
9. Tests come from the spec and independent oracles (official vectors, BouncyCastle, noble),
   never from the applet's own output.
10. The protocol is frozen after the external audit; afterwards changes ship only as a new
    protocol version with a new instance AID.

## Commands

- `./gradlew build` — CAP, all simulator tests, vectors, memory report.
- `./gradlew :tests:pitest` — mutation tests on gate classes.
- `./gradlew :tests:realCard -PrealCard="<reader>"` — real-card suite (never in CI).
- `./gradlew :sim:shadowJar` — `card-sim.jar`.

## Conventions

English everywhere; Conventional Commits (subject ≤ 50 chars, imperative); comments explain why
and cite spec sections; no decorative separator comments. Applet code AGPL-3.0-or-later;
`spec/**` MIT OR Apache-2.0; REUSE headers on every file.
````

## 14. Implementation plan

Each `protocol.md` section and each class is assigned to exactly one stage (the stage that
implements and tests it first and owns its acceptance); later stages keep it green. After every
stage: the CAP builds, installs in the simulator, and `./gradlew build` is green.

### 14.1 Section and class assignment

| Stage | `protocol.md` sections | Classes / modules |
| --- | --- | --- |
| `scaffold` | §2, §6, §9.1, §17, §18 | `WalletApplet` (skeleton); Gradle build; `sim` fork with the patches of §8; vector generator harness; CI; `AGENTS.md`, README, SECURITY, REUSE |
| `core` | §1, §4.1, §4.2, §4.3, §5.1, §5.2, §8.1, §8.2, §8.3, §8.4, §8.5, §9.2, §13.1, §13.2, §14.1, §14.2, §16.1, §16.2, §16.3, §16.4, §16.7 | `Const`, `Mem`, `Bytes`, `Kdf`, `Secp256k1`, `Identity`, `Session`, `State`; `host` module (session, records, certificates) |
| `wallet` | §7.1, §7.2, §7.3, §9.3, §9.4, §9.5, §9.6, §9.7, §9.8, §9.15, §10.1, §10.2, §10.3, §10.4 | `Wallet`, `Derivation`, `ModArith`, `Wei25519` |
| `sign` | §9.9, §9.10, §9.11, §12.1, §12.2, §12.3 | `Ecdsa`, `Bip340`, `Ed25519` |
| `sets` | §9.12, §9.13, §9.14, §10.5, §11.1, §11.2, §11.3, §16.5 | `Transfer` (uses `Secp256k1` decompression and `ModArith`'s `(p,(p+1)/4)` key) |
| `release` | §3, §14.3, §15, §16.6 | `NdefApplet`; `tools`; simulator server and `card-sim.jar`; real-card suite; `release.yml` |

Check: the union is every section of `protocol.md` (1, 2, 3, 4.1–4.3, 5.1–5.2, 6, 7.1–7.3,
8.1–8.5, 9.1–9.15, 10.1–10.5, 11.1–11.3, 12.1–12.3, 13.1–13.2, 14.1–14.3, 15, 16.1–16.7, 17, 18)
and no section appears twice; every class of §2 appears once.

### 14.2 `scaffold`

| # | Criterion | Check |
| --- | --- | --- |
| S1 | The old modules, tools, notes and protocol docs are deleted; `settings.gradle.kts` includes exactly `applet`, `sim`, `host`, `tests`, `tools` | `git ls-files` shows none of `wallet/ backup/ ndef/ shared/ notes/`; `grep include settings.gradle.kts` |
| S2 | `spec/protocol.md` committed byte-identical to the frozen spec; `spec/vectors/README` lists every file of §18 | `shasum -a 256` equals `FROZEN.md` |
| S3 | `./gradlew build` exit 0 from a clean clone; CAP built twice with the same SHA-256 | CI log |
| S4 | The CAP installs in the simulator; `SELECT` of `F0716E74780101` returns `9000` with no data; any other CLA returns `6E00`, unknown INS `6D00` | `SelectTest` |
| S5 | Every simulator patch of §8 has a passing test (RSA prime modulus; transaction rollback of arrays and key objects on abort and on tear; auto-abort `6F00`; compressed-point rejection; `PACE_GM` infinity exception; commit capacity exception; tear at write N; memory accounting failure above budget) | `sim` tests |
| S6 | Vector harness: a CI job runs both generators and fails on any byte difference | CI job `vectors` |
| S7 | REUSE lint, Spotless, CycloneDX pass; `AGENTS.md` equals §13 | CI |

### 14.3 `core`

| # | Criterion | Check |
| --- | --- | --- |
| C1 | `GET_IDENTITY`, `PERSONALIZE`: every status word of §14.1–14.2 in checking order; T-PERSO tearing at every write leaves `FACTORY` (nothing stored) or `BLANK` (all stored) | `PersonalizeTest`, `PersonalizeTearTest` |
| C2 | `OPEN`: checks and response per §8.1; the session signature over `… ‖ A` and the keys match `session.json`; no persistent write during `OPEN` (simulator write counter = 0) | `OpenTest` |
| C3 | Records: `record.json` passes; tampered tag, padding, length, `P1/P2`, replayed and reordered records each give outer `6982` and teardown; counter exhaustion tears down after `0xFFFF` | `RecordTest`, fuzz smoke |
| C4 | Inner dispatch implements §9.2 checking order and pending-state ending (tested with a stub inner command until later stages add real ones); unknown inner INS `6D00`; short plaintext `6700`; non-ISO exception `6F00` + teardown | `DispatchTest` |
| C5 | `cert.json`, `kdf.json` pass through `Identity` and `Kdf`; the `host` module passes the same vectors independently | `IdentityTest`, `host` tests |
| C6 | Coded constants equal §6; a corrupted `life` value yields `6F00`; `state` layout equals §4 and `fails` reads `0000 FFFF` after install (`STATUS` in `BLANK` returns `01 00`, not `6F00`) | `CodedStateTest` |
| C10 | Simulator commit accounting per page (§8 patch 2): T-PERSO ≤ 2,560 B | `CommitCapacityTest` |
| C7 | Teardown wipes per §8.5 after `SELECT`, `OPEN`, failure, `6F00` (inspect transient arrays in the simulator) | `TeardownTest` |
| C8 | PIT: no surviving mutant in `Session.unwrap`, `Identity.verify`, `Identity.personalize`, `WalletApplet.inner` | PIT report |
| C9 | Memory report ≤ §5.1 rows for `Session`, `Secp256k1`, `Mem`, `Identity` | build report |

### 14.4 `wallet`

| # | Criterion | Check |
| --- | --- | --- |
| W1 | `STATUS`, `CREATE`, `VERIFY`, `WAIT`, `CHANGE`, `ERASE`, `PUBLIC_KEY`: success path, every status word in checking order, every state | `WalletCommandTest` (from `apdu.json`) |
| W2 | `VERIFY` tearing and the read-back gate: tear at every write of T-FAIL, T-OK, T-ERASE for every value of `f`; assert §9.5 (no uncounted comparison; the gate catches a skipped or uncommitted T-FAIL, then aborts before T-ERASE; re-entry at `f = L` erases) | `VerifyTearTest` |
| W3 | Failure limit: 3 free attempts, then `6986` until 15 `WAIT`s per attempt, the 10th failure erases; 9 wrong + 1 right resets; `63Cx` values exact; every sequence of `verify-sequence.json`; `WAIT` runs exactly 400 SHA-256 iterations (counted by the simulator's `MessageDigest` call counter) | `FailureLimitTest` |
| W4 | `CREATE`, `CHANGE`, `ERASE` tearing at every write: state is either before or after the transaction | `WalletTearTest` |
| W5 | `access.json`, `wrap.json`, `derivation.json` (BIP-32 vectors 1–5, SLIP-10 1–2, template paths, invalid child) pass via commands and unit tests | `VectorTest` |
| W6 | Fault mutants (the primary fault evidence): deleting the T-FAIL call or `commitTransaction` is caught by the read-back gate (the latter ends in abort, T-ERASE, `6F00`); overwriting `f_a` after its complement check, or the value T-FAIL writes, is caught by the gate's comparison with `f_b + 1`; skipping the `f₀ ≥ L` test with `f = L`, forcing one comparison branch to pass, forcing the fingerprint check, skipping the `WAIT` gate (comparison count still ≤ L), skipping `ERASE`'s `verified` gate, skipping each `IMPORT` equality check in `LOADED` — each asserts no uncounted comparison, no T-OK, no output (P2/P3) | `FaultMutantTest` |
| W7 | `ModArith` vs BigInteger: 10⁵ random multiplications, squarings per modulus; constant-time structure (no secret-dependent branch: bytecode scan for `if*` on secret locals is part of the review checklist) | `ModArithTest` |
| W8 | `Wei25519` `x·B` against `derivation.json`/`ed25519.json` vectors; the Edwards encoding test lives in the `host` module (§10.4) | `Wei25519Test` |
| W9 | PIT: no survivor in `Wallet.verify`, `Wallet.create`, `Wallet.erase`, `Derivation.publicKey` | PIT report |
| W11 | Unverified writes on a `LOADED` card: for `STATUS`, `VERIFY` (wrong code), `WAIT` the persistent-write counter matches §16.1 item 7 | `UnverifiedWriteTest` |
| W10 | `ERASE` refuses an unverified session (`6982`); the `IMPORT` equality checks in `LOADED` are covered in `sets` | `WalletCommandTest` |

T-CREATE's link-key `setS` belongs to `Transfer` and was added by the `sets` stage inside the
same transaction, raising T-CREATE's commit charge from 1,536 B to 2,048 B.

### 14.5 `sign`

| # | Criterion | Check |
| --- | --- | --- |
| G1 | `SIGN_ECDSA`, `SIGN_BIP340`, `SIGN_ED25519` (begin data `path`, response `W(R)` 64 B; update/finish take the opaque stream; finish response `le32(S)` 32 B): every status word in checking order; stream ended by any other command | `SignCommandTest` |
| G2 | `ecdsa.json`, `bip340.json` (official vectors with fixed `aux`, BIP-86 tweaks), `ed25519.json` (RFC 8032 verification; fixed `N`/`Zr` exact; nonce input order `… ‖ ID(A) ‖ u32(N)`; `edCounter ← N`) pass | `SignVectorTest` |
| G3 | Differential: 10⁴ signatures per scheme verified by BouncyCastle and noble; Ed25519 message lengths 0–8 KiB, chunk sizes 1–236 | `SignDifferentialTest` |
| G4 | Self-verify: fault mutants corrupting the leaf key, nonce or final scalar give `6F00` and no signature | `SignFaultTest` |
| G5 | Ed25519 with a constant random stub: 1,000 signatures have distinct `r`; T-EDCTR tearing never repeats `N` | `NonceTest` |
| G6 | PIT: no survivor in `Ecdsa`, `Bip340.sign`, `Ed25519.finish`, `ModArith.mulMasked` | PIT report |

### 14.6 `sets`

| # | Criterion | Check |
| --- | --- | --- |
| T1 | `OFFER`, `EXPORT`, `IMPORT`: every status word in checking order; pending export/import ended by other commands; `OFFER` with a valid offer returns the same `LK` and writes nothing; `IMPORT` `P1=0` in `LOADED` from a non-member returns `6A80` with no write; a repeated `IMPORT` `P1=0` from the same member, and alternation between two members, write each slot at most once; `IMPORT` `P1=0` after a committed install returns `6985` | `TransferCommandTest` |
| T2 | `transfer.json` passes; full transfer between two and three simulated cards; flows of §11.3 (create k cards, re-seal a forgotten code on a `LOADED` card, limit-erased card) end with identical `WalletInfo` on all members | `TransferFlowTest` |
| T3 | Refusals: non-member target, own card, other batch CA, bad offer signature, tampered `E`/`ct`/`tag`, replayed export made for an earlier offer (target installed or erased, then offered again), payload not listing target or source, and `IMPORT` into `LOADED` with a different `fp`, `members` or `origin` | `TransferNegativeTest` |
| T4 | Invalid-curve and twist probes on `E` in `IMPORT` return `6A80` without ECDH | `PointTest` |
| T5 | `Secp256k1` decompression vectors (§10.5): 200 random keys equal libsecp256k1; `x ≥ p`, a non-residue `x` and a bad prefix byte → `6A80`; the parity rule picks the right root | `DecompressTest` |
| T6 | Tearing at every write of T-OFFER, T-INSTALL | `TransferTearTest` |
| T7 | PIT: no survivor in `Transfer.export0`, `Transfer.export1`, `Transfer.import0`, `Transfer.import1` | PIT report |

### 14.7 `release`

| # | Criterion | Check |
| --- | --- | --- |
| R1 | `NdefApplet`: §15 table, every status word; install rejects messages of 0 or > 100 bytes | `NdefTest` |
| R2 | `card-sim.jar`: TCP framing, multi-card, power and tear control; an end-to-end test drives a 3-card creation and an Ed25519 signature over TCP with the `host` library | `ServerTest` |
| R3 | `tools`: `install`, `personalise --test-ca`, `shell` work against the simulator and refuse production anchors in test mode | `ToolsTest` |
| R4 | Real-card suite compiles and lists every test of §10; it is reported as "not run" without hardware | `./gradlew :tests:realCard --dry-run` |
| R5 | `release.yml` dry run produces CAP, `card-sim.jar`, `vectors.zip`, SBOM, `SHA256SUMS`, provenance | workflow run on a test tag in a fork |
| R6 | Final budgets: memory report ≤ §5.1 total; CAP size reported; §16.6 time table reproduced from B2 in the README | build report |
| R7 | Every vector file of §18 exists and both generators agree | CI `vectors` |
