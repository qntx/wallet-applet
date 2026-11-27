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
├── tests/                     JUnit 6: unit, simulator command tests, tearing, vectors, fuzz; real-card suite
│   ├── src/test/java/
│   └── src/realCard/            §10 suite: java/ JUnit tests; javacard/ test-only probe and memprobe CAPs
├── tools/                     qntx-card CLI: install, personalise, registry, debug shell (picocli, GlobalPlatformPro, apdu4j)
├── spec/
│   ├── protocol.md            normative specification (MIT OR Apache-2.0)
│   └── vectors/               *.json + gen/java (BouncyCastle) + gen/ts (noble) + gen/apdu.py
├── AGENTS.md README.md SECURITY.md CONTRIBUTING.md LICENSE LICENSES/ REUSE.toml
├── buildSrc/                  the CAP conversion shared by applet/ and the test CAPs
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
| `WalletApplet` | `install` (allocation only), `select`, `process`; outer dispatch incl. the bounded initialisation gate of §4.3; inner dispatch with the checking order, pending-state ending and `6F00` mapping of `protocol.md` §9.2 | §4.3, §6, §9.1, §9.2 | scaffold |
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
| `ModArith` | Modular multiply/square through `ALG_RSA_NOPAD` (keys `(ℓ,2)`, `(n,2)`, `(p,2)`, `(p,(p+1)/4)`); constant-time 256-bit add, subtract, reduce, conditional negate; constant-time reduction of every RSA input below the modulus; share splitting | §16.2.7, §16.4 | wallet |
| `Wei25519` | Wei25519 domain, `x·B` (no Edwards encoding on the card; the map is host-side, §10.4) | §10.4 | wallet |
| `Ecdsa` | `SIGN_ECDSA`: sign, independent leaf public key, self-verify with rotating verify keys | §9.9, §12.1 | sign |
| `Bip340` | `SIGN_BIP340`: tweak, BIP-340 signing with masked `e·d`, self-verify | §9.10, §12.2 | sign |
| `Ed25519` | `SIGN_ED25519`: nonce, counter, stream, masked `k·a`, self-verify | §9.11, §12.3 | sign |
| `Transfer` | `OFFER` (idempotent while the offer is valid), `EXPORT`, `IMPORT` (incl. the membership check before decompression and the re-seal equality checks in `LOADED`), link key, the two peer-key slots, pending export/import | §9.12–9.14, §11 | sets |
| `NdefApplet` | Read-only Type 4 Tag | §15 | release |

## 3. Command dispatch

```text
process(apdu)
├─ selectingApplet()                → Session.teardown(); 9000                 (select() and deselect() also tear down)
├─ CLA ≠ 0x80                       → 6E00
├─ init ≠ INIT_DONE (coded, read    → INS GET_IDENTITY: run exactly one §4.3 step, then 6283
│    twice like life)                     while steps remain; every other INS → 6283;
│                                         a non-member or disagreeing init → 6F00
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
safe branch rather than `6F00` (audit-impl F-19). `deselect()` runs the same §8.5 teardown as
`select()` — defence in depth, since the NDEF applet shares the wallet's context and selecting
it does not clear `CLEAR_ON_DESELECT` memory; no property depends on the call being made. The
transient EC curve domains die with the selection epoch regardless; `select()` re-loads them
(§5.5).

The constructor writes nothing: it allocates the whole object graph (keys, engines, arrays —
"no allocation after install" holds) and calls `register`. Every persistent write the old
constructor did is a §4.3 initialisation step now — card A journals `install()` and the old
writes overflowed its 5,120 B journal (`install-diag/NOTES.txt`).

A `PACE_GM`/`PLAIN_XY` `CryptoException` on an infinite result during BIP-32 child computation
maps to `6A80` (invalid child, §10.3), not `6F00` (audit-impl F-13). The `6F00` mapping is
otherwise unchanged.

## 4. Persistent state

Every field of `protocol.md` §4.2 that is not a key object lives in one persistent `byte[274]`
array `state`, allocated by `State` in the constructor (the constructor writes nothing — the
zero-filled array reads `init = 0`, the first initialisation step):

| Offset | Length | Field | Representation | Owner |
| --- | --- | --- | --- | --- |
| 0 | 2 | `life` | coded `short` | `Wallet` (`Identity` writes `BLANK` in T-PERSO) |
| 2 | 4 | `fails` | `f ‖ ~f`; `fails ← 0` writes `0000 FFFF` (also at initialisation) | `Wallet` |
| 6 | 2 | `origin` | coded `short` | `Wallet` |
| 8 | 2 | `offer` | coded `short` | `Transfer` |
| 10 | 4 | `edCounter` | `u32` | `Ed25519` |
| 14 | 49 | `members` | count + 3 IDs | `Wallet` |
| 63 | 32 | `fp` | never output | `Wallet` |
| 95 | 64 | `ct` | | `Wallet` |
| 159 | 16 | `tag` | | `Wallet` |
| 175 | 97 | `cert` | | `Identity` |
| 272 | 2 | `init` | coded `short`: next initialisation step `0 … 6`, then `INIT_DONE = 0x9966` | `WalletApplet` (the step dispatcher) |

Key objects:

| Field | Representation | Owner |
| --- | --- | --- |
| `idKey` | `KeyPair(ALG_EC_FP, 256)`, private `TYPE_EC_FP_PRIVATE` | `Identity` |
| `caKey` | `ECPublicKey` (secp256k1 domain) | `Identity` |
| `wrapKey` | `AESKey` `TYPE_AES`, 128; in `BLANK` it holds a random key unrelated to any ciphertext (T-ERASE installs it inside the transaction) | `Wallet` |
| `linkKey` | `KeyPair(ALG_EC_FP, 256)`; T-CREATE/T-INSTALL/T-ERASE overwrite the private key with a fresh random scalar (`setS`) inside the transaction | `Transfer` |
| peer-key slots 0, 1 | two `ECPublicKey` (secp256k1 domain); initialised with the NUMS point `P_init` of `protocol.md` §16.1 item 1, whose discrete logarithm is unknown; the content is never trusted — it is compared with the recomputed peer key before each use | `Transfer` |

One array for every non-key field is the simplest layout in which each named transaction touches a
single array: `life`, `fails`, `offer` and `members` are each written by several transactions
with different field sets (audit-final F-15). The array's physical page alignment is unknown, so
each transaction is charged two array pages: with card A's page-granular commit buffer (512 B
per array page and per `setKey`/`setS`, 1,024 B per `setW`/`genKeyPair`, audit-impl F-12) the
worst case is T-PERSO, T-CREATE, T-INSTALL, T-ERASE and T-OFFER at 2,048 B (40 %), T-CHANGE
at 1,536 B, T-FAIL, T-OK and T-EDCTR at 1,024 B (measured by `CommitCapacityTest`). Card A's
memprobe charges the transactions one card can reach no higher — T-PERSO 1,536, T-CREATE
2,048, T-ERASE 2,048, T-OFFER 1,536, T-CHANGE 1,024, T-FAIL/T-OK/T-EDCTR 512 B
(`memory.json`); T-INSTALL is measured on silicon against a host-emulated member
(`EmuMember`, journal charge 0 B) — the two-card flow itself is not run, so the simulator
model is deliberately the conservative bound. There is no
`clearKey` anywhere (§16.1). Initialisation (`protocol.md` §4.3) runs in `N = 7` steps, each a
method on the class that owns the objects, dispatched by `WalletApplet` on `init`; `init`
advances by one atomic `Util.setShort` only after the step completed, and `INIT_DONE` is written
last (`INIT_DONE` is an RM(1,4) codeword whose Hamming distance to every step index is ≥ 5):

| `init` | Step | Owner |
| --- | --- | --- |
| 0 | secp256k1 domain on `idKey` (both halves) and `caKey` | `Identity.initDomains` |
| 1 | secp256k1 domain on `linkKey` and both peer slots; peer `setW(G)` | `Transfer.initDomains` |
| 2 | secp256k1 domain on the four verify keys | `Ecdsa.initDomains` |
| 3 | RSA moduli and exponents | `ModArith.initKeys` |
| 4 | `idKey.genKeyPair()` | `Identity.initKeys` |
| 5 | `linkKey.genKeyPair()` | `Transfer.initLink` |
| 6 | random `wrapKey`; `fails ← 0`; `offer = NONE`; `life = FACTORY` | `Wallet.initState` |

Each transaction of `protocol.md` §4.3 is one method
that begins, writes and commits, with no other persistent write inside or outside it.

## 5. Memory

### 5.1 Budget (card A: J3R180, JCOP build J3R351…)

Transient sizes measured in the simulator (sizes from card A); the persistent column stays an
estimate where nothing measures it.

| Class | Transient (`CLEAR_ON_DESELECT`) | Persistent (objects and arrays) |
| --- | --- | --- |
| `Session` | 4 AES transient keys 128; record engines: 3 AES-CBC 144, 2 CMAC 64; counter, `verified`, `waited`, stream/export/import state words 10 → **346** | key headers 160; engine objects 500 |
| `State` | — | `state` 274 (§4) |
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
| **Total** | **2,780** of 3,990 → margin 1,210 B (30 %) | **≈ 7.1 KB** + CAP 28,273 B load components (the `qntx-card.cap` file is 135,784 B) of 157,524 B |

Budget rule (acceptance): transient total ≤ 3,390 B (15 % margin on the 3,990 B JCAlgTest
pool) as reported by the simulator's memory accounting (§8) and, on real cards, by
`JCSystem.getAvailableMemory` after install (§10). The pool measured on card A is ≈ 4,130 B
(audit-impl §6): the final card-A run leaves 1,328 B of the 4,128 B `CLEAR_ON_DESELECT` pool free
after install (32 %) against the simulator's 2,780 B used, and the production install consumes
7,064 B of persistent memory (`memory.json`) against the ≈ 7.1 KB estimate above. The install
journal charge is 0 B on card A (`install-journal.json`), which calibrates
`INSTALL_ALLOC_CHARGE = 0` (§8 patch 2). Commit capacity is consumed per page: 512 B per array page and per
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
(`protocol.md` §16.3); when a command ends with an exception — e.g. a fault thrown inside
`Session.wrap` — `WalletApplet.process` wipes the whole APDU buffer before the status word is
returned, so the decrypted inner command never survives an error exit.

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
| `GET_IDENTITY` on an uninitialised card | one §4.3 step's writes, once per card per step — outside any transaction, so a torn step is repeated whole (the writes above the tear are done again) |

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
| `OFFER_NONE` | `0x3CC3` | `VERIFIED_SHADOW` | `0xA55A` |
| `PENDING_EXPORT` | `0x6996` | `PENDING_EXPORT_SHADOW` | `0xC33C` |

| Countermeasure (`protocol.md`) | Where |
| --- | --- |
| `init` gate: the coded value is read once; `INIT_DONE` re-read for agreement, a step index re-checked on the `GET_IDENTITY` path (`INIT_DONE` there → `6F00`); a non-member value → `6F00` (§16.2.1) | `WalletApplet.dispatch` |
| Lifecycle check with coded value, evaluated twice for `PERSONALIZE`, `CREATE`, `OFFER`, `IMPORT`, `ERASE`; any non-member value → `6F00` (§16.2.1) | `WalletApplet.inner` step 3; `Identity`, `Wallet`, `Transfer` before every T-* transaction |
| `verified` check at dispatch and again before output (§16.2.4) — `verified` is held in two transient words with different codes (`VERIFIED_YES`, `VERIFIED_SHADOW`): the dispatch gate and the first check read the first word, the last check before the effect reads the second | `WalletApplet.inner` step 6; `Derivation.publicKey`, `Ecdsa`, `Bip340`, `Ed25519.begin` (before T-EDCTR), `Ed25519.finish` (before `le32(S)`; `update` has no effect beyond hashing, the dispatch gate only), `Wallet.change`, `Wallet.erase` (before T-ERASE), `Transfer.export1` immediately before writing the response. In `Ecdsa`/`Bip340` the self-verification `setW` on a verify key precedes the second-level check: under a single fault that forced the dispatch gate in an unverified session the card may write one public, stateless verify key — absent faults no unverified write happens (§16.1 item 7) |
| `fails` read three times independently into `f_a`, `f_b`, `f_c` (three separate reads of the persistent array, the first two each with their complement check); the `f ≥ L` re-entry erase evaluated once on each of `f_a`, `f_b` (coded) at `VERIFY` step 2; `f_c` serves only the step-6 gate | `Wallet.verify` |
| T-FAIL writes `f_a + 1` and commits; then the read-back gate evaluated twice independently, each on a fresh read and each a coded result: `getTransactionDepth() = 0`, value/complement consistent, value `= f_b + 1` in the first evaluation and `= f_c + 1` in the second, value `≤ L`; any failure → `abortTransaction` if a transaction is open, then T-ERASE + `6F00`; the candidate is never used (§16.1.2, §16.2.2) | `Wallet.verify` |
| T-EDCTR read back (transaction closed, stored `edCounter = N`) before `r` is computed (§16.1 item 3) | `Ed25519.begin` |
| T-OFFER read back (transaction closed, stored `offer = VALID`) before `LK` is output (§16.1 item 4) | `Transfer.offer` |
| `WAIT` gate before the comparison once `f_a ≥ F` (§9.5): a single check — a skipped wait yields at most one unwaited attempt and the guess bound stays `L` | `Wallet.verify` |
| Two-branch structure for T-OK: two independent `KDF108` + CMAC computations; T-OK, seed decryption and `verified` are reachable only through two independent branches whose fall-through path is failure; each compares a coded result with `CHECK_OK` (§16.2.3) | `Wallet.verify` |
| Seed fingerprint: after a match, `fp'` recomputed and compared with the stored `fp` (constant time, twice) before T-OK (§9.5 step 8) | `Wallet.verify` |
| Verification results coded as `CHECK_OK`/`CHECK_FAIL`/`CHECK_MALFORMED` (§16.2 item 1): `Secp256k1.verifyHash` derives the coded result from the engine's boolean through two independent conditionals (`CHECK_FAIL ^ CHECK_STEP_1 ^ CHECK_STEP_2 = CHECK_OK`), so a single skipped branch yields a non-codeword every caller rejects. Double evaluation of a verification means recomputation, never a stored-result re-test: the transfer gates listed in the next row, `Identity.personalize`'s certificate (`verify` run twice), `Ecdsa` self-verification (`verifyHash` run twice); the BIP-340 and Ed25519 self-verifications compute `V` once and evaluate the comparison twice; the `Session.unwrap` record tag is computed once and compared twice; the `Identity.signHash` self-verification is evaluated once — releasing a bad identity signature needs a computation fault plus a skipped check | `Secp256k1.verifyHash`, `Identity`, `Ecdsa`, `Bip340`, `Ed25519`, `Session.unwrap`, `Transfer` |
| Independent recomputation of every check that gates seed export, the peer-key slot write or seed import (§16.2 item 4): each such check is evaluated once at its checking-order position (data error → `6A80`, missing condition → `6985`) and again by recomputation immediately before the effect it guards (`6F00`), reusing no result, flag, hash or key-object content of the first evaluation: `EXPORT` `P1 = 0x00` — certificate (`Identity.verifyCert`), membership (`memberSlot`, members re-read and IDs recomputed, the slot index compared) and `sig_T` (`offerSignature`: `A_T` decompressed again and compared in constant time with the peer-key slot read back by `getW`, the offer hash recomputed into a separate buffer, the verification repeated), recomputed after `hashM` and before `signHash`, which writes `sig_S` over the certificate's signature and `LK_T` in the buffer, and before the pending export keys and `E` are produced; `EXPORT` `P1 = 0x01` — the pending-export state checked on the pending word and then on a separate shadow word holding `PENDING_EXPORT_SHADOW`, before the payload is encrypted under `K_te`; `IMPORT` `P1 = 0x00` — certificate and, when not `BLANK`, membership with `life` read again before the peer-slot `setW`, `sig_S` (`verifyHash`: `A_S` decompressed again and compared with the slot read back, `A` and `LK` re-read, `TH` recomputed into a separate buffer, the verification repeated) before the pending import keys are derived from the recomputed `TH`; `IMPORT` `P1 = 0x01` — the MAC recomputed before the in-place decryption, and, when not `BLANK`, the three re-seal equality checks plus `life` equal to a value read again before T-INSTALL; `OFFER` — `life` before T-OFFER; `EXPORT` `P1 = 0x01` — `verified` (the shadow word) before the payload; the `LOADED`-only checks are written `if (life != BLANK)` so a skipped branch enters them. The peer-key slots hold `P_init` until written — a point whose discrete logarithm is unknown, so a slot never silently behaves as a key the attacker controls. Ending a pending state overwrites `K_te`/`K_tm` with fresh random values, never a constant, so a pending check bypassed by a fault encrypts/MACs under keys nobody holds | `Transfer`, `Session.endPending` |
| Key and seed derivations computed twice and compared (§16.2 item 5): `EXPORT`/`IMPORT` `P1 = 0x00` derive the transfer keys from two ECDH products in separate buffers — the scalar `e` is loaded twice and the range check repeated — with two `Kdf.kdf` calls whose outputs are compared in constant time before any `setKey`, and each loaded key is read back by `getKey` and compared; `OPEN` derives its session keys by two KDFs compared and read back the same way and re-checks `x` in range; `CREATE` `P1 = 0x00` draws `t` into a wiped slot checked non-zero and computes the seed twice into separate buffers, compared and checked non-zero (§9.4) | `Transfer.export0`/`import0`, `Transfer.loadKeys`, `Session.open`, `Secp256k1.inRange`, `Wallet.create` |
| Staged copies compared with their source (§16.2 item 5): every copy of seed material or of an access hash into a staging buffer that feeds T-CREATE, T-CHANGE, T-INSTALL or an `EXPORT` `P1 = 0x01` payload is followed by a constant-time `Bytes.equal` against the source — a skipped or mis-offset copy can only make the values differ | `Wallet.create` (seed, access hash), `Wallet.install` (seed, access hash), `Wallet.change` (access hash), `Transfer.export1` (seed, `accessHash_T`) |
| Bounded APDU reception: `receiveAll` faults `6F00` on a `receiveBytes` call that returns 0 bytes, so a transport or platform that stalls delivery faults instead of spinning | `WalletApplet.receiveAll` |
| Self-verification of every signature (§16.2.6): detects faults in the signing computation; for hardened ECDSA leaves and Ed25519 it does not detect a fault that rewrote the private key before signing — the host's check against the cached public key does; `Ecdsa` recomputes the verification twice, `Bip340`/`Ed25519` compute `V` once and evaluate the comparison twice, so a forced result needs a second, matching fault in the signing computation | `Ecdsa` (leaf public key via `PACE_GM(IL, K_par)` for non-hardened leaves), `Bip340` (`Q = P_even + t·G` via `PACE_GM`; check `s·G + (−e·Q) = R`), `Ed25519` (`S·B + (−k·A) = R`) |
| Share masking of secret products with the §16.2.7 order: `s = ((k + e·d₁) mod n + e·d₂) mod n`, `S = ((r + k·a₁) mod ℓ + k·a₂) mod ℓ`; `d₁`, `a₁` fresh uniform per signature; no intermediate equals `e·d` or `k·a` | `ModArith.mulMasked`, used by `Bip340` and `Ed25519` |
| Structural binding of the seed to the code (D6) | `Wallet.verify`/`unwrap` decrypt only after `CHECK_OK` |
| Constant time (§16.4); every RSA operand reduced below the modulus in constant time before `doFinal` | `Bytes.equal`, `ModArith` (fixed loop bounds, masks instead of branches) |
| Point rule (§16.5): explicit on-curve check; decompression `y = (x³+7)^((p+1)/4)` with `y²` check and parity (§10.5) | `Secp256k1.onCurve`/`decompress` used by `Transfer.export0`/`import0`; `Identity.personalize` checks `caKey` explicitly |
| Teardown wipe order (§8.5) | `Session.teardown` |

A failed re-evaluation behind a passed dispatch gate returns `6F00`.

Each gate below has two evaluations; the Shared inputs column lists everything both
evaluations read and why a single fault on it releases nothing. One fault is therefore refused,
and a release needs the faults listed in the last column.

| Gate | First evaluation | Second evaluation | Shared inputs | One fault | A release needs |
| --- | --- | --- | --- | --- | --- |
| `EXPORT` `P1 = 0x00` certificate | `verifyCert` (`6A80`) | `verifyCert` again before `signHash` (`6F00`) | command data (attacker-chosen anyway); `caKey`, written only by T-PERSO; SHA-256/ECDSA engines, re-initialised per call | refused | both evaluations faulted |
| `EXPORT` `P1 = 0x00` membership | `memberSlot` (`6A80`) | `memberSlot` again, slot compared (`6F00`) | persistent `members` and the identity key, re-read | refused | both evaluations faulted |
| `EXPORT` `P1 = 0x00` `sig_T` | `offerSignature` under the slot written by `setPeer` (`6A80`) | `A_T` decompressed again and compared with the slot's `getW`; offer hash into its own buffer; `verifyHash` again (`6F00`) | the slot key object — its content is compared with the recomputed key before the second verification; a slot that was not written holds `P_init` or another member's key, under which no attacker signature verifies; the slot index, bound by the membership recompute and the read-back | refused | both verifications faulted |
| `EXPORT` `P1 = 0x01` pending export | pending word `= PENDING_EXPORT` (`6985`) | shadow word `= PENDING_EXPORT_SHADOW` (`6F00`) | none — two words, two codes; outside a pending export `K_te`/`K_tm` hold fresh random values | refused | both words faulted, plus `K_te` and `K_tm` known (each needs its own skipped random overwrite, or an RNG failure) — and with the pending state genuine, knowing the keys additionally needs faults on both derivations of the transfer-key row below |
| `EXPORT` `P1 = 0x01` and every verified-only command: `verified` | dispatch gate and first check on the `verified` word (`6982` / `6F00`) | last check before the effect on the shadow word (`6F00`) | none — two words, two codes; in an unverified session the seed is zero (D6) | refused | both words faulted (and the effect then operates on a zero seed) |
| `IMPORT` `P1 = 0x00` certificate | `verifyCert` (`6A80`) | `verifyCert` again before the slot write (`6F00`) | as in the `EXPORT` certificate row | refused | both evaluations faulted |
| `IMPORT` `P1 = 0x00` membership (`LOADED`) | `memberSlot` with `life` read at command start (`6A80`) | `memberSlot` again with `life` read again (`6F00`) | persistent `members`, re-read | refused | both evaluations faulted |
| `IMPORT` `P1 = 0x00` `sig_S` | `verifyHash` under the slot over `TH` (`6A80`) | `A_S` decompressed again and compared with the slot's `getW`; `A`, `LK` re-read; `TH` recomputed into its own buffer; `verifyHash` again; the pending import keys derived from the recomputed `TH` (`6F00`) | the slot key object and index, bound as in the `sig_T` row | refused | both verifications faulted |
| `IMPORT` `P1 = 0x01` MAC | `mac` (`6A80`) | `mac` again before the in-place decryption (`6F00`) | `K_tm`/`K_te`, derived twice and compared under §16.2 item 5 — a single fault on a product, a KDF, the compare or a `setKey` is refused before any key is loaded (random outside a pending import): a fault that makes `K_tm` known passes both MAC evaluations, but the payload still decrypts under `K_te` | refused | both MAC evaluations faulted, or `K_tm` and `K_te` both known |
| `IMPORT` `P1 = 0x01` re-seal (`LOADED`) | `reseal` (`6A80`) | each check again before T-INSTALL with `life` read again; `Wallet.install` re-reads `life` twice (`6F00`) | the decrypted payload (authentic only under the transfer keys) and the persistent `fp`/`origin`/`members`, re-read | refused | both evaluations faulted |
| Transfer key derivation (`EXPORT` `P1 = 0x00`) | `agree(ephKey, LK_T)` + `Kdf.kdf` over `TH` → `K1` | `mul(e, LK_T)` + `Kdf.kdf` over the same `TH` → `K2`, compared, then each key read back by `getKey` and compared with `K2` | `e` — loaded twice, a fault on one load desynchronises the two products; `Z` of each product — one fault changes one `K`, the compare refuses; `TH` — shared by both derivations and public context, so a fault on it yields consistent keys that are still secret (`Z` stays secret) and a `sig_S` the target rejects; the KDF scratch — no buffer is shared between the two derivations | refused | two matching faults (both products or both comparisons faulted in the same direction) |
| Transfer key derivation (`IMPORT` `P1 = 0x00`) | `agree(linkPrivate, E)` + `Kdf.kdf` over `TH` → `K1` | `agree(linkPrivate, E)` + `Kdf.kdf` over the independently recomputed `TH` → `K2`, compared, `getKey` read-back as in the `EXPORT` row | as in the `EXPORT` row, but both `agree` calls use the persistent `linkPrivate` key object directly — no `setS` is involved; it is written only inside T-OFFER/T-CREATE/T-INSTALL/T-ERASE | refused | two matching faults (both products or both comparisons faulted in the same direction) |
| Session key derivation (`OPEN`) | `Kdf.kdf` → `K1` (`kce ‖ kcm ‖ kre ‖ krm`) | `Kdf.kdf` → `K2`, compared; each `setKey` read back by `getKey` and compared | `Z` — shared: a fault on it desynchronises the card from the host, whose independent derivation refuses the first record; `x` — range-checked twice | refused | both KDFs faulted identically, or both comparisons faulted |
| `CREATE` seed | `seedHash` → `mem.seed` | `seedHash` again → `H`, compared, then `mem.seed` checked non-zero | the draw `t` — its slot is wiped first and checked non-zero after the draw; `hostEntropy` and the label — public command input | refused | both `seedHash` computations faulted identically, or the draw plus both compares faulted |
| Staged copies (seed and access hashes into `H`/`W` before T-CREATE/T-CHANGE/T-INSTALL and the `EXPORT` `P1 = 0x01` payload) | the `arrayCopy` itself | `Bytes.equal` against the source, constant time | the source — persistent state or command data re-read; a fault on it makes the compare fail, never pass | refused | the copy plus the compare both faulted |
| `VERIFY` step 2 | `f_a` | `f_b` | none (independent reads) | refused | both reads faulted |
| `VERIFY` step 6 read-back | fresh read `= f_b + 1` | fresh read `= f_c + 1` | none (three independent reads) | refused | the skipped T-FAIL write plus matching faults on both `f_b` and `f_c` |
| `VERIFY` step 7 match | KDF108 + CMAC | KDF108 + CMAC again | the candidate (command data) and the stored `wrapKey`/`ct`/`tag`, re-read: a forced match without the code decrypts garbage, which fails step 8 | refused | both matches and both fingerprint comparisons faulted |
| `VERIFY` step 8 fingerprint | `fp'` vs stored `fp` | recomputed and re-read | the decrypted seed (one decryption): a fault on it makes both comparisons fail, never pass | refused | both comparisons faulted |
| Self-verification (§16.2 item 6) — ECDSA | `verifyHash` | `verifyHash` again | the leaf public key and its verify slot, written once: a fault on them makes a correct signature fail; it cannot make a faulty signature verify | refused | a faulty signature plus both verifications faulted |
| Self-verification — BIP-340 / Ed25519 | `V = R` compared | compared again | `V`, computed once: releasing a faulty signature needs `V` to equal its `R` — a second, matching fault | refused | a faulty signature plus a matching fault on `V` (or both comparisons) |
| `Identity.signHash` self-verification | once | — | — | a computation fault alone is refused | a computation fault plus a skipped check |
| `verifyHash` coded result | — | — | the engine boolean belongs to one call; every gate's two evaluations are two calls | one skipped conditional yields a non-codeword; a corrupted boolean affects one evaluation | — |

The simulator's single-fault sweep (`GateSweepTest`, §9) instruments the applet with five
site kinds — branches, invokes, data loads, stores and arithmetic — and, per scenario, counts
one unfaulted run (which must be refused), then re-runs the scenario on a fresh card once per
(site, occurrence, mode) under a watchdog of fifty times the counting run's site hits. Branch
sites are swept TAKE and FALL; invoke sites SKIP and — for `short`/`byte`/`boolean` results,
applet and Java Card API calls alike — FORCED to every coded value of `Const`; data loads
ZERO, ONES and FLIP; stores skipped; arithmetic evaluated to its left operand. Data, store
and arithmetic faults are woven only inside the gate methods this section lists; branch and
invoke faults apply to every applet method. Branch and invoke sites are swept at every
occurrence; a data, store or arithmetic site executed more than eight times is sampled at
occurrences {1, 2, 3, last} plus four evenly spaced ones (each CSV row carries a `sampled`
flag).

Two scenario families are swept. The attack scenarios replay an outsider's path — `VERIFY`
with a wrong code at each count boundary, the unverified forms of `CHANGE`, `ERASE`,
`PUBLIC_KEY` and the three signing commands, `EXPORT` to a non-member, a foreign-batch or
attacker-keyed target, `EXPORT` with no pending offer, `IMPORT` of an attacker seed, a
different wallet and a zero-key record — and require every faulted run refused exactly as the
unfaulted one is. The legitimate-flow scenarios run a genuine command and judge the released
effect against the public candidate set (zero, the card's compressed identity and its hash, a
genuine member's identity and certificate, the public windows of the scratch arrays): `SXe`
(export, predicate R-X — the payload keys must need the target's link key), `SIe` and `SIn`
(import and install, R-I — the pending keys must need the source's `e`), `SCr` (`CREATE`
P1=0, R-C — the seed must come from the card's own random), `SCi` (`CREATE` P1=1, R-S — the
stored seed is the one sent), `SCh` (`CHANGE`) and the access-binding half of `SCr`/`SCi`/
`SIn` (R-A — the stored wrap opens only under the access hash the host sent, evaluated
host-side from `ct`/`tag` and the stored `wrapKey`), and `SO` (`OPEN`, R-O — the session
keys are neither equal under two RNG draws nor in the candidate set). `SXe` and `SO` also
release when the produced ephemeral equals `s·G` for any scalar `s` taken from the public
windows — the blob bytes, public scratch windows, transcript hash, point x-coordinates and
0x00…01 — because such an ephemeral lets the peer derive the same keys — the public-ephemeral clause. An outcome
whose keys
differ from correct but match no candidate is DEVIATED — listed, not a failure; a run
exceeding the watchdog is a HANG row; the test fails only on RELEASED. Every release
predicate is pinned by `GateSweepPredicateTest`, which arms a deliberate fault combination
that must RELEASED (e.g. skipping a staged copy together with forcing its comparison) so a
vacuously-false predicate cannot pass unnoticed.

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
   The same charging applies to the install phase: `Phase.INSTALL` writes (array spans, key
   setters, `setW`/`genKeyPair`) count against the same 5,120 B — card A's install journal —
   and install throws `TransactionException` `BUFFER_FULL` beyond it; nothing is journaled for
   rollback (a failed install is discarded whole). The charge is exposed as
   `Card.installBytes()`; `InstallJournalTest` asserts both applets ≤ 3,072 B and that a
   test-only applet replaying the pre-F1 constructor fails with `BUFFER_FULL`, while the
   real-card suite measures the charge with the memprobe (`install-journal.json`, §10).
   Allocations (`buildKey`, `new`, `makeTransient*`, `getInstance`) charge the single constant
   `INSTALL_ALLOC_CHARGE`, 0 — measured on card A: allocations are not charged to the install
   journal (`install-journal.json`).
   `<clinit>` is not woven (patch 5's agent skips it): the constants it fills are CAP-loaded
   bytes, not runtime persistent writes.
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
8. Call skipping, counting and store faults: the agent guards every call from applet code to a
   void applet method and to `JCSystem.begin/commit/abortTransaction` with `Fault.skip`; a test
   arms the n-th call to be skipped, and `Fault.countCalls`/`calls` counts the same sites without
   arming (the teardown test counts `Session.initEngines` to prove the record engines are
   re-armed on the zeroed keys). `Fault.armStore(n, v)` makes the n-th persistent
   `Util.setShort` store `v`.
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
| Fault mutants | Hand-written fault mutants are the primary fault evidence (PIT mutates JVM bytecode, not CAP instruction skips): delete the T-FAIL call; delete `commitTransaction` (assert abort, T-ERASE, `6F00`, card `BLANK`, no comparison); overwrite `f_a` with a smaller value after its complement check; overwrite the value T-FAIL writes; skip the `f ≥ L` test with `f = L`; force one comparison branch to pass; force the fingerprint check; skip the `WAIT` gate (assert the comparison count still stays ≤ L); skip `ERASE`'s `verified` gate; skip each `IMPORT` equality check in `LOADED`. Each asserts no uncounted comparison, no T-OK and no output, per P2/P3 of `threat-model.md`. The mutation gate also comprises the single-fault sweep `GateSweepTest` (branch take/fall, invoke skip and forced coded results including Java Card API calls, data-load zero/ones/flip, store skip, arithmetic keep-left, forced woven calls and ECDSA verification — every scenario re-run once per executed site; §6) and `ReviewMutantTest` (persistent instruction-site faults Q01/Q02 at `Transfer.setPeer`) | `tests` |
| Real card | §10, gated by `-PrealCard=<reader>`; never run in CI; reports "not run" | `tests/src/realCard` |

## 10. Real-card suite and silicon admission

Run on each silicon batch and before the protocol freeze; results recorded in the batch record.
The suite lives in `tests/src/realCard`: JUnit 6 classes under `java/` and the test-only
card-side artifacts under `javacard/` — the §3 admission probe (`probe/`, package
`F0716E7478FF`, applet `F0716E7478FF01`, CAP `tests/build/cap/qntx-probe.cap`) and the memprobe
(`memprobe/`: `MemProbe.java` plus `memprobe.patch` applied to a copy of the applet sources at
build time, CAP `tests/build/cap/qntx-memprobe.cap`; the production sources stay untouched and
the build fails if the patch no longer applies). Neither CAP is part of a release artifact; the
prebuilt production CAP is checked before install (`-PrealCardCap`, sha256 printed by the task)
and the suite asserts `qntx-card.cap` never contains `MemProbe`.

The suite is gated by `-PrealCard=<reader>` (PC/SC terminal name); without a reader every test
is skipped as "not run" and `-PrealCardList` enumerates the suite as skipped without touching
hardware. `Fixture` manages one card per run: it installs the CAPs with the `gp` wrapper
(`-Pqntx.gp`), reuses the wallet across tests to stay inside the wear allowance, and deletes
the qntx AIDs in `@AfterAll` unless `-PrealCardKeep`. Card identity is checked before any
install: the ATR, the ISD's CPLC and the JCOP IDENTIFY build string must name a development
card of `REALCARD.md`, never a production batch.

| Code under test | Real-card test | Packet / files / assertions |
| --- | --- | --- |
| dispatch, §6 SELECT, §7, §8 records | `CoreRealCardTest` | ATR + CPLC + JCOP IDENTIFY vs `REALCARD.md`; wrong CLA `6E00`, unknown INS `6D00`; identity is a stable on-card compressed key across a power cycle; PERSONALIZE gates and `6A80` rejects; OPEN `6985`/`6A86`, record-layer `6982`/`6985`, select and power-cycle teardown, OPEN across selection epochs (D2) |
| §3 item 1 — `ALG_RSA_NOPAD` | `AdmissionRealCardTest` (`rsaNopadUnder256`) | probe `0x01/0x02/0x03`: 512-bit moduli, exponents 2 and 32-byte; 1,000 random inputs per modulus vs BigInteger; every input ≥ `m` throws |
| §3 item 2 — `ALG_EC_PACE_GM` | `AdmissionRealCardTest` (`paceGmAndPlainXyOnBothCurves`) | probe `0x13` on secp256k1 and Wei25519: result is the 65-byte `s·G' + H`; an infinite result throws `CryptoException` |
| §3 item 3 — `PLAIN_XY` | same test | probe `0x14`: off-curve, compressed and `x ≥ p` inputs are rejected — required by §3; valid input gives the 65-byte product |
| §3 item 4 — `sign/verifyPreComputedHash` | `AdmissionRealCardTest` (`precomputedHashEcdsaSignsAndVerifies`) | probe `0x15/0x16`: card sign → host verify, host sign → card verify, corrupt signature rejected |
| §3 item 5 — custom domains | `AdmissionRealCardTest` (`ecDomainsAcceptedOnEveryKeyKind`) | probe `0x10`: persistent, TRANSIENT_RESET/DESELECT keys and keypairs take both domains |
| §3 item 6 — RandomData | `AdmissionRealCardTest` (`rngPassesStatisticsAndDoesNotRepeatAcrossPowerUps`) | probe `0x30`: `-PrealCardSequences` sequences of 10⁶ bits (default 80) through the SP 800-22 subset with the §4.2 two-level decision rule (per-statistic pass proportion and P-value_T); the first 32 bytes after each of 100 power-ups are pairwise distinct (`rng.json`, `rng.bin`) |
| §3 item 7 — keys in transactions | `AdmissionRealCardTest` (`persistentKeySettersJoinAndAbortTransactions`) | probe `0x21`: `setKey`/`setS`/`setW`/`setExponent`/`genKeyPair` abort back to the previous value and commit persistently |
| §3 item 8 — commit capacity | `AdmissionRealCardTest` (`platformEnginesAndCommitCapacity`), `MemoryRealCardTest` | probe `0x50` capscan reports `getMaxCommitCapacity`/`getUnusedCommitCapacity` (`commit-capacity.json`); memprobe `80 FE` reports `max − unused` before every commit of each named transaction — each ≤ 50 % (`memory.json`) |
| §3 item 9 — WAIT unit | `TimingRealCardTest` | WAIT median of 20 runs ∈ [0.9, 1.1] s (`timing.json`, `timing.md`) |
| §14.3 install, §4.3 init, §8.5 epochs | `InstallRealCardTest` | production CAP installs (registry = baseline + load file + instance); `GET_IDENTITY` polls return `6283` until `INIT_DONE` (bound 16, each ≤ 500 ms per §16.6, `init.json`); every other outer command answers `6283`; the memprobe twin reports the install journal charge ≤ 60 % of the commit capacity (`install-journal.json`); personalise, then `OPEN` ×3 across re-SELECTs and once across a power cycle; `qntx-card.cap` contains no `MemProbe` |
| §16.6 command timing | `TimingRealCardTest` | every named command, 20 runs (10 for the EXPORT/IMPORT rows, timed against `EmuMember`), host-clock median/max vs the B2 basis; every command ≤ 1,500 ms (`timing.json`, `timing.md`) |
| platform primitives | `PrimitiveRealCardTest` | probe `0x60` (P1 = primitive, P2 = r): per-op cost = (t(r) − t(0)) / r over 20 medians at r ∈ {0, 4, 16} for the exact engine shapes the wallet uses — AES-CBC/CMAC, SHA-256/512, the RSA square, `setS`/`setW`/`setDomain`, `PLAIN_XY`/`PACE_GM`, precomputed-hash ECDSA, `nextBytes`, `arrayFillNonAtomic` and a `Bytes.equal`-style byte loop (`primitives.json`, `primitives.md`) |
| §3 APDU `Lc = 248` | `SignRealCardTest` (`ed25519ChunkBoundaries`) | a 236-byte inner chunk is the largest record that fits `Lc = 248`; maximal updates + empty finish verify |
| §9.5/§9.6 wallet | `WalletRealCardTest` | lifecycle and the failure-limit story (~110 real WAITs, run once); derivation vectors of `derivation.json` |
| §12 signing | `SignRealCardTest`, `DifferentialRealCardTest` | every signature verified against vector/host key material (platform RNG forbids vector equality); `qntx.realcard.differential` signatures (default 1,000) written in the noble verify format (`signatures.json`) |
| memory | `MemoryRealCardTest` | install/init/current pools, per-step §4.3 deltas, DESELECT pool ≥ 15 % free after init (`memory.json`) |
| flows (B2) | `FlowRealCardTest` | `unavailable` until the phone harness lands — before freeze |
| tearing | `TearingRealCardTest` | `unavailable` until a programmable reader exists — before freeze |
| NVM endurance | `NvmRealCardTest` | `unavailable` until a sacrificial card exists — before freeze, never a development card |

Rows 1–9 are the admission items of `protocol.md` §3. Evidence lands under `-PrealCardOut`
(default `tests/build/realcard/`): the `*.json`/`*.bin` reports above plus `apdu.log`,
`gp-*.log` and `cplc.bin`, which feed the batch record. A run with a reader ends with
`record.txt` (the `realCardRecord` task, `finalizedBy` `realCard`): the `record 3`
format — the run's CAP sha256, commit, the five `tree-*` lines of `tests`/`applet`/
`host`/`sim`/`buildSrc`, the effective run parameters, reader, the card's identity
files, totals, per-class `PASS`/`SKIP` verdicts and the timing table — committed as
`realcard/<cap-sha256>.txt` before a tag (§12). Audit-impl ran admission 1–5 and 7 on
development card A (J3R180 hardware reporting JCOP build `J3R3510236310400`, CPLC IC type
`D321`, batch `2092`) and they passed
(`$A/audit-impl/evidence/card/functional.out`); admission must be repeated on each production
batch. Multi-card flows are simulation-only while only one development card exists.

Final card-A run (2026-11-25, CAP sha256 `39cc8dac…6ea9a436`, record
`realcard/39cc8dac….txt`): the whole suite passed once,
63 tests green, flows/tearing/NVM rows `unavailable` as designed; admission 6 ran the full
§4.2 decision rule (80 × 10⁶ bits, every statistic's proportion and P-value_T inside bounds,
`rng.json`); every timing row is inside its bound (`timing.md`, reproduced in the README;
EXPORT/IMPORT timed against a host-emulated member, `EmuMember`);
the install journal charged 0 B and `CLEAR_ON_DESELECT` shows 32 % free after init
(`install-journal.json`, `memory.json`).

## 11. Tools

`tools` builds `qntx-card` (picocli):

- `install` — load and install the CAP over SCP02 (`i = 55`) or SCP03 as recorded for the batch
  at admission (GlobalPlatformPro library), check the load-file hash against the release,
  compare the registry with the admission baseline plus exactly the load file and the two
  instances (`protocol.md` §14.3 steps 2, 3, 7), and drive §4.3 initialisation
  (`Init.drive`: `SELECT` + `GET_IDENTITY` until not `6283`, bound 16), printing the number of
  steps and each step's duration.
- `personalise` — accept an uninitialised card and drive §4.3 initialisation first, then
  `GET_IDENTITY`, obtain the certificate from the HSM interface (PKCS#11), send
  `PERSONALIZE`, verify `OPEN`, perform the step-7 registry check, replace ISD keys with
  discarded random keys, append the batch record (steps 4–10). It records and prints the short ID
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

- `ci.yml` (pull requests, `main` and `workflow_call`): REUSE lint, Spotless check, build CAP
  (twice, compare hash), unit + command + tearing + vector + fuzz-smoke tests, vector
  generator agreement (JDK 25 and Bun), PIT on gate classes, memory report vs §5.1 budget, CAP
  size report. Actions pinned by commit SHA, `permissions: contents: read`.
- `release.yml` (tags `v*`): a `gate` job runs `ci.yml` on the tagged commit; the release job
  then checks tag = version, requires a committed `realcard/<cap-sha256>.txt` record for the
  CAP hash that is consistent with the tag — the commit an ancestor of HEAD, the five
  `tree-*` lines the tagged trees, `params` the release parameters, `failed 0`, SKIP only
  for `Flow`/`Nvm`/`Tearing` and `InstallRealCardTest` PASS — rebuilds `build/dist/` with
  toolchain auto-download off, re-proves the CAP reproducible, verifies `SHA256SUMS` and
  uploads `qntx-card.cap`, `card-sim.jar`, `vectors.zip`, the `tools` distribution, the
  CycloneDX SBOM; build provenance via `actions/attest-build-provenance`; release notes list
  the protocol version, the CAP hash and the record. Top-level `permissions: {}`; the release
  job holds `contents: write`, `id-token: write`, `attestations: write`.
- Before any tag, the real-card gate of §10 — install the production CAP on card A, then `OPEN`
  across three select epochs and a power cycle (`InstallRealCardTest`) — MUST have passed on
  the tagged commit; CI cannot run it, so a passing `record.txt` is committed as
  `realcard/<cap-sha256>.txt` and the release job checks the file itself.

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
| R4 | Real-card suite compiles and lists every test of §10; it is reported as "not run" without hardware | `./gradlew :tests:realCard -PrealCardList` |
| R5 | `release.yml` dry run produces CAP, `card-sim.jar`, `vectors.zip`, SBOM, `SHA256SUMS`, provenance | workflow run on a test tag in a fork |
| R6 | Final budgets: memory report ≤ §5.1 total; CAP size reported; §16.6 time table reproduced from B2 in the README | build report |
| R7 | Every vector file of §18 exists and both generators agree | CI `vectors` |
