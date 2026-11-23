<!--
SPDX-FileCopyrightText: 2026 QuantX
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# qntx card threat model

Scope: the card (wallet applet, NDEF applet, silicon), the protocol of `protocol.md`, the
personalisation process, and the host obligations of `host.md` that the card's guarantees rely
on. Citation keys are those of `decisions.md` §0. Security properties are stated with their
assumptions, the mechanism that provides them, and the test or analysis that supports them.

## 1. System

```text
 user ──▶ main runtime (JS, UI, NFC transport) ──ciphertext──▶ card
               │  requests / approvals
               ▼
            kernel (enclave): access code → accessHash, session endpoint, signing plans,
                              public-key cache, verification of every card output
```

The card has no screen and no button. The kernel decides what is signed and shows it to the
user, through a surface the main runtime cannot alter, before asking for a tap (`host.md` §7);
the card enforces who may sign or erase (access code), what can leave the card (signatures,
public keys, encrypted transfers to member cards), how often a code may be guessed, and how fast
guessing can destroy a wallet.

## 2. Assets

| Id | Asset | Where it exists |
| --- | --- | --- |
| A1 | Seed (64 B) and every key derived from it | Card: encrypted in NVM (`ct`); decrypted only in transient memory of a verified session. Imported mode: also transiently in the kernel at creation, and wherever the user's mnemonic is |
| A2 | Access code / `accessHash` | User's memory; kernel transiently; kernel record if the user chose to save it (DEK-sealed) |
| A3 | Card identity private key (`idKey`) | Card only |
| A4 | Batch CA private keys | Offline HSM |
| A5 | Session keys | Card transient memory, kernel memory |
| A6 | Signing authority (the ability to obtain a valid signature for an attacker-chosen digest) | Card + access code |
| A7 | Availability of the wallet (at least one usable card, or the mnemonic) | Card set |
| A8 | Link key (`linkKey`) during a transfer | Target card NVM until install |
| A9 | Privacy: link between a card, its set and the wallet's addresses | Card certificate, member list, public keys |

## 3. Actors and capabilities

| Id | Actor | Capabilities assumed |
| --- | --- | --- |
| X1 | Thief holding one card | Unlimited NFC/contact access to that card, own reader and software, tearing (power cuts at chosen instants), EM probes under 5,000 USD [T2 L381]; no access code |
| X2 | Thief holding two or all cards of a set | X1 on each card |
| X3 | Malicious or compromised main runtime (phone JS layer) | Sees and controls all APDUs between kernel and card (ciphertext), can open its own sessions with any card in the field for as long as the user holds it there, can relay a step to a remote card, renders every screen of the app except the kernel-controlled OS surfaces of `host.md` §7 |
| X4 | Compromised kernel | Everything the kernel can do: run sessions, know `accessHash` once entered, choose digests, tweaks, paths, export targets and `accessHash_T` |
| X5 | Relay attacker | Forwards NFC traffic between a card and a distant reader in real time |
| X6 | Malicious personaliser or supply chain | Controls the loaded load file, the personalisation steps and the shipped cards before the user |
| X7 | Fake card | A device that speaks the protocol but is not a genuine card (no certified identity key), or a genuine card under attacker control |
| X8 | Lab attacker within the chip certification | Fault injection (laser, glitch, EM) and side channels at the level considered by the chip's AVA_VAN.5 evaluation |
| X9 | Lab attacker beyond the certification | Invasive NVM read-out, multi-fault campaigns the chip evaluation did not consider |
| X10 | Malicious "backup" card | A genuine card of another set or batch, or a card controlled by X6/X9, offered as a transfer target or source |
| X11 | Nearby attacker | Brief NFC proximity to a carried card (seconds); ISO 14443 skimming ranges of 15–27 cm with enlarged antennas are reported (`$A/audit-product/evidence/web/hancke-2010-skimming.txt`); whether a P71 completes `OPEN` at that range is UNVERIFIED |
| X12 | Other app on the user's phone | Opens its own ISO-DEP sessions with any card the user taps while it is in the foreground (Android `android.permission.NFC` is a normal permission; any iOS app may list the AID) |
| X13 | Heir or coerced user | Holds the cards, or is forced to hand over cards and codes |

## 4. Trust assumptions

| Id | Assumption |
| --- | --- |
| S1 | The silicon (JCOP 4 P71) meets its Common Criteria EAL6+ security target for the certified cryptographic operations, tearing recovery, memory isolation and fault detection (RP §1.2, §3.1) |
| S2 | The kernel is not compromised for properties that say so; the kernel's text for every approval and card step reaches the user through an OS surface the main runtime cannot alter (native secure input view, iOS NFC sheet text set by the kernel, Android `BiometricPrompt`), and access codes are typed into the native secure input view (`host.md` §7). On iOS the Face ID prompt shows no custom text, so the NFC sheet text (`alertMessage`) is the only trusted carrier of what is being signed; its required content is `host.md` §3. Card wallets do not ship without these surfaces |
| S3 | Batch CA private keys are only in the offline HSM; the personalisation tool follows `protocol.md` §14.3 |
| S4 | The platform random generator (`ALG_KEYGENERATION`, DRG.3 on JCOP4, RP §2.7) is unpredictable, except where a property states robustness against its failure |
| S5 | SHA-256, SHA-512, AES-128, CMAC, ECDSA/secp256k1, BIP-340, Ed25519 are secure as standardised |

## 5. Security properties

Each property is a testable statement. "Test" refers to `architecture.md` §9; "analysis" to the
audit stages (`$A/audit-*/findings.md`).

| Id | Property | Assumptions | Mechanism | Support |
| --- | --- | --- | --- | --- |
| P1 | No command outputs the seed, a private key, a chain code of the master node, the seed fingerprint or an access code | S1 | Command set (`protocol.md` §9): outputs are WalletInfo, public keys, signatures, encrypted transfer payloads | Static review of every response; per-command output-length tests; fuzzing every inner command |
| P2 | An actor without the access code of a card (X1, X2, X3 or X12 opening its own session, X11) obtains from that card no signature, no wallet public key, no member list and no seed, and cannot replace its access code or erase it with `ERASE`, even if a single check in the applet is skipped by a fault | S1, S5 | `verified` gate (coded, evaluated twice); structurally: the seed is decrypted only after a matching MAC under a key derived from the candidate code (D6), so a skipped gate operates on a zero or garbage seed unrelated to A1; a re-seal needs an export from a member whose code is verified | Tests: every verified-only command returns `6982` unverified; fault mutants that delete each gate and assert the outputs are not valid under the real wallet keys |
| P3 | Between two successful verifications a card performs at most `L = 10` comparisons of candidate codes; neither a power loss at any persistent write nor a single skipped instruction, skipped commit or data fault on the counter value yields an uncounted comparison or a lost failure; a forced match does not reset the count | S1 | `fails` read twice independently (`f_a`, `f_b`); T-FAIL writes `f_a + 1` and is committed; transaction depth and read-back value (`= f_b + 1`, `≤ L`) checked twice before the candidate is used, so the written and the expected value come from independent reads; erase at the limit and on re-entry with `f = L` (evaluated twice); T-OK only behind two independent branches and the fingerprint of the decrypted seed (`protocol.md` §9.5, §16.2) | Tearing tests at every persistent write of `VERIFY`; fault mutants: delete the T-FAIL call, delete `commitTransaction`, overwrite `f_a` (or the written value) after its complement check, skip the `f ≥ L` test, force one comparison branch, force the fingerprint check; card A shows that an uncommitted update reads back as new and is rolled back on return with its response data still sent (`$A/audit-impl/evidence/card/functional.out`) |
| P4 | An X1/X2 actor guesses a uniformly chosen code from a space of size `N` with probability at most `L/N` per card | P3, S1 | Failure limit | Analysis; P3 tests |
| P5 | The seed is released by `EXPORT` only encrypted for the link key of a genuine card whose card ID is in `members` and that is `BLANK`, or `LOADED` with the same wallet, when it imports; no actor without the target's link private key learns anything about the payload. A device that holds the extracted identity private key of a member card (X9 on that card) can receive the seed in one transfer that a user with a member's code starts towards it | S1, S3, S5 | Certificate check, membership check, decompressed peer key, offer signature, ECDH with fresh `e`, KDF bound to `M`, CBC + CMAC (`protocol.md` §9.13) | Tests in `transfer.json` (non-member, wrong batch, bad offer signature, own card); ProVerif `transfer.pv`, `transfer-fs.pv`, `transfer-kci-skt.pv` (audit-crypto) |
| P6 | A target installs only a payload produced by a genuine card of its batch, for this target's current link key, listing the target and the source as members; a `LOADED` target accepts it only for the wallet it already holds (equal `fp`, `origin`, `members`). Membership is named by the creator and proves no possession: anyone holding a genuine card of the batch can install a foreign wallet into a `BLANK` card in their field | S1, S3, S5 | `IMPORT` checks (`protocol.md` §9.14); export signature over `M` binding `A_T` and `LK_T`; MAC; equality checks in `LOADED` | Tests: tampered `ct`, `tag`, `E`, foreign `LK`, replay of an older export, non-member payload, re-seal with a different `fp`, `origin` or member list; ProVerif `transfer.pv` Q3 shows the foreign-wallet install (audit-crypto F-9) |
| P7 | The host accepts a session only with a genuine card, attributes it to the card whose certificate it verified, and within a session detects any modification, replay, reordering, truncation (except of the last response) or reflection of records and ends the session | S3, S5 | Certificate + signed DH over both ephemerals and `A` (`protocol.md` §8.1); EtM record with per-direction keys and implicit counter | `session.json`, `record.json`, record-layer fuzzing on both sides; ProVerif `session.pv`, `session-bound.pv` |
| P8 | The access code and `accessHash` never cross the NFC interface or the kernel/main-runtime boundary unencrypted (once entered into the kernel), and the kernel sends an `accessHash` only to a card whose card ID it expects | S2 | `accessHash` sent only inside records; card-ID check before any record carrying an access hash (`host.md` §2); host leak test | Kernel message leak test (`host.md` §8); ProVerif `session-unchecked.pv` vs `session.pv` (audit-crypto F-6) |
| P9 | Every signature output by the card verifies under the key the card used; a fault in the signing computation is not output. For non-hardened ECDSA leaves and BIP-340 the verification key is derived independently of the signing scalar; for hardened ECDSA leaves and Ed25519 a fault that rewrote the private value before signing is caught only by the host's verification against its cached public key | S1, S2 | Self-verification (`protocol.md` §16.2 item 5); host verification (`host.md` §2) | Fault mutants that corrupt the derived key, the nonce or the final scalar; assert `6F00` or host rejection |
| P10 | Ed25519 nonces never repeat for one key, on one card or across the cards of a set, even if the random generator returns constant output, and are unpredictable even if the counter is faulted | S1, S5 | `r` from random `Zr`, secret `prefix`, the card ID and a persistent counter committed before use | Test with a constant random stub on two simulated member cards: distinct `r` across signatures, cards and power loss (`$A/resolve-1/evidence/worked.out`) |
| P11 | After `ERASE` or the failure limit, no command yields any output derived from the erased wallet, and the erased ciphertext is unusable even if read later | S1 | T-ERASE clears `ct`, `tag`, `fp` and writes a fresh `wrapKey`; `wrapKey` regenerated on every install (`protocol.md` §10.1) | Tests after `ERASE` and after the limit; tearing at every write of T-ERASE |
| P12 | A card never leaves `FACTORY` without a certificate that verifies under its stored `caKey`, never returns to `FACTORY`, and has no state outside §4.1 | S1 | `PERSONALIZE` checks (explicit curve check of `caKey`); lifecycle code set, checks evaluated twice | State-machine tests over every command × state |
| P13 | The reference host never proceeds with a card whose certificate fails against its anchors (or, for a card already in a record, does not equal the recorded certificate) or whose session signature fails | S2 | Host obligation `host.md` §2 | Host tests with forged, wrong-batch, revoked-batch and test-anchor cards |
| P14 | A new session never inherits `verified`, the seed, completed `WAIT` units or any pending state of an earlier one | S1 | Explicit wipe in `select()` and `OPEN`; `CLEAR_ON_DESELECT`; `0x0000` read as the cleared state | Tests: verified commands after re-`OPEN` and re-`SELECT` return `6982`; `VERIFY` after re-`OPEN` with `f ≥ F` returns `6986` |
| P15 | Wallet private keys and the link key are multiplied only by valid points; external public keys are checked before `setW`; the identity key never performs key agreement | S1 | `protocol.md` §10.5, §16.5 | Invalid-curve and twist probes on every point input; non-residue and wrong-parity decompression vectors |
| P16 | An actor without the code needs at least `F` immediate attempts plus `(L − F)·W = 105` completed `WAIT` units (about 103 s of card time on the development card, at least 96 s on any admitted batch, each attempt beyond `F` inside one continuous session of about 15 s) to erase a card's wallet; a power loss discards incomplete waiting but never a counted failure | S1 | `ERASE` needs `verified`; `WAIT` gate of `VERIFY` (`protocol.md` §9.5, §9.15); `waited` is transient | Tests: unverified `ERASE` returns `6982`; `VERIFY` with `f ≥ F` returns `6986` until `W` WAITs in the same session; timing on the real card (`WAIT` 900–1100 ms, `protocol.md` §3 item 9; 2.37 ms per iteration measured on card A, `$A/audit-final/evidence/card/sha-bench.out`); budget `$A/resolve-2/evidence/budget_r2.out` ("Destroy without the code": 103 s card time, 107 s with transport) |
| P17 | Forgetting the code of one card never requires destroying that card's ciphertext: a member whose code is known re-seals it while it stays `LOADED` | S1 | `OFFER` and `IMPORT` in `LOADED` for the same wallet (`protocol.md` §9.12, §9.14, §11.3) | `TransferFlowTest` re-seal case (`architecture.md` §14) |
| P18 | Reading out one card's NVM (X9) gives an offline search over its code at one Argon2id evaluation (64 MiB, 3 passes) per guess; the salt makes the search specific to that card (no precomputation, no amortisation over several read-out cards), but its result is the access code itself, which opens every card of the set that uses the same code (the host default, `host.md` §7 item 4) | S5 | Per-card salt `ID(A)` and Argon2id in `protocol.md` §7.1 | `access.json`; T-L2 table |
| P19 | On a `LOADED` card, an actor without the code who does not cut the field (X3, X11, X12) causes at most `L` T-FAIL commits before the wallet is erased or the user's next success resets the count, one T-OFFER per offer (an offer stays valid until a re-seal, install or erase), and one `setW` per peer-key slot; no other persistent write except a re-seal (T-INSTALL), which needs an export from a member whose code was verified | S1 | `protocol.md` §16.1 item 7: `OFFER` writes nothing while `offer = VALID`; `IMPORT` `P1 = 0x00` checks membership before decompression and skips `setW` when the slot already holds the sender's key; every other unverified command writes nothing | Simulator write counter per command and state in an unverified session (`architecture.md` §9); sacrificial-card endurance test on the remaining paths (`architecture.md` §10) |

## 6. Attack catalogue mapping

All 40 attacks of `RL` §4 (numbered as there), plus the attacks the audits added (A41–A47).
Verdict: **prevented** (the attack cannot reach its goal under the stated assumptions),
**detected** (it is noticed and stopped, possibly after denial of service), **accepted**
(residual risk, with the reason). "Host" means the mechanism is a `host.md` obligation, not the
card.

| # | Attack | Verdict | Mechanism or reason |
| --- | --- | --- | --- |
| 1 | Tearing bypasses the failure count | Prevented | T-FAIL committed, transaction depth and expected value read back before the candidate is used (P3); tearing tests at every write |
| 2 | EM distinguishes right from wrong code before power is cut | Prevented | No computation depends on the candidate before T-FAIL is committed and checked (`protocol.md` §16.1 item 2) |
| 3 | Code-derived channel keys turn decryption into a code oracle | Prevented | Session keys come from ECDH only; the code is sent inside the session (`protocol.md` §8.1) |
| 4 | Passive NFC eavesdropping | Prevented (content); accepted (metadata) | Record layer encrypts whole inner APDUs and status words; lengths and timing remain visible |
| 5 | Single laser fault skips a release gate | Prevented for signing and key output by structure (P2); prevented for the counter (P3, read-back gate and two branches evaluated twice); prevented for transfer install (a `BLANK` target only receives into an empty card; a `LOADED` target needs equal `fp`, `origin` and members, each checked twice); accepted for multi-fault campaigns (X9, T-L3) | D6, D22: seed decrypts only with the right code; coded flags and double checks (`protocol.md` §16.2) |
| 6 | Fault forces the recovery path after recovery was disabled | Prevented | No recovery flag exists (D9); a re-seal is an ordinary transfer from a verified member, and replaces only the code of the same wallet |
| 7 | Wired DC power speeds up computational delays | Accepted (bounded) | `WAIT` units are computation and run faster on faster power or silicon; they only slow destruction (P16), the guessing bound `L/N` does not depend on them; admission requires 900–1100 ms per unit on a contactless reader |
| 8 | Online brute force of a weak code with no total limit | Prevented to the bound `L/N`; accepted for very weak codes | Failure limit (P4); host requires ≥ 8 characters by default, 6–7 only after an explicit acknowledgement, and warns on common codes (`host.md` §7) |
| 9 | Client logic lets a failed genuineness check be overridden | Prevented in the reference host | Host aborts with no "continue" option (P13) |
| 10 | Client does not verify the certificate | Prevented in the reference host; accepted for third-party hosts | Card signs every handshake; reference host enforces (P13) |
| 11 | Secrets written to app logs | Host: prevented | Seed never reaches the host in card-generated mode; kernel leak test covers `accessHash`, session keys, imported seeds (`host.md` §8) |
| 12 | Scalar-length timing leak (lattice) | Prevented for ECDSA (platform, certified, S1); prevented for software scalar operations | Constant-time byte code (`protocol.md` §16.4) and share masking (§16.2 item 6) |
| 13 | EM side channel on a non-constant-time modular inverse | Prevented (not applicable) | The applet inverts no value; its only modular exponentiation (decompression, `protocol.md` §10.5) is on public values; Ed25519 encoding is done by the host; ECDSA inversion is the platform's (S1) |
| 14 | EM side channel on the chip's ECDSA (thousands of traces) | Accepted (chip level); limited | An actor without the code gets no wallet signatures at all (P2); with the code the actor already has signing authority. The identity key signs every `OPEN` for anyone (an unlimited signing oracle for SCA, S1) |
| 15 | Flawed on-chip key generation (ROCA class) | Prevented for seeds; accepted for identity keys | Generated seeds mix host entropy (D4); a flawed identity key generator would let an attacker impersonate a card (chip level, S1) |
| 16 | Fault attack on deterministic signatures | Prevented | Hedged nonces for BIP-340 and Ed25519 (D17) and self-verification (P9) |
| 17 | Biased nonces (lattice over many signatures) | Accepted reliance on S4 | ECDSA nonces are the platform's; BIP-340 and Ed25519 nonces are hashed from secret material and random input |
| 18 | Invalid-curve / small-subgroup ECDH | Prevented | Point rule `protocol.md` §16.5 (P15) |
| 19 | Twist attack on x-only ladders | Prevented | Only full uncompressed points enter ECDH; `IMPORT` checks the curve equation; decompression checks `y² = x³ + 7` |
| 20 | Faulty signature reveals the key (Bellcore class) | Prevented for computation faults; host-detected for key-rewrite faults | Self-verification before output; host verification against the cached key (P9) |
| 21 | NFC relay | Detected for injection; accepted for a relay during the user's own tap; host-detected at creation | Session terminates in the kernel (P7); a relayed target at creation is caught by the typed short-ID confirmation (A41, T-R3) |
| 22 | Malicious signer exfiltrates the seed through nonces | Accepted for X6 | Reproducible build, load-file hash check and registry check at personalisation, ISD keys destroyed (`protocol.md` §14.3); a malicious personaliser is outside the protocol's protection (§7) |
| 23 | JCVM type confusion / firewall bypass via a loaded applet | Prevented after issuance | No further loading: ISD keys destroyed (D25); only the two audited applets exist |
| 24 | Pre-seeded or counterfeit hardware | Prevented | Cards ship `BLANK`; the kernel creates wallets only on `BLANK` cards (`STATUS`) and checks genuineness (P13) |
| 25 | Voltage glitching a general-purpose MCU | Prevented | Certified secure element (D1) |
| 26 | Weak host entropy makes the mnemonic predictable | Prevented for card-generated wallets; accepted for imported wallets | D4: `seed = SHA-512(label ‖ TRNG ‖ hostEntropy)`; imported mode depends on the host's BIP-39 generation |
| 27 | Weak key generation tools (vanity) | Prevented (not applicable) | No host-side key generation; keys derive from the seed |
| 28 | Tampered signing UI leads to blind signing | Host: prevented if the kernel is intact and its text reaches the user through a trusted surface (S2); accepted for X4 | Kernel decodes the full request, computes the digest itself and shows recipient, asset and amount in a kernel-controlled OS surface with per-approval `hardware` verification; on iOS that surface is the NFC sheet text, which MUST carry the decoded summary (`host.md` §3, §7) |
| 29 | Poisoned host dependency | Host: mitigated | Kernel isolation, pinned dependencies; protocol client uses only already-pinned noble and the injected native Argon2id (`host.md` §1) |
| 30 | Address poisoning | Host | Kernel checks recipients against own accounts and contacts |
| 31 | EIP-7702 authorisation phishing | Host | Kernel decodes and confirms the authorisation separately (`host.md` §7) |
| 32 | Permit / EIP-712 phishing | Host | Kernel decodes EIP-712 and labels approvals |
| 33 | Clipboard hijacking | Host | Kernel shows and checks the full address |
| 34 | Fake app lures the user into "reset" or mnemonic entry | Prevented for card-generated wallets; accepted for imported wallets | No export command; a re-seal needs another member card and its code; an imported wallet's mnemonic can be phished like any mnemonic |
| 35 | MAC comparison timing oracle | Prevented | Constant-time comparison; any failure tears the session down |
| 36 | Verified state survives into a new session | Prevented | P14 |
| 37 | Unauthenticated wipe / nearby destruction | Prevented for brief contact; accepted for long contact | `ERASE` needs the code (P2); guessing to the limit needs about 103 s of card time in sessions of about 15 s each (P16). Anyone who holds a card long enough, or a phone app the user keeps tapping for long holds, can still erase it (T-D1); physical destruction is always possible |
| 38 | Static identifier tracking | Accepted | The certificate (in `OPEN`), the CPLC data (`GET DATA 9F7F`, readable without authentication on the development card, `$A/audit-product/evidence/card/probe.out`), the ATR and the NDEF message identify the card or its batch to any reader (T-X1) |
| 39 | CA compromise forges "genuine" blank cards to receive a clone | Mitigated | Per-batch CA keys in an HSM (D14); a forged card can only receive a wallet if it was named in `CREATE`, i.e. was confirmed by its printed short ID during the user's own creation; hosts stop accepting the batch anchor for new cards while recorded cards stay pinned (T-A1) |
| 40 | Reused temporary object signs with the wrong key | Prevented | Self-verification (P9), vector and differential tests (`architecture.md` §9) |
| A41 | Compromised main runtime relays a creation or transfer step to a remote attacker card, which becomes a member with a code the attacker chose (audit-product F-2) | Detected (host) | The user types each card's printed short ID into the native secure input view; the kernel compares it with the certificate before naming or exporting to the card; codes never pass through the main runtime (S2, `host.md` §7) |
| A42 | A forged success screen hides that a card was erased or never imported (audit-product F-1, F-5) | Mitigated (host) | Kernel-controlled sheet text; record state `incomplete`; health check with last-verified time per card (`host.md` §4) |
| A43 | Code collected by a card that is genuine but not the user's (an extracted identity key, a CA compromise) (audit-crypto F-6) | Prevented (host) | Card-ID check before any record carrying an access hash (P8); per-card salt means a collected hash cannot be replayed to another card, but it still allows an offline Argon2id search for the code, whose result opens every card that shares it (P18) |
| A44 | Identity mis-binding of the session (audit-crypto F-8) | Prevented | `A` in `TH` and in the session signature (P7) |
| A45 | Random generator that repeats after power-up: two `OPEN`s give the identity key; two ECDSA signatures give a wallet key (audit-crypto F-5) | Detected (admission, host); accepted (S4) | Admission power-cycle test; the host stops using a card whose `cardEph` repeats (`host.md` §2); Ed25519 and BIP-340 stay safe (P10) |
| A46 | Relay shell sold as a card forwards to a remote genuine card (audit-product F-20) | Accepted | Indistinguishable by protocol; the shell can carry the remote card's printed ID. Buy only from official channels (`host.md` §7) |
| A47 | Nearby reader or other app wears out a card's NVM with unauthenticated commands (`OFFER`, `IMPORT` `P1 = 0x00`) (audit-final F-3) | Prevented on `LOADED` cards without tearing (P19); accepted for `BLANK` cards and for an actor who holds the card and tears every write | `OFFER` is idempotent while an offer is valid; `IMPORT` `P1 = 0x00` requires a member sender in `LOADED` and skips an unchanged peer-key write. A `BLANK` card holds no wallet; an actor who can tear at will for hours can also destroy the card physically. NVM endurance on this silicon is UNVERIFIED (`architecture.md` §5.4) |

## 7. Residual risks and non-goals

The design does **not** protect against the following. Each is stated so that it can be shown
to the user or the owner without qualification.

| Id | Situation | What the attacker gets | Why it is accepted |
| --- | --- | --- | --- |
| T-K1 | Compromised kernel (X4) while the user taps a card and enters the code | Signatures on any digest for any path, as many as fit in the tap | A card without a screen cannot see what it signs (fixed point 1). Same as every screenless card |
| T-K2 | Compromised kernel (X4) | The access code (once entered) and the public-key cache | The kernel is the session endpoint by design |
| T-K3 | Compromised kernel (X4) + a stolen member card (no code needed: `OFFER` works in `LOADED` and `BLANK`) + the user unlocking another member | The wallet re-sealed onto the stolen card with an attacker-chosen code, i.e. lasting signing authority | Members can always re-provision each other (D3, D9). The attacker must hold one of the user's own cards; with X4 alone the attacker already signs arbitrarily during the tap |
| T-M1 | Extracted identity private key of a member card (X9 on that card, which needs the card) + one transfer towards that identity started by a user who knows a member's code | The seed | The protocol cannot tell an extracted key from the card; the host shows the target's short ID and asks the user to confirm the physical card (`host.md` §7) |
| T-R1 | Card wallet shipped without the native secure input view, or the code typed elsewhere | The code; with the card in the field later, the attacker's own session can sign | The secure input view is a launch prerequisite for card wallets (S2, `host.md` §7); this row describes what happens without it |
| T-R2 | Saved `accessHash` + a phone that can be unlocked or is rooted/jailbroken + the card tapped on that phone | Signing authority without the user typing | Saving is allowed only with the app lock on and every card approval behind a `hardware` factor (`host.md` §7); a rooted phone can still obtain the DEK (RW §3) |
| T-R3 | Compromised main runtime at creation relays a target step to a remote genuine card, and the user does not compare the printed short ID | A member card with an attacker-chosen code, lasting signing authority | Caught when the user types the printed short ID (A41); a user who copies the ID shown on screen instead of reading the card defeats it |
| T-R4 | X3 or X12 with the card in the field during the user's taps | Up to `F` failed attempts per tap without the user noticing; further failures only during long holds the app asks for; a long-held card can be erased (P16) | Guessing must stay possible from any phone (new phone, lost phone); the kernel compares `tries` with the value it recorded at the end of its last session with that card and, on fewer tries or an unexpected `BLANK`, stops the operation, warns on a kernel-controlled surface and asks for no other card in that operation (`host.md` §2 step 3) |
| T-C1 | Thief with a card and a weak code | Success probability `L/N` (6 digits: 10⁻⁵ per card; three cards with the same code: 3·10⁻⁵) | Bound by P4; the host requires ≥ 8 characters by default |
| T-C2 | Thief with all cards of a set and all their codes | The wallet | Knowledge of the code is the authorisation |
| T-D1 | Anyone holding a card for about two minutes (X1, a card kept in a phone case with a malicious app, a long tap on a compromised phone) | Erasure of the wallet on that card | Guessing must stay possible; the erased card can be re-provisioned from a member; the host advises against keeping a card in a phone case |
| T-D2 | Loss of all cards of a card-generated wallet, or forgetting all codes with none saved | Funds are lost | Intended: the seed exists only on the cards (D6) |
| T-D3 | One card lost | The lost card stays a copy of the wallet protected only by its code and limit, forever; the set cannot gain a replacement member | Members are fixed (D3); the only way to remove the copy is to migrate the funds to a new set (`host.md` §4) |
| T-I1 | Heir with the cards but without the codes (X13) | Nothing; at most `L` guesses per card, then erasure | Same property that stops a thief; the host tells the user to store the code separately in writing (`host.md` §7) |
| T-U1 | Coercion (X13) | Handing over the code hands over the wallet; there is no decoy wallet | No duress code (`open.md` Q10) |
| T-P1 | Malicious personaliser or supply chain (X6) | Arbitrary behaviour, including seed exfiltration through nonces | The protocol cannot attest code; mitigated procedurally (`protocol.md` §14.3). A customer can verify only: the certificate under a published anchor, the session signature, the printed short ID matching the certificate, and `BLANK` on first use. A customer cannot verify the byte code, the registry, the ISD keys or the personalisation station |
| T-L1 | Lab attacker within certification (X8) on Ed25519 / BIP-340 software arithmetic | Possibly key bits from side channels of byte code and RSA-engine use with secret operands | Outside the chip's certified scope (RP §4.3); first-order shares with a fixed recombination order (`protocol.md` §16.2 item 6). Residual: `k` and `r` appear unmasked in the additions; the 512-bit reduction of `r` uses the RSA engine unmasked; the RSA engine's countermeasures target secret exponents, not secret bases; BIP-32 `IL + k_par` repeats per path (template and horizontal attacks). Reachable only after a successful `VERIFY` |
| T-L2 | Lab attacker beyond certification (X9): invasive NVM read-out | `wrapKey`, `ct`, `tag` → offline search at one Argon2id (64 MiB, t = 3, p = 4) per guess: about 88 ms on one Apple M5 (`$A/resolve-1/evidence/access_argon2.out`), so 6 digits ≈ 24 h, 8 lowercase letters or digits (2.8·10¹²) ≈ 7,800 years on one machine, linear in the attacker's hardware; without Argon2id the same read-out gave 13,166 guesses/s in Python (`$A/audit-crypto/evidence/guess_rate.out`) | No hardware root beyond the chip; GPU rates for this memory cost are UNVERIFIED |
| T-L3 | Multi-fault campaigns (X9) on the counter path | More than `L` guesses | Two precise faults per extra guess (both evaluations of the read-back gate, both comparison branches, or matching data faults on both independent reads of `fails`), or a fault plus a timed power cut with EM observation for the re-entry case |
| T-A1 | Batch CA compromise | Forged blank cards accepted as genuine for new registrations until the anchor is revoked | HSM custody, per-batch keys (D14). Revoking an anchor stops new registrations only; cards already in a record stay pinned by their recorded certificate (`host.md` §2), so genuine users keep access and are told to migrate |
| T-N1 | Platform random generator failure | ECDSA with a repeated nonce leaks the wallet key from two public signatures; two `OPEN`s with a repeated nonce leak the identity key to any reader (impersonation, T-M1); a repeated `x` in `OPEN` exposes past sessions to invalid-point probing; BIP-340 degrades to deterministic (still unique per message); Ed25519 keeps unique nonces (P10) | S4; admission power-cycle test; hosts stop on a repeated `cardEph` or a repeated ECDSA `r` within an operation (A45) |
| T-X1 | Tracking by card identity | Linkability of a card across readers (certificate, CPLC, ATR, NDEF) | #38; whether CPLC can be disabled on the production batch is UNVERIFIED and recorded at admission |
| T-H1 | Hyperliquid trading through the kernel's hot agent key | Orders signed without the card | Wallet product design (RW §4); the card protects only `chain.sign` requests |
| T-H2 | Imported or upgraded wallets | The seed existed on the phone and on paper | Labelled honestly (D5, `host.md` §7) |
| T-F1 | Defect found after freeze | Shipped cards keep it | Cards cannot be updated (fixed point 3); the host stops new wallets on the affected batch or version and guides migration (`protocol.md` §17) |

Non-goals: what-you-see-is-what-you-sign on the card; revocation of a lost card (members are equal
and cannot be told apart by the chain); attestation of the code running on the card; protection
against coercion (T-U1); recovery without any code (T-I1, T-D2).

## 8. Actor walkthrough

| Actor | Outcome |
| --- | --- |
| X1 thief, one card | No signatures, public keys or seed without the code (P2); ≤ 10 guesses then erasure (P3); erasing takes about 103 s of card time (P16, T-D1) |
| X2 thief, all cards | Same per card; codes are independent attempts; no "two cards reset" exists (D9) |
| X3 main runtime | Cannot read or forge records (P7); can deny service, replay (detected), open its own sessions while a card is in the field (T-R4), relay a creation step (A41, T-R3), show fake screens outside the kernel-controlled surfaces (S2) |
| X4 kernel | T-K1, T-K2, T-K3 |
| X5 relay | Forwards ciphertext only; cannot inject into the kernel's session; no transfer is possible without a verified member |
| X6 personaliser | T-P1 |
| X7 fake card | Rejected by the host (P13); cannot send a payload a genuine target accepts (P6); cannot receive one (P5) unless it holds the extracted identity key of a member (T-M1); a relay shell is A46 |
| X8 lab, certified scope | Structural protection P2 removes the value of skipping gates; the counter needs two faults per guess (P3); signing-path attacks need the code; T-L1 |
| X9 lab, beyond | T-L2, T-L3, T-M1 |
| X10 malicious backup card | Genuine card not in `members`: refused by the source (P5). Card of another batch: certificate fails. A card named at `CREATE` is a member by the user's choice, confirmed by its printed short ID |
| X11 nearby | At most `F` failed attempts per brief contact (P16), no erasure, no output (P2), bounded persistent writes (P19); T-X1 |
| X12 other app | As X3 opening its own sessions: T-R4; bounded persistent writes on a `LOADED` card (P19, A47) |
| X13 heir or coercer | T-I1, T-U1 |
