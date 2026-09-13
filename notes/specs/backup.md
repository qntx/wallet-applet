<!--
SPDX-FileCopyrightText: 2026 meowl.social contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# meowl backup card

Normative description of the meowl **backup applet** (`social.meowl.backup.BackupApplet`, CAP
`meowl-backup.cap`) — a single-slot BIP-39 seed-backup card aligned with the Ledger Recovery Key
threat model, built on the meowl Secure Channel. It is a self-contained package, independent of the
wallet and NDEF CAPs. The applet sources under `backup/`, `BackupPinTest` under `tests/`, and
`BackupAppletIT` under `tests/src/realCard/` are the ultimate source of truth; where this document
and the code disagree, **the code wins**.

The card stores the **raw BIP-39 entropy** (16/24/32 bytes) so it can recover any BIP-39 wallet,
including the meowl wallet itself. It holds no derived keys and performs no signing.

## 1. Design rationale

The transport reuses the meowl Secure Channel (see [`protocol.md`](./protocol.md) §6): on the
target J3R180, native `AES-CMAC-128` + `AES-CBC` + `ECDH` make a double-ECDHE + signature-
authenticated channel the strongest *available* construction (the chip exposes neither AES-GCM/CCM
nor HMAC). The storage and fault-tolerance hardening is adapted from the Synacktiv-audited Ledger
Recovery Key: seed in an `AESKey` object, a seed-keyed integrity tag, random-overwrite erase, and a
no-PUK PIN that wipes on exhaustion. Only the seed vault and PIN are backup-specific; everything
cryptographic is the shared `social.meowl.shared` source injected at build time.

## 2. Roles and AID

| Item | Value |
| --- | --- |
| Package AID | `F06D656F776C02` |
| Applet (declared + instance) AID | `F06D656F776C0201` |
| CLA | `0x80` |

```sh
make build-backup            # ./gradlew :backup:buildCap
make install-backup          # gp install under F06D656F776C0201
```

Host operations use the `meowl backup` CLI group (`status`, `provision`, `restore`, `change-pin`,
`set-name`, `factory-reset`), e.g. `meowl backup provision --pin 1234 --entropy <hex>` then
`meowl backup restore --pin 1234`.

## 3. Lifecycle FSM

A persistent three-step forward FSM (the shared `LifecycleState` ordinals, with backup-meaningful
names). The authentikey — the card's stable Secure Channel identity — is generated at install and
**survives every reset**.

```text
FRESH(0) ──SETUP_PIN──▶ PIN_SET(1) ──BACKUP_SEED──▶ SEEDED(2)
   ▲                                                     │
   └──────────── RESET_TO_FACTORY / PIN exhaustion ──────┘
```

## 4. Seed vault

- **Storage** — the entropy lives in a persistent `AESKey` (AES-256) object, inheriting the secure
  element's hardware key protection. 16/24-byte entropy is right-aligned in the 32-byte key with the
  leading bytes zeroed; the true length is recorded separately.
- **Integrity** — a 16-byte `AES-CMAC-128` tag is computed over a fixed domain label concatenated
  with the length byte, **keyed by the seed itself**, and verified (constant-time) before every read.
  A mismatch raises `6FD0` and never returns suspect bytes; it binds both the entropy and its
  declared length.
- **Single slot** — a second `BACKUP_SEED` is rejected with `6FD1`. Re-backup requires a factory
  reset first.
- **Erase** — `wipe` overwrites the key with fresh TRNG bytes before clearing it, leaving no
  plaintext remnant in the key store.
- **Presence flag** — encoded with two Hamming-distant magic constants (not `0`/`1`) so a single-bit
  fault cannot forge "present".

## 5. PIN

A single user PIN, **no PUK** (Ledger model). 4–8 bytes, `OwnerPIN`-backed bounded retries.

- Exhausting the 3-try counter is treated as a brute-force signal: the applet **wipes the seed** and
  returns `6983`. There is no recovery path — the scorched-earth policy suits a cold backup card.
- A wrong PIN consumes a try (`63Cn`); an out-of-policy length returns `6700` and consumes none.
- The PIN-verified flag is session-scoped and bound to the Secure Channel: a re-handshake clears it.
- The provisioning flag is magic-coded for fault resistance.

## 6. APDU protocol

`CLA = 0x80`. Outer commands run in cleartext; every secret-touching command is an **inner** APDU
carried inside an `OPEN_SECURE_CHANNEL` envelope (`[CLA INS P1 P2 LC data]`, AES-256-CBC + CMAC).

### Outer surface

| INS | Command | Notes |
| --- | --- | --- |
| `01` | `GET_INFO` | status TLV (see §7); no Secure Channel required |
| `02` | `GET_AUTHENTIKEY` | compressed card-identity public key (anchors the SC handshake) |
| `03` | `RESET_TO_FACTORY` | `RESET_REQUIRED_INVOCATIONS` (4) consecutive calls wipe; countdown `6FA3→6FA0`, no PIN |
| `10` | `INIT_SECURE_CHANNEL` | ECDHE handshake; resets the prior session + PIN-verified flag |
| `11` | `OPEN_SECURE_CHANNEL` | envelopes an inner APDU |

### Inner surface (Secure Channel only)

| INS | Command | Gate | Inner data |
| --- | --- | --- | --- |
| `20` | `SETUP_PIN` | `FRESH` | `[pinLen(1), PIN]` |
| `21` | `VERIFY_PIN` | `≥ PIN_SET` | `PIN` (exhaustion wipes) |
| `22` | `CHANGE_PIN` | `≥ PIN_SET` | `[oldLen, old, newLen, new]` |
| `43` | `BACKUP_SEED` | `PIN_SET` + PIN verified | `[entLen(1), entropy]` (16/24/32) |
| `44` | `RESTORE_SEED` | `SEEDED` + PIN verified | — → entropy |
| `45` | `VERIFY_SEED` | `SEEDED` + PIN verified | — (integrity self-check) |
| `46` | `SET_NAME` | `≥ PIN_SET` + PIN verified | label bytes (≤ 32) |

`FACTORY_RESET` is the outer `RESET_TO_FACTORY` countdown (no PIN, anti-fat-finger), so a holder who
forgot the PIN can still wipe and reuse the card.

### Status words

| SW | Meaning |
| --- | --- |
| `9000` | Success |
| `6700` | Wrong length / out-of-policy PIN or entropy length |
| `6982` | Security status not satisfied — PIN not verified in this session |
| `6983` | Authentication blocked — PIN exhausted (seed wiped) |
| `63Cn` | Wrong PIN, `n` tries remaining |
| `6985` | Conditions not satisfied — wrong lifecycle / second SETUP |
| `6A86` | Incorrect `P1`/`P2` |
| `6D00` | Instruction not supported |
| `6FB0` | Lifecycle state forbids this command |
| `6FB1` / `6FB2` | Secure Channel required / cryptographic check failed |
| `6FA0`–`6FA3` | `RESET_TO_FACTORY` countdown (`6FA0` = wipe done) |
| `6FD0` | Seed integrity (CMAC) check failed |
| `6FD1` | Seed already present (single slot occupied) |

## 7. GET_INFO status TLV

Tags (application-private, single byte): `01` protocol version (2), `02` applet version (2), `03`
lifecycle state (1), `04` capabilities (2), `06` seed present (1), `07` PIN tries remaining (1), `08`
card label (variable), `09` stored entropy length (1), `05` compressed authentikey (33).

## 8. Security model

- **End-to-end confidentiality** — the entropy never crosses the wire in cleartext; `BACKUP_SEED`
  and `RESTORE_SEED` payloads are AES-256-CBC encrypted and CMAC-authenticated under the Secure
  Channel, with forward secrecy from the double-ephemeral ECDHE handshake.
- **Authorisation** — storing or restoring the seed requires a PIN verified inside the current
  Secure Channel session; the flag never carries across handshakes.
- **Anti-brute-force** — no PUK; the seed is wiped after 3 wrong PINs.
- **Anti-fault** — magic-coded state flags, a seed-keyed integrity tag binding entropy + length,
  and atomic transactions around every persistent mutation.
- **Erase** — random overwrite before key clear.

## 9. Out of scope

Card-certificate-chain attestation (the SC authentikey already authenticates the card; a chain can
be added later via the wallet's PKI flow), GP `UpgradeManager` seed-preserving firmware upgrade,
multi-secret storage (Seedkeeper-style), BIP-39 passphrase storage, and the mobile/host application.
This revision is the focused single-seed backup card.
