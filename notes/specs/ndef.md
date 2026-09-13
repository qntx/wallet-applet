<!--
SPDX-FileCopyrightText: 2026 meowl.social contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# meowl NDEF tag

Normative description of the meowl **NDEF Type 4 tag** applet (`social.meowl.ndef.NdefApplet`, CAP `meowl-ndef.cap`). It is a self-contained package, independent of the wallet and backup CAPs, that turns a tap into an app launch. The applet sources under `ndef/` and `NdefAppletTest` under `tests/` are the ultimate source of truth; where this document and the code disagree, **the code wins**.

This tag is a generic, openly readable and writable NFC Forum Type 4 tag. It holds **no Nostr key and no wallet code** — the key material lives in the wallet CAP, and the payload written here is a public profile pointer (see §6).

## 1. Roles and AID

The tag is selected by a phone's NFC stack via the NFC Forum well-known Type 4 application AID `D2760000850101`. The CAP declares the meowl-namespaced applet AID `F06D656F776C0301`; the GP `install [for install]` step assigns the well-known instance AID so stock phones discover it:

```sh
./gradlew :ndef:buildCap
make install-ndef            # NDEF_AID defaults to D2760000850101
```

## 2. Files

Two elementary files, addressed by the NFC Forum Type 4 file ids:

| File id | Name | Access | Size |
| --- | --- | --- | --- |
| `E103` | Capability Container (CC) | read-only | 15 bytes |
| `E104` | NDEF file | read **and** write | 1024 bytes |

## 3. Capability Container (`E103`)

A fixed 15-byte CC, mapping version 2.0:

| Offset | Field | Value |
| --- | --- | --- |
| `0..1` | `CCLEN` | `000F` (15) |
| `2` | Mapping version | `20` (2.0) |
| `3..4` | `MLe` (max `READ_BINARY` response) | `00FF` (255) |
| `5..6` | `MLc` (max `UPDATE_BINARY` command) | `00FF` (255) |
| `7` | NDEF File Control TLV — tag | `04` |
| `8` | — length | `06` |
| `9..10` | NDEF file id | `E104` |
| `11..12` | Max NDEF file size | `0400` (1024) |
| `13` | Read access | `00` (granted) |
| `14` | Write access | `00` (granted) |

The CC itself is immutable; `UPDATE_BINARY` against `E103` returns `6985`.

## 4. NDEF file (`E104`)

A 1024-byte elementary file:

```text
[0..1]  NLEN  — big-endian length of the NDEF message that follows
[2..]   NDEF message (NLEN bytes); trailing bytes are padding
```

At install the file is seeded with a default message so a blank card still resolves somewhere:

```text
NLEN = 0011 (17)
D1 01 0D 55 04 "meowl.social"   — one well-known URI record, prefix 0x04 = "https://"
```

i.e. `https://meowl.social`. The meowl app overwrites this with the holder's profile link (§6).

## 5. APDU protocol

`CLA = 00`. The applet implements exactly the Type 4 command subset.

### SELECT — `00 A4 00 0C 02 <file-id>`

`P1=00` (by file id), `P2=0C` (first or only, no FCI returned, permitted by RQ_T4T_NDA_034). The data field is the two-byte file id. Selects `E103` or `E104`.

### READ_BINARY — `00 B0 <offset-hi> <offset-lo> <Le>`

Returns up to `min(Le, 255, remaining)` bytes of the selected file from `offset`.

### UPDATE_BINARY — `00 D6 <offset-hi> <offset-lo> <Lc> <data>`

Writes `data` into the **NDEF** file at `offset`. Writes are atomic per command (`Util.arrayCopy`). The CC is read-only.

### Status words

| SW | Meaning |
| --- | --- |
| `9000` | Success |
| `6700` | Wrong length — `SELECT` file id not 2 bytes, or `UPDATE_BINARY` spills past the file end |
| `6985` | Conditions not satisfied — no file selected, or `UPDATE_BINARY` against the CC |
| `6A82` | File not found — `SELECT` of an unknown file id |
| `6A86` | Incorrect `P1`/`P2` — `SELECT` not `00`/`0C` |
| `6B00` | Wrong `P1`/`P2` — read/write offset outside the file |
| `6D00` | Instruction not supported |

### Write procedure

Readers follow the NFC Forum write flow, which the applet supports as plain offset writes:

1. `UPDATE_BINARY` `NLEN = 0000` (invalidates the message).
2. `UPDATE_BINARY` the NDEF message at offset `2`, chunked to `MLc` (255).
3. `UPDATE_BINARY` the real `NLEN` at offset `0` (commits).

A tear between steps leaves `NLEN = 0` (an empty, valid tag) rather than a half-written message, so the procedure is tearing-resilient without an on-card transaction.

## 6. Content convention (host)

meowl is a **decentralised (Nostr)** social product: identity is a key pair, the public key (`npub`) is the self-sovereign identity, and the profile is a signed `kind:0` event on relays. There is no centralised backend.

- The Nostr identity is the **wallet's NIP-06 key** — derived from the wallet seed at `m/44'/1237'/0'/0/0` (secp256k1, 32-byte x-only Schnorr public key), the same cryptography the wallet already implements.
- The meowl app reads that public key from the wallet, encodes an `nprofile`/`npub`, and writes an **`https://`** URL into this tag, e.g. `https://meowl.social/p/<nprofile>`.
- `https://` (not the `nostr:` scheme) is required: iOS only auto-launches background tag reads for `http(s)` URLs. The destination is a stateless renderer plus Universal/App Links — it stores no account data and resolves the profile from relays client-side. An Android Application Record (AAR) may be appended to force-open the meowl app.
- Holders change their nickname, avatar and links by signing a new `kind:0` on relays from the app. **The tag is not rewritten for profile edits** — it carries only the stable identity pointer.

## 7. Security model

Open read **and** open write, no authentication — by design:

- The payload is a **public** profile pointer, not a secret.
- Holders rewrite their own card from the app over NFC; requiring authentication would block that self-service flow without a meaningful gain.
- An NDEF tag is read passively by any phone, so it is inherently copyable; **anti-clone and authenticity are app/relay concerns** (e.g. challenge–response with the wallet), never a property of a passive tag.
- The CC is read-only; only the NDEF message file is writable.

Accepted consequence: anyone with physical access can overwrite the tag over NFC. This is the standard behaviour of a writable NFC tag and is acceptable for a public business-card pointer.

## 8. Out of scope

Per-card factory provisioning, authenticated/locked writes, write-once, cross-CAP coupling with the wallet (SIO), on-card `npub` derivation or bech32 encoding, and the mobile app / relays / web renderer. This revision is intentionally the simplest standard Type 4 read/write tag.
