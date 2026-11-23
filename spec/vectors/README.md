<!--
SPDX-FileCopyrightText: 2026 QuantX
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# qntx card test vectors

The vector files of `spec/protocol.md` §18, licensed `MIT OR Apache-2.0`. Keys in them are public
test keys and must not be used for funds. Every file is written by two independent generators that
must produce identical bytes: `gen/java` (BouncyCastle) and `gen/ts` (noble). The card tests
(`tests`) and the qntx/wallet host consume the same files.

## Files

| File | `protocol.md` sections | Independent oracle | Generated from stage | Present |
| --- | --- | --- | --- | --- |
| `kdf.json` | 1, 8.1, 10.1 | NIST SP 800-38B CMAC examples; Python `cryptography` | `core` | yes |
| `cert.json` | 5 | noble `secp256k1`; BouncyCastle | `core` | yes |
| `session.json` | 8.1–8.2 | noble; Python `cryptography` | `core` | yes |
| `record.json` | 1, 8.3–8.4 | Python `cryptography` | `core` | yes |
| `access.json` | 7.1 | `argon2-cffi` (reference C); noble `argon2id` | `wallet` | yes |
| `wrap.json` | 7.2, 10.1 | Python `cryptography`, `hashlib` | `wallet` | yes |
| `transfer.json` | 9.12–9.14, 10.5, 11 | noble; Python `cryptography`; libsecp256k1 (`coincurve`) | `sets` | yes |
| `derivation.json` | 10.2–10.4 | Official BIP-32 and SLIP-10 vectors; `@scure/bip32`; OpenSSL and libsodium Ed25519 public keys | `wallet` | yes |
| `ecdsa.json` | 12.1 | noble `secp256k1`; BouncyCastle | `sign` | yes |
| `bip340.json` | 12.2 | BIP-340 reference CSV; BIP-86 vectors; noble `schnorr` | `sign` | yes |
| `ed25519.json` | 10.4, 12.3 | RFC 8032; noble `ed25519`; libsodium | `sign` | yes |
| `apdu.json` | 9, 13, 14 | Generated from the protocol tables by `gen/apdu.py` | `core`, extended by every later stage for its commands | yes |
| `verify-sequence.json` | 7.3, 9.3, 9.5, 9.15 | Generated from §9 by `gen/sequence.py`; the OFFER/IMPORT sequences of §18 land with stage `sets` | `wallet` | yes |
| `ndef.json` | 15 | NFC Forum T4T 2.0 §5 by hand | `release` | not yet |

The stage column is the implementation stage of `qntx/wallet-applet` that adds the file to both
generators (the stage owning the sections it covers).

## Encoding

Each file is one JSON document, ASCII, LF line ends, two-space indentation, object keys in the order
the generator writes them, and a final newline — exactly `JSON.stringify(value, null, 2) + "\n"`.
Values are objects, arrays, booleans, integers within ±(2⁵³ − 1), and strings; byte strings are
lowercase hexadecimal without prefix.

## Generating and checking

```bash
spec/vectors/gen/check.sh
```

runs `./gradlew :tests:generateVectors` (Java, output `tests/build/vectors/java`) and
`bun generate.ts` in `gen/ts` (output `tests/build/vectors/ts`), fails on any byte difference
between the two, and fails unless the committed `*.json` here are exactly the generated protocol
files. Both generators also write `selftest.json` (hashes, HMAC-SHA512 and secp256k1 public keys
through each generator's libraries and encoder), which is compared but never committed. CI runs the
script in the `vectors` job.
