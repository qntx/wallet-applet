# meowl-applet documentation

These documents back the project, separated by audience:

| Document | Path | Audience |
| --- | --- | --- |
| **Wire protocol** | [`./specs/protocol.md`](./specs/protocol.md) | Host SDK authors, integrators, security auditors |
| **NDEF tag** | [`./specs/ndef.md`](./specs/ndef.md) | NFC integrators, app authors |
| **Backup card** | [`./specs/backup.md`](./specs/backup.md) | Wallet integrators, security auditors |
| **README, CONTRIBUTING, SECURITY** | repository root | Contributors, operators, vulnerability reporters |

[`specs/protocol.md`](./specs/protocol.md) is the **sole normative** specification of the on-card protocol — APDU framing, the Secure Channel, the lifecycle state machine, PIN/PUK, HD derivation, signing and status words. The applet sources under `applet/` and the test suite under `tests/` are the ultimate source of truth; where the document and the code disagree, **the code wins**.

## Conventions

- **Byte order** — every multi-byte field on the wire is **big-endian** unless an upstream standard mandates otherwise (notably RFC 8032 Ed25519, which serialises little-endian).
- **Hex notation** — `0x...` for inline byte literals, lowercase digits.

## Project README

The repository [README](../README.md) covers what `meowl-applet` is at a product level (multi-chain hardware-wallet applet, JavaCard 3.0.5, AGPL-3.0). It is not part of the protocol specification and may evolve independently of it.
