<!-- markdownlint-disable MD033 MD041 -->

# wallet-applet

The qntx card: an NFC Java Card applet that holds an HD wallet seed and signs for
[qntx/wallet](https://github.com/qntx/wallet). The card has no screen and no button; private keys
are generated on the card (or transferred once from another card of the same set) and no command
reveals a key, the seed or the access code.

[`spec/protocol.md`](spec/protocol.md) is the single normative specification (protocol 1, not yet
frozen); [`spec/vectors/`](spec/vectors/) holds its test vectors. [`AGENTS.md`](AGENTS.md) lists
the invariants every change keeps.

## Status

The repository is being rewritten from zero against `spec/protocol.md`. This revision implements
identity, personalisation, the secure session, the wallet commands, derivation, the three
signing commands and multi-card transfer (§5–§9.15, §10.1–10.5, §11–§12); NDEF and the tools
follow.

## Layout

| Path | Content | License |
| --- | --- | --- |
| `applet/` | The one CAP: package `org.qntx.card` (Java Card 3.0.5 Classic) | AGPL-3.0-or-later |
| `sim/` | jcardsim fork (`sim/jcardsim`, pinned upstream commit plus patches) with transactions, power-loss injection and memory accounting | Apache-2.0 (fork), AGPL-3.0-or-later |
| `host/` | Reference host library written from the specification | AGPL-3.0-or-later |
| `tests/` | Simulator, vector and mutation tests | AGPL-3.0-or-later |
| `tools/` | `qntx-card` installation and personalisation tool | AGPL-3.0-or-later |
| `spec/` | Protocol specification and vectors | MIT OR Apache-2.0 |
| `sdks/` | Oracle Java Card SDKs (submodule; the JCDK converter) | Oracle |

Identifiers: load file `F0716E747800`, wallet applet `F0716E74780101` (`spec/protocol.md` §2).

## Build

Requirements: JDK 25 (Gradle provisions it through the toolchain if missing), the submodule, and
Bun for the TypeScript vector generator.

```bash
git clone --recurse-submodules https://github.com/qntx/wallet-applet.git
cd wallet-applet
./gradlew build            # CAP, simulator and tests, memory report
./gradlew :tests:pitest    # mutation tests on the gate classes
spec/vectors/gen/check.sh  # both vector generators agree
```

The CAP is `applet/build/cap/qntx-card.cap`; two builds of the same sources have the same SHA-256.
Tests run the applet's JVM classes in the simulator with the `sim` agent (`-javaagent`), which
journals persistent writes, injects power loss and accounts transient memory with sizes measured on
the baseline chip (NXP JCOP 4 P71).

## License

The applet, simulator patches, host, tests and tools are licensed under the GNU Affero General
Public License v3.0 or later ([LICENSE](LICENSE)). The specification and vectors under `spec/` are
licensed under MIT OR Apache-2.0. The vendored jcardsim under `sim/jcardsim` remains Apache-2.0.
Every file carries REUSE metadata ([`REUSE.toml`](REUSE.toml), [`LICENSES/`](LICENSES/)).

---

<div align="center">

A **[QuantX](https://qntx.org)** project.

<a href="https://qntx.org"><img alt="QuantX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx.svg" /></a>

Code is law. We write both.

</div>
