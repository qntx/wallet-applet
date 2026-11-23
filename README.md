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

Everything of qntx card protocol 1 is implemented: the wallet and NDEF applets (§5–§15), the
simulator, the host library, the provisioning tool and the vectors. The protocol is **not
frozen**: it freezes only after the external audit (`spec/protocol.md` §17), and the real-card
suite below has not run on hardware yet — every §10 row exists and has been self-checked on the
simulator only.

## Layout

| Path | Content | License |
| --- | --- | --- |
| `applet/` | The one CAP: package `org.qntx.card` (Java Card 3.0.5 Classic), wallet + NDEF applets | AGPL-3.0-or-later |
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

## Simulator (`card-sim.jar`)

`./gradlew :sim:shadowJar` builds `sim/build/libs/card-sim.jar`, a fat jar of the simulator,
applet and host classes. The manifest's `Launcher-Agent-Class` starts the bytecode agent that
makes persistent writes tearable; run it directly:

```bash
java -jar card-sim.jar [--cards N] [--port P] [--state empty|factory|blank]
```

- `--cards N`: simulated cards, 1–16 (default 3). Card `i` listens on `127.0.0.1:P+i`;
  `--port 0` gives every card an ephemeral port.
- `--port P`: first TCP port (default 35963, vpcd's port).
- `--state empty`: no package and no applets — only the issuer security domain (below).
- `--state factory`: install the wallet and NDEF applets, run the §4.3 initialisation and
  stop (life `FACTORY`).
- `--state blank` (default): also personalise each card under the `ca1` test CA of
  `spec/vectors/cert.json` (life `BLANK`).

In `factory` and `blank` states every card carries the wallet applet (`F0716E74780101`) and the
NDEF applet (`D2760000850101`, message "qntx card"). Startup prints one `card` line per card —
`empty` cards have no identity, so their lines end after the port — then, in `blank` state only,
a single `anchor` line, then `ready`:

```text
card <i> port <port> id <ID(A), 32 hex> short <XXXX-XXXX>
anchor <ca1 public key, 130 hex>
ready
```

Bad arguments print usage on stderr and exit 2; `--help` prints it on stdout and exits 0.

### Framing

Each card's TCP connection carries vpcd-style frames `u16(len) ‖ payload` (vsmartcard vpcd):

| `len` | Payload | Meaning | Reply |
| --- | --- | --- | --- |
| ≥ 4 | command APDU | transmit to the card | `u16(len) ‖ R-APDU` |
| 1 | `00` | power off | none |
| 1 | `01` | power on (a power cycle when unpowered; no-op when powered) | none |
| 1 | `02` | reset (power cycle) | none |
| 1 | `04` | get ATR | `u16(len) ‖ ATR` |
| 3 | `10 ‖ u16(N)` | arm power loss at the N-th persistent write of the next command that makes at least N writes | none |

A new connection powers the card on with a power cycle; closing it powers the card off. Card
state (persistent memory) lives as long as the server process; one connection per card at a time,
a second connection waits until the first closes. Anything else — `len` 0 or 2, a 3-byte payload
not starting with `10`, an unknown control byte, `N = 0` — closes the connection.

An APDU on an unpowered card, or an APDU during which the armed tear fired, is answered with the
empty frame `00 00` — no response, the field was lost. After a tear the card is unpowered until a
power-on or reset control. The armed tear is a per-command write count: it stays armed until it
fires or the card is power-cycled/powered off.

### Issuer security domain

Every card answers as a simulated GlobalPlatform issuer security domain, AID
`A000000151000000`, selected by default at power-up and answering SELECT-by-empty-AID with the
FCI `6F108408A000000151000000A5049F6501FF`. One AES-128 key set at KVN `0x30`, ENC = MAC = DEK =
`404142434445464748494A4B4C4D4E4F` (the GP test key). Emulated:

- SCP03 with `i = 0x00` (random card challenge, no sequence counter, no R-MAC/R-ENC, S8 MACs):
  INITIALIZE UPDATE (KVN `00` or `30`, else `6A88`), EXTERNAL AUTHENTICATE with security level
  `01` or `03`, and from then on only `84`-wrapped commands — a bad C-MAC closes the channel.
- GET DATA `9F 7F` returns the CPLC (fixed bytes except a per-card IC serial); unknown tags and
  other GET DATA → `6A88`.
- GET STATUS (`80 F2`) for the ISD, applications, load files and modules, in the card A formats.
- INSTALL [for load] + LOAD: the `C4` block must be a concatenation of components each
  byte-identical to the same-tagged component of the CAP embedded in the jar and covering all of
  them except Descriptor and Debug; an LFDBH, when present, must equal the block's SHA-256.
- INSTALL [for install and make selectable]: loaded package, class AID `F0716E74780101` or
  `F0716E74780201`, free instance AID, empty privileges, applet data from the `C9` TLV.
- PUT KEY `80 D8 kvn 81` replacing all three keys as `GPPro putKeys(keys, true)` encodes them —
  AES or DES entries encrypted under the static DEK, each KCV verified — after which the old keys
  no longer open a channel.

Not emulated: SCP02/SCP01 (INITIALIZE UPDATE with `i ≠ 00` gets `6A86`), key diversification,
sequence counters, R-MAC, DAP blocks, receipts, install tokens, delegated management, extradition
and DELETE — anything not listed answers `6D00`, and management commands outside a secure channel
answer `6982`.

## Real-card suite

`tests/src/realCard` implements the rows of `docs/architecture.md` §10: the nine silicon
admission items of `spec/protocol.md` §3 plus install/init, timing, the `Lc = 248` APDU
receive case, protocol cells, session, wallet lifecycle, signing and memory. It drives a card
through a PC/SC terminal (`javax.smartcardio`), installs the test-only probe CAP
(`javacard/probe`, package `F0716E7478FF`, → `tests/build/cap/qntx-probe.cap`) and the
memprobe CAP (`javacard/memprobe`, the production sources plus `MemProbe` applied by
`memprobe.patch` at build time → `tests/build/cap/qntx-memprobe.cap`) through the `gp`
wrapper, and deletes the qntx AIDs afterwards. Neither test CAP is a release artifact; a test
asserts `qntx-card.cap` contains no `MemProbe`.

```bash
./gradlew :tests:realCard                          # no reader: every test reports "not run"
./gradlew :tests:realCard -PrealCardList           # enumerate the suite as skipped
./gradlew :tests:realCard -PrealCard="ACS ACR"     # PC/SC terminal name
```

The suite never runs in CI and is not attached to `check` (`check` still builds both test CAPs
and the suite classes). Properties: `-PrealCard=<reader>` (required to run),
`-PrealCard{Cap,MemCap,ProbeCap}=<path>` (prebuilt CAPs; defaults are the in-tree builds,
sha256 printed), `-Pqntx.gp=<path>` (`gp` wrapper), `-PrealCardOut=<dir>` (evidence,
default `tests/build/realcard`), `-PrealCardKeep` (keep installed packages),
`-PrealCardDifferential=<n>` (default 1,000), `-PrealCardRng=<bytes>` (default 1 MiB). The
flow, tearing and NVM-endurance rows report `unavailable` until their hardware requirements
exist (see §10); the card identity policy of `REALCARD.md` refuses anything that is not a
development card before the first install.

Every run leaves its evidence under `$realCardOut`: `apdu.log`, `gp-*.log`, `cplc.bin` and the
per-row `*.json`/`*.bin` reports (`init.json`, `install-journal.json`, `commit-capacity.json`,
`rng.json`, `memory.json`, `timing.json`/`timing.md`, `signatures.json`,
`primitives.json`/`primitives.md`), which feed the batch
record of §10.

No hardware has been run in this repository yet: the suite exists, compiles and lists every
test as "not run" without a reader.

### Timings (measured on J3R180 (card A))

Filled from `timing.md` of the first card run; the suite writes the table there.

## Tools (`qntx-card`)

`./gradlew :tools:installDist` builds the batch provisioning CLI at
`tools/build/install/qntx-card/bin/qntx-card` (also in the `qntx-card-<version>.zip` release
artifact). Every subcommand takes exactly one transport — `--sim host:port` for a `card-sim.jar`
TCP endpoint or `--reader <name>` for a PC/SC terminal — and opens a GlobalPlatform secure
channel with `--scp 03` or `--scp 02-55`. Secrets come from the environment only, never
arguments or output: `QNTX_ISD_KEY` (the card's ISD key, hex) for every subcommand and
`QNTX_HSM_PIN` for `personalise --hsm-config`.

- `registry` prints the card's issuer security domain, applications and load files as sorted
  `<ISD|SSD|APP|PKG> <AID> <lifecycle>` lines — the baseline file format the other subcommands
  diff against. An empty card prints exactly `ISD A000000151000000 01`.
- `install --cap <file> --cap-sha256 <hex> --scp <s> --baseline <file> --ndef <hex>` checks the
  CAP hash before touching the card, loads it and installs both applets (the NDEF message is
  1–100 bytes, hex), asserts the registry is baseline + the package and the two
  applications, then drives the §4.3 initialisation (`SELECT` + `GET_IDENTITY` until not
  `6283`, bound 16) and prints each step's duration.
- `personalise --scp <s> --baseline <file> --batch-record <file> --test-ca <file> |
  --hsm-config <file> --hsm-key <label>` runs §14.3 steps 4–10: it accepts an uninitialised
  card and drives initialisation first, then CPLC and identity, certificate
  issued by the CA (`--test-ca` accepts only the pinned ca1/ca2 test anchors; HSM mode accepts
  only production anchors), the read-back short ID to type, and independent replacement ISD keys.
  Each card appends one JSON line
  `{"cardId":"…","shortId":"…","cplc":"…","cert":"…","loadFileHash":"…"}` to the batch record.
- `shell --test-anchors` opens a session REPL (`open`, `verify`, `inner`, `apdu`) for
  development against `--sim`.

Example against a fresh simulator:

```bash
java -jar sim/build/libs/card-sim.jar --cards 1 --state empty &
export QNTX_ISD_KEY=404142434445464748494a4b4c4d4e4f
qntx-card registry --sim 127.0.0.1:35963 > baseline.txt      # ISD A000000151000000 01
qntx-card install  --sim 127.0.0.1:35963 --cap applet/build/cap/qntx-card.cap \
                   --cap-sha256 $(sha256sum applet/build/cap/qntx-card.cap | cut -d' ' -f1) \
                   --scp 03 --baseline baseline.txt --ndef D1010C5402656E7178742063617264
qntx-card personalise --sim 127.0.0.1:35963 --scp 03 --baseline baseline.txt \
                      --batch-record batch.jsonl --test-ca spec/vectors/cert.json
```

## Budgets

Measured on this tree (architecture §14.7 R6; the CI build job reports them again):

- **CAP**: `qntx-card.cap` is 132,086 B; the load-file components inside it
  (`org/qntx/card/javacard/*.cap`) total 27,458 B.
- **Transient**: the simulator's memory report ends `total 2568 / 3990 (budget 3390)` — 2,568 B
  of the 3,990 B JCAlgTest pool, inside the §5.1 acceptance budget of 3,390 B.
- **Persistent**: ≈ 6.6 KB of objects and arrays plus the ≈ 27 KB CAP against the 157,524 B
  J3R180 NVM (architecture §5.1). That is the architecture estimate — the simulator accounts
  transient bytes only, so it is not re-measured here.
- **Card time** (protocol §16.6, computed from unit costs measured on development card A; full
  commands not yet timed — the real-card `Timing` row does that):

| Command | ms | bytes up | bytes down |
| --- | ---: | ---: | ---: |
| SELECT | 2 | 13 | 2 |
| OPEN | 160 | 71 | 228 |
| STATUS | 17 | 30 | 26 |
| VERIFY | 124 | 62 | 106 |
| WAIT | 965 | 30 | 26 |
| CREATE | 106 | 126 | 106 |
| CHANGE | 27 | 62 | 26 |
| ERASE | 25 | 30 | 26 |
| OFFER | 137 | 30 | 154 |
| OFFER_VALID | 78 | 30 | 154 |
| EXPORT0 | 424 | 254 | 154 |
| EXPORT1 | 21 | 62 | 202 |
| IMPORT0 | 471 | 254 | 26 |
| IMPORT1 | 103 | 206 | 106 |
| PUBLIC_KEY secp256k1 depth 3 cold | 202 | 46 | 90 |
| PUBLIC_KEY ed25519 depth 4 cold | 217 | 46 | 90 |
| SIGN_ECDSA depth 5 cold | 411 | 78 | 90 |
| SIGN_BIP340 depth 5 cold | 724 | 110 | 90 |
| SIGN_ED25519 BEGIN depth 4 cold | 430 | 46 | 90 |
| SIGN_ED25519 UPDATE 236 B | 21 | 254 | 26 |
| SIGN_ED25519 FINISH | 486 | 30 | 58 |

## Releases

Tag `v<version>` (the `version` in `gradle.properties`) runs `release.yml`, which builds from a
clean checkout, runs the full gate, produces `build/dist/` and publishes it as a GitHub release:

- `qntx-card.cap` — the one CAP (package `F0716E747800`)
- `card-sim.jar` — the simulator
- `vectors.zip` — `spec/vectors` plus its MIT/Apache-2.0 licenses
- `qntx-card-<version>.zip` — the `qntx-card` tool distribution
- `qntx-card.cdx.json` — the aggregate CycloneDX SBOM
- `SHA256SUMS` — `<sha256>  <name>` for every other file

Verify a downloaded release:

```bash
cd dist
sha256sum -c SHA256SUMS
gh attestation verify qntx-card.cap --repo qntx/wallet-applet
```

qntx/wallet CI pins a release tag and the `card-sim.jar` SHA-256 from `SHA256SUMS`; the
simulator is not hardware evidence.

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
