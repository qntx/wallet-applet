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
frozen**: it freezes only after the external audit (`spec/protocol.md` §17). The real-card
suite below has run once on development card A (J3R180 hardware reporting JCOP build
`J3R3510236310400`); its multi-card flow, tearing and NVM-endurance rows report
`unavailable` until the hardware they need exists (a second card, a programmable reader, a
sacrificial card), and fault injection on silicon has not been done.

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
card A (J3R180 hardware reporting JCOP build `J3R3510236310400`).

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
`-PrealCardDifferential=<n>` (default 1,000), `-PrealCardSequences=<n>` (admission 6's RNG
sequences of 10⁶ bits each; default 80 = the SP 800-22 §4.2 decision-rule size, `1` runs the
single-sequence p-value checks). The
flow, tearing and NVM-endurance rows report `unavailable` until their hardware requirements
exist (see §10); the card identity policy of `REALCARD.md` refuses anything that is not a
development card before the first install.

Every run leaves its evidence under `$realCardOut`: `apdu.log`, `gp-*.log`, `cplc.bin` and the
per-row `*.json`/`*.bin` reports (`init.json`, `install-journal.json`, `commit-capacity.json`,
`rng.json`, `memory.json`, `timing.json`/`timing.md`, `signatures.json`,
`primitives.json`/`primitives.md`), which feed the batch
record of §10. A run with a reader also writes `record.txt` (the `realCardRecord` task
finalizes `realCard`, and only on a clean `tests/` + `applet/` + `host/` + `sim/` +
`buildSrc/` tree with every input file stamped by that run): the `qntx-card real-card
record 3` format — CAP sha256, the commit, the five git trees, the effective run
parameters, date and reader, ATR/CPLC/IDENTIFY, totals and one `PASS`/`SKIP` line per
`suite.txt` class (SKIP only for the three rows hardware cannot host) — then the timing
table. It is copied to
[`realcard/<cap-sha256>.txt`](realcard/) and committed before a release tag —
`release.yml` refuses the tag without it.

Without `-PrealCard` every test still skips as "not run"; the table below is the suite's own
`timing.md` of the run recorded in
[`realcard/39cc8dac35d46327c07b9df03c75dbbb4c59d3cc8957c987c9fdd5246ea9a436.txt`](realcard/39cc8dac35d46327c07b9df03c75dbbb4c59d3cc8957c987c9fdd5246ea9a436.txt)
(2026-11-25 UTC, ACS ACR1552 1S CL Reader PICC, contactless; CAP sha256
`39cc8dac35d46327c07b9df03c75dbbb4c59d3cc8957c987c9fdd5246ea9a436`). EXPORT/IMPORT
are timed against a host-emulated member card (`EmuMember`, test CA) — only one card exists,
so the peer's crypto runs on the host, off the card's clock.

### Timings (measured on card A — J3R180 hardware reporting JCOP build `J3R3510236310400`)

| command | n | min | median | p95 | max | bound ms | ≤bound |
| --- | --- | --- | --- | --- | --- | --- | --- |
| INIT_STEP | 7 | 29.4 | 59.8 | 148.3 | 148.3 | 500 | yes |
| GET_IDENTITY | 1 | 29.4 | 29.4 | 29.4 | 29.4 | 1500 | yes |
| PERSONALIZE | 1 | 602.8 | 602.8 | 602.8 | 602.8 | 1500 | yes |
| OPEN | 20 | 315.0 | 317.3 | 317.8 | 317.9 | 1500 | yes |
| VERIFY wrong | 20 | 79.9 | 80.1 | 80.2 | 80.7 | 1500 | yes |
| VERIFY right | 20 | 214.9 | 215.4 | 215.5 | 217.9 | 1500 | yes |
| STATUS | 20 | 33.1 | 33.2 | 33.4 | 33.9 | 1500 | yes |
| PUBLIC_KEY secp depth3 cold | 20 | 235.7 | 237.3 | 237.5 | 237.6 | 1500 | yes |
| PUBLIC_KEY secp depth3 warm | 20 | 124.2 | 124.5 | 125.0 | 125.0 | 1500 | yes |
| PUBLIC_KEY secp depth5 cold | 20 | 411.6 | 412.1 | 412.3 | 412.4 | 1500 | yes |
| PUBLIC_KEY secp depth5 warm | 20 | 125.3 | 125.6 | 125.8 | 125.9 | 1500 | yes |
| PUBLIC_KEY ed25519 depth3 cold | 20 | 211.7 | 211.9 | 212.1 | 212.1 | 1500 | yes |
| PUBLIC_KEY ed25519 depth3 warm | 20 | 150.0 | 150.3 | 150.5 | 150.5 | 1500 | yes |
| PUBLIC_KEY ed25519 depth5 cold | 20 | 253.8 | 254.1 | 254.2 | 254.6 | 1500 | yes |
| PUBLIC_KEY ed25519 depth5 warm | 20 | 151.0 | 151.3 | 151.6 | 151.8 | 1500 | yes |
| SIGN_ECDSA depth5 cold | 20 | 603.1 | 603.7 | 606.7 | 609.5 | 1500 | yes |
| SIGN_ECDSA depth5 warm | 20 | 315.1 | 315.8 | 316.1 | 318.4 | 1500 | yes |
| SIGN_BIP340 untweaked cold | 20 | 1008.1 | 1009.9 | 1012.4 | 1012.4 | 1500 | yes |
| SIGN_BIP340 untweaked warm | 20 | 722.9 | 727.0 | 727.7 | 727.7 | 1500 | yes |
| SIGN_BIP340 tweak cold | 20 | 1059.3 | 1060.0 | 1060.5 | 1060.9 | 1500 | yes |
| SIGN_BIP340 tweak warm | 20 | 769.7 | 770.1 | 770.9 | 771.0 | 1500 | yes |
| SIGN_ED25519 begin cold | 60 | 495.0 | 498.4 | 498.7 | 498.8 | 1500 | yes |
| SIGN_ED25519 finish cold | 60 | 669.0 | 670.3 | 673.8 | 674.2 | 1500 | yes |
| SIGN_ED25519 64B total cold | 20 | 1170.8 | 1171.9 | 1172.8 | 1173.0 | — | — |
| SIGN_ED25519 begin warm | 60 | 415.6 | 416.1 | 416.5 | 417.0 | 1500 | yes |
| SIGN_ED25519 finish warm | 60 | 668.8 | 670.3 | 670.9 | 671.2 | 1500 | yes |
| SIGN_ED25519 64B total warm | 20 | 1085.7 | 1087.0 | 1087.5 | 1087.5 | — | — |
| SIGN_ED25519 update | 880 | 43.5 | 46.0 | 46.2 | 46.9 | 1500 | yes |
| SIGN_ED25519 1232B total cold | 20 | 1393.1 | 1396.9 | 1397.5 | 1398.1 | — | — |
| SIGN_ED25519 1232B total warm | 20 | 1313.6 | 1314.4 | 1314.8 | 1315.1 | — | — |
| SIGN_ED25519 4032B total cold | 20 | 1942.4 | 1943.6 | 1944.8 | 1946.4 | — | — |
| SIGN_ED25519 4032B total warm | 20 | 1859.9 | 1861.5 | 1863.1 | 1864.1 | — | — |
| WAIT | 20 | 968.4 | 968.6 | 968.8 | 968.8 | 1500 | yes |
| CREATE P1=0 | 20 | 207.0 | 207.2 | 207.6 | 209.8 | 1500 | yes |
| ERASE | 40 | 54.0 | 54.2 | 54.3 | 54.4 | 1500 | yes |
| CREATE P1=1 | 20 | 202.2 | 202.4 | 202.5 | 202.5 | 1500 | yes |
| OFFER offer=NONE | 1 | 216.7 | 216.7 | 216.7 | 216.7 | 1500 | yes |
| OFFER offer=VALID | 20 | 162.8 | 163.2 | 163.4 | 163.4 | 1500 | yes |
| EXPORT P1=0 | 10 | 1059.6 | 1060.3 | 1064.4 | 1064.4 | 1500 | yes |
| EXPORT P1=1 | 10 | 60.7 | 60.8 | 60.9 | 60.9 | 1500 | yes |
| IMPORT P1=0 | 10 | 1128.3 | 1128.7 | 1131.3 | 1131.3 | 1500 | yes |
| IMPORT P1=1 | 10 | 255.0 | 255.2 | 255.6 | 255.6 | 1500 | yes |
| SELECT | 20 | 31.0 | 31.0 | 31.1 | 62.6 | 1500 | yes |
| SELECT after reset | 20 | 31.1 | 31.3 | 31.4 | 31.6 | 1500 | yes |

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

- **CAP**: `qntx-card.cap` is 135,784 B; the load-file components inside it
  (`org/qntx/card/javacard/*.cap`) total 28,273 B.
- **Transient**: the simulator's memory report ends `total 2780 / 3990 (budget 3390)` — 2,780 B
  of the 3,990 B JCAlgTest pool, inside the §5.1 acceptance budget of 3,390 B.
- **Persistent**: ≈ 7.1 KB of objects and arrays plus the ≈ 28 KB CAP against the 157,524 B
  NVM of card A's silicon (architecture §5.1). That is the architecture estimate — the
  simulator accounts transient bytes only, so it is not re-measured here.
- **Card time**: measured on card A — see the Timings table above and `spec/protocol.md`
  §16.6 (EXPORT/IMPORT are measured against a host-emulated member card).

## Hosts

- Reader transceive timeout must be at least 5,000 ms (§16.6); slower values drop WAIT replies.
- During a `VERIFY` when `STATUS` reports `tries = 1`, the card must stay in the field until the
  response arrives: T-FAIL is committed before the comparison, so losing the field mid-command
  erases the wallet at the next `VERIFY` even when the code was right (§9.5).

## Releases

Tag `v<version>` (the `version` in `gradle.properties`) runs `release.yml`. First the `gate`
job calls `ci.yml` as a workflow — REUSE lint, Spotless, build + all tests, the noble
differential, reproducible CAP and card-sim, PIT, the SBOM, `dist` and both vector generators
must pass on the tagged commit. Then the `release` job checks the tag equals the version,
refuses the tag unless a committed real-card record
[`realcard/<cap-sha256>.txt`](realcard/) passes `./gradlew :tests:checkRealCardRecord`:
the record's `cap` is the released CAP's sha256, its `commit` an ancestor of the tag and
its five `tree-*` lines the tagged `tests`/`applet`/`host`/`sim`/`buildSrc` trees, its
`params` the release parameters, `failed 0`, every `suite.txt` class PASS or SKIP with
SKIP only for `Flow`/`Nvm`/`Tearing`, and `InstallRealCardTest` PASS. It rebuilds `build/dist/` with toolchain auto-download off (the
JDK comes only from setup-java), proves the rebuilt CAP is byte-identical to the released one,
verifies `SHA256SUMS`, attests build provenance and publishes a GitHub release:

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
