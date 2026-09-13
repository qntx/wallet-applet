# Contributing to meowl-applet

Thanks for your interest. This applet is the trust anchor of every meowl.social hardware wallet — it runs on a tamper-resistant secure element holding custodial keys, so contributions are reviewed strictly. Read [`SECURITY.md`](./SECURITY.md) for the threat model before proposing changes that touch sensitive code paths.

## Prerequisites

- **JDK 25** on `PATH` — Temurin 25 LTS recommended. Gradle's toolchain auto-provisions via foojay if missing, but having a system JDK avoids the first-run download.
- **Git** with submodule support — the Oracle JavaCard SDK ships as a submodule under `sdks/`.
- A **PC/SC** reader (built-in on Windows/macOS; install `pcscd` on Linux) only if you want to install onto a physical card.

### Behind a proxy

The JVM does **not** pick up Windows or shell proxy settings automatically. Add the following to `~/.gradle/gradle.properties` (or pass via `GRADLE_OPTS`) so the wrapper, dependency resolution, and the Spotless plugin can reach `services.gradle.org` and Maven Central:

```properties
systemProp.https.proxyHost=127.0.0.1
systemProp.https.proxyPort=7897
systemProp.http.proxyHost=127.0.0.1
systemProp.http.proxyPort=7897
```

## Quick start

```bash
git clone --recurse-submodules https://github.com/qntx/meowl-applet.git
cd meowl-applet
./gradlew spotlessCheck :wallet:buildCap :tests:test
```

The CAP file lands in `wallet/build/cap/meowl-wallet.cap`.

## Project layout

```text
.
├── applet/   # JavaCard source — compiled into the CAP
├── tests/    # JCardSim integration tests (JUnit 6)
├── tools/    # Host-side CLI + GlobalPlatformPro wrapper
├── sdks/     # ← submodule: Oracle JavaCard SDKs
├── gradle/   # Wrapper + libs.versions.toml (version catalog)
├── config/   # Spotless license header template
└── .github/  # GitHub Actions CI + Dependabot
```

## Common tasks

```bash
# Format Java and Kotlin Gradle files
./gradlew spotlessApply

# Build the CAP file
./gradlew :wallet:buildCap

# Run the JCardSim test suite (no physical card required)
./gradlew :tests:test

# Install onto a connected card using GlobalPlatformPro defaults
./gradlew :tools:installCap

# Send an APDU through apdu4j to the connected card
./gradlew :tools:run --args="80010000"

# Pass arbitrary arguments through to GlobalPlatformPro
./gradlew :tools:gp -Pargs="--list"
```

## Configuration knobs

Applet identifiers and the CAP package version are overridable via Gradle properties (`-Pwallet.xxx=...`):

| Property | Default | Purpose |
| --- | --- | --- |
| `wallet.packageAid` | `F06D656F776C` | CAP package AID (hex) |
| `wallet.appletAid` | `F06D656F776C01` | Applet instance AID |
| `wallet.class` | `social.meowl.wallet.WalletApplet` | Applet class FQN |
| `wallet.packageName` | `social.meowl.wallet` | Java package |
| `wallet.capVersion` | `0.1` | CAP package version (MAJOR.MINOR) |

## Workflow

1. Open an issue first for non-trivial changes.
2. Branch from `main` using a Conventional-Commits-style prefix: `git checkout -b feat/<topic>` or `fix/<topic>`.
3. Keep the diff focused — one logical change per PR.
4. Run the full local pipeline before pushing: `./gradlew spotlessApply :wallet:buildCap :tests:test`.
5. Commit using **Conventional Commits** in English (subject ≤ 72 chars):

   ```text
   feat(wallet): add PIN unblock flow
   fix(tests): correct expected SW for unknown CLA
   docs: explain target SDK choice
   ```

6. Open a PR against `main`. CI is the source of truth — `commitlint`, Spotless, the CAP build, and the JCardSim test suite must all pass.

## Coding rules

- **Java source/target: 1.8** in `wallet/` (JCDK v26.0 converter limit). `var` is permitted only in `tools/` and `tests/`.
- **No `String` in applet code paths** — concatenation allocates and the card has no GC. Use `byte[]` plus `Util.arrayCopyNonAtomic`.
- **No floating point**, **no multi-dimensional arrays**, **no threads**.
- Sensitive data must live in `JCSystem.makeTransientByteArray(...)` and be wiped after use.
- All write paths to persistent state must be wrapped in `JCSystem.beginTransaction()` / `commitTransaction()`.
- Run `./gradlew spotlessApply` before pushing — CI rejects unformatted code.

## Adding a new APDU

1. Reserve an `INS` constant in `WalletApplet`.
2. Add a private handler and dispatch it from `process(...)`.
3. Add a JCardSim test under `tests/` covering both the success path and the relevant failure status words.
4. Document the APDU in `notes/specs/protocol.md` (create the file if it does not yet exist).
5. If the APDU exposes secrets, justify the secure-channel choice in the PR description.
