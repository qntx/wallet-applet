# Security policy

## Reporting a vulnerability

Do not open a public issue. Report privately through GitHub's
[private vulnerability reporting](https://github.com/qntx/wallet-applet/security/advisories/new)
with the command sequence (or a simulator test under `tests/`), the expected and the observed
behaviour, and whether it reproduces in the simulator, on a card, or both.

## Scope

The applet implements `spec/protocol.md`; a deviation from the specification is a vulnerability
when it weakens a property the specification states. The protocol is not yet frozen: until the
external audit (`spec/protocol.md` §17) no card built from this repository is a production card.
Shipped cards cannot be updated, so a defect found after the freeze is handled by the host
(`spec/protocol.md` §17).

What the card cannot protect against is part of the design and not a vulnerability: a compromised
wallet kernel that asks the card to sign a different digest after the user unlocked it; a thief who
holds the card and knows the access code; a malicious personaliser; attacks on the chip beyond its
certification.

## Supply chain

The CAP build is reproducible (fixed timestamps, sorted inputs; CI builds it twice and compares the
SHA-256). Dependency versions are pinned in `gradle/libs.versions.toml` and
`spec/vectors/gen/ts/bun.lock`; GitHub Actions are pinned by commit.

The Java Card converter comes from the git submodule `martinpaljak/oracle_javacard_sdks`
pinned by commit (SHA-1), and every file of the `jc320v26.0_kit` the converter and its Ant
task use is verified against the SHA-256 recorded in `gradle/jcdk-sha256.txt` before any CAP
converts; the hashes were recorded at first use from that commit (trust on first use), so a
substituted or tampered toolchain file fails the build, but the pin cannot detect a toolchain
that was wrong at the pinned commit. For the same reason the reproducible-build check compares
two builds made with the *same* toolchain — it does not detect a substituted toolchain.
Every Gradle dependency hash is trust-on-first-use and signatures are not verified; the JDK
(`actions/setup-java` in CI, toolchain resolution locally) is not verified by hash. The REUSE
lint image in CI is pinned by multi-arch digest (`fsfe/reuse:6.3.0@sha256:2748d04c…`).

Every Gradle artifact resolved from Maven Central, the Gradle plugin portal or the third-party
repository `mvn.javacard.pro` (which serves the `com.github.martinpaljak` group: ant-javacard,
GlobalPlatformPro and apdu4j) is checked against the SHA-256 recorded in
`gradle/verification-metadata.xml`; a missing or different checksum fails the build in CI and in
release. The hashes were recorded at first resolution (trust on first use); the ant-javacard and
GlobalPlatformPro artifacts were additionally cross-checked by direct download against the upstream
GitHub release assets of `martinpaljak/ant-javacard` and `martinpaljak/GlobalPlatformPro`: the
assets are fat executable jars, different bytes than the thin Maven artifacts, but every class the
thin jar contains is byte-identical inside them. Signatures are not verified. The Gradle wrapper is
pinned by `distributionSha256Sum`, the JDK comes from `actions/setup-java` in CI and release, and
release builds disable toolchain auto-download.

The real-card record (`realcard/<cap-sha256>.txt`, gated by `:tests:checkRealCardRecord` in
`release.yml`) is a maintainer assertion: the suite generates it from the files of one bound
run — the `tests/`, `applet/`, `host/`, `sim/` and `buildSrc/` trees must be clean and every
input stamped by that run. The checker only establishes that the record is consistent with
this build — the CAP hash, the five git trees, the commit, the run parameters and the suite
shape; it cannot establish that a card was used, and nothing signs the record. The `main`
ruleset (`.github/rulesets/`) requires a pull request and green CI but no second approval, so
nothing but the maintainer's review stands behind the commit that adds a record.
