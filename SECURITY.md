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
