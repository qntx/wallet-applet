# AGENTS.md — qntx/wallet-applet

The qntx card: a Java Card 3.0.5 applet (one CAP, package `org.qntx.card`) that holds an HD
wallet seed and signs for qntx/wallet. `spec/protocol.md` is the single normative specification;
code and spec change in the same pull request, and a disagreement between them is a bug in both.

## Invariants

1. No command outputs a private key, the seed or an access code. The only key-material output is
   the encrypted transfer to a member card (`spec/protocol.md` §11).
2. The seed is stored only encrypted under keys derived from the access code; it is decrypted
   only after a matching MAC and the stored fingerprint check, after the failure count was
   committed and read back.
3. Every persistent change is inside the transaction the spec names for it; commits precede the
   comparison, output or signature they guard.
4. `ERASE` requires a verified session. In an unverified session a `LOADED` card writes only
   what `spec/protocol.md` §16.1 item 7 allows.
5. Every signature is self-verified before output.
6. Security-relevant flags use the coded constants of `Const`; never `boolean` or `0/1`.
7. No allocation after install; no recursion; no `String`, `int`, floating point or
   multi-dimensional arrays in `applet`; every secret is in transient memory and wiped on all
   paths; comparisons of secrets are constant time.
8. Only standard Java Card 3.0.5 APIs listed in `spec/protocol.md` §3; no vendor APIs.
9. Tests come from the spec and independent oracles (official vectors, BouncyCastle, noble),
   never from the applet's own output.
10. The protocol is frozen after the external audit; afterwards changes ship only as a new
    protocol version with a new instance AID.

## Commands

- `./gradlew build` — CAP, all simulator tests, vectors, memory report.
- `./gradlew :tests:pitest` — mutation tests on gate classes.
- `./gradlew :tests:realCard -PrealCard="<reader>"` — real-card suite (never in CI).
- `./gradlew :sim:shadowJar` — `card-sim.jar`.
- `./gradlew clean --write-verification-metadata sha256 build :tests:pitest spotlessCheck
  cyclonedxBom dist :sim:shadowJar :tools:installDist :tests:realCardClasses
  :tests:admissionProbeCap :tests:memProbeCap :tests:realCard :tests:generateVectors` —
  regenerate `gradle/verification-metadata.xml` after any dependency change; `clean` forces the
  lazily-resolved configurations; review the diff.

## Conventions

English everywhere; Conventional Commits (subject ≤ 50 chars, imperative); comments explain why
and cite spec sections; no decorative separator comments. Applet code AGPL-3.0-or-later;
`spec/**` MIT OR Apache-2.0; REUSE headers on every file.
