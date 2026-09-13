# Security Policy

## Supported versions

Only the latest tagged release of `meowl-applet` receives security fixes. Because this applet is the trust anchor of the meowl.social hardware wallet, we strongly recommend keeping cards up to date with the most recent CAP build.

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

Email `security@meowl.social` with:

- A clear description of the issue — the APDU sequence, expected vs. actual behaviour.
- A minimal reproducer if possible: a JCardSim test under `tests/`, or a host-side script.
- Whether the issue is exploitable on a physical card or only in the simulator.
- Your preferred credit (GitHub handle, real name, or anonymous).

We acknowledge reports within **72 hours** and aim to ship a fix within **30 days** for severity High and above. Coordinated disclosure is appreciated; we will publish an advisory and credit you once a patched release is available.

## Threat model

The applet is the only trusted component on the card and **must** assume that:

1. The host (USB / NFC initiator) is hostile.
2. Power-analysis and fault-injection attacks are realistic on commodity cards.
3. APDU transcripts may be replayed, truncated, or selectively dropped.

## Mitigations

The codebase and release process enforce:

- `OwnerPIN` with bounded retries — no plaintext PIN comparison anywhere in the applet.
- Constant-time comparisons for every sensitive byte sequence.
- All write paths to persistent state wrapped in `JCSystem.beginTransaction()` / `commitTransaction()`.
- Secure-channel (SCP-class) handshake required for any command that exposes secrets.
- Verifiable supply chain — every release publishes a SLSA Level 3 build provenance attestation (Sigstore keyless OIDC), a CycloneDX 1.6 SBOM, and `sha256sums.txt`. Verify with:

  ```bash
  sha256sum -c sha256sums.txt
  gh attestation verify meowl-wallet.cap --repo qntx/meowl-applet
  ```

## Operating assumptions

The applet is correct only under the following platform assumptions; deployments that diverge from them must re-audit the affected paths:

- **Single logical channel.** The applet assumes the GlobalPlatform-defined basic-channel model: at any time exactly one channel holds the applet selected and `process(APDU)` is reentrant only across distinct `select()` boundaries. The `LifecycleState`, `SecureChannel` and `PinManager` state machines are not declared `volatile` and would race under simultaneous logical channels. JC 3.0.5 host platforms typically do not multiplex this applet across channels; deployments that do MUST add explicit cross-channel coordination.
- **Silicon-validated ECDH.** As required by [the protocol spec](./notes/specs/protocol.md) §6, the underlying `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` implementation is trusted to reject peer pubkeys that are not on the secp256k1 curve. Deployments MUST add an admission check (e.g. JCAlgTest probe) that exercises an off-curve point and verifies a `6FB2` response.
- **TRNG availability.** ECDSA nonces, Schnorr aux randomness and `GENERATE_SEED` rely on `RandomData.ALG_KEYGENERATION` falling back to `ALG_TRNG`. Cards whose `RandomData` is software-only (DRBG seeded by power-on counter) MUST NOT be qualified for production.

## Hardware lifecycle considerations

- **EEPROM endurance.** The persistent `bip32_scalarKey` slot is rewritten on every BIP-32 derivation that crosses a non-cached node (and on Schnorr/ECDSA leaf-key materialisation). Mainstream silicon rates this at 100 k–1 M erase cycles per row; at ≈10 derivations per signing action and the typical wallet's signing cadence, the 1 M-cycle floor exceeds expected card lifetime by ≥3 orders of magnitude. Deployments with abnormally high signing throughput (automated treasury bots, fast-channel Lightning nodes) SHOULD monitor for derivation latency increases that indicate the silicon's wear-levelling running out of margin; the applet itself has no in-band wear telemetry.
- **Reset-to-factory completeness.** A full reset-to-factory wipes the seed, PIN/PUK, BIP-32/SLIP-10 derived material and the manufacturer-issued certificate but preserves the `authentikey` (so a re-personalised card retains a stable cryptographic identity). Deployments that need to retire a card entirely MUST physically destroy it; software wipe alone does not satisfy NIST 800-88 destruction.

## Build-time licensing

- **Oracle JavaCard SDK.** The `sdks/` submodule (vendored from `martinpaljak/oracle_javacard_sdks`) ships the Oracle Binary Code License-restricted JCDK toolchain. It is used only at build time and is NOT distributed inside the released CAP file; the CAP contains no Oracle-licensed bytecode. Re-distributors of source builds MUST accept Oracle's BCL terms separately. Re-distributors of binary CAP artifacts incur no additional Oracle obligation.
- **AGPL-3.0-or-later source attribution.** Every applet source file is solely held by the meowl.social contributors under AGPL-3.0-or-later; [`BigNat`](wallet/src/main/java/social/meowl/wallet/BigNat.java) was clean-room rewritten in commit `c3352dc`, retiring the earlier Toporin Satochip / Radboud OV-chip 2.0 GPL-2.0-or-later upstream chain. The audit conclusion lives in [`ADR-004`](docs/adr/ADR-004-bignat-clean-room-rewrite.md). The release SBOM (`*.cdx.json`) enumerates every transitive build-time dependency with its declared SPDX identifier.
