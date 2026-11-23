<!-- SPDX-FileCopyrightText: 2026 QuantX -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Real-card lane — card identity policy

The real-card suite (`tests/src/realCard`, `docs/architecture.md` §10) installs test packages
and writes persistent memory. It must only ever run against a **development card**, never a
personalised or production-batch card. `RealCard` enforces this policy at connect and before
the first `gp --install`; a card that cannot be identified stops the whole run.

## Development card A

| Card | ATR | CPLC fabricator | CPLC IC type | Silicon |
| --- | --- | --- | --- | --- |
| A | `3B8580018073C821100E` | `4790` | `D321` | JCOP4 P71 (`J3R…` build string) |

A card is accepted only when **all** of these hold:

1. its ATR is `RealCard.EXPECTED_ATR` (`3B8580018073C821100E`), checked on connect and after
   every power cycle;
2. the ISD's CPLC (`GET DATA 9F7F`) names fabricator `4790` and IC type `D321` — stored as
   `cplc.bin` for the batch record;
3. the GP wrapper's `--info` output carries the JCOP IDENTIFY build string (`J3R…`).

## Rules

1. Never silently extend the identity checks: a new development card means editing this file
   and `RealCard.EXPECTED_ATR` / `verifySilicon` in the same commit.
2. The NVM-endurance row additionally requires a sacrificial card; it stays `unavailable`
   until one exists.
3. `-PrealCardKeep` keeps the installed test packages for inspection; without it the suite
   deletes the qntx package/instance AIDs in `@AfterAll` (the memprobe and probe CAPs share the
   production package/instance AIDs — the delete removes whatever test CAP is installed, never
   a released load file).
