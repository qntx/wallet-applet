// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0

// TypeScript generator (noble) of the files of spec/protocol.md §18. Usage: `bun generate.ts <outDir>`.
// Each implementation stage adds the files it owns to FILES; selftest.json is the harness's own
// agreement check and is never committed. Output is canonical: JSON.stringify(value, null, 2) + "\n".
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { accessDoc } from './access.ts';
import { bip340Doc } from './bip340.ts';
import { certDoc } from './cert.ts';
import { derivationDoc } from './derivation.ts';
import { ecdsaDoc } from './ecdsa.ts';
import { ed25519Doc } from './ed25519.ts';
import { kdfDoc } from './kdf.ts';
import { ndefDoc } from './ndef.ts';
import { recordDoc } from './record.ts';
import { selftest } from './selftest.ts';
import { sessionDoc } from './session.ts';
import { transferDoc } from './transfer.ts';
import { wrapDoc } from './wrap.ts';

const FILES: Record<string, () => unknown> = {
  'selftest.json': selftest,
  'kdf.json': kdfDoc,
  'cert.json': certDoc,
  'session.json': sessionDoc,
  'record.json': recordDoc,
  'access.json': accessDoc,
  'wrap.json': wrapDoc,
  'derivation.json': derivationDoc,
  'ecdsa.json': ecdsaDoc,
  'bip340.json': bip340Doc,
  'ed25519.json': ed25519Doc,
  'transfer.json': transferDoc,
  'ndef.json': ndefDoc,
};

const out = process.argv[2];
if (!out) throw new Error('usage: bun generate.ts <outDir>');
mkdirSync(out, { recursive: true });
for (const [name, build] of Object.entries(FILES)) {
  writeFileSync(join(out, name), `${JSON.stringify(build(), null, 2)}\n`, 'ascii');
}
