// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0

// transfer.json: the multi-card wallet transfer vectors of spec/protocol.md §9.12–9.14 and §11 —
// three deterministic cards, the decompress table of §10.5, two wallets (one imported, one
// generated), five transfers, the rejected offer/export checks of §9.13–9.14 and the rejected
// payload checks of §9.14 P1 = 0x01. Mirrors gen/java/.../TransferDoc.java; every claim is
// asserted against noble while it is written.
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE } from '@noble/curves/utils.js';
import { mod, pow } from '@noble/curves/abstract/modular.js';
import {
  aesCbc,
  bytesToHex,
  cmacOf,
  compress,
  concatBytes,
  det,
  detLen,
  detScalar,
  kdf,
  m2pad,
  N,
  publicKey,
  scalarBytes,
  sha256,
  sha512,
  sign,
  utf8ToBytes,
  verify,
} from './lib.ts';
import { cardId, CA1, CA2, identityPrivate, issue } from './cards.ts';
import { bip32Derive } from './derivation.ts';

const LABEL_OFFER = utf8ToBytes('qntx-card/v1/offer');
const LABEL_EXPORT = utf8ToBytes('qntx-card/v1/export');
const LABEL_KDF = utf8ToBytes('qntx-card/v1/kdf-transfer');
const LABEL_SEED = utf8ToBytes('qntx-card/v1/seed');

const P: bigint = secp256k1.Point.CURVE().p;
const LEGENDRE = (P - 1n) >> 1n;
const SQRT = (P + 1n) >> 2n;
const ZEROS = new Uint8Array(16);

const assert = (cond: boolean, what: string): void => {
  if (!cond) throw new Error(`transfer.json assertion failed: ${what}`);
};

interface Card {
  name: string;
  privateKey: bigint;
  a: Uint8Array;
  uncompressed: Uint8Array;
  id: Uint8Array;
  cert: Uint8Array;
}

const cardOf = (name: string, oddY: boolean): Card => {
  const d = identityPrivate(`transfer/${name}`, oddY);
  const uncompressed = publicKey(d);
  const a = compress(uncompressed);
  const cert = issue(CA1, a);
  return { name, privateKey: d, a, uncompressed, id: cardId(a), cert };
};

interface Wallet {
  name: string;
  creator: string;
  create: unknown;
  seed: Uint8Array;
  origin: number;
  memberIds: Uint8Array;
  masterPublicKey: Uint8Array;
}

/** c ‖ IDs, the stored members block. */
const membersOf = (w: Wallet): Uint8Array => concatBytes(
  new Uint8Array([w.memberIds.length / 16]), w.memberIds);

/** masterPublicKey ‖ origin ‖ c ‖ IDs, the WalletInfo of §9.2. */
const walletInfoOf = (w: Wallet): Uint8Array =>
  concatBytes(w.masterPublicKey, new Uint8Array([w.origin]), membersOf(w));

interface Transfer {
  name: string;
  wallet: Wallet;
  source: Card;
  target: Card;
  targetLife: string;
  slotOnSource: number;
  slotOnTarget: number;
  linkPrivate: bigint;
  lk: Uint8Array;
  offerHash: Uint8Array;
  offerSignature: Uint8Array;
  e: bigint;
  ep: Uint8Array;
  z: Uint8Array;
  m: Uint8Array;
  th: Uint8Array;
  exportSignature: Uint8Array;
  kTe: Uint8Array;
  kTm: Uint8Array;
  accessHashT: Uint8Array;
  payload: Uint8Array;
  ct: Uint8Array;
  tag: Uint8Array;
  walletInfo: Uint8Array;
}

/** The card's own §10.5 check: null when the point decompresses, else the reason. */
const decompressReason = (compressed: Uint8Array): string | null => {
  const prefix = compressed[0];
  if (prefix !== 0x02 && prefix !== 0x03) return 'prefix not 02 or 03';
  const xv = bytesToNumberBE(compressed.subarray(1, 33));
  if (xv >= P) return 'x >= p';
  const rhs = mod(pow(xv, 3n, P) + 7n, P);
  if (!isResidue(rhs)) return 'x^3 + 7 is a quadratic non-residue';
  return null;
};

/** The peer-key slot of §16.1 item 1; BLANK always slot 0. */
const slot = (card: Card, peer: Card, wallet: Wallet, life: string): number => {
  if (life === 'BLANK') return 0;
  const members = membersOf(wallet);
  const c = members[0];
  let self = -1;
  let found = -1;
  for (let i = 0; i < c; i++) {
    const id = members.subarray(1 + 16 * i, 1 + 16 * (i + 1));
    if (bytesToHex(id) === bytesToHex(card.id)) self = i;
    if (bytesToHex(id) === bytesToHex(peer.id)) found = i;
  }
  assert(self >= 0 && found >= 0 && self !== found, 'slot: peer not a member');
  return found - (found > self ? 1 : 0);
};

const transferOf = (
  name: string, wallet: Wallet, source: Card, target: Card, targetLife: string,
): Transfer => {
  const linkPrivate = detScalar(`transfer/${name}/link`);
  const e = detScalar(`transfer/${name}/e`);
  const accessHashT = det(`transfer/${name}/accessHashT`);

  const lk = publicKey(linkPrivate);
  const offerHash = sha256(concatBytes(LABEL_OFFER, lk));
  const offerSignature = sign(target.privateKey, offerHash);
  assert(verify(target.uncompressed, offerHash, offerSignature), `${name} offerSignature`);

  const ep = publicKey(e);
  assert(decompressReason(compress(ep)) === null, `${name} E`);
  const z = secp256k1.Point.fromBytes(lk).multiply(e).toBytes(false).subarray(1, 33);
  const z2 = secp256k1.Point.fromBytes(ep).multiply(linkPrivate).toBytes(false).subarray(1, 33);
  assert(bytesToHex(z) === bytesToHex(z2), `${name} Z mismatch`);
  const m = concatBytes(LABEL_EXPORT, source.a, target.a, lk, ep);
  assert(m.length === 215, `${name} M length`);
  const th = sha256(m);
  const exportSignature = sign(source.privateKey, th);
  assert(verify(source.uncompressed, th, exportSignature), `${name} exportSignature`);

  const keys = kdf(z, LABEL_KDF, th, 32);
  const kTe = keys.subarray(0, 16);
  const kTm = keys.subarray(16, 32);

  const payload = concatBytes(
    new Uint8Array([wallet.origin]), wallet.seed, accessHashT, membersOf(wallet));
  const ct = aesCbc(kTe, ZEROS, m2pad(payload));
  const tag = cmacOf(kTm, ct);

  return {
    name, wallet, source, target, targetLife,
    slotOnSource: slot(source, target, wallet, 'LOADED'),
    slotOnTarget: slot(target, source, wallet, targetLife),
    linkPrivate, lk, offerHash, offerSignature, e, ep, z, m, th,
    exportSignature, kTe, kTm, accessHashT, payload, ct, tag,
    walletInfo: walletInfoOf(wallet),
  };
};

const transferRow = (t: Transfer): unknown => ({
  name: t.name,
  wallet: t.wallet.name,
  source: t.source.name,
  target: t.target.name,
  targetLife: t.targetLife,
  slotOnSource: t.slotOnSource,
  slotOnTarget: t.slotOnTarget,
  linkPrivate: bytesToHex(scalarBytes(t.linkPrivate)),
  LK: bytesToHex(t.lk),
  offerHash: bytesToHex(t.offerHash),
  offerSignature: bytesToHex(t.offerSignature),
  e: bytesToHex(scalarBytes(t.e)),
  E: bytesToHex(t.ep),
  Z: bytesToHex(t.z),
  M: bytesToHex(t.m),
  TH: bytesToHex(t.th),
  exportSignature: bytesToHex(t.exportSignature),
  kTe: bytesToHex(t.kTe),
  kTm: bytesToHex(t.kTm),
  accessHashT: bytesToHex(t.accessHashT),
  payload: bytesToHex(t.payload),
  ct: bytesToHex(t.ct),
  tag: bytesToHex(t.tag),
  walletInfo: bytesToHex(t.walletInfo),
});

const legendre = (v: bigint): number => {
  const l = pow(v, LEGENDRE, P);
  return l === 1n ? 1 : l === P - 1n ? -1 : 0;
};

const isResidue = (v: bigint): boolean => legendre(v) === 1;

/** The even square root of the residue v (p ≡ 3 mod 4). */
const evenSqrt = (v: bigint): bigint => {
  let y = pow(v, SQRT, P);
  if ((y & 1n) === 1n) y = P - y;
  assert(mod(y * y, P) === v, 'sqrt');
  return y;
};

const point = (xv: bigint, yv: bigint): Uint8Array =>
  concatBytes(new Uint8Array([0x04]), scalarBytes(xv), scalarBytes(yv));

/** 04 ‖ x=5 ‖ y with y² = (5³ + 7)·d mod p for the smallest non-residue d ≥ 2: a twist point. */
const twistPoint = (): Uint8Array => {
  let d = 2n;
  while (isResidue(d)) d += 1n;
  const rhs = mod(132n * d, P);
  assert(isResidue(rhs), 'twist rhs should be a residue');
  return point(5n, evenSqrt(rhs));
};

/** 04 ‖ 1 ‖ y with y² = 2 mod p: on y² = x³ + 1, off this curve. */
const invalidCurvePoint = (): Uint8Array => {
  assert(isResidue(2n), '2 should be a residue');
  return point(1n, evenSqrt(2n));
};

const decompressRow = (name: string, compressed: Uint8Array): unknown => {
  const reason = decompressReason(compressed);
  assert(reason === null, `${name} unexpectedly invalid: ${reason}`);
  const uncompressed = secp256k1.Point.fromBytes(compressed).toBytes(false);
  assert(uncompressed.length === 65 && uncompressed[0] === 0x04, name);
  return {
    name,
    compressed: bytesToHex(compressed),
    valid: true,
    uncompressed: bytesToHex(uncompressed),
  };
};

const invalidRow = (name: string, compressed: Uint8Array): unknown => {
  const reason = decompressReason(compressed);
  assert(reason !== null, `${name} unexpectedly valid`);
  return { name, compressed: bytesToHex(compressed), valid: false, reason };
};

const decompressRows = (cards: Card[]): unknown[] => {
  const rows: unknown[] = [];
  const randoms: Uint8Array[] = [];
  for (const c of cards) rows.push(decompressRow(`card-${c.name}`, c.a));
  for (let i = 0; i < 16; i++) {
    const pub = publicKey(detScalar(`transfer/decompress/${i}`));
    randoms.push(pub);
    rows.push(decompressRow(`random-${i}`, compress(pub)));
  }
  for (let i = 0; i < 2; i++) {
    const flipped = new Uint8Array(33);
    flipped[0] = (randoms[i][64] & 1) === 0 ? 0x03 : 0x02;
    flipped.set(randoms[i].subarray(1, 33), 1);
    rows.push(decompressRow(`parity-flip-${i}`, flipped));
  }
  for (let xv = 1n; xv < 5n; xv++) {
    assert(isResidue(mod(pow(xv, 3n, P) + 7n, P)), `x = ${xv} should be a residue`);
  }
  assert(!isResidue(132n), 'x = 5 should be a non-residue');
  const even5 = new Uint8Array(33);
  even5[0] = 0x02;
  even5[32] = 0x05;
  const odd5 = even5.slice();
  odd5[0] = 0x03;
  const xIsP = new Uint8Array(33);
  xIsP[0] = 0x02;
  xIsP.set(scalarBytes(P), 1);
  const xMax = new Uint8Array(33);
  xMax[0] = 0x03;
  xMax.fill(0xff, 1);
  const prefix04 = new Uint8Array(33);
  prefix04[0] = 0x04;
  prefix04.set(cards[0].a.subarray(1, 33), 1);
  const prefix00 = new Uint8Array(33);
  prefix00.set(cards[0].a.subarray(1, 33), 1);
  rows.push(invalidRow('non-residue-even', even5));
  rows.push(invalidRow('non-residue-odd', odd5));
  rows.push(invalidRow('x-is-p', xIsP));
  rows.push(invalidRow('x-max', xMax));
  rows.push(invalidRow('prefix-04', prefix04));
  rows.push(invalidRow('prefix-00', prefix00));
  return rows;
};

const cardRow = (c: Card): unknown => ({
  name: c.name,
  private: bytesToHex(scalarBytes(c.privateKey)),
  A: bytesToHex(c.a),
  uncompressed: bytesToHex(c.uncompressed),
  id: bytesToHex(c.id),
  cert: bytesToHex(c.cert),
});

/** Compressed kM·G of the BIP-32 master; bip32Derive asserts validity. */
const masterPublicKey = (seed: Uint8Array): Uint8Array =>
  compress(publicKey(bytesToNumberBE(bip32Derive(seed, 'm').privateKey)));

const importedWallet = (source: Card, target: Card): Wallet => {
  const seed = detLen('transfer/imported/seed', 64);
  const accessHash = det('transfer/imported/accessHash');
  const memberIds = concatBytes(source.id, target.id);
  return {
    name: 'imported',
    creator: source.name,
    create: {
      p1: '01',
      accessHash: bytesToHex(accessHash),
      seed: bytesToHex(seed),
      others: [bytesToHex(target.id)],
    },
    seed,
    origin: 0x02,
    memberIds,
    masterPublicKey: masterPublicKey(seed),
  };
};

const generatedWallet = (source: Card, target: Card, third: Card): Wallet => {
  const t = detScalar('transfer/generated/t');
  const hostEntropy = det('transfer/generated/hostEntropy');
  const seed = sha512(concatBytes(LABEL_SEED, scalarBytes(t), hostEntropy));
  const accessHash = det('transfer/generated/accessHash');
  const memberIds = concatBytes(source.id, target.id, third.id);
  return {
    name: 'generated',
    creator: source.name,
    create: {
      p1: '00',
      accessHash: bytesToHex(accessHash),
      hostEntropy: bytesToHex(hostEntropy),
      t: bytesToHex(scalarBytes(t)),
      others: [bytesToHex(target.id), bytesToHex(third.id)],
    },
    seed,
    origin: 0x01,
    memberIds,
    masterPublicKey: masterPublicKey(seed),
  };
};

const walletRow = (w: Wallet): unknown => ({
  name: w.name,
  creator: w.creator,
  create: w.create,
  seed: bytesToHex(w.seed),
  origin: w.origin.toString(16).padStart(2, '0'),
  members: bytesToHex(membersOf(w)),
  masterPublicKey: bytesToHex(w.masterPublicKey),
});

const signForOffer = (target: Card, lk: Uint8Array): Uint8Array => {
  const hash = sha256(concatBytes(LABEL_OFFER, lk));
  const sig = sign(target.privateKey, hash);
  assert(verify(target.uncompressed, hash, sig), 'offer sign');
  return sig;
};

const rejectedOffer = (
  name: string, cert: Uint8Array, lk: Uint8Array, signature: Uint8Array,
  check: number, reason: string,
): unknown => ({
  name,
  transfer: 'imported-to-target',
  cert: bytesToHex(cert),
  LK: bytesToHex(lk),
  signature: bytesToHex(signature),
  check,
  reason,
});

const rejectedOffers = (t: Transfer, target: Card, third: Card, twist: Uint8Array): unknown[] => {
  const certOtherCa = issue(CA2, target.a);
  const sigByThird = sign(third.privateKey, sha256(concatBytes(LABEL_OFFER, t.lk)));

  const lk03 = t.lk.slice();
  lk03[0] = 0x03;
  const lkOffCurve = t.lk.slice();
  lkOffCurve[64] ^= 0x01;
  const lkXIsP = t.lk.slice();
  lkXIsP.set(scalarBytes(P), 1);
  const badSig = t.offerSignature.slice();
  badSig[63] ^= 0x01;

  return [
    rejectedOffer('cert-other-ca', certOtherCa, t.lk, signForOffer(target, t.lk), 1,
      'certificate does not verify under caKey'),
    rejectedOffer('cert-own', t.source.cert, t.lk, signForOffer(target, t.lk), 2,
      'target certificate is the own card'),
    rejectedOffer('cert-non-member', third.cert, t.lk, sigByThird, 3,
      'target is not a member'),
    rejectedOffer('offer-prefix-03', target.cert, lk03, signForOffer(target, lk03), 5,
      'LK_T[0] is not 0x04'),
    rejectedOffer('offer-bad-signature', target.cert, t.lk, badSig, 5,
      'sig_T does not verify under A_T'),
    rejectedOffer('offer-wrong-key', target.cert, t.lk, sigByThird, 5,
      'sig_T does not verify under A_T'),
    rejectedOffer('lk-off-curve', target.cert, lkOffCurve, signForOffer(target, lkOffCurve), 6,
      'LK_T is not a valid point'),
    rejectedOffer('lk-x-is-p', target.cert, lkXIsP, signForOffer(target, lkXIsP), 6,
      'LK_T is not a valid point'),
    rejectedOffer('lk-twist', target.cert, twist, signForOffer(target, twist), 6,
      'LK_T is not a valid point'),
  ];
};

const exportRow = (
  name: string, transfer: string, cert: Uint8Array, e: Uint8Array, signature: Uint8Array,
  check: number, reason: string,
): unknown => ({
  name,
  transfer,
  cert: bytesToHex(cert),
  E: bytesToHex(e),
  signature: bytesToHex(signature),
  check,
  reason,
});

/** A check-6 row: signed by the source over M built with the bad E and the transfer's LK. */
const badE = (name: string, t: Transfer, e: Uint8Array, check: number, reason: string): unknown => {
  const m = concatBytes(LABEL_EXPORT, t.source.a, t.target.a, t.lk, e);
  const sig = sign(t.source.privateKey, sha256(m));
  return exportRow(name, t.name, t.source.cert, e, sig, check, reason);
};

const rejectedExports = (
  t: Transfer, reseal: Transfer, source: Card, target: Card, third: Card,
  twist: Uint8Array, invalidCurve: Uint8Array,
): unknown[] => {
  const certOtherCa = issue(CA2, source.a);
  const staleLk = publicKey(detScalar('transfer/stale/link'));
  const tampered = t.ep.slice();
  tampered[64] ^= 0x01;

  const rows: unknown[] = [];
  rows.push(exportRow('cert-other-ca', t.name, certOtherCa, t.ep, t.exportSignature, 1,
    'certificate does not verify under caKey'));
  rows.push(exportRow('cert-own', t.name, target.cert, t.ep, t.exportSignature, 2,
    'sender certificate is the own card'));
  rows.push(exportRow('cert-non-member-loaded', reseal.name, third.cert, reseal.ep,
    reseal.exportSignature, 3, 'sender is not a member'));
  rows.push(exportRow('cert-not-sender-blank', t.name, third.cert, t.ep, t.exportSignature, 5,
    'sig_S does not verify under A_S'));
  rows.push(exportRow('tampered-e', t.name, source.cert, tampered, t.exportSignature, 5,
    'sig_S does not cover this E'));
  const staleM = concatBytes(LABEL_EXPORT, source.a, target.a, staleLk, t.ep);
  const staleSig = sign(source.privateKey, sha256(staleM));
  rows.push(exportRow('stale-lk', t.name, source.cert, t.ep, staleSig, 5,
    'sig_S covers a different LK'));

  const reason = 'E is not a valid point';
  rows.push(badE('e-off-curve', t, tampered, 6, reason));
  const xIsP = t.ep.slice();
  xIsP.set(scalarBytes(P), 1);
  rows.push(badE('e-x-is-p', t, xIsP, 6, reason));
  const prefix02 = t.ep.slice();
  prefix02[0] = 0x02;
  rows.push(badE('e-prefix-02', t, prefix02, 6, reason));
  rows.push(badE('e-zero', t, new Uint8Array(65), 6, reason));
  rows.push(badE('e-twist', t, twist, 6, reason));
  rows.push(badE('e-invalid-curve', t, invalidCurve, 6, reason));
  return rows;
};

const payloadRow = (
  name: string, transfer: string, plaintext: Uint8Array, ct: Uint8Array, tag: Uint8Array,
  check: number, reason: string,
): unknown => ({
  name,
  transfer,
  plaintext: bytesToHex(plaintext),
  ct: bytesToHex(ct),
  tag: bytesToHex(tag),
  check,
  reason,
});

/** M2-pad, encrypt and tag a (possibly modified) payload under the transfer's keys. */
const honestRow = (
  name: string, t: Transfer, payload: Uint8Array, check: number, reason: string,
): unknown => {
  const padded = m2pad(payload);
  const ct = aesCbc(t.kTe, ZEROS, padded);
  return payloadRow(name, t.name, padded, ct, cmacOf(t.kTm, ct), check, reason);
};

/** A row whose member IDs are replaced while the rest of the payload is kept. */
const idsRow = (name: string, t: Transfer, ids: Uint8Array, check: number, reason: string) => {
  const out = new Uint8Array(98 + ids.length);
  out.set(t.payload.subarray(0, 97));
  out[97] = ids.length / 16;
  out.set(ids, 98);
  return honestRow(name, t, out, check, reason);
};

const rejectedPayloads = (t: Transfer, reseal: Transfer, third: Card): unknown[] => {
  const rows: unknown[] = [];

  const badTag = t.tag.slice();
  badTag[15] ^= 0x01;
  const badCt = t.ct.slice();
  badCt[0] ^= 0x01;
  const padded = m2pad(t.payload);
  const noPad = padded.slice();
  noPad[t.payload.length] = 0x00;
  const noPadCt = aesCbc(t.kTe, ZEROS, noPad);

  rows.push(payloadRow('tag-flipped', t.name, padded, t.ct, badTag, 1,
    'tag does not match ct'));
  rows.push(payloadRow('ct-flipped', t.name, padded, badCt, t.tag, 1,
    'tag does not match ct'));
  rows.push(payloadRow('bad-padding', t.name, noPad, noPadCt, cmacOf(t.kTm, noPadCt), 2,
    'M2 unpadding fails'));

  const countMismatch = t.payload.slice();
  countMismatch[97] = 0x03;
  const countOne = t.payload.slice();
  countOne[97] = 0x01;
  const origin00 = t.payload.slice();
  origin00[0] = 0x00;
  const origin03 = t.payload.slice();
  origin03[0] = 0x03;

  rows.push(honestRow('count-mismatch', t, countMismatch, 2,
    'payload length does not match c'));
  rows.push(honestRow('count-one', t, countOne, 2, 'payload length does not match c'));
  rows.push(honestRow('origin-00', t, origin00, 3, 'origin is not 0x01 or 0x02'));
  rows.push(honestRow('origin-03', t, origin03, 3, 'origin is not 0x01 or 0x02'));

  rows.push(idsRow('ids-duplicate', t, concatBytes(t.source.id, t.source.id), 3,
    'member IDs are not pairwise distinct'));
  rows.push(idsRow('not-listing-target', t, concatBytes(t.source.id, third.id), 3,
    'the importing card is not among the members'));
  rows.push(idsRow('not-listing-source', t, concatBytes(third.id, t.target.id), 3,
    'the sender is not among the members'));

  const otherSeed = reseal.payload.slice();
  const newSeed = detLen('transfer/other/seed', 64);
  otherSeed.set(newSeed, 1);
  bip32Derive(newSeed, 'm'); // check 4 must pass for the row to reach check 5
  rows.push(honestRow('reseal-other-seed', reseal, otherSeed, 5,
    'fingerprint does not equal the stored fp'));

  const otherOrigin = reseal.payload.slice();
  otherOrigin[0] = 0x01;
  rows.push(honestRow('reseal-other-origin', reseal, otherOrigin, 5,
    'origin does not equal the stored origin'));

  const swapped = reseal.payload.slice();
  swapped.set(reseal.payload.subarray(98 + 16, 98 + 32), 98);
  swapped.set(reseal.payload.subarray(98, 98 + 16), 98 + 16);
  rows.push(honestRow('reseal-other-members', reseal, swapped, 5,
    'members do not equal the stored members'));

  const three = new Uint8Array(146);
  three.set(reseal.payload.subarray(0, 97));
  three[97] = 0x03;
  three.set(reseal.payload.subarray(98, 130), 98);
  three.set(third.id, 130);
  rows.push(honestRow('reseal-other-members-three', reseal, three, 5,
    'members do not equal the stored members'));
  return rows;
};

export function transferDoc(): unknown {
  const source = cardOf('source', false);
  const target = cardOf('target', true);
  const third = cardOf('third', false);
  const cards = [source, target, third];

  const imported = importedWallet(source, target);
  const generated = generatedWallet(source, target, third);

  const transfers = [
    transferOf('imported-to-target', imported, source, target, 'BLANK'),
    transferOf('imported-reseal-target', imported, source, target, 'LOADED'),
    transferOf('generated-to-target', generated, source, target, 'BLANK'),
    transferOf('generated-to-third', generated, source, third, 'BLANK'),
    transferOf('generated-reseal-third-from-target', generated, target, third, 'LOADED'),
  ];

  const twist = twistPoint();
  const invalidCurve = invalidCurvePoint();

  return {
    labels: {
      offer: bytesToHex(LABEL_OFFER),
      export: bytesToHex(LABEL_EXPORT),
      kdfTransfer: bytesToHex(LABEL_KDF),
    },
    ca: bytesToHex(publicKey(CA1)),
    cards: cards.map(cardRow),
    decompress: decompressRows(cards),
    wallets: [walletRow(imported), walletRow(generated)],
    transfers: transfers.map(transferRow),
    probes: { twist: bytesToHex(twist), invalidCurve: bytesToHex(invalidCurve) },
    rejectedOffers: rejectedOffers(transfers[0], target, third, twist),
    rejectedExports: rejectedExports(
      transfers[0], transfers[1], source, target, third, twist, invalidCurve),
    rejectedPayloads: rejectedPayloads(transfers[0], transfers[1], third),
  };
}
