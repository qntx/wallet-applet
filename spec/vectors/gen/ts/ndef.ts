// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0

// ndef.json: the §15 capability container and NDEF file for the sample messages (lengths 1, 16,
// 100), the READ BINARY rows of the 16-byte message and the rejected install lengths. Independent
// oracle: NFC Forum T4T 2.0 §5, built by hand here. Mirrors gen/java .../NdefDoc.java.
import { bytesToHex, hexToBytes, u16 } from './lib.ts';

/** The "qntx card" NDEF Text record, 16 bytes. */
const MSG16 = 'd1010c5402656e716e74782063617264';

/** §15: 000F ‖ 20 ‖ 00FF ‖ 00FF ‖ 04 06 ‖ E104 ‖ u16(2+|msg|) ‖ 00 ‖ FF. */
function cc(msgLen: number): Uint8Array {
  const out = new Uint8Array([
    0x00, 0x0f, 0x20, 0x00, 0xff, 0x00, 0xff, 0x04, 0x06, 0xe1, 0x04, 0x00, 0x00, 0x00, 0xff,
  ]);
  out.set(u16(msgLen + 2), 11);
  return out;
}

/** §15: u16(|msg|) ‖ msg. */
function ndef(msg: Uint8Array): Uint8Array {
  const out = new Uint8Array(msg.length + 2);
  out.set(u16(msg.length), 0);
  out.set(msg, 2);
  return out;
}

function message(msg: Uint8Array): unknown {
  return { msg: bytesToHex(msg), cc: bytesToHex(cc(msg.length)), ndefFile: bytesToHex(ndef(msg)) };
}

/** READ BINARY rows of the 16-byte message (§15): off × le, data = min(Ne, size−off). */
function reads(): unknown[] {
  const msg = hexToBytes(MSG16);
  const files: [string, Uint8Array][] = [
    ['cc', cc(msg.length)],
    ['ndef', ndef(msg)],
  ];
  const rows: unknown[] = [];
  for (const [file, content] of files) {
    const size = content.length;
    for (const off of [0, 1, size - 1, size, size + 1, 0x8000, 0xffff]) {
      for (const le of [1, 15, 0]) {
        const ne = le === 0 ? 256 : le;
        const sw = off > size ? '6b00' : '9000';
        const len = off > size ? 0 : Math.min(ne, size - off);
        rows.push({ file, off, le, data: bytesToHex(content.subarray(off, off + len)), sw });
      }
    }
  }
  return rows;
}

export function ndefDoc(): unknown {
  const messages = [
    message(new Uint8Array([0x55])),
    message(hexToBytes(MSG16)),
    message(Uint8Array.from({ length: 100 }, (_, i) => i + 1)),
  ];
  return { messages, reads: reads(), rejectedInstall: [0, 101] };
}
