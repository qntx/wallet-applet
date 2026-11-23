// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

/** APDU client of the admission probe applets (tests/src/admission, package F0716E7478FF). */
final class Probe {
    static final byte[] AID = Apdu.hex("F0716E7478FF01");
    static final byte[] AID2 = Apdu.hex("F0716E7478FF02");

    private final Reader reader;

    private Probe(Reader reader) {
        this.reader = reader;
    }

    /** Selects the probe applet and returns its command channel. */
    static Probe open(Reader reader) {
        byte[] r = reader.transmit(Apdu.select(AID));
        if (Apdu.sw(r) != 0x9000) {
            throw new IllegalStateException(
                    "SELECT probe failed: sw=" + Integer.toHexString(Apdu.sw(r)));
        }
        return new Probe(reader);
    }

    /** A probe response: response data with the status word. */
    record Rsp(byte[] data, int sw) {}

    Rsp cmd(int ins, int p1, int p2, byte[] data) {
        byte[] r = reader.transmit(Apdu.cmd(0x80, ins, p1, p2, data));
        return new Rsp(Apdu.data(r), Apdu.sw(r));
    }

    Rsp cmd(int ins) {
        return cmd(ins, 0, 0, Apdu.EMPTY);
    }

    byte[] ok(int ins, int p1, int p2, byte[] data) {
        Rsp r = cmd(ins, p1, p2, data);
        if (r.sw() != 0x9000) {
            throw new IllegalStateException(
                    "probe INS "
                            + Integer.toHexString(ins)
                            + " failed: sw="
                            + Integer.toHexString(r.sw()));
        }
        return r.data();
    }

    /** Platform info: the three memory pools, commit capacities and protocol versions. */
    byte[] info() {
        return ok(0x01, 0, 0, Apdu.EMPTY);
    }

    /** Loads the 195-byte domain blob of curve {@code which} (0 secp256k1, 1 Wei25519). */
    void domain(int which, byte[] blob195) {
        ok(0x04, which, 0, blob195);
    }

    /** Allocates every object of the probe; returns one status byte per item (0 = ok). */
    byte[] setup() {
        return ok(0x05, 0, 0, Apdu.EMPTY);
    }

    void rsaSetModulus(int slot, byte[] modulus64) {
        ok(0x10, slot, 0, modulus64);
    }

    void rsaSetExponent(int slot, byte[] exponent) {
        ok(0x10, slot, 1, exponent);
    }

    /** RSA NOPAD with a fresh cipher init; response {@code u16(len) ‖ result}. */
    Rsp rsa(int slot, byte[] input64) {
        return cmd(0x11, slot, 0, input64);
    }

    /** PLAIN_XY (ins 0x20) or PACE_GM (0x21) on curve {@code curve}: {@code s(32) ‖ point}. */
    Rsp ec(int ins, int curve, byte[] s32, byte[] point) {
        byte[] data = new byte[32 + point.length];
        System.arraycopy(s32, 0, data, 0, 32);
        System.arraycopy(point, 0, data, 32, point.length);
        return cmd(ins, curve, 0, data);
    }

    /**
     * {@code setS} + {@code getS} on key {@code which} (0/1 transient curves, 2 persistent secp).
     */
    Rsp setS(int which, byte[] s32) {
        return cmd(0x22, which, 0, s32);
    }

    /** ECDSA: {@code s(32) ‖ msg}; p1 0 = signPreComputedHash (needs 32-byte hash). */
    Rsp sign(int p1, byte[] privAndMsg) {
        return cmd(0x23, p1, 0, privAndMsg);
    }

    /** ECDSA verify: {@code pub(65|33) ‖ hash(32) ‖ derSig}; returns one byte. */
    Rsp verify(int p1, byte[] pubHashSig) {
        return cmd(0x24, p1, 0, pubHashSig);
    }

    /** {@code setW} + {@code getW} on pub key {@code which} (0 secp256k1, 1 Wei25519). */
    Rsp setW(int which, byte[] w) {
        return cmd(0x25, which, 0, w);
    }

    /** Transaction semantics probe, sub-command {@code sub}. */
    Rsp tx(int sub, byte[] data) {
        return cmd(0x30, sub, 0, data);
    }

    /** The persistent failure counter pair and the transaction depth. */
    byte[] failctr() {
        return ok(0x31, 0, 0, Apdu.EMPTY);
    }

    /** {@code reps} repetitions of bench {@code op} with {@code data} as the operand. */
    Rsp bench(int op, int reps, byte[] data) {
        return cmd(0x60, op, reps, data);
    }

    /** {@code n} bytes (1–255) of {@code ALG_KEYGENERATION} output. */
    byte[] rnd(int n) {
        return ok(0x61, (n >>> 8) & 0xFF, n & 0xFF, Apdu.EMPTY);
    }

    /** The first 32 output bytes since the last power-up; {@code 6985} if already drawn. */
    Rsp first() {
        return cmd(0x62);
    }

    /**
     * Named-transaction replica {@code id} (0 T-PERSO … 8 T-EDCTR); response {@code u16 used ‖ u16
     * maxCommit ‖ u32 deselect ‖ u32 reset ‖ u32 persistent}.
     */
    byte[] replica(int id) {
        return ok(0x70, id, 0, Apdu.EMPTY);
    }
}
