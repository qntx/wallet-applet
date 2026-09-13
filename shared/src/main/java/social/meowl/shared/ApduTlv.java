/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.shared;

import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * Helpers for writing simplified BER-TLV records of the form {@code [tag(1) | length(1) |
 * value(length)]} with {@code length ∈ [0, 255]} per {@code notes/specs/protocol.md} §5.
 *
 * <p>Every method returns the offset immediately past the last byte written, so call sites can
 * chain writes without keeping a separate cursor. Misuse (oversized value, illegal offset,
 * source/destination overrun) raises {@link Constants#SW_WRONG_LENGTH}.
 */
public final class ApduTlv {

    /** Maximum value length supported by the single-byte length form (inclusive [0, 255]). */
    private static final short MAX_VALUE_LEN = (short) 0xFF;

    /** Fixed length of the value carried by {@link #putByte(byte[], short, byte, byte)}. */
    private static final short BYTE_VALUE_LEN = (short) 1;

    /** Fixed length of the value carried by {@link #putShort(byte[], short, byte, short)}. */
    private static final short SHORT_VALUE_LEN = (short) 2;

    private ApduTlv() {}

    /**
     * Writes a TLV record carrying a single byte value.
     *
     * @return the offset immediately after the written record
     */
    public static short putByte(byte[] dst, short offset, byte tag, byte value) {
        Bounds.requireCapacity(dst, offset, (short) (2 + BYTE_VALUE_LEN));
        dst[offset] = tag;
        dst[(short) (offset + 1)] = (byte) BYTE_VALUE_LEN;
        dst[(short) (offset + 2)] = value;
        return (short) (offset + 2 + BYTE_VALUE_LEN);
    }

    /**
     * Writes a TLV record carrying a 16-bit big-endian short value.
     *
     * @return the offset immediately after the written record
     */
    public static short putShort(byte[] dst, short offset, byte tag, short value) {
        Bounds.requireCapacity(dst, offset, (short) (2 + SHORT_VALUE_LEN));
        dst[offset] = tag;
        dst[(short) (offset + 1)] = (byte) SHORT_VALUE_LEN;
        Util.setShort(dst, (short) (offset + 2), value);
        return (short) (offset + 2 + SHORT_VALUE_LEN);
    }

    /**
     * Reserves a TLV header at {@code offset}, returning the offset where the value should be
     * written. After {@code length} value bytes have been emitted the header is back-patched via
     * {@link #finishReserved(byte[], short, short)} — the streaming-TLV equivalent that lets the
     * value be built directly in the destination buffer with no intermediate copy.
     *
     * @return the offset immediately after the reserved 2-byte header
     */
    public static short reserve(byte[] dst, short offset, byte tag) {
        Bounds.requireCapacity(dst, offset, (short) 2);
        dst[offset] = tag;
        // length placeholder; back-patched by finishReserved().
        dst[(short) (offset + 1)] = (byte) 0;
        return (short) (offset + 2);
    }

    /**
     * Completes a record previously opened with {@link #reserve(byte[], short, byte)}.
     *
     * <p>The {@code header + value} range is bounds-checked against {@code dst} so a programmer
     * error (value written past the buffer end) surfaces as {@link Constants#SW_WRONG_LENGTH}
     * rather than a {@code 6F00} from the runtime's {@link IndexOutOfBoundsException}.
     *
     * @param headerOffset the offset returned by the original {@code reserve} call, minus 2 — i.e.
     *     the offset of the tag byte
     * @param valueLen the number of value bytes the caller wrote past the reserved header
     */
    public static void finishReserved(byte[] dst, short headerOffset, short valueLen) {
        if (valueLen < 0 || valueLen > MAX_VALUE_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        Bounds.requireCapacity(dst, headerOffset, (short) (2 + valueLen));
        dst[(short) (headerOffset + 1)] = (byte) valueLen;
    }
}
