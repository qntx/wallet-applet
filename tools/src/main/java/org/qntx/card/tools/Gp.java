// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tools;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBO;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HexFormat;
import pro.javacard.capfile.AID;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.GPSession.APDUMode;
import pro.javacard.gp.keys.PlaintextKeys;

/**
 * ISD-side helpers for the §14.3 commands: the transport key from {@code QNTX_ISD_KEY}, the {@code
 * --scp} value, and opening the secure channel exactly as recorded for the batch.
 */
final class Gp {

    /** The simulated/production ISD AID every command selects. */
    static final byte[] ISD_AID = HexFormat.of().parseHex("A000000151000000");

    /** The ISD transport key environment variable. Never an option, never printed. */
    static final String ISD_KEY_ENV = "QNTX_ISD_KEY";

    private Gp() {}

    /**
     * The {@code --scp} argument: {@code 03} (SCP03 {@code i = 00}) or {@code 02-55} (SCP02 {@code
     * i = 55}), the protocol recorded for the batch at admission.
     */
    static GPSecureChannelVersion scp(String value) {
        return switch (value) {
            case "03" -> new GPSecureChannelVersion(GPSecureChannelVersion.SCP.SCP03, 0x00);
            case "02-55" -> new GPSecureChannelVersion(GPSecureChannelVersion.SCP.SCP02, 0x55);
            default ->
                    throw new IllegalArgumentException("--scp must be 03 or 02-55, got " + value);
        };
    }

    /**
     * {@code QNTX_ISD_KEY}: 32 hex digits (one key for ENC/MAC/DEK) or 96 (ENC ‖ MAC ‖ DEK). Key
     * version is left 0 so INITIALIZE UPDATE addresses whatever KVN the card holds.
     */
    static PlaintextKeys isdKeys(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException(ISD_KEY_ENV + " is not set");
        }
        hex = hex.trim();
        byte[] raw;
        try {
            raw = HexFormat.of().parseHex(hex);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(ISD_KEY_ENV + " is not hex", e);
        }
        byte[] enc;
        byte[] mac;
        byte[] dek;
        if (raw.length == 16) {
            enc = mac = dek = raw;
        } else if (raw.length == 48) {
            enc = Arrays.copyOfRange(raw, 0, 16);
            mac = Arrays.copyOfRange(raw, 16, 32);
            dek = Arrays.copyOfRange(raw, 32, 48);
        } else {
            throw new IllegalArgumentException(ISD_KEY_ENV + " must be 32 or 96 hex digits");
        }
        return PlaintextKeys.fromBytes(enc, mac, dek, null, null, null, 0)
                .orElseThrow(() -> new IllegalArgumentException(ISD_KEY_ENV + " rejected"));
    }

    /**
     * SELECT the ISD and open the secure channel with security level C-MAC + C-DECRYPTION ({@link
     * APDUMode#MAC} | {@link APDUMode#ENC}). GlobalPlatformPro verifies the card cryptogram itself
     * inside {@code openSecureChannel} before it answers with EXTERNAL AUTHENTICATE
     * (GPSession.java, "Verify card cryptogram"), so a card without the keys is refused before it
     * sees a management command. The card's reported protocol must equal the batch's {@code want} —
     * a card answering a different SCP version is refused.
     */
    static GPSession open(BIBO bibo, PlaintextKeys keys, GPSecureChannelVersion want)
            throws GPException {
        GPSession session = GPSession.connect(new APDUBIBO(bibo), new AID(ISD_AID));
        session.openSecureChannel(keys, want, null, EnumSet.of(APDUMode.MAC, APDUMode.ENC));
        // The card's reported SCP must equal the batch's; SCP03's i is compared too because the
        // card sends it in key-info. SCP02's i cannot be compared: the INITIALIZE UPDATE
        // response carries no i byte for SCP01/02 and GlobalPlatformPro parses i only when
        // scpv == 0x03 (GPSession.java, "get the protocol 'i' parameter, if SCP03"), so 02-55
        // pins the version while i stays a batch-recorded fact, not negotiated on the wire.
        GPSecureChannelVersion got = session.getSecureChannel();
        if (got == null
                || got.scp != want.scp
                || (want.scp == GPSecureChannelVersion.SCP.SCP03 && got.i != want.i)) {
            throw new GPException(
                    "card offered "
                            + (got == null ? "no channel" : got)
                            + ", batch requires "
                            + want);
        }
        return session;
    }
}
