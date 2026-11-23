// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import java.util.Arrays;
import org.qntx.card.NdefApplet;
import org.qntx.card.WalletApplet;
import org.qntx.card.admission.Probe;
import org.qntx.card.admission.Probe2;
import org.qntx.card.host.Certificates;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.TestCa;

/**
 * The in-process simulator as a suite reader: a self-check of the suite, the probe and the product
 * applet against the same machine that runs the simulator tests — never hardware evidence. The
 * simulator reports meaningful values for commit-buffer and transient-pool accounting; it does not
 * model reader timing, contactless transport, RNG quality or the failure behaviour of the silicon.
 */
final class SimReader implements Reader {
    private static final byte[] GET_IDENTITY = {(byte) 0x80, (byte) 0xE0, 0x00, 0x00, 0x00};
    private static final byte[] NDEF_MESSAGE = Apdu.hex("D1010C5402656E716E74782063617264");

    private final Card card;

    SimReader() {
        card = new Card();
        // wallet first: the probe's install-time pool capture must see the product applet's
        // transient consumption, like on a real card where the probe installs last
        card.install(Apdu.WALLET_AID, WalletApplet.class);
        card.install(Apdu.NDEF_AID, NdefApplet.class, NDEF_MESSAGE);
        personalize();
        card.install(org.qntx.card.realcard.Probe.AID, Probe.class);
        card.install(org.qntx.card.realcard.Probe.AID2, Probe2.class);
    }

    /** The §14.3 personalisation of the test card: init drive, cert under ca1, life → BLANK. */
    private void personalize() {
        // §14.3: repeat SELECT + GET_IDENTITY until it stops answering 6283, at most 16 times
        byte[] rapdu = null;
        for (int i = 0; i < 16; i++) {
            expectOk(card.transmit(Apdu.select(Apdu.WALLET_AID)), "SELECT wallet");
            rapdu = card.transmit(GET_IDENTITY);
            if (Apdu.sw(rapdu) != 0x6283) {
                break;
            }
        }
        expectOk(rapdu, "GET_IDENTITY");
        byte[] a = Arrays.copyOf(rapdu, rapdu.length - 2);
        byte[] cert = Certificates.issue(TestCa.PRIVATE, a);
        byte[] personalize = new byte[5 + 162];
        personalize[0] = (byte) 0x80;
        personalize[1] = (byte) 0xE2;
        personalize[4] = (byte) 162;
        System.arraycopy(cert, 0, personalize, 5, 97);
        System.arraycopy(TestCa.PUBLIC, 0, personalize, 102, 65);
        expectOk(card.transmit(personalize), "PERSONALIZE");
    }

    private static void expectOk(byte[] r, String what) {
        if (Apdu.sw(r) != 0x9000) {
            throw new IllegalStateException(
                    what + " failed: sw=" + Integer.toHexString(Apdu.sw(r)));
        }
    }

    @Override
    public byte[] transmit(byte[] command) {
        return card.transmit(command);
    }

    @Override
    public void powerCycle() {
        card.powerCycle();
    }

    @Override
    public String describe() {
        return "sim";
    }

    @Override
    public Boolean contactless() {
        return null;
    }

    @Override
    public byte[] cplc() {
        return null;
    }

    @Override
    public boolean isSim() {
        return true;
    }
}
