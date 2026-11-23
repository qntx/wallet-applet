// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import java.security.SecureRandom;
import java.util.List;
import org.qntx.card.host.AccessCode;
import org.qntx.card.host.CardNotGenuineException;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Open;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.SessionBrokenException;
import org.qntx.card.host.TestAnchors;

/**
 * One OPEN session with the product wallet applet through a {@link Reader}: SELECT, the §8.1
 * handshake against the test anchors, then {@code inner} command records. The wallet is the device
 * under test for the Timing and ApduLc248 rows; the probe applet covers the platform rows.
 */
final class WalletSession {
    static final int INS_STATUS = 0x20;
    static final int INS_CREATE = 0x21;
    static final int INS_VERIFY = 0x22;
    static final int INS_ERASE = 0x24;
    static final int INS_WAIT = 0x25;
    static final int INS_PUBLIC_KEY = 0x30;
    static final int INS_SIGN_ECDSA = 0x31;
    static final int INS_SIGN_BIP340 = 0x32;
    static final int INS_SIGN_ED25519 = 0x33;
    static final int INS_OFFER = 0x40;
    static final int INS_EXPORT = 0x41;
    static final int INS_IMPORT = 0x42;

    private final Reader reader;
    private final Session session;

    private WalletSession(Reader reader, Session session) {
        this.reader = reader;
        this.session = session;
    }

    /** SELECT the wallet and run the §8.1 OPEN handshake; returns the connected session. */
    static WalletSession open(Reader reader, SecureRandom rng) throws CardNotGenuineException {
        byte[] r = reader.transmit(Apdu.select(Apdu.WALLET_AID));
        if (Apdu.sw(r) != 0x9000) {
            throw new IllegalStateException(
                    "SELECT wallet failed: sw=" + Integer.toHexString(Apdu.sw(r)));
        }
        Open.Request req = Open.request(rng);
        byte[] rsp = reader.transmit(req.apdu());
        return attach(
                reader, Open.response(req.secret(), req.apdu(), rsp, List.of(TestAnchors.CA1)));
    }

    /** Wraps an already-established session — for callers that time the OPEN APDU themselves. */
    static WalletSession attach(Reader reader, Session session) {
        return new WalletSession(reader, session);
    }

    Session session() {
        return session;
    }

    byte[] identity() {
        return session.identity();
    }

    byte[] cert() {
        return session.cert();
    }

    byte[] cardId() {
        return Ids.cardId(identity());
    }

    /** One inner command record; {@code |data| ≤ 236}. */
    Response inner(int ins, int p1, int p2, byte[] data) {
        try {
            return session.unwrap(reader.transmit(session.wrap(ins, p1, p2, data)));
        } catch (SessionBrokenException e) {
            throw new IllegalStateException("session broken: " + e.getMessage(), e);
        }
    }

    Response inner(int ins, int p1, int p2) {
        return inner(ins, p1, p2, Apdu.EMPTY);
    }

    byte[] innerOk(int ins, int p1, int p2) {
        return innerOk(ins, p1, p2, Apdu.EMPTY);
    }

    /** Inner command expecting inner SW {@code 9000}. */
    byte[] innerOk(int ins, int p1, int p2, byte[] data) {
        Response r = inner(ins, p1, p2, data);
        if (r.sw() != 0x9000) {
            throw new IllegalStateException(
                    "inner "
                            + Integer.toHexString(ins)
                            + " failed: sw="
                            + Integer.toHexString(r.sw()));
        }
        return r.data();
    }

    /** The access-code hash of §7.2 for {@code code} on this card's identity. */
    byte[] accessHash(String code) {
        return AccessCode.hash(code, cardId());
    }
}
