// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.realcard;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.List;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.CardNotGenuineException;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Open;
import org.qntx.card.host.Paths;
import org.qntx.card.host.TestAnchors;

/**
 * The Timing row (architecture §10): every command of protocol §16.6 through the product applet,
 * asserted ≤ 1,500 ms and recorded next to the §16.6/B2 reference. {@code EXPORT}/{@code IMPORT}
 * need a second card; without {@code -PrealCardPeer=<reader>} they are skipped with a reason.
 * Timings taken on the simulator are meaningless and labelled {@code reader: sim}.
 */
final class Timing extends Suite {
    private static final long LIMIT = 1500;
    private static final String CODE = "realCard-h3";
    private static final String SECP_PATH = "m/44'/60'/0'/0/0";
    private static final String ED_PATH = "m/44'/501'/0'/0'/0'";

    private final SecureRandom rng = new SecureRandom();

    @Test
    void everyCommandWithin1500ms() throws CardNotGenuineException {
        // the peer for EXPORT/IMPORT, opened first so its ID can be a CREATE member
        Reader peerReader = null;
        WalletSession peer = null;
        String peerProp = System.getProperty("realCardPeer");
        if (peerProp != null && !peerProp.isEmpty()) {
            peerReader = Readers.create(peerProp);
            peer = WalletSession.open(peerReader, rng);
        }
        try {
            timedOpen(peer);
        } finally {
            if (peerReader != null) {
                peerReader.close();
            }
        }
    }

    private void timedOpen(WalletSession peer) throws CardNotGenuineException {
        byte[] r = reader.transmit(Apdu.select(Apdu.WALLET_AID));
        assertEquals(0x9000, Apdu.sw(r), "SELECT wallet");
        Open.Request req = Open.request(rng);
        long t0 = System.nanoTime();
        byte[] rsp = reader.transmit(req.apdu());
        check("OPEN", ms(t0), 160);
        WalletSession card =
                WalletSession.attach(
                        reader,
                        Open.response(req.secret(), req.apdu(), rsp, List.of(TestAnchors.CA1)));

        byte[] accessHash = card.accessHash(CODE);
        byte[] create = new byte[64 + (peer == null ? 0 : 16)];
        System.arraycopy(accessHash, 0, create, 0, 32);
        byte[] entropy = new byte[32];
        rng.nextBytes(entropy);
        System.arraycopy(entropy, 0, create, 32, 32);
        if (peer != null) {
            System.arraycopy(Ids.cardId(peer.identity()), 0, create, 64, 16);
        }
        check("CREATE", timed(() -> card.innerOk(WalletSession.INS_CREATE, 0, 0, create)), 106);
        check("VERIFY", timed(() -> card.innerOk(WalletSession.INS_VERIFY, 0, 0, accessHash)), 124);
        check("WAIT", timed(() -> card.innerOk(WalletSession.INS_WAIT, 0, 0)), 965);

        // cold derivations: VERIFY wipes the caches before each cold sign
        card.innerOk(WalletSession.INS_VERIFY, 0, 0, accessHash);
        byte[] digest = new byte[32];
        rng.nextBytes(digest);
        byte[] secpPath = Paths.wire(SECP_PATH);
        check(
                "SIGN_ECDSA cold depth-5",
                timed(
                        () ->
                                card.innerOk(
                                        WalletSession.INS_SIGN_ECDSA,
                                        0,
                                        0,
                                        join(digest, secpPath))),
                411);

        card.innerOk(WalletSession.INS_VERIFY, 0, 0, accessHash);
        byte[] msgTweak = new byte[64];
        rng.nextBytes(msgTweak);
        check(
                "SIGN_BIP340 cold",
                timed(
                        () ->
                                card.innerOk(
                                        WalletSession.INS_SIGN_BIP340,
                                        0,
                                        0,
                                        join(msgTweak, secpPath))),
                724);

        card.innerOk(WalletSession.INS_VERIFY, 0, 0, accessHash);
        byte[] edPath = Paths.wire(ED_PATH);
        check(
                "SIGN_ED25519 begin",
                timed(() -> card.innerOk(WalletSession.INS_SIGN_ED25519, 0, 0, edPath)),
                430);
        check(
                "SIGN_ED25519 update 236B",
                timed(() -> card.innerOk(WalletSession.INS_SIGN_ED25519, 1, 0, new byte[236])),
                21);
        check(
                "SIGN_ED25519 finish",
                timed(() -> card.innerOk(WalletSession.INS_SIGN_ED25519, 2, 0, new byte[32])),
                486);
        check(
                "PUBLIC_KEY ed25519",
                timed(() -> card.innerOk(WalletSession.INS_PUBLIC_KEY, 1, 0, edPath)),
                217);
        check("OFFER", timed(() -> card.innerOk(WalletSession.INS_OFFER, 0, 0)), 137);
        check("OFFER valid", timed(() -> card.innerOk(WalletSession.INS_OFFER, 0, 0)), 78);

        if (peer == null) {
            Results.row(
                    "Timing",
                    "EXPORT/IMPORT P1=0",
                    "skip",
                    "needs a second card: pass -PrealCardPeer=<reader>");
        } else {
            byte[] offer = peer.innerOk(WalletSession.INS_OFFER, 0, 0);
            byte[] exportData = new byte[226];
            System.arraycopy(peer.cert(), 0, exportData, 0, 97);
            System.arraycopy(offer, 0, exportData, 97, 129);
            byte[] exported =
                    timedBytes(
                            "EXPORT P1=0",
                            () -> card.innerOk(WalletSession.INS_EXPORT, 0, 0, exportData),
                            424);
            byte[] importData = new byte[226];
            System.arraycopy(card.cert(), 0, importData, 0, 97);
            System.arraycopy(exported, 0, importData, 97, 129);
            timedBytes(
                    "IMPORT P1=0",
                    () -> peer.innerOk(WalletSession.INS_IMPORT, 0, 0, importData),
                    471);
        }

        // leave the card in BLANK
        card.innerOk(WalletSession.INS_ERASE, 0, 0);
    }

    private void check(String name, long ms, long ref) {
        Results.row(
                "Timing",
                name,
                ms <= LIMIT ? "pass" : "fail",
                ms + " ms (§16.6 ref " + ref + " ms, limit " + LIMIT + " ms)");
        assertTrue(ms <= LIMIT, name + " took " + ms + " ms > " + LIMIT + " ms");
    }

    private long timed(Runnable r) {
        long t0 = System.nanoTime();
        r.run();
        return ms(t0);
    }

    private byte[] timedBytes(String name, Supplier<byte[]> s, long ref) {
        long t0 = System.nanoTime();
        byte[] out = s.get();
        check(name, ms(t0), ref);
        return out;
    }

    private static long ms(long t0) {
        return (System.nanoTime() - t0) / 1_000_000;
    }

    private static byte[] join(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
