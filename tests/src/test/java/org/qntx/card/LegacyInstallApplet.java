// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.security.ECPrivateKey;
import javacard.security.KeyPair;

/**
 * The pre-F1 constructor shape of {@link WalletApplet}: the same object graph, but every persistent
 * write — domains, RSA moduli, key generations, peer {@code setW}, the random {@code wrapKey} and
 * the {@code State} fields — inside {@code install()}. Card A's install journal cannot hold it (the
 * real finding), so the simulator's install journal must throw {@code
 * TransactionException.BUFFER_FULL}. Test-only; never installed on a card.
 */
public final class LegacyInstallApplet extends Applet {

    private LegacyInstallApplet(byte[] bArray, short bOffset) {
        Const.init();
        Mem mem = new Mem();
        State state = new State();
        ModArith modArith = new ModArith(mem);
        Secp256k1 secp = new Secp256k1(mem, modArith);
        Wei25519 wei = new Wei25519(mem);
        Identity identity = new Identity(mem, state, secp);
        Session session = new Session(mem, state, secp, identity);
        Derivation derivation = new Derivation(mem, session, secp, wei, modArith);
        Ecdsa ecdsa = new Ecdsa(mem, session, derivation, secp);
        Bip340 bip340 = new Bip340(mem, session, derivation, secp, modArith);
        Ed25519 ed25519 = new Ed25519(mem, state, session, derivation, wei, modArith, identity);
        KeyPair link = Transfer.newLinkKey();
        Wallet wallet =
                new Wallet(
                        mem,
                        state,
                        session,
                        identity,
                        derivation,
                        secp,
                        (ECPrivateKey) link.getPrivate());
        Transfer transfer =
                new Transfer(mem, state, session, identity, secp, derivation, wallet, link);
        // the writes §4.3 moved out of install, in constructor order: state fields first, then
        // the RSA moduli, the domains, the key generations and the wrap key
        wallet.initState();
        modArith.initKeys();
        identity.initDomains();
        transfer.initDomains();
        ecdsa.initDomains();
        identity.initKeys();
        transfer.initLink();
        register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new LegacyInstallApplet(bArray, bOffset);
    }

    @Override
    public void process(APDU apdu) {}
}
