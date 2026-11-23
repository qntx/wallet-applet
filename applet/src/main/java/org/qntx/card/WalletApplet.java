// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.ECPrivateKey;
import javacard.security.KeyPair;

/**
 * The qntx card wallet applet (protocol.md §2, §6, §9.1). Constructs the object graph once — {@code
 * Mem, State, ModArith, Secp256k1, Wei25519, Identity, Session, Derivation, Wallet} — and
 * dispatches the outer commands of §9.1 and, inside a session record, the inner commands of §9.2.
 */
public final class WalletApplet extends Applet {
    private final Mem mem;
    private final State state;
    private final Secp256k1 secp;
    private final Wei25519 wei;
    private final Identity identity;
    private final Session session;
    private final Derivation derivation;
    private final Ecdsa ecdsa;
    private final Bip340 bip340;
    private final Ed25519 ed25519;
    private final Wallet wallet;
    private final Transfer transfer;

    private WalletApplet(byte[] bArray, short bOffset) {
        Const.init();
        mem = new Mem();
        state = new State();
        ModArith modArith = new ModArith(mem);
        secp = new Secp256k1(mem, modArith);
        wei = new Wei25519(mem);
        identity = new Identity(mem, state, secp);
        session = new Session(mem, state, secp, identity);
        derivation = new Derivation(mem, session, secp, wei, modArith);
        ecdsa = new Ecdsa(mem, session, derivation, secp);
        bip340 = new Bip340(mem, session, derivation, secp, modArith);
        ed25519 = new Ed25519(mem, state, session, derivation, wei, modArith, identity);
        // §4.2/§4.3: the link key pair of §11, owned by Transfer; Wallet only
        // overwrites its private half inside its own transactions
        KeyPair link = Transfer.newLinkKey();
        wallet =
                new Wallet(
                        mem,
                        state,
                        session,
                        identity,
                        derivation,
                        secp,
                        (ECPrivateKey) link.getPrivate());
        transfer = new Transfer(mem, state, session, identity, secp, derivation, wallet, link);
        register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    /** GlobalPlatform install entry; the instance AID is taken from the install data. */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new WalletApplet(bArray, bOffset);
    }

    /** SELECT of the wallet applet tears down any session (§6, §8.5); it writes nothing. */
    public boolean select() {
        session.teardown();
        // a transient EC key's domain parameters die with the selection epoch like the
        // transient arrays (§8.5), so they are re-loaded on every selection before any
        // signing path can run; the writes land on transient objects only, keeping
        // select() free of persistent writes
        secp.loadEphDomain();
        wei.loadDomain();
        return true;
    }

    /**
     * Outer dispatch in the order of protocol.md §9.1. Handlers write their response at buffer
     * offset 0 and return its length; scratch is wiped before every response or error so no command
     * residue leaves the card (§8.1, §16.3 item 3).
     */
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        short len;
        try {
            len = dispatch(apdu);
        } catch (ISOException e) {
            mem.wipeScratch();
            if (e.getReason() == Const.SW_FAULT) {
                session.teardown();
            }
            throw e;
        } catch (Exception e) {
            // §16.3 item 4: unexpected exceptions map to 6F00, reason codes never escape
            mem.wipeScratch();
            session.teardown();
            ISOException.throwIt(Const.SW_FAULT);
            return;
        }
        mem.wipeScratch();
        apdu.setOutgoingAndSend((short) 0, len);
    }

    /** The §9.1 outer table: CLA, reception, then the INS row's own checking order. */
    private short dispatch(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_CLA] != Const.CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        short lc = receiveAll(apdu);
        short len;
        switch (buf[ISO7816.OFFSET_INS]) {
            case Const.INS_GET_IDENTITY:
                len = identity.getIdentity(apdu, lc);
                break;
            case Const.INS_PERSONALIZE:
                len = identity.personalize(apdu, lc);
                break;
            case Const.INS_OPEN:
                len = session.open(apdu, lc);
                break;
            case Const.INS_SESSION:
                len = session(apdu, lc);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                return 0;
        }
        return len;
    }

    /**
     * The SESSION path (§8.3–8.4): {@code unwrap} throws the outer status on record failures; the
     * inner result (a status word plus optional data at buffer offset 0) is wrapped into a response
     * record with outer {@code 9000}.
     */
    private short session(APDU apdu, short lc) {
        byte[] buf = apdu.getBuffer();
        short plain = session.unwrap(apdu, lc);
        short dataLen = 0;
        short sw = ISO7816.SW_NO_ERROR;
        try {
            if (plain < 3) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            dataLen = inner(buf, plain);
        } catch (ISOException e) {
            sw = e.getReason();
        } catch (Exception e) {
            sw = Const.SW_FAULT;
        }
        // §16.1 item 2: a still-open transaction after dispatch is a detected fault (a skipped
        // commit); no response data is sent while a transaction is open
        if (JCSystem.getTransactionDepth() != 0) {
            JCSystem.abortTransaction();
            sw = Const.SW_FAULT;
            dataLen = 0;
        }
        short len = session.wrap(apdu, dataLen, sw);
        session.afterResponse(sw);
        return len;
    }

    /**
     * Inner dispatch (§9.2): pending states first, then the §9.2 checking order — INS known, life
     * gate, {@code P1}/{@code P2}, length, verified gate — then the handler, whose response goes to
     * buffer offset 0. Returns the response length.
     */
    private short inner(byte[] buf, short plain) {
        byte ins = buf[ISO7816.OFFSET_CDATA];
        byte p1 = buf[(short) (ISO7816.OFFSET_CDATA + 1)];
        byte p2 = buf[(short) (ISO7816.OFFSET_CDATA + 2)];
        short pending = session.beginDispatch(ins, p1);
        short sw = ISO7816.SW_NO_ERROR;
        try {
            short row = -1;
            for (short i = 0; i < Const.INNER_INS.length; i++) {
                if (Const.INNER_INS[i] == ins) {
                    row = i;
                }
            }
            if (row < 0) {
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
            short life = state.life();
            short bit =
                    life == Const.LIFE_BLANK
                            ? Const.LIFE_BIT_BLANK
                            : life == Const.LIFE_LOADED ? Const.LIFE_BIT_LOADED : (short) 0;
            if ((short) (Const.INNER_LIFE[row] & bit) == 0) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            if (p2 != 0 || (short) (p1 & 0xFF) > Const.INNER_P1_MAX[row]) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            short dataOff = (short) (ISO7816.OFFSET_CDATA + 3);
            short dataLen = (short) (plain - 3);
            checkLength(ins, p1, buf, dataOff, dataLen);
            if (Const.INNER_VERIFIED[row] != 0 && session.verified() != Const.VERIFIED_YES) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            short out = 0;
            switch (ins) {
                case Const.INS_STATUS:
                    out = wallet.status(buf, (short) 0);
                    break;
                case Const.INS_CREATE:
                    out = wallet.create(buf, p1, dataOff, dataLen);
                    break;
                case Const.INS_VERIFY:
                    out = wallet.verify(buf, dataOff);
                    break;
                case Const.INS_CHANGE:
                    wallet.change(buf, dataOff);
                    break;
                case Const.INS_ERASE:
                    wallet.erase();
                    break;
                case Const.INS_WAIT:
                    wallet.waitUnit();
                    break;
                case Const.INS_PUBLIC_KEY:
                    out = derivation.publicKey(buf, p1, dataOff, dataLen);
                    break;
                case Const.INS_SIGN_ECDSA:
                    out = ecdsa.sign(buf, dataOff);
                    break;
                case Const.INS_SIGN_BIP340:
                    out = bip340.sign(buf, dataOff);
                    break;
                case Const.INS_OFFER:
                    out = transfer.offer(buf);
                    break;
                case Const.INS_EXPORT:
                    out = p1 == 0 ? transfer.export0(buf, dataOff) : transfer.export1(buf, dataOff);
                    break;
                case Const.INS_IMPORT:
                    out =
                            p1 == 0
                                    ? transfer.import0(buf, dataOff)
                                    : transfer.import1(buf, dataOff, dataLen);
                    break;
                case Const.INS_SIGN_ED25519:
                    // §9.11 streams the message; checkLength already bounded dataLen per P1
                    if (p1 == 0) {
                        out = ed25519.begin(buf, dataOff);
                    } else if (p1 == 1) {
                        out = ed25519.update(buf, dataOff, dataLen);
                    } else {
                        out = ed25519.finish(buf, dataOff, dataLen);
                    }
                    break;
                default:
                    break;
            }
            return out;
        } catch (ISOException e) {
            sw = e.getReason();
            throw e;
        } catch (Exception e) {
            sw = Const.SW_FAULT;
            throw e;
        } finally {
            session.endDispatch(pending, ins, p1, sw);
        }
    }

    /**
     * The per-INS length check of the §9.2 checking order: STATUS/ERASE/WAIT {@code 0};
     * VERIFY/CHANGE {@code 32}; CREATE {@code 64/80/96} for {@code P1 = 0} and {@code 96/112/128}
     * for {@code P1 = 1}; PUBLIC_KEY {@code 1 + 4·depth} (a depth byte of 0 with length 1 passes —
     * the command's own data check rejects it with {@code 6A80}).
     */
    private static void checkLength(byte ins, byte p1, byte[] buf, short dataOff, short dataLen) {
        switch (ins) {
            case Const.INS_STATUS:
            case Const.INS_ERASE:
            case Const.INS_WAIT:
                if (dataLen != 0) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                return;
            case Const.INS_VERIFY:
            case Const.INS_CHANGE:
                if (dataLen != Const.HASH_LEN) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                return;
            case Const.INS_CREATE:
                short rest = (short) (dataLen - (p1 == 0 ? 64 : 96));
                if (rest < 0 || rest > 32 || (short) (rest & 0x0F) != 0) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                return;
            case Const.INS_PUBLIC_KEY:
                // the depth-prefix check subsumes dataLen < 1: no byte value makes
                // 0 == 1 + depth*4 hold
                short depth = (short) (buf[dataOff] & 0xFF);
                if (dataLen != (short) (1 + depth * 4)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                return;
            case Const.INS_SIGN_ECDSA:
                // §9.9: digest(32) ‖ path — a shorter body can't equal 33 + 4·depth ≥ 33;
                // the depth-byte read lands in the APDU buffer (≥ 133 bytes, always)
                if (dataLen != (short) (33 + (buf[(short) (dataOff + 32)] & 0xFF) * 4)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                return;
            case Const.INS_SIGN_BIP340:
                // §9.10: message(32) ‖ tweak(32) ‖ path — a shorter body can't
                // equal 65 + 4·depth ≥ 65 (the depth-byte read stays in the buffer)
                if (dataLen != (short) (65 + (buf[(short) (dataOff + 64)] & 0xFF) * 4)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                return;
            case Const.INS_OFFER:
                if (dataLen != 0) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                return;
            case Const.INS_EXPORT:
                if (dataLen != (p1 == 0 ? (short) 226 : Const.HASH_LEN)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                return;
            case Const.INS_IMPORT:
                if (p1 == 0) {
                    if (dataLen != (short) 226) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    }
                } else if (dataLen != (short) 160 && dataLen != (short) 176) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                return;
            case Const.INS_SIGN_ED25519:
                // §9.11: begin carries a path (1 + 4·depth), update and finish a
                // 1..236-byte chunk; depth is checked by the command, length here
                // only bounds it
                if (p1 == 0) {
                    // a body under one byte can't equal 1 + 4·depth ≥ 1
                    if (dataLen != (short) (1 + (buf[dataOff] & 0xFF) * 4)) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    }
                } else if (dataLen < 1) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                // no upper bound to check: the record layer never delivers more
                // than the 236-byte maximum a chunk or tail may carry
                return;
            default:
                // checkLength runs only for §9.2-table INS values; the row lookup and
                // the dispatch switch are what reject anything else
                return;
        }
    }

    /** Receives the full command body; returns the declared Lc. Reception has no status word. */
    private static short receiveAll(APDU apdu) {
        short received = apdu.setIncomingAndReceive();
        short lc = apdu.getIncomingLength();
        while (received < lc) {
            received += apdu.receiveBytes((short) (ISO7816.OFFSET_CDATA + received));
        }
        return lc;
    }
}
