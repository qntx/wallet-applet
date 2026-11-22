// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.probe;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Silicon admission probe of architecture.md §10 and protocol.md §3: a minimal applet that exposes
 * the platform behaviours the wallet applet depends on, each as one command on class byte {@code
 * 0x80}. Standard Java Card 3.0.5 APIs only; every object is allocated at install.
 *
 * <p>Commands (CLA {@code 0x80}; every command ends with {@code Le = 00}):
 *
 * <pre>
 * INS  P1   Data                                Response
 * 01   rsa  modulus(64)                         —        setModulus
 * 02   rsa  exponent(1..64)                     —        setExponent
 * 03   rsa  input(64)                           out(64)  ALG_RSA_NOPAD doFinal
 * 10   ec   P‖A‖B‖G‖R‖K = 32+32+32+65+32+2      —        EC domain (195 B)
 * 11   ec   s(32)                               —        setS (private slots)
 * 12   ec   W(65)                               —        setW (public slots)
 * 13   ec   H(65)                               out(65)  ALG_EC_PACE_GM: s·G' + H
 * 14   ec   P(65)                               out(65)  ALG_EC_SVDP_DH_PLAIN_XY: s·P
 * 15   ec   hash(32)                            sig(DER) signPreComputedHash
 * 16   ec   hash(32)‖sig(DER)                   ok(1)    verifyPreComputedHash
 * 20   gen  —                                   —        genKeyPair (initialises the pair)
 * 22   0    AES key(16)                         —        setKey outside a transaction (tx baseline)
 * 21   1    new AES key(16)                     old‖inside‖after (48)   tx abort
 * 21   2    new S(32)                           old‖inside‖after (96)   tx abort
 * 21   3    new W(65)                           old‖inside‖after (195)  tx abort
 * 21   4    new exponent(≤32)                   old‖inside‖after padded (96) tx abort
 * 21   5    —                                   insideInit‖insideS‖insideW‖afterInit (99) tx abort
 * 21   6    —                                   S-triple old‖inside‖after of pair2 (96) tx abort
 * 21   7    —                                   W-triple old‖inside‖after of pair2 (195) tx abort
 * 30   n    —                                   random(n)  n ≤ 240, ALG_KEYGENERATION
 * 40   —                                        mem(12)    getAvailableMemory, 3 types
 * </pre>
 *
 * <p>Key slots: RSA private 0–1 ({@code TYPE_RSA_PRIVATE}/{@code LENGTH_RSA_512}); EC slots 0–1
 * persistent {@code TYPE_EC_FP_PRIVATE}, 2–3 persistent {@code TYPE_EC_FP_PUBLIC}, 4 {@code
 * TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT} (all 256-bit); the tx probe also uses the AES slot ({@code
 * TYPE_AES}/128), RSA slot 0, EC slots 0 and 2 and the two EC key pairs (domain slots 5–8: 5/6 the
 * pre-generated pair's private/public, 7/8 the never-generated pair's private/public).
 *
 * <p>A {@link CryptoException} maps to {@code 6F00 | reason}, so a thrown check stays
 * distinguishable from {@code 9000} and from the ISO status words the probe itself returns.
 */
public final class AdmissionProbe extends Applet {
    private static final byte CLA = (byte) 0x80;

    private static final byte INS_RSA_MOD = 0x01;
    private static final byte INS_RSA_EXP = 0x02;
    private static final byte INS_RSA_DO = 0x03;
    private static final byte INS_EC_DOMAIN = 0x10;
    private static final byte INS_EC_SET_S = 0x11;
    private static final byte INS_EC_SET_W = 0x12;
    private static final byte INS_PACE_GM = 0x13;
    private static final byte INS_PLAIN_XY = 0x14;
    private static final byte INS_SIGN = 0x15;
    private static final byte INS_VERIFY = 0x16;
    private static final byte INS_GENPAIR = 0x20;
    private static final byte INS_TX = 0x21;
    private static final byte INS_AES_SET = 0x22;
    private static final byte INS_RNG = 0x30;
    private static final byte INS_MEM = 0x40;
    private static final byte INS_CAPSCAN = 0x50;

    private final RSAPrivateKey[] rsa;
    private final ECPrivateKey[] ecPriv;
    private final ECPublicKey[] ecPub;
    private final ECPrivateKey ecPrivTransient;
    private final AESKey aes;
    private final KeyPair pairUsed;
    private final KeyPair pairFresh;
    private final Cipher rsaCipher;
    private final KeyAgreement paceGm;
    private final KeyAgreement plainXy;
    private final Signature ecdsa;
    private final RandomData random;
    private final short[] mem;
    private final byte[] txOut;
    // lazy capability-scan slots: the engines/keys Mem allocates that install() does not
    private AESKey capAes;
    private RSAPrivateKey capRsa;
    private ECPrivateKey capEcTransient;
    private Object[] capArrays;

    private AdmissionProbe() {
        rsa = new RSAPrivateKey[2];
        for (short i = 0; i < 2; i++) {
            rsa[i] =
                    (RSAPrivateKey)
                            KeyBuilder.buildKey(
                                    KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
        }
        ecPriv = new ECPrivateKey[2];
        ecPub = new ECPublicKey[2];
        for (short i = 0; i < 2; i++) {
            ecPriv[i] =
                    (ECPrivateKey)
                            KeyBuilder.buildKey(
                                    KeyBuilder.TYPE_EC_FP_PRIVATE,
                                    KeyBuilder.LENGTH_EC_FP_256,
                                    false);
            ecPub[i] =
                    (ECPublicKey)
                            KeyBuilder.buildKey(
                                    KeyBuilder.TYPE_EC_FP_PUBLIC,
                                    KeyBuilder.LENGTH_EC_FP_256,
                                    false);
        }
        ecPrivTransient =
                (ECPrivateKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                                KeyBuilder.LENGTH_EC_FP_256,
                                false);
        aes = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        pairUsed = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        pairFresh = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        paceGm = KeyAgreement.getInstance(KeyAgreement.ALG_EC_PACE_GM, false);
        plainXy = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        random = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        mem = new short[6];
        txOut = JCSystem.makeTransientByteArray((short) 195, JCSystem.CLEAR_ON_DESELECT);
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new AdmissionProbe();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_CLA] != CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        short lc = receiveAll(apdu);
        short len;
        try {
            len = dispatch(apdu, buf, lc);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (0x6F00 | (e.getReason() & 0x00FF)));
            return;
        } catch (SystemException e) {
            // transaction/memory failures stay readable too: 6E00 | reason
            ISOException.throwIt((short) (0x6E00 | (e.getReason() & 0x00FF)));
            return;
        }
        apdu.setOutgoingAndSend((short) 0, len);
    }

    private short dispatch(APDU apdu, byte[] buf, short lc) {
        byte p1 = buf[ISO7816.OFFSET_P1];
        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_RSA_MOD:
                require(lc, (short) 64);
                rsaSlot(p1).setModulus(buf, ISO7816.OFFSET_CDATA, (short) 64);
                return 0;
            case INS_RSA_EXP:
                if (lc < 1 || lc > 64) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                rsaSlot(p1).setExponent(buf, ISO7816.OFFSET_CDATA, lc);
                return 0;
            case INS_RSA_DO:
                require(lc, (short) 64);
                rsaCipher.init(rsaSlot(p1), Cipher.MODE_DECRYPT);
                return rsaCipher.doFinal(buf, ISO7816.OFFSET_CDATA, (short) 64, buf, (short) 0);
            case INS_EC_DOMAIN:
                require(lc, (short) 195);
                setDomain(ecSlot(p1), buf, ISO7816.OFFSET_CDATA);
                return 0;
            case INS_EC_SET_S:
                require(lc, (short) 32);
                ecPrivSlot(p1).setS(buf, ISO7816.OFFSET_CDATA, (short) 32);
                return 0;
            case INS_EC_SET_W:
                require(lc, (short) 65);
                ecPubSlot(p1).setW(buf, ISO7816.OFFSET_CDATA, (short) 65);
                return 0;
            case INS_PACE_GM:
                require(lc, (short) 65);
                paceGm.init(ecPrivSlot(p1));
                return paceGm.generateSecret(buf, ISO7816.OFFSET_CDATA, (short) 65, buf, (short) 0);
            case INS_PLAIN_XY:
                require(lc, (short) 65);
                plainXy.init(ecPrivSlot(p1));
                return plainXy.generateSecret(
                        buf, ISO7816.OFFSET_CDATA, (short) 65, buf, (short) 0);
            case INS_SIGN:
                require(lc, (short) 32);
                ecdsa.init(ecPrivSlot(p1), Signature.MODE_SIGN);
                return ecdsa.signPreComputedHash(
                        buf, ISO7816.OFFSET_CDATA, (short) 32, buf, (short) 0);
            case INS_VERIFY:
                if (lc < (short) 35) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                ecdsa.init(ecPubSlot(p1), Signature.MODE_VERIFY);
                boolean ok =
                        ecdsa.verifyPreComputedHash(
                                buf,
                                ISO7816.OFFSET_CDATA,
                                (short) 32,
                                buf,
                                (short) (ISO7816.OFFSET_CDATA + 32),
                                (short) (lc - 32));
                buf[0] = (byte) (ok ? 1 : 0);
                return 1;
            case INS_GENPAIR:
                // only the "used" pair; pairFresh must stay ungenerated for the P1 = 5 abort test
                pairUsed.genKeyPair();
                return 0;
            case INS_TX:
                return txAbort(p1, buf, lc);
            case INS_AES_SET:
                require(lc, (short) 16);
                aes.setKey(buf, ISO7816.OFFSET_CDATA);
                return 0;
            case INS_RNG:
                // P1 is unsigned on the wire: 240 is a valid request, a byte compare is not
                short n = (short) (p1 & 0xFF);
                if (n == 0 || n > 240) {
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
                random.generateData(buf, (short) 0, n);
                return n;
            case INS_MEM:
                JCSystem.getAvailableMemory(mem, (short) 0, JCSystem.MEMORY_TYPE_PERSISTENT);
                JCSystem.getAvailableMemory(mem, (short) 2, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
                JCSystem.getAvailableMemory(
                        mem, (short) 4, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
                for (short i = 0; i < 6; i++) {
                    buf[(short) (i * 2)] = (byte) (mem[i] >> 8);
                    buf[(short) (i * 2 + 1)] = (byte) mem[i];
                }
                return 12;
            case INS_CAPSCAN:
                return capScan(p1, buf, lc);
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                return 0;
        }
    }

    /**
     * Lazy capability scan of the pieces {@code Mem}/{@code Session}/{@code ModArith} allocate that
     * the probe's own {@code install} does not — the suspects when a CAP loads but {@code install}
     * fails with 6F00. One item per call; CryptoException maps to {@code 6F00|reason} and {@link
     * SystemException} (transient-memory, transaction) to {@code 6E00|reason} by {@link #process}.
     * P1: 1 = SHA-256, 2 = SHA-512, 3 = AES-CMAC, 4 = AES-CBC-NOPAD, 5 = transient AES-128 key, 6 =
     * extra RSA-512 key + setModulus/setExponent (data = modulus(64)), 7 = transient
     * CLEAR_ON_DESELECT byte[] into slot P2 (data = size, 2 B), 8 = second transient EC-FP private
     * key.
     */
    private short capScan(byte p1, byte[] buf, short lc) {
        switch (p1) {
            case 1:
                MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
                break;
            case 2:
                MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
                break;
            case 3:
                Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
                break;
            case 4:
                Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
                break;
            case 5:
                if (capAes == null) {
                    capAes =
                            (AESKey)
                                    KeyBuilder.buildKey(
                                            KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                                            KeyBuilder.LENGTH_AES_128,
                                            false);
                }
                break;
            case 6:
                if (capRsa == null) {
                    capRsa =
                            (RSAPrivateKey)
                                    KeyBuilder.buildKey(
                                            KeyBuilder.TYPE_RSA_PRIVATE,
                                            KeyBuilder.LENGTH_RSA_512,
                                            false);
                }
                if (lc >= (short) 64) {
                    capRsa.setModulus(buf, ISO7816.OFFSET_CDATA, (short) 64);
                    capRsa.setExponent(EXP2, (short) 0, (short) EXP2.length);
                }
                break;
            case 7:
                {
                    if (lc < (short) 2
                            || buf[ISO7816.OFFSET_P2] < 0
                            || buf[ISO7816.OFFSET_P2] > 7) {
                        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                    }
                    if (capArrays == null) {
                        capArrays = new Object[8];
                    }
                    short slot = (short) (buf[ISO7816.OFFSET_P2] & 0xFF);
                    if (capArrays[slot] == null) {
                        capArrays[slot] =
                                JCSystem.makeTransientByteArray(
                                        Util.makeShort(
                                                buf[ISO7816.OFFSET_CDATA],
                                                buf[(short) (ISO7816.OFFSET_CDATA + 1)]),
                                        JCSystem.CLEAR_ON_DESELECT);
                    }
                    break;
                }
            case 8:
                if (capEcTransient == null) {
                    capEcTransient =
                            (ECPrivateKey)
                                    KeyBuilder.buildKey(
                                            KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                                            KeyBuilder.LENGTH_EC_FP_256,
                                            false);
                }
                break;
            case 9:
                // the journal window that decides how much an install() may write (§3 item 8)
                Util.setShort(buf, (short) 0, JCSystem.getMaxCommitCapacity());
                Util.setShort(buf, (short) 2, JCSystem.getUnusedCommitCapacity());
                return 4;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        return 0;
    }

    /** The even exponent {@code 2} ModArith uses for its modular-squaring oracle. */
    private static final byte[] EXP2 = {2};

    /**
     * Admission item 7 (protocol.md §3): one persistent key-object setter per P1 inside an open
     * transaction, then {@link JCSystem#abortTransaction()}; the response is {@code old ‖ inside ‖
     * after} so the host checks the abort restored the previous value. {@code genKeyPair} variants:
     * P1 = 5 leaves {@link #pairFresh} generated then aborted back to uninitialised; P1 = 6/7
     * re-generate the already-initialised {@link #pairUsed} and report its S/W triple.
     */
    private short txAbort(byte p1, byte[] buf, short lc) {
        byte[] out = txOut;
        short len;
        switch (p1) {
            case 1:
                require(lc, (short) 16);
                len = txKey(out, buf, ISO7816.OFFSET_CDATA);
                break;
            case 2:
                require(lc, (short) 32);
                len = txS(out, buf, ISO7816.OFFSET_CDATA);
                break;
            case 3:
                require(lc, (short) 65);
                len = txW(out, buf, ISO7816.OFFSET_CDATA);
                break;
            case 4:
                if (lc < 1 || lc > 32) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                len = txExp(out, buf, ISO7816.OFFSET_CDATA, lc);
                break;
            case 5:
                require(lc, (short) 0);
                len = txFresh(out);
                break;
            case 6:
            case 7:
                require(lc, (short) 0);
                if (!((ECPrivateKey) pairUsed.getPrivate()).isInitialized()) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                len = txUsed(out, p1 == (byte) 7);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                return 0;
        }
        Util.arrayCopy(out, (short) 0, buf, (short) 0, len);
        return len;
    }

    private short txKey(byte[] out, byte[] buf, short off) {
        aes.getKey(out, (short) 0);
        JCSystem.beginTransaction();
        aes.setKey(buf, off);
        aes.getKey(out, (short) 16);
        JCSystem.abortTransaction();
        aes.getKey(out, (short) 32);
        return 48;
    }

    private short txS(byte[] out, byte[] buf, short off) {
        ecPriv[0].getS(out, (short) 0);
        JCSystem.beginTransaction();
        ecPriv[0].setS(buf, off, (short) 32);
        ecPriv[0].getS(out, (short) 32);
        JCSystem.abortTransaction();
        ecPriv[0].getS(out, (short) 64);
        return 96;
    }

    private short txW(byte[] out, byte[] buf, short off) {
        ecPub[0].getW(out, (short) 0);
        JCSystem.beginTransaction();
        ecPub[0].setW(buf, off, (short) 65);
        ecPub[0].getW(out, (short) 65);
        JCSystem.abortTransaction();
        ecPub[0].getW(out, (short) 130);
        return 195;
    }

    private short txExp(byte[] out, byte[] buf, short off, short lc) {
        pad(out, (short) 0, rsa[0].getExponent(out, (short) 0), (short) 32);
        JCSystem.beginTransaction();
        rsa[0].setExponent(buf, off, lc);
        pad(out, (short) 32, rsa[0].getExponent(out, (short) 32), (short) 32);
        JCSystem.abortTransaction();
        pad(out, (short) 64, rsa[0].getExponent(out, (short) 64), (short) 32);
        return 96;
    }

    private short txFresh(byte[] out) {
        ECPrivateKey priv = (ECPrivateKey) pairFresh.getPrivate();
        ECPublicKey pub = (ECPublicKey) pairFresh.getPublic();
        JCSystem.beginTransaction();
        pairFresh.genKeyPair();
        out[0] = (byte) (priv.isInitialized() ? 1 : 0);
        priv.getS(out, (short) 1);
        pub.getW(out, (short) 33);
        JCSystem.abortTransaction();
        out[98] = (byte) (priv.isInitialized() ? 1 : 0);
        return 99;
    }

    private short txUsed(byte[] out, boolean w) {
        ECPrivateKey priv = (ECPrivateKey) pairUsed.getPrivate();
        ECPublicKey pub = (ECPublicKey) pairUsed.getPublic();
        if (w) {
            pub.getW(out, (short) 0);
            JCSystem.beginTransaction();
            pairUsed.genKeyPair();
            pub.getW(out, (short) 65);
            JCSystem.abortTransaction();
            pub.getW(out, (short) 130);
            return 195;
        }
        priv.getS(out, (short) 0);
        JCSystem.beginTransaction();
        pairUsed.genKeyPair();
        priv.getS(out, (short) 32);
        JCSystem.abortTransaction();
        priv.getS(out, (short) 64);
        return 96;
    }

    private static void pad(byte[] out, short off, short len, short to) {
        for (short i = len; i < to; i++) {
            out[(short) (off + i)] = 0;
        }
    }

    private static void setDomain(ECKey key, byte[] p, short off) {
        key.setFieldFP(p, off, (short) 32);
        key.setA(p, (short) (off + 32), (short) 32);
        key.setB(p, (short) (off + 64), (short) 32);
        key.setG(p, (short) (off + 96), (short) 65);
        key.setR(p, (short) (off + 161), (short) 32);
        key.setK((short) ((p[(short) (off + 193)] & 0xFF) << 8 | (p[(short) (off + 194)] & 0xFF)));
    }

    private RSAPrivateKey rsaSlot(byte p1) {
        if (p1 < 0 || p1 > 1) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        return rsa[p1];
    }

    private ECKey ecSlot(byte p1) {
        if (p1 == 4) {
            return ecPrivTransient;
        }
        if (p1 == 5) {
            return (ECKey) pairUsed.getPrivate();
        }
        if (p1 == 6) {
            return (ECKey) pairUsed.getPublic();
        }
        if (p1 == 7) {
            return (ECKey) pairFresh.getPrivate();
        }
        if (p1 == 8) {
            return (ECKey) pairFresh.getPublic();
        }
        if (p1 < 0 || p1 > 3) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        return p1 < 2 ? (ECKey) ecPriv[p1] : (ECKey) ecPub[(short) (p1 - 2)];
    }

    private ECPrivateKey ecPrivSlot(byte p1) {
        if (p1 == 4) {
            return ecPrivTransient;
        }
        if (p1 == 5) {
            return (ECPrivateKey) pairUsed.getPrivate();
        }
        if (p1 == 7) {
            return (ECPrivateKey) pairFresh.getPrivate();
        }
        if (p1 < 0 || p1 > 1) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        return ecPriv[p1];
    }

    private ECPublicKey ecPubSlot(byte p1) {
        if (p1 == 6) {
            return (ECPublicKey) pairUsed.getPublic();
        }
        if (p1 == 8) {
            return (ECPublicKey) pairFresh.getPublic();
        }
        if (p1 < 2 || p1 > 3) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        return ecPub[(short) (p1 - 2)];
    }

    private static void require(short actual, short expected) {
        if (actual != expected) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
    }

    private static short receiveAll(APDU apdu) {
        short received = apdu.setIncomingAndReceive();
        short lc = apdu.getIncomingLength();
        while (received < lc) {
            received += apdu.receiveBytes((short) (ISO7816.OFFSET_CDATA + received));
        }
        return lc;
    }
}
