// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.admission;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.TransactionException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Admission probe of the real-card suite (architecture §10), a trimmed port of the audit probe at
 * {@code applet-audit/audit-impl/evidence/probe/Probe.java} with two additions the audit probe did
 * not have: the first-random-output command of Admission 6 and the named-transaction replicas of
 * Admission 8. Test-only: every command is a measurement and this package never ships in a release
 * artifact.
 *
 * <p>Replica write sets (one persistent {@code byte[274]} at the architecture §4.2 offsets plus
 * key-object writes on the same object types as production — {@code AESKey}, persistent secp256k1
 * {@code ECPrivateKey}/{@code ECPublicKey} and {@code KeyPair}), derived from protocol §4.3 and
 * {@code State}, {@code Wallet}, {@code Transfer}, {@code Identity}:
 *
 * <ul>
 *   <li>T-PERSO: {@code nv[175..272) cert} (97 B copy), {@code ecPub.setW}, {@code nv[0..2) life}
 *   <li>T-CREATE / T-INSTALL: {@code aesP.setKey}, {@code nv[95..159) ct}, {@code nv[159..175)
 *       tag}, {@code nv[63..95) fp}, {@code nv[6..8) origin}, {@code nv[14..63) members}, {@code
 *       nv[2..6) fails}, {@code ecPriv.setS}, {@code nv[8..10) offer}, {@code nv[0..2) life}
 *   <li>T-FAIL / T-OK: {@code nv[2..6) fails} (two coded writes)
 *   <li>T-CHANGE: {@code aesP.setKey}, {@code nv[95..175) ct ‖ tag}
 *   <li>T-ERASE: {@code nv[0..2) life}, {@code aesP.setKey}, clear {@code nv[6..8) origin} and
 *       {@code nv[14..175) members ‖ fp ‖ ct ‖ tag} in ≤32 B chunks, {@code nv[2..6) fails}, {@code
 *       ecPriv.setS}, {@code nv[8..10) offer}
 *   <li>T-OFFER: {@code kp.genKeyPair}, {@code nv[8..10) offer}
 *   <li>T-EDCTR: {@code nv[10..14) edCounter}
 * </ul>
 */
public class Probe extends Applet {
    private static final short DOM_LEN = 195;
    private static final short STATE_LEN = 274;
    private static final short OFF_LIFE = 0;
    private static final short OFF_FAILS = 2;
    private static final short OFF_ORIGIN = 6;
    private static final short OFF_OFFER = 8;
    private static final short OFF_EDCOUNTER = 10;
    private static final short OFF_MEMBERS = 14;
    private static final short OFF_FP = 63;
    private static final short OFF_CT = 95;
    private static final short OFF_TAG = 159;
    private static final short OFF_CERT = 175;
    private static final short SW_ONCE = (short) 0x6985;

    private final short[] memBuf = new short[2];
    private final short[] f = new short[2];
    private final byte[] nv = new byte[STATE_LEN];
    private static final byte[] ZEROS = new byte[32];
    private static final byte[] ONE = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    };
    private final byte[] domS = new byte[DOM_LEN];
    private final byte[] domW = new byte[DOM_LEN];
    private final byte[] scratch;
    private final byte[] firstFlag;

    private RSAPrivateKey[] rsa;
    private Cipher rsaCipher;
    private ECPrivateKey ecPrivT;
    private ECPrivateKey ecPrivT2;
    private ECPrivateKey ecPriv;
    private ECPrivateKey ecPrivW;
    private ECPublicKey ecPub;
    private ECPublicKey ecPubW;
    private KeyPair kp;
    private KeyAgreement kaXY;
    private KeyAgreement kaGM;
    private Signature ecdsa;
    private AESKey aesP;
    private RandomData rnd;

    /**
     * Per-item allocation result of the constructor (0 = allocated); reported again by {@code
     * setup} so an algorithm missing on a particular card still surfaces as a status byte instead
     * of a failed install. Objects are allocated at install because field writes during a command
     * are an allocation-after-install defect the simulator (and the product invariant) rejects.
     */
    private final byte[] allocStatus = new byte[14];

    /**
     * CLEAR_ON_DESELECT bytes still free before this applet's own transient objects exist. The
     * product applet is already installed when the probe installs, so the figure is the
     * post-install pool Admission 8 measures — the probe's own consumption must not pollute it.
     */
    private final short poolAtInstall;

    protected Probe() {
        poolAtInstall = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        scratch = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
        firstFlag = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        for (short item = 0; item < 14; item++) {
            try {
                allocate(item);
            } catch (CryptoException e) {
                allocStatus[item] = (byte) (0x10 + e.getReason());
            } catch (SystemException e) {
                allocStatus[item] = (byte) (0x20 + e.getReason());
            } catch (CardRuntimeException e) {
                allocStatus[item] = (byte) (0x50 + e.getReason());
            } catch (RuntimeException e) {
                allocStatus[item] = (byte) 0x4F;
            }
        }
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // register after construction: a call on `this` inside the constructor is a this-escape
        new Probe().register();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_CLA] != (byte) 0x80) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        short lc = apdu.setIncomingAndReceive();
        short off = ISO7816.OFFSET_CDATA;
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short out = 0;
        try {
            switch (buf[ISO7816.OFFSET_INS]) {
                case 0x01:
                    out = info(buf);
                    break;
                case 0x04:
                    Util.arrayCopy(buf, off, p1 == 0 ? domS : domW, (short) 0, DOM_LEN);
                    break;
                case 0x05:
                    out = setup(buf);
                    break;
                case 0x10:
                    if (p2 == 0) {
                        rsa[p1].setModulus(buf, off, lc);
                    } else {
                        rsa[p1].setExponent(buf, off, lc);
                    }
                    break;
                case 0x11:
                    if ((p2 & 1) == 0) {
                        rsaCipher.init(rsa[p1], Cipher.MODE_DECRYPT);
                    }
                    Util.arrayCopyNonAtomic(buf, off, scratch, (short) 0, lc);
                    out = rsaCipher.doFinal(scratch, (short) 0, lc, buf, (short) 2);
                    Util.setShort(buf, (short) 0, out);
                    out += 2;
                    break;
                case 0x12:
                    buf[0] = rsa[p1].isInitialized() ? (byte) 1 : (byte) 0;
                    Util.setShort(buf, (short) 1, rsa[p1].getSize());
                    out = rsa[p1].getModulus(buf, (short) 4);
                    buf[3] = (byte) out;
                    out += 4;
                    break;
                case 0x20:
                case 0x21:
                    {
                        ECPrivateKey k = p1 == 0 ? ecPrivT : ecPrivT2;
                        k.setS(buf, off, (short) 32);
                        KeyAgreement ka = buf[ISO7816.OFFSET_INS] == 0x20 ? kaXY : kaGM;
                        ka.init(k);
                        Util.arrayCopyNonAtomic(
                                buf, (short) (off + 32), scratch, (short) 0, (short) (lc - 32));
                        out =
                                ka.generateSecret(
                                        scratch, (short) 0, (short) (lc - 32), buf, (short) 0);
                        break;
                    }
                case 0x22:
                    {
                        ECPrivateKey k =
                                p1 == 0
                                        ? ecPrivT
                                        : (p1 == 1 ? ecPrivT2 : (p1 == 2 ? ecPriv : ecPrivW));
                        k.setS(buf, off, lc);
                        out = k.getS(buf, (short) 0);
                        break;
                    }
                case 0x23:
                    ecPriv.setS(buf, off, (short) 32);
                    ecdsa.init(ecPriv, Signature.MODE_SIGN);
                    Util.arrayCopyNonAtomic(
                            buf, (short) (off + 32), scratch, (short) 0, (short) (lc - 32));
                    if (p1 == 0) {
                        out =
                                ecdsa.signPreComputedHash(
                                        scratch, (short) 0, (short) (lc - 32), buf, (short) 0);
                    } else {
                        out = ecdsa.sign(scratch, (short) 0, (short) (lc - 32), buf, (short) 0);
                    }
                    break;
                case 0x24:
                    {
                        short ql = (short) (buf[off] == 0x04 ? 65 : 33);
                        ecPub.setW(buf, off, ql);
                        ecdsa.init(ecPub, Signature.MODE_VERIFY);
                        short sl = (short) (lc - ql - 32);
                        Util.arrayCopyNonAtomic(
                                buf, (short) (off + ql), scratch, (short) 0, (short) (lc - ql));
                        boolean ok;
                        if (p1 == 0) {
                            ok =
                                    ecdsa.verifyPreComputedHash(
                                            scratch,
                                            (short) 0,
                                            (short) 32,
                                            scratch,
                                            (short) 32,
                                            sl);
                        } else {
                            ok =
                                    ecdsa.verify(
                                            scratch,
                                            (short) 0,
                                            (short) 32,
                                            scratch,
                                            (short) 32,
                                            sl);
                        }
                        buf[0] = ok ? (byte) 1 : (byte) 0;
                        out = 1;
                        break;
                    }
                case 0x25:
                    {
                        ECPublicKey k = p1 == 0 ? ecPub : ecPubW;
                        k.setW(buf, off, lc);
                        out = k.getW(buf, (short) 0);
                        break;
                    }
                case 0x30:
                    out = tx(buf, p1, off, lc);
                    break;
                case 0x31:
                    Util.setShort(buf, (short) 0, f[0]);
                    Util.setShort(buf, (short) 2, f[1]);
                    buf[4] = JCSystem.getTransactionDepth();
                    out = 5;
                    break;
                case 0x60:
                    out = bench(buf, p1, (short) (p2 & 0xFF), off, lc);
                    break;
                case 0x61:
                    out = Util.getShort(buf, ISO7816.OFFSET_P1);
                    if ((short) (out - 1) < 0 || out > 255) {
                        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                    }
                    rnd.nextBytes(buf, (short) 0, out);
                    break;
                case 0x62:
                    if (firstFlag[0] != 0) {
                        ISOException.throwIt(SW_ONCE);
                    }
                    firstFlag[0] = 1;
                    rnd.nextBytes(buf, (short) 0, (short) 32);
                    out = 32;
                    break;
                case 0x70:
                    out = replica(buf, p1);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (CryptoException e) {
            ISOException.throwIt((short) (0x6F10 + e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (0x6F20 + e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (0x6F30 + e.getReason()));
        } catch (ISOException e) {
            throw e;
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (0x6F50 + e.getReason()));
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt((short) 0x6F40);
        } catch (NullPointerException e) {
            ISOException.throwIt((short) 0x6F41);
        } catch (SecurityException e) {
            ISOException.throwIt((short) 0x6F42);
        } catch (RuntimeException e) {
            ISOException.throwIt((short) 0x6F4F);
        }
        if (out > 0) {
            apdu.setOutgoingAndSend((short) 0, out);
        }
    }

    private short putMem(byte[] buf, short o, byte type) {
        JCSystem.getAvailableMemory(memBuf, (short) 0, type);
        if (memBuf[0] == 0 && memBuf[1] == 0) {
            // the array overload is a no-op on the simulator; it implements only the scalar form
            memBuf[0] = JCSystem.getAvailableMemory(type);
        }
        Util.setShort(buf, o, memBuf[0]);
        Util.setShort(buf, (short) (o + 2), memBuf[1]);
        return (short) (o + 4);
    }

    private short info(byte[] buf) {
        short o = putMem(buf, (short) 0, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        o = putMem(buf, o, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        o = putMem(buf, o, JCSystem.MEMORY_TYPE_PERSISTENT);
        Util.setShort(buf, o, JCSystem.getMaxCommitCapacity());
        Util.setShort(buf, (short) (o + 2), JCSystem.getUnusedCommitCapacity());
        Util.setShort(buf, (short) (o + 4), APDU.getInBlockSize());
        Util.setShort(buf, (short) (o + 6), APDU.getOutBlockSize());
        Util.setShort(buf, (short) (o + 8), JCSystem.getVersion());
        buf[(short) (o + 10)] = JCSystem.isObjectDeletionSupported() ? (byte) 1 : (byte) 0;
        Util.setShort(buf, (short) (o + 11), poolAtInstall);
        return (short) (o + 13);
    }

    private void domain(ECPrivateKey pk, ECPublicKey pub, byte[] d) {
        if (pk != null) {
            pk.setFieldFP(d, (short) 0, (short) 32);
            pk.setA(d, (short) 32, (short) 32);
            pk.setB(d, (short) 64, (short) 32);
            pk.setG(d, (short) 96, (short) 65);
            pk.setR(d, (short) 161, (short) 32);
            pk.setK(Util.getShort(d, (short) 193));
        }
        if (pub != null) {
            pub.setFieldFP(d, (short) 0, (short) 32);
            pub.setA(d, (short) 32, (short) 32);
            pub.setB(d, (short) 64, (short) 32);
            pub.setG(d, (short) 96, (short) 65);
            pub.setR(d, (short) 161, (short) 32);
            pub.setK(Util.getShort(d, (short) 193));
        }
    }

    /**
     * The 14 allocation items (one status byte each, reported by {@code setup}): the object set of
     * the audit probe — RSA-512 keys and cipher, transient and persistent EC keys on both curves,
     * the EC key pair, the two KeyAgreement algorithms, ECDSA, AES and {@code ALG_KEYGENERATION}
     * random. Runs at install; a card that lacks an item keeps it unallocated and reports the
     * reason.
     */
    private void allocate(short item) {
        switch (item) {
            case 0:
                rsa = new RSAPrivateKey[4];
                for (short i = 0; i < 4; i++) {
                    rsa[i] =
                            (RSAPrivateKey)
                                    KeyBuilder.buildKey(
                                            KeyBuilder.TYPE_RSA_PRIVATE,
                                            KeyBuilder.LENGTH_RSA_512,
                                            false);
                }
                break;
            case 1:
                rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
                break;
            case 2:
                ecPrivT =
                        (ECPrivateKey)
                                KeyBuilder.buildKey(
                                        KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                                        KeyBuilder.LENGTH_EC_FP_256,
                                        false);
                break;
            case 3:
                ecPrivT2 =
                        (ECPrivateKey)
                                KeyBuilder.buildKey(
                                        KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                                        KeyBuilder.LENGTH_EC_FP_256,
                                        false);
                break;
            case 4:
                ecPriv =
                        (ECPrivateKey)
                                KeyBuilder.buildKey(
                                        KeyBuilder.TYPE_EC_FP_PRIVATE,
                                        KeyBuilder.LENGTH_EC_FP_256,
                                        false);
                break;
            case 5:
                ecPrivW =
                        (ECPrivateKey)
                                KeyBuilder.buildKey(
                                        KeyBuilder.TYPE_EC_FP_PRIVATE,
                                        KeyBuilder.LENGTH_EC_FP_256,
                                        false);
                break;
            case 6:
                ecPub =
                        (ECPublicKey)
                                KeyBuilder.buildKey(
                                        KeyBuilder.TYPE_EC_FP_PUBLIC,
                                        KeyBuilder.LENGTH_EC_FP_256,
                                        false);
                break;
            case 7:
                ecPubW =
                        (ECPublicKey)
                                KeyBuilder.buildKey(
                                        KeyBuilder.TYPE_EC_FP_PUBLIC,
                                        KeyBuilder.LENGTH_EC_FP_256,
                                        false);
                break;
            case 8:
                kp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
                break;
            case 9:
                kaXY = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
                break;
            case 10:
                kaGM = KeyAgreement.getInstance(KeyAgreement.ALG_EC_PACE_GM, false);
                break;
            case 11:
                ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
                break;
            case 12:
                aesP =
                        (AESKey)
                                KeyBuilder.buildKey(
                                        KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
                break;
            case 13:
                rnd = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
                break;
            default:
                break;
        }
    }

    /**
     * The post-domain setup of the audit probe: a card lacking an item reports its install-time
     * status; otherwise the domain parameters and the AES key content are written here, after the
     * host has loaded the two curve domains.
     */
    private short setup(byte[] buf) {
        Util.arrayFillNonAtomic(buf, (short) 0, (short) 14, (byte) 0);
        for (short item = 0; item < 14; item++) {
            if (allocStatus[item] != 0) {
                buf[item] = allocStatus[item];
                continue;
            }
            try {
                configure(item);
            } catch (CryptoException e) {
                buf[item] = (byte) (0x10 + e.getReason());
            } catch (SystemException e) {
                buf[item] = (byte) (0x20 + e.getReason());
            } catch (CardRuntimeException e) {
                buf[item] = (byte) (0x50 + e.getReason());
            } catch (RuntimeException e) {
                buf[item] = (byte) 0x4F;
            }
        }
        return 14;
    }

    private void configure(short item) {
        switch (item) {
            case 2:
                domain(ecPrivT, null, domS);
                break;
            case 3:
                domain(ecPrivT2, null, domW);
                break;
            case 4:
                // W = the domain's own G: the persistent keys must be initialized because the
                // transaction tests read getW/getS before writing
                domain(ecPriv, null, domS);
                ecPriv.setS(ONE, (short) 0, (short) 32);
                break;
            case 5:
                domain(ecPrivW, null, domW);
                ecPrivW.setS(ONE, (short) 0, (short) 32);
                break;
            case 6:
                domain(null, ecPub, domS);
                ecPub.setW(domS, (short) 96, (short) 65);
                break;
            case 7:
                domain(null, ecPubW, domW);
                ecPubW.setW(domW, (short) 96, (short) 65);
                break;
            case 8:
                domain((ECPrivateKey) kp.getPrivate(), (ECPublicKey) kp.getPublic(), domS);
                break;
            case 12:
                aesP.setKey(domS, (short) 16);
                break;
            default:
                break;
        }
    }

    /**
     * Transaction semantics of arrays and key objects: sub 0 AES {@code setKey}, 1 {@code setW}, 2
     * {@code genKeyPair}, 4 {@code setExponent}, 5 persistent array write, 6 a transaction left
     * open for power loss, 12 {@code setS}. Every case except 6 aborts or commits explicitly.
     */
    private short tx(byte[] buf, byte sub, short off, short lc) {
        Util.arrayCopyNonAtomic(buf, off, scratch, (short) 0, lc);
        switch (sub) {
            case 0:
                {
                    aesP.getKey(buf, (short) 0);
                    short c0 = JCSystem.getUnusedCommitCapacity();
                    JCSystem.beginTransaction();
                    short c1 = JCSystem.getUnusedCommitCapacity();
                    aesP.setKey(scratch, (short) 0);
                    short c2 = JCSystem.getUnusedCommitCapacity();
                    JCSystem.abortTransaction();
                    aesP.getKey(buf, (short) 16);
                    Util.setShort(buf, (short) 32, c0);
                    Util.setShort(buf, (short) 34, c1);
                    Util.setShort(buf, (short) 36, c2);
                    return 38;
                }
            case 1:
                {
                    short o = ecPub.getW(buf, (short) 0);
                    JCSystem.beginTransaction();
                    short c1 = JCSystem.getUnusedCommitCapacity();
                    ecPub.setW(scratch, (short) 0, lc);
                    short c2 = JCSystem.getUnusedCommitCapacity();
                    JCSystem.abortTransaction();
                    o = ecPub.getW(buf, (short) 65);
                    Util.setShort(buf, (short) 130, c1);
                    Util.setShort(buf, (short) 132, c2);
                    return 134;
                }
            case 2:
                {
                    ((ECPublicKey) kp.getPublic()).getW(buf, (short) 0);
                    JCSystem.beginTransaction();
                    short c1 = JCSystem.getUnusedCommitCapacity();
                    kp.genKeyPair();
                    short c2 = JCSystem.getUnusedCommitCapacity();
                    JCSystem.abortTransaction();
                    ((ECPublicKey) kp.getPublic()).getW(buf, (short) 65);
                    Util.setShort(buf, (short) 130, c1);
                    Util.setShort(buf, (short) 132, c2);
                    return 134;
                }
            case 4:
                {
                    short e0 = rsa[0].getExponent(buf, (short) 1);
                    buf[0] = (byte) e0;
                    JCSystem.beginTransaction();
                    short c1 = JCSystem.getUnusedCommitCapacity();
                    rsa[0].setExponent(scratch, (short) 0, lc);
                    short c2 = JCSystem.getUnusedCommitCapacity();
                    JCSystem.abortTransaction();
                    short p = (short) (e0 + 1);
                    short e2 = rsa[0].getExponent(buf, (short) (p + 1));
                    buf[p] = (byte) e2;
                    p = (short) (p + 1 + e2);
                    Util.setShort(buf, p, c1);
                    Util.setShort(buf, (short) (p + 2), c2);
                    return (short) (p + 4);
                }
            case 5:
                {
                    buf[0] = nv[0];
                    JCSystem.beginTransaction();
                    nv[0] = (byte) (nv[0] + 1);
                    JCSystem.abortTransaction();
                    buf[1] = nv[0];
                    return 2;
                }
            case 6:
                {
                    short f0 = f[0];
                    JCSystem.beginTransaction();
                    f[0] = (short) (f0 + 1);
                    f[1] = (short) ~(f0 + 1);
                    Util.setShort(buf, (short) 0, f[0]);
                    Util.setShort(buf, (short) 2, f[1]);
                    buf[4] = (f[0] == (short) ~f[1]) ? (byte) 1 : (byte) 0;
                    buf[5] = JCSystem.getTransactionDepth();
                    return 6;
                }
            case 12:
                {
                    ecPriv.getS(buf, (short) 0);
                    JCSystem.beginTransaction();
                    short c1 = JCSystem.getUnusedCommitCapacity();
                    ecPriv.setS(scratch, (short) 0, (short) 32);
                    short c2 = JCSystem.getUnusedCommitCapacity();
                    JCSystem.abortTransaction();
                    ecPriv.getS(buf, (short) 32);
                    Util.setShort(buf, (short) 64, c1);
                    Util.setShort(buf, (short) 66, c2);
                    return 68;
                }
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        return 0;
    }

    /**
     * Endurance and write shapes for the NVM row: op 16 {@code ecPub.setW}, 19 the T-FAIL/T-OK
     * fails pair, 27 {@code ecPriv.setS}, 30 the T-OFFER shape ({@code genKeyPair} + offer write in
     * one transaction).
     */
    private short bench(byte[] buf, byte op, short reps, short off, short lc) {
        Util.arrayCopyNonAtomic(buf, off, scratch, (short) 0, lc);
        for (short i = 0; i < reps; i++) {
            switch (op) {
                case 16:
                    ecPub.setW(scratch, (short) 0, (short) 65);
                    break;
                case 19:
                    JCSystem.beginTransaction();
                    f[0] = (short) (f[0] + 1);
                    f[1] = (short) ~f[0];
                    JCSystem.commitTransaction();
                    break;
                case 27:
                    ecPriv.setS(scratch, (short) 0, (short) 32);
                    break;
                case 30:
                    JCSystem.beginTransaction();
                    kp.genKeyPair();
                    Util.setShort(nv, OFF_OFFER, (short) 0x5555);
                    JCSystem.commitTransaction();
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        }
        Util.setShort(buf, (short) 0, reps);
        return 2;
    }

    /**
     * One named-transaction replica (Admission 8, see the class table): the production write set
     * executed inside one transaction, then {@code max - unused} commit bytes, the maximum commit
     * capacity and the three memory pools. {@code scratch} supplies the fresh random stand-ins.
     */
    private short replica(byte[] buf, byte id) {
        rnd.nextBytes(scratch, (short) 0, (short) 160);
        JCSystem.beginTransaction();
        switch (id) {
            case 0:
                Util.arrayCopy(scratch, (short) 0, nv, OFF_CERT, (short) 97);
                ecPub.setW(domS, (short) 96, (short) 65);
                Util.setShort(nv, OFF_LIFE, (short) 0x0FF0);
                break;
            case 1:
            case 2:
                aesP.setKey(scratch, (short) 0);
                writeCreate(scratch);
                ecPriv.setS(scratch, (short) 16, (short) 32);
                Util.setShort(nv, OFF_OFFER, (short) 0x3CC3);
                Util.setShort(nv, OFF_LIFE, (short) 0x3333);
                break;
            case 3:
                kp.genKeyPair();
                Util.setShort(nv, OFF_OFFER, (short) 0x5555);
                break;
            case 4:
                aesP.setKey(scratch, (short) 0);
                Util.arrayCopy(scratch, (short) 16, nv, OFF_CT, (short) 64);
                Util.arrayCopy(scratch, (short) 80, nv, OFF_TAG, (short) 16);
                break;
            case 5:
                Util.setShort(nv, OFF_LIFE, (short) 0x0FF0);
                aesP.setKey(scratch, (short) 0);
                clear(nv, OFF_ORIGIN, (short) 2);
                clear(nv, OFF_MEMBERS, (short) (OFF_TAG + 16 - OFF_MEMBERS));
                Util.setShort(nv, OFF_FAILS, (short) 0);
                Util.setShort(nv, (short) (OFF_FAILS + 2), (short) -1);
                ecPriv.setS(scratch, (short) 16, (short) 32);
                Util.setShort(nv, OFF_OFFER, (short) 0x3CC3);
                break;
            case 6:
                f[0] = (short) (f[0] + 1);
                Util.setShort(nv, OFF_FAILS, f[0]);
                Util.setShort(nv, (short) (OFF_FAILS + 2), (short) ~f[0]);
                break;
            case 7:
                Util.setShort(nv, OFF_FAILS, (short) 0);
                Util.setShort(nv, (short) (OFF_FAILS + 2), (short) -1);
                break;
            case 8:
                Util.arrayCopy(scratch, (short) 0, nv, OFF_EDCOUNTER, (short) 4);
                break;
            default:
                JCSystem.abortTransaction();
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        short used = (short) (JCSystem.getMaxCommitCapacity() - JCSystem.getUnusedCommitCapacity());
        JCSystem.commitTransaction();
        Util.setShort(buf, (short) 0, used);
        Util.setShort(buf, (short) 2, JCSystem.getMaxCommitCapacity());
        short o = putMem(buf, (short) 4, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        o = putMem(buf, o, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        return putMem(buf, o, JCSystem.MEMORY_TYPE_PERSISTENT);
    }

    /** The T-CREATE / T-INSTALL state writes (production order in {@code Wallet.tCreate}). */
    private void writeCreate(byte[] scratch) {
        Util.arrayCopy(scratch, (short) 16, nv, OFF_CT, (short) 64);
        Util.arrayCopy(scratch, (short) 80, nv, OFF_TAG, (short) 16);
        Util.arrayCopy(scratch, (short) 96, nv, OFF_FP, (short) 32);
        Util.setShort(nv, OFF_ORIGIN, (short) 0x33CC);
        Util.arrayCopy(scratch, (short) 128, nv, OFF_MEMBERS, (short) 49);
        Util.setShort(nv, OFF_FAILS, (short) 0);
        Util.setShort(nv, (short) (OFF_FAILS + 2), (short) -1);
    }

    /** The chunked persistent clear of {@code State.clear} (32 B atomic copies at most). */
    private static void clear(byte[] dst, short off, short len) {
        short at = off;
        short left = len;
        while (left != 0) {
            short n = left;
            if ((short) (n - 33) >= 0) {
                n = 32;
            }
            Util.arrayCopy(ZEROS, (short) 0, dst, at, n);
            at += n;
            left -= n;
        }
    }
}
