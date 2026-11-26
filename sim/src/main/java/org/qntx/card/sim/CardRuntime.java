// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import com.licel.jcardsim.base.SimulatorRuntime;
import com.licel.jcardsim.base.SimulatorSystem;
import com.licel.jcardsim.crypto.ByteContainer;
import com.licel.jcardsim.framework.APDUProxy;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import javacard.framework.SystemException;
import javacard.framework.TransactionException;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Card A runtime model (architecture spec section 8): command-local persistent-write counting, an
 * armed tear point, the transaction journal with measured commit-buffer accounting, and the
 * measured transient pool. The {@link Agent} routes applet bytecode writes through {@link
 * Nvm}/{@link Memory}, which land here.
 *
 * <p>The journal records byte-level pre-images of persistent arrays and reflective pre-images of
 * {@link ByteContainer}-backed key fields, so abort and power loss restore the same state a real
 * commit buffer would have held. The buffer is charged in 1024 B spans per touched array and in
 * measured flat amounts for key writes (512 B setters, 1024 B {@code setW}/{@code genKeyPair}),
 * capped at 5120 B.
 */
public final class CardRuntime extends SimulatorRuntime {

    enum Phase {
        INSTALL,
        COMMAND
    }

    public static final int MAX_COMMIT = 5120;
    public static final int COMMIT_SPAN = 1024;
    public static final int COMMIT_PAGE = 512;
    public static final int SET_KEY_CHARGE = 512;
    public static final int SET_W_CHARGE = 1024;
    public static final int KEY_GEN_CHARGE = 1024;
    public static final int TRANSIENT_POOL = 3990;
    public static final int TRANSIENT_BUDGET = 3390;

    private static final ThreadLocal<CardRuntime> CURRENT = new ThreadLocal<>();

    static CardRuntime current() {
        return CURRENT.get();
    }

    private Phase phase;
    private int writes;
    private int armedWrite;
    private int commitUsed;
    private int lastCommitBytes;
    private final List<Integer> commits = new ArrayList<>();
    private final List<Runnable> journal = new ArrayList<>();
    private final IdentityHashMap<Object, int[]> spans = new IdentityHashMap<>();
    private final IdentityHashMap<Object, Object> keySnapshots = new IdentityHashMap<>();
    private final Set<Object> appletArrays = Collections.newSetFromMap(new IdentityHashMap<>());
    private int transientUsed;
    private final List<String> transientAllocations = new ArrayList<>();
    private final int[] digestCalls = new int[64];
    private final int[] digestBytes = new int[64];
    private final int[] digestResets = new int[64];

    /**
     * Per-allocation charge of the install journal: the memprobe measured 0 on card A (architecture
     * §8 patch 2) — allocations are not charged to the install journal there.
     */
    static final int INSTALL_ALLOC_CHARGE = 0;

    /** Commit-buffer bytes charged by the current (or last) install phase. */
    private int installUsed;

    void bind(Phase newPhase) {
        CURRENT.set(this);
        phase = newPhase;
        if (newPhase == Phase.INSTALL) {
            installUsed = 0;
            spans.clear();
        }
    }

    void unbind() {
        CURRENT.remove();
        phase = null;
    }

    /** The installed applet object, for tests that inspect transient state by reflection. */
    public javacard.framework.Applet applet(javacard.framework.AID aid) {
        return getApplet(aid);
    }

    /**
     * Deselects the currently selected applet the way the platform does on a SELECT of something
     * else: {@code Applet.deselect()}, an open transaction aborted, CLEAR_ON_DESELECT transient
     * memory cleared ({@code SimulatorRuntime.deselect}).
     */
    void deselectCurrent() {
        if (getAID() != null) {
            deselect(lookupApplet(getAID()));
        }
        currentAID = null;
    }

    /**
     * Transient EC keys created through {@link Memory#buildKey}, split by clearing event (patch
     * 13): jcardsim clears transient arrays on deselection but leaves key objects alone, while on
     * card A a {@code TRANSIENT_DESELECT} EC key loses its domain parameters — not only its value —
     * when its applet is deselected, and a {@code TRANSIENT_RESET} key loses them on reset
     * (audit-impl probe-transient-reselect). The lists hold at most a handful of install-time keys;
     * clearing is idempotent, so running it on every deselection boundary is enough.
     */
    private final List<Key> deselectEcKeys = new ArrayList<>();

    private final List<Key> resetEcKeys = new ArrayList<>();

    /** Registers a transient EC private key under its clearing event; other types are ignored. */
    void trackTransientEc(byte keyType, Key key) {
        if (keyType == KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT) {
            deselectEcKeys.add(key);
        } else if (keyType == KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET) {
            resetEcKeys.add(key);
        }
    }

    /**
     * Patch 13: after the platform's own deselection work, clear every {@code TRANSIENT_DESELECT}
     * EC key — value and domain — the way card A clears them. A cleared key refuses {@code setS}
     * with {@code CryptoException.ILLEGAL_VALUE} until its domain is loaded again, which the wallet
     * applet does in {@code select()}.
     */
    @Override
    protected void deselect(ApplicationInstance applicationInstance) {
        super.deselect(applicationInstance);
        for (Key key : deselectEcKeys) {
            key.clearKey();
        }
    }

    /** Largest chunk one {@code APDU.receiveBytes} call delivers; 0 = single delivery. */
    private short receiveChunk;
    private boolean stall;

    /**
     * Sim switch for the multi-block receive path (§16.3): {@code APDU.receiveBytes} delivers at
     * most {@code n} bytes per call while this command runs; {@code n ≤ 0} restores single
     * delivery.
     */
    void receiveChunk(int n) {
        receiveChunk = (short) n;
    }

    /** Sim switch: {@code APDU.receiveBytes} returns 0 from the next command on (§16.3). */
    void receiveStall(boolean stall) {
        this.stall = stall;
    }

    /** {@code APDU.receiveBytes} calls since {@link #startCommand}. */
    int receiveCalls() {
        return SimulatorSystem.receiveCalls;
    }

    void startCommand() {
        writes = 0;
        commits.clear();
        APDUProxy.setReceiveChunk(receiveChunk);
        SimulatorSystem.receiveStall = stall;
        SimulatorSystem.receiveCalls = 0;
        Arrays.fill(digestCalls, 0);
        Arrays.fill(digestBytes, 0);
        Arrays.fill(digestResets, 0);
        // lastCommitBytes intentionally survives: it reports the last
        // transaction's commit-buffer consumption until the next one ends
        bind(Phase.COMMAND);
    }

    boolean inCommand() {
        return phase == Phase.COMMAND;
    }

    /**
     * Records a wrapped digest's input (patch 6): {@code doFinal} calls count once per call; {@code
     * update} and {@code doFinal} inputs add to the command's byte total.
     */
    void digest(byte algorithm, int inputBytes, boolean isFinal) {
        digestBytes[algorithm & 0xFF] += inputBytes;
        if (isFinal) {
            digestCalls[algorithm & 0xFF]++;
        }
    }

    /** {@code reset} calls on wrapped {@code algorithm} engines during the last command. */
    void digestReset(byte algorithm) {
        digestResets[algorithm & 0xFF]++;
    }

    /** {@code doFinal} calls on wrapped {@code algorithm} engines during the last command. */
    int digests(byte algorithm) {
        return digestCalls[algorithm & 0xFF];
    }

    /** Input bytes fed to wrapped {@code algorithm} engines during the last command. */
    int digestBytes(byte algorithm) {
        return digestBytes[algorithm & 0xFF];
    }

    /** {@code reset} calls on wrapped {@code algorithm} engines during the last command. */
    int resets(byte algorithm) {
        return digestResets[algorithm & 0xFF];
    }

    /** Registers an array allocated by instrumented applet bytecode as applet-owned card memory. */
    void registerArray(Object array) {
        installAlloc();
        appletArrays.add(array);
    }

    /**
     * Persistent arrays are exactly the arrays the applet allocated itself. APDU buffers,
     * transient-memory allocations, jcardsim temporaries and arrays other agents plant inside the
     * applet (coverage probes) never qualify.
     */
    boolean isPersistentArray(Object array) {
        return appletArrays.contains(array);
    }

    /**
     * One atomic persistent write of {@code length} bytes at {@code offset}: commit-buffer check,
     * write counter/tear point, then span accounting and pre-image journaling while a transaction
     * is open. The store itself happens in {@link Nvm} after this call returns, so a {@link
     * PowerLoss} here leaves it unwritten.
     */
    void arrayWrite(Object array, int offset, int length) {
        int delta = 0;
        if (transactionDepth != 0) {
            delta = spanDelta(array, offset, offset + length);
            checkCommitCapacity(delta);
        } else if (phase == Phase.INSTALL) {
            delta = spanDelta(array, offset, offset + length);
            checkInstallJournal(delta);
        }
        countWrite();
        if (transactionDepth != 0) {
            applySpan(array, offset, offset + length);
            journalArray(array, offset, length);
            commitUsed += delta;
        } else if (phase == Phase.INSTALL) {
            // the install journal charges like an open transaction but journals no pre-image:
            // a failed install is discarded whole
            applySpan(array, offset, offset + length);
            installUsed += delta;
        }
    }

    /**
     * A non-atomic write point: counted and tearable, never journaled or charged, so a torn copy
     * can stop half-written (patch 5).
     */
    void arrayWritePoint() {
        countWrite();
    }

    /**
     * A persistent key-object write: flat commit-buffer charge, one counted write, and a one-time
     * reflective snapshot of the key's {@link ByteContainer} fields while a transaction is open.
     */
    void keyWrite(Object key, int charge) {
        if (transactionDepth != 0) {
            checkCommitCapacity(charge);
        } else if (phase == Phase.INSTALL) {
            checkInstallJournal(charge);
        }
        countWrite();
        if (transactionDepth != 0) {
            commitUsed += charge;
            snapshotKeyOnce(key);
        } else if (phase == Phase.INSTALL) {
            installUsed += charge;
        }
    }

    /** {@code KeyPair.genKeyPair}: one shared 1024 B charge, both keys snapshotted. */
    void keyPairWrite(Object publicKey, Object privateKey) {
        if (transactionDepth != 0) {
            checkCommitCapacity(KEY_GEN_CHARGE);
        } else if (phase == Phase.INSTALL) {
            checkInstallJournal(KEY_GEN_CHARGE);
        }
        countWrite();
        if (transactionDepth != 0) {
            commitUsed += KEY_GEN_CHARGE;
            if (publicKey instanceof Key && !Nvm.isTransientKeyType(((Key) publicKey).getType())) {
                snapshotKeyOnce(publicKey);
            }
            if (privateKey instanceof Key
                    && !Nvm.isTransientKeyType(((Key) privateKey).getType())) {
                snapshotKeyOnce(privateKey);
            }
        } else if (phase == Phase.INSTALL) {
            installUsed += KEY_GEN_CHARGE;
        }
    }

    /**
     * Charge of one applet allocation observed by the agent ({@code new T[]}, {@code buildKey},
     * {@code makeTransient*}, engine {@code getInstance}) against the install journal — {@link
     * #INSTALL_ALLOC_CHARGE} as measured on card A.
     */
    void installAlloc() {
        if (phase == Phase.INSTALL) {
            checkInstallJournal(INSTALL_ALLOC_CHARGE);
            installUsed += INSTALL_ALLOC_CHARGE;
        }
    }

    /** Commit-buffer bytes the last install phase charged (like {@link #lastCommitBytes}). */
    int installUsed() {
        return installUsed;
    }

    private void checkInstallJournal(int delta) {
        if (installUsed + delta > MAX_COMMIT) {
            TransactionException.throwIt(TransactionException.BUFFER_FULL);
        }
    }

    /**
     * The command's persistent-write counter and the armed tear point. Only command-phase writes
     * count; firing throws {@link PowerLoss} before the write it was armed on takes effect, so
     * write N of a torn command leaves exactly writes 1..N-1 applied.
     */
    private void countWrite() {
        if (phase != Phase.COMMAND) {
            return;
        }
        writes++;
        if (armedWrite > 0 && writes >= armedWrite) {
            armedWrite = 0;
            throw new PowerLoss();
        }
    }

    /**
     * Grow the touched span of {@code array} to cover [{@code lo}, {@code hiExclusive}) and return
     * the extra commit bytes the merged span costs: every started 512 B page bills two pages, so
     * span charge = ceil(spanBytes / 512) * 1024 (audit F-6).
     */
    private int spanDelta(Object array, int lo, int hiExclusive) {
        int[] span = spans.get(array);
        int newLo = span == null ? lo : Math.min(span[0], lo);
        int newHi = span == null ? hiExclusive : Math.max(span[1], hiExclusive);
        int oldCharge = span == null ? 0 : spanCharge(span[1] - span[0]);
        return spanCharge(newHi - newLo) - oldCharge;
    }

    private void applySpan(Object array, int lo, int hiExclusive) {
        int[] span = spans.get(array);
        if (span == null) {
            spans.put(array, new int[] {lo, hiExclusive});
        } else {
            span[0] = Math.min(span[0], lo);
            span[1] = Math.max(span[1], hiExclusive);
        }
    }

    private static int spanCharge(int spanBytes) {
        return ((spanBytes + COMMIT_PAGE - 1) / COMMIT_PAGE) * COMMIT_SPAN;
    }

    private void checkCommitCapacity(int delta) {
        if (commitUsed + delta > MAX_COMMIT) {
            TransactionException.throwIt(TransactionException.BUFFER_FULL);
        }
    }

    private void journalArray(Object array, int offset, int length) {
        if (array instanceof byte[] bytes) {
            byte[] preimage = new byte[length];
            System.arraycopy(bytes, offset, preimage, 0, length);
            journal.add(() -> System.arraycopy(preimage, 0, bytes, offset, length));
        } else if (array instanceof short[] shorts) {
            short[] preimage = new short[length];
            System.arraycopy(shorts, offset, preimage, 0, length);
            journal.add(() -> System.arraycopy(preimage, 0, shorts, offset, length));
        } else if (array instanceof boolean[] booleans) {
            boolean[] preimage = new boolean[length];
            System.arraycopy(booleans, offset, preimage, 0, length);
            journal.add(() -> System.arraycopy(preimage, 0, booleans, offset, length));
        }
    }

    /**
     * Snapshot the key's writable {@link ByteContainer} fields and scalar state once per
     * transaction; the undo entry restores all of them, which is what a real commit buffer covering
     * key EEPROM does.
     */
    private void snapshotKeyOnce(Object key) {
        if (keySnapshots.containsKey(key)) {
            return;
        }
        List<Object[]> saved = new ArrayList<>();
        for (Class<?> c = key.getClass(); c != null; c = c.getSuperclass()) {
            for (Field field : c.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers()) || field.isSynthetic()) {
                    continue;
                }
                try {
                    field.setAccessible(true);
                    if (ByteContainer.class.isAssignableFrom(field.getType())) {
                        ByteContainer container = (ByteContainer) field.get(key);
                        if (container != null) {
                            saved.add(new Object[] {field, container.save(), Boolean.TRUE});
                        }
                    } else {
                        saved.add(new Object[] {field, field.get(key), Boolean.FALSE});
                    }
                } catch (ReflectiveOperationException | RuntimeException e) {
                    // a field we cannot snapshot would restore
                    // incompletely on rollback with no other signal
                    throw new IllegalStateException("cannot journal key field " + field, e);
                }
            }
        }
        keySnapshots.put(key, saved);
        journal.add(() -> restoreKey(key, saved));
    }

    private static void restoreKey(Object key, List<Object[]> saved) {
        for (Object[] record : saved) {
            Field field = (Field) record[0];
            try {
                if (record[2] == Boolean.TRUE) {
                    ((ByteContainer) field.get(key)).restore(record[1]);
                } else {
                    field.set(key, record[1]);
                }
            } catch (ReflectiveOperationException | RuntimeException e) {
                throw new IllegalStateException("journal restore failed for " + field, e);
            }
        }
    }

    @Override
    public void beginTransaction() {
        super.beginTransaction();
        journal.clear();
        spans.clear();
        keySnapshots.clear();
        commitUsed = 0;
    }

    @Override
    public void commitTransaction() {
        super.commitTransaction();
        recordCommit();
        journal.clear();
        spans.clear();
        keySnapshots.clear();
    }

    @Override
    public void abortTransaction() {
        super.abortTransaction();
        rollback();
        recordCommit();
    }

    private void rollback() {
        for (int i = journal.size() - 1; i >= 0; i--) {
            journal.get(i).run();
        }
        journal.clear();
        spans.clear();
        keySnapshots.clear();
    }

    private void recordCommit() {
        lastCommitBytes = commitUsed;
        commits.add(commitUsed);
        commitUsed = 0;
    }

    /**
     * Power loss while a transaction is open rolls the buffer back before the card resets, so the
     * next power-up sees pre-transaction state (patch 5).
     */
    void powerLoss() {
        if (transactionDepth != 0) {
            rollback();
            recordCommit();
            transactionDepth = 0;
        }
        armedWrite = 0;
        reset();
    }

    @Override
    public void reset() {
        super.reset();
        for (Key key : deselectEcKeys) {
            key.clearKey();
        }
        for (Key key : resetEcKeys) {
            key.clearKey();
        }
        journal.clear();
        spans.clear();
        keySnapshots.clear();
        commitUsed = 0;
        armedWrite = 0;
    }

    void armTear(int n) {
        armedWrite = n;
    }

    int writes() {
        return writes;
    }

    int lastCommitBytes() {
        return lastCommitBytes;
    }

    List<Integer> commits() {
        return List.copyOf(commits);
    }

    /** Measured 5120 B commit buffer (audit-impl card memory dump). */
    @Override
    public short getMaxCommitCapacity() {
        return MAX_COMMIT;
    }

    @Override
    public short getUnusedCommitCapacity() {
        return (short) (MAX_COMMIT - commitUsed);
    }

    @Override
    public short getAvailableTransientResetMemory() {
        return (short) (TRANSIENT_POOL - transientUsed);
    }

    @Override
    public short getAvailableTransientDeselectMemory() {
        return (short) (TRANSIENT_POOL - transientUsed);
    }

    /**
     * Charge {@code bytes} against the shared 3990 B transient pool and record the allocation for
     * {@link #memoryReport()}.
     */
    void chargeTransient(int bytes, String description) {
        if (transientUsed + bytes > TRANSIENT_POOL) {
            SystemException.throwIt(SystemException.NO_TRANSIENT_SPACE);
        }
        transientUsed += bytes;
        transientAllocations.add(description + " " + bytes);
    }

    /**
     * Measured transient-key cost of a {@code KeyBuilder} type/length pair (patch 6, audit-impl
     * memory.out). Persistent keys are free; a transient pair card A does not carry must fail
     * instead of simulating unmeasured memory.
     */
    void chargeTransientKey(byte keyType, short keyLength) {
        installAlloc();
        switch (keyType) {
            case KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET:
                if (keyLength == KeyBuilder.LENGTH_EC_FP_256) {
                    chargeTransient(272, "EC FP private transient 256");
                    return;
                }
                break;
            case KeyBuilder.TYPE_AES_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_AES_TRANSIENT_RESET:
                if (keyLength == KeyBuilder.LENGTH_AES_128) {
                    chargeTransient(32, "AES transient 128");
                    return;
                }
                break;
            default:
        }
        if (Nvm.isTransientKeyType(keyType)) {
            throw new IllegalStateException(
                    "unmeasured transient key on card A: type " + keyType + " length " + keyLength);
        }
    }

    /**
     * Measured engine transient sizes (patch 6, audit-impl memory.out); any other algorithm fails
     * the allocation loudly.
     */
    void chargeEngine(String kind, byte algorithm) {
        installAlloc();
        int size =
                switch (kind) {
                    case "cipher" ->
                            switch (algorithm) {
                                case Cipher.ALG_AES_BLOCK_128_CBC_NOPAD -> 48;
                                case Cipher.ALG_RSA_NOPAD -> 0;
                                default -> rejectUnmeasured("Cipher algorithm " + algorithm);
                            };
                    case "signature" ->
                            switch (algorithm) {
                                case Signature.ALG_AES_CMAC_128 -> 32;
                                case Signature.ALG_ECDSA_SHA_256 -> 112;
                                default -> rejectUnmeasured("Signature algorithm " + algorithm);
                            };
                    case "digest" ->
                            switch (algorithm) {
                                case MessageDigest.ALG_SHA_256 -> 128;
                                case MessageDigest.ALG_SHA_512 -> 208;
                                default -> rejectUnmeasured("MessageDigest algorithm " + algorithm);
                            };
                    case "agreement" ->
                            switch (algorithm) {
                                case KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY,
                                        KeyAgreement.ALG_EC_PACE_GM ->
                                        0;
                                default -> rejectUnmeasured("KeyAgreement algorithm " + algorithm);
                            };
                    case "random" ->
                            switch (algorithm) {
                                case RandomData.ALG_KEYGENERATION -> 0;
                                default -> rejectUnmeasured("RandomData algorithm " + algorithm);
                            };
                    default -> throw new IllegalArgumentException(kind);
                };
        chargeTransient(size, kind + " algorithm " + algorithm);
    }

    /**
     * Reject engine instances card A does not support or measure; creating one must fail loudly
     * rather than simulate unmeasured memory (patch 6). Typed so it can arm a switch branch.
     */
    <T> T rejectUnmeasured(String what) {
        throw new IllegalStateException("unmeasured engine on card A: " + what);
    }

    int transientUsed() {
        return transientUsed;
    }

    String memoryReport() {
        StringBuilder report = new StringBuilder();
        for (String allocation : transientAllocations) {
            report.append(allocation).append('\n');
        }
        report.append("total ")
                .append(transientUsed)
                .append(" / ")
                .append(TRANSIENT_POOL)
                .append(" (budget ")
                .append(TRANSIENT_BUDGET)
                .append(')');
        return report.toString();
    }

    /** A copy of the simulator's shared APDU buffer as the last command left it. */
    byte[] apduBuffer() {
        byte[] buffer = getCurrentAPDU().getBuffer();
        return Arrays.copyOf(buffer, buffer.length);
    }
}
