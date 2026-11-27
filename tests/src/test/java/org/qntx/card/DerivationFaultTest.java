// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import javacard.framework.Applet;
import javacard.framework.Util;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Transfer;
import org.qntx.card.sim.Agent;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.tests.EmuMember;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * §5.2 regression tests for the §16.2 item-5 derivation gates: the transfer keys of EXPORT/IMPORT
 * P1=00 come from two independent ECDH products and KDFs compared before {@code setKey} and read
 * back after, the CREATE seed and every staged copy of seed material or an access hash is compared
 * with its source, OPEN derives its session keys twice and reads the key objects back, and {@code
 * receiveAll} is bounded. Each test arms one fault and asserts {@code 6F00} (or refusal) with the
 * card's state unchanged — before the fix the same faults produced {@code 9000} with a public or
 * zero key, seed or access hash (evidence: the released-behavior run of these cases).
 *
 * <p>API-call faults are armed as invoke-site skips on the caller's site, so this class needs the
 * {@code sites} weave (the {@code gateSweep} task); it self-skips under the plain weave. Site
 * numbers (javap order):
 *
 * <ul>
 *   <li>{@code Session.open}: i9 {@code randomScalar}, i24/i25 {@code Kdf.kdf}, i28..i31 {@code
 *       setKey}, i32..i35 {@code getKey}
 *   <li>{@code Transfer.export0}: i13 {@code randomScalar}, i19 {@code agree} (product 1), i22
 *       {@code mul} (product 2); {@code Transfer.import0}: i30/i33 {@code agree}
 *   <li>{@code Transfer.loadKeys}: i3 {@code kTe.setKey}, i4 {@code kTm.setKey}
 *   <li>{@code Transfer.export1}: i4 seed copy, i5 access-hash copy
 *   <li>{@code Wallet.install}: i1 seed copy, i2 access-hash copy, i3 member copy
 *   <li>{@code Wallet.create}: i7 {@code nextBytes(t)}, i10/i11 {@code seedHash}, i17 P1=01 seed
 *       copy, i29 access-hash copy
 *   <li>{@code Wallet.seedHash}: i3 {@code update(t)}, i4 {@code doFinal}; {@code Kdf.kdf}: i3
 *       {@code update(z)}, i6 {@code doFinal}; {@code Secp256k1.agree}: i2 {@code generateSecret}
 *   <li>{@code WalletApplet.receiveAll}: i1 {@code setIncomingAndReceive}, i4 {@code receiveBytes}
 * </ul>
 */
final class DerivationFaultTest {

    private static final int INS_CREATE = 0x21;
    private static final int INS_VERIFY = 0x22;
    private static final int INS_OFFER = 0x40;
    private static final int INS_EXPORT = 0x41;
    private static final int INS_IMPORT = 0x42;
    private static final byte[] EMPTY = new byte[0];

    @BeforeEach
    void needsSites() {
        assumeTrue(Agent.siteWeaving(), "instruction-site weaving is not enabled");
    }

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    private static final class Side {
        final Card card;
        final byte[] a;
        final byte[] cert;
        Session session;

        Side() throws Exception {
            card = Vecs.factory();
            a = Vecs.cardA(card);
            cert = Vecs.certFor(a);
            Vecs.blankFor(card, a);
            session = Vecs.open(card);
        }

        Response inner(int ins, int p1, byte[] data) throws Exception {
            return Vecs.roundtrip(card, session, ins, p1, 0, data);
        }

        void create(byte[]... ids) throws Exception {
            byte[] data = new byte[96 + 16 * ids.length];
            System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
            System.arraycopy(Vecs.seed(), 0, data, 32, 64);
            for (int i = 0; i < ids.length; i++) {
                System.arraycopy(ids[i], 0, data, 96 + 16 * i, 16);
            }
            assertEquals(0x9000, inner(INS_CREATE, 1, data).sw(), "CREATE");
        }

        void verify() throws Exception {
            assertEquals(0x9000, inner(INS_VERIFY, 0, Vecs.accessHash()).sw(), "VERIFY");
        }

        byte[] offer() throws Exception {
            Response r = inner(INS_OFFER, 0, EMPTY);
            assertEquals(0x9000, r.sw(), "OFFER");
            return r.data();
        }

        /** A 6F00 tears the card session down: a fresh OPEN and, for a LOADED card, VERIFY. */
        void reopen(boolean andVerify) throws Exception {
            session = Vecs.open(card);
            if (andVerify) {
                verify();
            }
        }

        boolean blank() {
            Applet app = card.applet(Spec.WALLET_AID);
            return Util.getShort(Internals.stateArray(app), State.OFF_LIFE) == Const.LIFE_BLANK;
        }
    }

    /** A verified LOADED card holding a wallet shared with {@code member}. */
    private static Side loaded(EmuMember member) throws Exception {
        Side side = new Side();
        side.create(member.cardId);
        side.verify();
        return side;
    }

    /**
     * Asserts the fault scenario: {@code site} must be an invoke site the unfaulted {@code run}
     * executes (the assertion fails loudly if the bytecode is renumbered), then a fresh {@code
     * side}/faulted run must produce {@code 6F00}.
     */
    private static void assertSite(String prefix, String site, Runnable probe) {
        Fault.countCalls();
        try {
            probe.run();
        } finally {
            // siteCounts returns a live view: copy before reset clears it
            Map<String, Integer> sites = new TreeMap<>(Fault.siteCounts());
            Fault.reset();
            assertTrue(
                    sites.keySet().stream().anyMatch(k -> k.equals(site)),
                    site + " is not an executed site of " + prefix + ": " + sites.keySet());
        }
    }

    // ── EXPORT P1=00: two products, two KDFs, read-back (E8, E10/E11, E17) ────

    /**
     * O2's twin on the export path: a skipped scalar draw leaves the wiped {@code H[65..97)}; the
     * second {@code inRange} check refuses — before the fix a zeroed or host-computable {@code e}
     * made the transfer keys public ({@code 9000}).
     */
    @Test
    void exportZeroScalarIsCaught() throws Exception {
        EmuMember target = new EmuMember();
        Side source = loaded(target);
        Fault.armSkip("Secp256k1.randomScalar", 1);
        assertEquals(0x6F00, source.inner(INS_EXPORT, 0, target.exportRequest()).sw());
        source.reopen(true);
        assertEquals(0x6985, source.inner(INS_EXPORT, 1, Vecs.accessHashNew()).sw(), "no pending");
    }

    /**
     * Each product of the dual derivation skipped in turn: a skipped {@code agree} returns zero
     * into the product check ({@code 6A80}, an invalid-product refusal), a skipped product-2 {@code
     * mul} leaves a stale buffer whose KDF output differs from the other derivation's, so {@code
     * loadKeys} refuses ({@code 6F00}) before any key is loaded.
     */
    @Test
    void exportProductSkipsAreCaught() throws Exception {
        String[][] cases = {
            {"Transfer.export0#i19", "0x6A80"},
            {"Transfer.export0#i22", "0x6F00"},
        };
        for (String[] c : cases) {
            String site = c[0];
            int want = Integer.decode(c[1]);
            EmuMember target = new EmuMember();
            Side probe = loaded(target);
            assertSite("export0", site, () -> export0(probe, target));
            Side source = loaded(target);
            Fault.armSite(site, 1, Fault.SITE_SKIP);
            assertEquals(want, source.inner(INS_EXPORT, 0, target.exportRequest()).sw(), site);
            source.reopen(true);
            assertEquals(0x6985, source.inner(INS_EXPORT, 1, Vecs.accessHashNew()).sw());
        }
    }

    /** {@code generateSecret} inside the first {@code agree} skipped → product 1 is stale. */
    @Test
    void exportGenerateSecretSkipIsCaught() throws Exception {
        EmuMember target = new EmuMember();
        Side probe = loaded(target);
        assertSite("agree", "Secp256k1.agree#i2", () -> export0(probe, target));
        Side source = loaded(target);
        Fault.armSite("Secp256k1.agree#i2", 1, Fault.SITE_SKIP);
        assertEquals(0x6F00, source.inner(INS_EXPORT, 0, target.exportRequest()).sw());
    }

    /** Each {@code Kdf.kdf} of the two derivations skipped → outputs differ → {@code 6F00}. */
    @Test
    void exportKdfSkipsAreCaught() throws Exception {
        for (int k = 1; k <= 2; k++) {
            EmuMember target = new EmuMember();
            Side source = loaded(target);
            Fault.armSkip("Kdf.kdf", k);
            assertEquals(
                    0x6F00,
                    source.inner(INS_EXPORT, 0, target.exportRequest()).sw(),
                    "Kdf.kdf " + k);
        }
    }

    /**
     * One {@code update(z)} or {@code doFinal} inside {@code Kdf.kdf} skipped per derivation
     * ({@code nth} 1 = K1, 2 = K2): the skipped block's output differs → {@code 6F00}.
     */
    @Test
    void exportKdfStepSkipsAreCaught() throws Exception {
        for (String site : new String[] {"Kdf.kdf#i3", "Kdf.kdf#i6"}) {
            for (int nth = 1; nth <= 2; nth++) {
                EmuMember target = new EmuMember();
                Side source = loaded(target);
                Fault.armSite(site, nth, Fault.SITE_SKIP);
                assertEquals(
                        0x6F00,
                        source.inner(INS_EXPORT, 0, target.exportRequest()).sw(),
                        site + " nth=" + nth);
            }
        }
    }

    /** {@code kTe.setKey}/{@code kTm.setKey} skipped: the {@code getKey} read-back refuses. */
    @Test
    void exportSetKeySkipsAreCaught() throws Exception {
        for (String site : new String[] {"Transfer.loadKeys#i3", "Transfer.loadKeys#i4"}) {
            EmuMember target = new EmuMember();
            Side source = loaded(target);
            Fault.armSite(site, 1, Fault.SITE_SKIP);
            assertEquals(0x6F00, source.inner(INS_EXPORT, 0, target.exportRequest()).sw(), site);
            source.reopen(true);
            assertEquals(0x6985, source.inner(INS_EXPORT, 1, Vecs.accessHashNew()).sw());
        }
    }

    // ── IMPORT P1=00: two products, two KDFs, read-back (I6/I7, I10) ──────────

    /** A BLANK target with a live offer and a member source's genuine import head. */
    private static Object[] importHead(Side target, EmuMember source) throws Exception {
        byte[] offer = target.offer();
        byte[] lk = Arrays.copyOf(offer, 65);
        byte[][] head = source.importHead(target.a, lk);
        return new Object[] {head[0]};
    }

    private static void export0(Side source, EmuMember target) {
        try {
            assertEquals(
                    0x9000,
                    source.inner(INS_EXPORT, 0, target.exportRequest()).sw(),
                    "probe EXPORT0");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void importProductSkipsAreCaught() throws Exception {
        for (String site : new String[] {"Transfer.import0#i30", "Transfer.import0#i33"}) {
            EmuMember source = new EmuMember();
            Side target = new Side();
            byte[] head = (byte[]) importHead(target, source)[0];
            Fault.armSite(site, 1, Fault.SITE_SKIP);
            assertEquals(0x6F00, target.inner(INS_IMPORT, 0, head).sw(), site);
            target.reopen(false);
            assertEquals(0x6985, target.inner(INS_IMPORT, 1, new byte[160]).sw(), "no pending");
        }
    }

    @Test
    void importGenerateSecretSkipIsCaught() throws Exception {
        for (int nth = 1; nth <= 2; nth++) {
            EmuMember source = new EmuMember();
            Side target = new Side();
            byte[] head = (byte[]) importHead(target, source)[0];
            Fault.armSite("Secp256k1.agree#i2", nth, Fault.SITE_SKIP);
            assertEquals(0x6F00, target.inner(INS_IMPORT, 0, head).sw(), "nth=" + nth);
        }
    }

    @Test
    void importKdfSkipsAreCaught() throws Exception {
        for (int k = 1; k <= 2; k++) {
            EmuMember source = new EmuMember();
            Side target = new Side();
            byte[] head = (byte[]) importHead(target, source)[0];
            Fault.armSkip("Kdf.kdf", k);
            assertEquals(0x6F00, target.inner(INS_IMPORT, 0, head).sw(), "Kdf.kdf " + k);
        }
    }

    @Test
    void importSetKeySkipsAreCaught() throws Exception {
        for (String site : new String[] {"Transfer.loadKeys#i3", "Transfer.loadKeys#i4"}) {
            EmuMember source = new EmuMember();
            Side target = new Side();
            byte[] head = (byte[]) importHead(target, source)[0];
            Fault.armSite(site, 1, Fault.SITE_SKIP);
            assertEquals(0x6F00, target.inner(INS_IMPORT, 0, head).sw(), site);
            target.reopen(false);
            assertEquals(0x6985, target.inner(INS_IMPORT, 1, new byte[160]).sw());
        }
    }

    // ── EXPORT P1=01 staged copies (X4/X5) ───────────────────────────────────

    /**
     * The payload's seed or access-hash staging copy skipped → the staged buffer holds zeros and
     * the source comparison refuses. Before the fix the sealed record carried {@code 0⁶⁴} resp.
     * {@code 0³²} and installed under it.
     */
    @Test
    void export1StagedCopySkipsAreCaught() throws Exception {
        for (String site : new String[] {"Transfer.export1#i4", "Transfer.export1#i5"}) {
            EmuMember target = new EmuMember();
            Side source = loaded(target);
            export0(source, target);
            Fault.armSite(site, 1, Fault.SITE_SKIP);
            assertEquals(
                    0x6F00,
                    source.inner(INS_EXPORT, 1, Vecs.accessHashNew()).sw(),
                    site + " staged copy");
            source.reopen(true);
            assertEquals(0x6985, source.inner(INS_EXPORT, 1, Vecs.accessHashNew()).sw());
        }
    }

    // ── Wallet.install staged copies (J8/J9) ─────────────────────────────────

    /**
     * Runs {@code IMPORT P1=01} of a genuine record sealed for {@code target}'s pending import with
     * {@code site} skipped.
     */
    private static Response faultedImport1(Side target, EmuMember source, String site)
            throws Exception {
        byte[] offer = target.offer();
        byte[] lk = Arrays.copyOf(offer, 65);
        byte[][] head = source.importHead(target.a, lk);
        assertEquals(0x9000, target.inner(INS_IMPORT, 0, head[0]).sw(), "IMPORT0");
        byte[] z = EmuMember.ecdhX(new BigInteger(1, head[1]), lk);
        byte[] m =
                EmuMember.transcript(source.a, target.a, lk, Arrays.copyOfRange(head[0], 97, 162));
        byte[] payload =
                EmuMember.payload(
                        0x02,
                        Vecs.seed(),
                        Vecs.accessHashNew(),
                        source.cardId,
                        Ids.cardId(target.a));
        byte[] record = EmuMember.sealRecord(z, m, payload);
        Fault.armSite(site, 1, Fault.SITE_SKIP);
        return target.inner(INS_IMPORT, 1, Transfer.import1(record));
    }

    /**
     * On a BLANK target the skipped seed copy leaves the wiped {@code mem.seed} (zeros), the
     * skipped access-hash copy leaves {@code W[0..32)} residue — each staged-copy comparison
     * refuses and the card stays BLANK. Before the fix the zero seed/hash installed ({@code 9000}).
     */
    @Test
    void installCopySkipsBlankAreCaught() throws Exception {
        for (String site : new String[] {"Wallet.install#i1", "Wallet.install#i2"}) {
            EmuMember source = new EmuMember();
            Side target = new Side();
            assertEquals(0x6F00, faultedImport1(target, source, site).sw(), site);
            assertTrue(target.blank(), site + " changed the BLANK state");
        }
    }

    /**
     * The LOADED twin: the same skip in {@code Wallet.install} must refuse before T-INSTALL; the
     * stored wrap still opens under the original access hash (the session is unverified, so {@code
     * mem.seed} is zeros and the seed compare catches the skip too).
     */
    @Test
    void installCopySkipsLoadedAreCaught() throws Exception {
        for (String site : new String[] {"Wallet.install#i1", "Wallet.install#i2"}) {
            EmuMember source = new EmuMember();
            Side target = loaded(source);
            target.reopen(false);
            // a LOADED install re-seals the same wallet: the record must carry the
            // stored members and fp — built with the stored access hash
            byte[] offer = target.offer();
            byte[] lk = Arrays.copyOf(offer, 65);
            byte[][] head = source.importHead(target.a, lk);
            assertEquals(0x9000, target.inner(INS_IMPORT, 0, head[0]).sw(), "IMPORT0");
            byte[] z = EmuMember.ecdhX(new BigInteger(1, head[1]), lk);
            byte[] m =
                    EmuMember.transcript(
                            source.a, target.a, lk, Arrays.copyOfRange(head[0], 97, 162));
            byte[] payload =
                    EmuMember.payload(
                            0x02,
                            Vecs.seed(),
                            Vecs.accessHash(),
                            Ids.cardId(target.a),
                            source.cardId);
            byte[] record = EmuMember.sealRecord(z, m, payload);
            Fault.armSite(site, 1, Fault.SITE_SKIP);
            assertEquals(0x6F00, target.inner(INS_IMPORT, 1, Transfer.import1(record)).sw(), site);
            target.reopen(false);
            target.verify();
        }
    }

    // ── CREATE entropy, seed hash and staged copies (C2–C4, C6, C7, C9) ──────

    /**
     * {@code nextBytes} of the {@code t} draw skipped → the wiped slot stays {@code 0³²} and the
     * non-zero check refuses; the card stays BLANK (before: {@code 9000} with a host-computable
     * seed).
     */
    @Test
    void createEntropySkipIsCaught() throws Exception {
        Side card = new Side();
        byte[] data = cat(Vecs.accessHash(), Vecs.entropy(), new EmuMember().cardId);
        Fault.armSite("Wallet.create#i7", 1, Fault.SITE_SKIP);
        assertEquals(0x6F00, card.inner(INS_CREATE, 0, data).sw());
        assertTrue(card.blank(), "CREATE changed the BLANK state");
    }

    /**
     * One {@code update(t)} or {@code doFinal} of one {@code seedHash} skipped per evaluation
     * ({@code nth} 1 = the {@code mem.seed} hash, 2 = the {@code H_SEED} hash): the two seeds
     * differ → {@code 6F00} (before: {@code 9000} with {@code 0⁶⁴} or a host-computable seed).
     */
    @Test
    void createSeedHashStepSkipsAreCaught() throws Exception {
        for (String site : new String[] {"Wallet.seedHash#i3", "Wallet.seedHash#i4"}) {
            for (int nth = 1; nth <= 2; nth++) {
                Side card = new Side();
                byte[] data = cat(Vecs.accessHash(), Vecs.entropy(), new EmuMember().cardId);
                Fault.armSite(site, nth, Fault.SITE_SKIP);
                assertEquals(0x6F00, card.inner(INS_CREATE, 0, data).sw(), site + " nth=" + nth);
                assertTrue(card.blank(), "state changed under " + site);
            }
        }
    }

    /** A whole {@code seedHash} of the two evaluations skipped → outputs differ → {@code 6F00}. */
    @Test
    void createSeedHashSkipsAreCaught() throws Exception {
        for (int k = 1; k <= 2; k++) {
            Side card = new Side();
            byte[] data = cat(Vecs.accessHash(), Vecs.entropy(), new EmuMember().cardId);
            Fault.armSkip("Wallet.seedHash", k);
            assertEquals(0x6F00, card.inner(INS_CREATE, 0, data).sw(), "seedHash " + k);
            assertTrue(card.blank());
        }
    }

    /**
     * The P1=01 seed copy skipped → {@code mem.seed} stays the wiped zeros and the staged
     * comparison refuses (before: {@code 9000} with a zero seed stored).
     */
    @Test
    void createSeedCopySkipIsCaught() throws Exception {
        Side card = new Side();
        Fault.armSite("Wallet.create#i17", 1, Fault.SITE_SKIP);
        assertEquals(
                0x6F00,
                card.inner(
                                INS_CREATE,
                                1,
                                cat(Vecs.accessHash(), Vecs.seed(), new EmuMember().cardId))
                        .sw());
        assertTrue(card.blank());
    }

    /**
     * The access-hash staging copy skipped, in both modes → {@code W[0..32)} holds residue, never
     * the sent hash, and the comparison refuses before T-CREATE (before: {@code 9000} — the card
     * opened under {@code SHA-256(A)} or another public candidate).
     */
    @Test
    void createAccessHashCopySkipIsCaught() throws Exception {
        for (int p1 = 0; p1 <= 1; p1++) {
            Side card = new Side();
            byte[] data =
                    p1 == 0
                            ? cat(Vecs.accessHash(), Vecs.entropy(), new EmuMember().cardId)
                            : cat(Vecs.accessHash(), Vecs.seed(), new EmuMember().cardId);
            Fault.armSite("Wallet.create#i29", 1, Fault.SITE_SKIP);
            assertEquals(0x6F00, card.inner(INS_CREATE, p1, data).sw(), "P1=" + p1);
            assertTrue(card.blank(), "state changed at P1=" + p1);
        }
    }

    // ── OPEN: scalar range check, two KDFs, key read-back (O2, O5, O6) ────────

    /**
     * The scalar draw skipped → {@code x = 0³²} (scratch is wiped after every command) and the
     * second {@code inRange} check refuses (before: only the platform's {@code 0·G} behaviour stood
     * between a zero scalar and the session keys).
     */
    @Test
    void openZeroScalarIsCaught() throws Exception {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        Vecs.blankFor(card, a);
        Fault.armSkip("Secp256k1.randomScalar", 1);
        org.qntx.card.host.Open.Request req = org.qntx.card.host.Open.request(Vecs.RND);
        byte[] rapdu = card.transmit(req.apdu());
        assertEquals(0x6F00, swOf(rapdu));
        // the card still works: a fresh OPEN completes
        Fault.reset();
        Vecs.open(card);
    }

    /** Each of the two {@code Kdf.kdf} derivations skipped → outputs differ → {@code 6F00}. */
    @Test
    void openKdfSkipsAreCaught() throws Exception {
        for (int k = 1; k <= 2; k++) {
            Card card = Vecs.factory();
            byte[] a = Vecs.cardA(card);
            Vecs.blankFor(card, a);
            Fault.armSkip("Kdf.kdf", k);
            org.qntx.card.host.Open.Request req = org.qntx.card.host.Open.request(Vecs.RND);
            assertEquals(0x6F00, swOf(card.transmit(req.apdu())), "Kdf.kdf " + k);
        }
    }

    /**
     * The second block of the second {@code Kdf.kdf} skipped ({@code doFinal} execution 4 of 4):
     * {@code K2[32..64)} stays zero while {@code W_KEYS} is complete → {@code 6F00}. Before the fix
     * the single derivation left {@code K_re ‖ K_rm = 0³²} and the next response decrypted under a
     * public {@code K_re}.
     */
    @Test
    void openKdfSecondBlockSkipIsCaught() throws Exception {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        Vecs.blankFor(card, a);
        Fault.armSite("Kdf.kdf#i6", 4, Fault.SITE_SKIP);
        org.qntx.card.host.Open.Request req = org.qntx.card.host.Open.request(Vecs.RND);
        assertEquals(0x6F00, swOf(card.transmit(req.apdu())));
    }

    /**
     * Each {@code setKey} skipped in turn: the {@code getKey} read-back sees the zeroed slot and
     * refuses (before: {@code 9000} and the session answered under a zero {@code K_re}).
     */
    @Test
    void openSetKeySkipsAreCaught() throws Exception {
        for (int i = 28; i <= 31; i++) {
            Card card = Vecs.factory();
            byte[] a = Vecs.cardA(card);
            Vecs.blankFor(card, a);
            Fault.armSite("Session.open#i" + i, 1, Fault.SITE_SKIP);
            org.qntx.card.host.Open.Request req = org.qntx.card.host.Open.request(Vecs.RND);
            assertEquals(0x6F00, swOf(card.transmit(req.apdu())), "setKey site i" + i);
        }
    }

    private static int swOf(byte[] rapdu) {
        return ((rapdu[rapdu.length - 2] & 0xFF) << 8) | (rapdu[rapdu.length - 1] & 0xFF);
    }

    private static byte[] cat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }
}
