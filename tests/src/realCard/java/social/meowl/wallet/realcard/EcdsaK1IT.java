/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.wallet.realcard;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.Security;
import java.util.Arrays;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import social.meowl.wallet.Constants;
import social.meowl.wallet.realcard.support.ApduCodec;
import social.meowl.wallet.realcard.support.CardLifecycle;
import social.meowl.wallet.realcard.support.HostSession;
import social.meowl.wallet.realcard.support.RealCardClient;
import social.meowl.wallet.realcard.support.TestConstants;

/**
 * End-to-end tests for the {@code SIGN_ECDSA_K1} primitive — secp256k1 ECDSA signing under a
 * BIP-32-derived key.
 *
 * <p>The card draws a fresh random nonce per ECDSA signature (JC 3.0.5 does not expose an RFC 6979
 * hook), so the tests cannot pin {@code r,s} to a fixed expected pair. Instead each test verifies
 * the structural and cryptographic invariants: per call:
 *
 * <ol>
 *   <li>The signature verifies against the BIP-32-derived pubkey that {@code EXPORT_XPUB} would
 *       return for the same path (proving the card signs with the right scalar).
 *   <li>{@code s ≤ ⌊n/2⌋} (proving the on-card low-{@code s} normalisation per BIP-62 / EIP-2).
 * </ol>
 */
class EcdsaK1IT {

    private static final ECDomainParameters DOMAIN =
            new ECDomainParameters(
                    TestConstants.SECP256K1.getCurve(),
                    TestConstants.SECP256K1.getG(),
                    TestConstants.SECP256K1.getN(),
                    TestConstants.SECP256K1.getH());
    private static final BigInteger HALF_N = TestConstants.SECP256K1.getN().shiftRight(1);

    private static final byte[] SAMPLE_DIGEST =
            TestConstants.parseHex(
                    "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e");

    private RealCardClient card;
    private HostSession session;

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        card = RealCardClient.connect(TestConstants.APPLET_AID_BYTES);
        session = CardLifecycle.bringToSetupDoneAndVerifyPin(card);
        // SIGN_ECDSA_K1 needs a seeded card; install vector 1 seed before each test.
        session.sendInnerExpectOk(
                Constants.INS_IMPORT_SEED,
                (byte) 0,
                (byte) 0,
                ApduCodec.prefixLen(TestConstants.BIP32_VECTOR_1_SEED));
    }

    @AfterEach
    void tearDown() {
        if (card != null) {
            try {
                CardLifecycle.resetCard(card);
            } catch (Exception ignored) {
                // best-effort reset; the next test's @BeforeEach will surface real problems
            }
            card.close();
        }
    }

    @Nested
    @DisplayName("ECDSA signing — happy path, verified against the derived pubkey")
    class HappyPath {

        @Test
        @DisplayName("m — sign at the master, verify with the master pubkey")
        void signAtMaster() {
            int[] path = new int[] {};
            byte[] pubkey = derivePubkey(path);
            byte[] sig = signEcdsa(path, SAMPLE_DIGEST);
            assertEquals(Constants.SIG_LEN_R_S, sig.length);
            assertTrue(
                    verifyEcdsa(pubkey, SAMPLE_DIGEST, sig),
                    "sig must verify under derived pubkey");
            assertLowS(sig);
        }

        @Test
        @DisplayName("m/0H — sign at a hardened child")
        void signAtHardenedChild() {
            int[] path = {0x80000000};
            byte[] pubkey = derivePubkey(path);
            byte[] sig = signEcdsa(path, SAMPLE_DIGEST);
            assertTrue(verifyEcdsa(pubkey, SAMPLE_DIGEST, sig));
            assertLowS(sig);
        }

        @Test
        @DisplayName("m/0H/1 — sign at a non-hardened grandchild")
        void signAtNonHardenedGrandchild() {
            int[] path = {0x80000000, 1};
            byte[] pubkey = derivePubkey(path);
            byte[] sig = signEcdsa(path, SAMPLE_DIGEST);
            assertTrue(verifyEcdsa(pubkey, SAMPLE_DIGEST, sig));
            assertLowS(sig);
        }

        @Test
        @DisplayName("m/0H/1/2H/2/1000000000 — sign at the deepest BIP-32 vector 1 path")
        void signAtDeepPath() {
            int[] path = {0x80000000, 1, 0x80000002, 2, 1000000000};
            byte[] pubkey = derivePubkey(path);
            byte[] sig = signEcdsa(path, SAMPLE_DIGEST);
            assertTrue(verifyEcdsa(pubkey, SAMPLE_DIGEST, sig));
            assertLowS(sig);
        }

        @Test
        @DisplayName("All-zero digest — degenerate but valid input must still sign and verify")
        void signAllZeroDigest() {
            int[] path = {0};
            byte[] pubkey = derivePubkey(path);
            byte[] sig = signEcdsa(path, new byte[Constants.DIGEST_LEN]);
            assertTrue(verifyEcdsa(pubkey, new byte[Constants.DIGEST_LEN], sig));
            assertLowS(sig);
        }

        @Test
        @DisplayName("Five different digests at the same path all verify and are all low-s")
        void multipleDigestsSamePath() {
            int[] path = {0x80000001};
            byte[] pubkey = derivePubkey(path);
            for (int i = 0; i < 5; i++) {
                byte[] digest = new byte[Constants.DIGEST_LEN];
                TestConstants.RANDOM.nextBytes(digest);
                byte[] sig = signEcdsa(path, digest);
                assertTrue(verifyEcdsa(pubkey, digest, sig), "iteration " + i);
                assertLowS(sig);
            }
        }

        @Test
        @DisplayName(
                "Two signatures over the same (path, digest) are both valid (nonce policy is"
                        + " environment-dependent)")
        void repeatedSignAtSamePathValid() {
            // Real JCOP silicon draws a fresh random k per ECDSA signature (JC 3.0.5 exposes no
            // RFC 6979 hook), so two signatures over the same (path, digest) almost always differ.
            // This test asserts only the property we actually rely on — that both signatures
            // verify under the derived pubkey — rather than pinning equality either way.
            int[] path = {0};
            byte[] sig1 = signEcdsa(path, SAMPLE_DIGEST);
            byte[] sig2 = signEcdsa(path, SAMPLE_DIGEST);
            byte[] pubkey = derivePubkey(path);
            assertTrue(verifyEcdsa(pubkey, SAMPLE_DIGEST, sig1));
            assertTrue(verifyEcdsa(pubkey, SAMPLE_DIGEST, sig2));
            assertLowS(sig1);
            assertLowS(sig2);
        }
    }

    @Nested
    @DisplayName("ECDSA signing — host-side recovery byte computation works")
    class RecoveryByte {

        @Test
        @DisplayName("Host can recover v ∈ {0, 1} from (r, s, digest, pubkey)")
        void recoveryByteIsComputable() {
            int[] path = {0x80000000, 1};
            byte[] pubkey = derivePubkey(path);
            for (int i = 0; i < 5; i++) {
                byte[] digest = new byte[Constants.DIGEST_LEN];
                TestConstants.RANDOM.nextBytes(digest);
                byte[] sig = signEcdsa(path, digest);
                int v = recoverV(pubkey, digest, sig);
                assertTrue(v == 0 || v == 1, "v must be 0 or 1; got " + v);
            }
        }
    }

    @Nested
    @DisplayName("SIGN_ECDSA_K1 — negative / gating cases")
    class Negative {

        @Test
        @DisplayName("depth > HD_MAX_DEPTH is rejected with SW_WRONG_LENGTH")
        void depthTooDeep() {
            int[] tooDeep = new int[Constants.HD_MAX_DEPTH + 1];
            for (int i = 0; i < tooDeep.length; i++) tooDeep[i] = 0x80000000 | i;
            ResponseAPDU r = signEcdsaResp(tooDeep, SAMPLE_DIGEST);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("digest shorter than 32 bytes is rejected with SW_WRONG_LENGTH")
        void digestTooShort() {
            byte[] req = ApduCodec.encodeSignRequest(new int[] {0}, new byte[16]);
            ResponseAPDU r =
                    session.sendInner(Constants.INS_SIGN_ECDSA_K1, (byte) 0, (byte) 0, req);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("Empty request is rejected with SW_WRONG_LENGTH")
        void emptyRequest() {
            ResponseAPDU r =
                    session.sendInner(Constants.INS_SIGN_ECDSA_K1, (byte) 0, (byte) 0, new byte[0]);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("Truncated path (declared depth ≠ supplied bytes) is rejected")
        void truncatedPath() {
            // Claim depth=2 but only supply 4 bytes of path (one index) + 32-byte digest.
            byte[] req = new byte[1 + 4 + Constants.DIGEST_LEN];
            req[0] = 2; // depth = 2
            ResponseAPDU r =
                    session.sendInner(Constants.INS_SIGN_ECDSA_K1, (byte) 0, (byte) 0, req);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }
    }

    @Nested
    @DisplayName("SIGN_ECDSA_K1 — lifecycle / PIN gating")
    class Gating {

        @Test
        @DisplayName("SIGN_ECDSA_K1 before SEEDED is rejected with SW_LIFECYCLE_INVALID")
        void signBeforeSeeded() throws Exception {
            // The @BeforeEach left the card SEEDED; drive RESET_TO_FACTORY so the rebuilt session
            // can re-run bringToSetupDoneAndVerifyPin from UNINITIALIZED, then stop at SETUP_DONE
            // (i.e. NOT seed it) so the sign attempt actually hits the lifecycle guard.
            CardLifecycle.resetCard(card);
            card.close();
            card = RealCardClient.connect(TestConstants.APPLET_AID_BYTES);
            session = CardLifecycle.bringToSetupDoneAndVerifyPin(card);
            // Do NOT import a seed: lifecycle is SETUP_DONE, not SEEDED.
            ResponseAPDU r = signEcdsaResp(new int[] {0}, SAMPLE_DIGEST);
            assertEquals(Constants.SW_LIFECYCLE_INVALID & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("SIGN_ECDSA_K1 without a verified PIN is rejected (after SC re-handshake)")
        void signWithoutPinIsRejected() throws Exception {
            // Re-handshake clears the session-scoped PIN-verified flag.
            session = HostSession.open(card);
            ResponseAPDU r = signEcdsaResp(new int[] {0}, SAMPLE_DIGEST);
            assertEquals(Constants.SW_SECURITY_STATUS_NOT_SATISFIED & 0xFFFF, r.getSW());
        }
    }

    @Nested
    @DisplayName("Capability advertisement")
    class Capabilities {

        @Test
        @DisplayName("CAP_K1_ECDSA bit is now advertised in GET_INFO")
        void capK1EcdsaIsAdvertised() throws Exception {
            byte[] tlv =
                    CardLifecycle.transmitOuter(card, Constants.INS_GET_INFO & 0xFF, 0, 0, null)
                            .getData();
            short caps = ApduCodec.readCapabilities(tlv);
            assertNotEquals(
                    (short) 0,
                    (short) (caps & Constants.CAP_K1_ECDSA),
                    "CAP_K1_ECDSA must be advertised");
        }
    }

    /*  ECDSA-specific helpers.  */

    private byte[] derivePubkey(int[] path) {
        byte[] req = ApduCodec.encodeXpubRequest(Constants.CURVE_SECP256K1, path);
        byte[] resp = session.sendInnerExpectOk(Constants.INS_EXPORT_XPUB, (byte) 0, (byte) 0, req);
        return Arrays.copyOfRange(resp, 0, Constants.EC_POINT_COMPRESSED_LEN);
    }

    private byte[] signEcdsa(int[] path, byte[] digest) {
        byte[] req = ApduCodec.encodeSignRequest(path, digest);
        return session.sendInnerExpectOk(Constants.INS_SIGN_ECDSA_K1, (byte) 0, (byte) 0, req);
    }

    private ResponseAPDU signEcdsaResp(int[] path, byte[] digest) {
        byte[] req = ApduCodec.encodeSignRequest(path, digest);
        return session.sendInner(Constants.INS_SIGN_ECDSA_K1, (byte) 0, (byte) 0, req);
    }

    private static boolean verifyEcdsa(byte[] compressedPub, byte[] digest, byte[] sig64) {
        ECPoint pub = TestConstants.SECP256K1.getCurve().decodePoint(compressedPub).normalize();
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig64, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig64, 32, 64));
        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, new ECPublicKeyParameters(pub, DOMAIN));
        return verifier.verifySignature(digest, r, s);
    }

    private static void assertLowS(byte[] sig64) {
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig64, 32, 64));
        assertTrue(
                s.compareTo(HALF_N) <= 0,
                "s must be ≤ n/2 (low-s canonical form); got " + s.toString(16));
    }

    /**
     * Recovers the public-key recovery byte {@code v ∈ {0, 1}} from a low-{@code s} signature by
     * trying both candidates and comparing against the expected pubkey. This mirrors the host-side
     * recovery work that {@code notes/specs/protocol.md} §10 delegates off-card.
     */
    private static int recoverV(byte[] expectedCompressedPub, byte[] digest, byte[] sig64) {
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig64, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig64, 32, 64));
        BigInteger e = new BigInteger(1, digest);
        BigInteger n = TestConstants.SECP256K1.getN();
        for (int v = 0; v < 2; v++) {
            try {
                BigInteger x = r;
                if (x.compareTo(TestConstants.SECP256K1.getCurve().getField().getCharacteristic())
                        >= 0) continue;
                // Compress: 0x02 (even y) or 0x03 (odd y) per v.
                byte[] enc = new byte[33];
                enc[0] = (v == 0) ? (byte) 0x02 : (byte) 0x03;
                byte[] xBytes = bigIntToFixed(x, 32);
                System.arraycopy(xBytes, 0, enc, 1, 32);
                ECPoint R = TestConstants.SECP256K1.getCurve().decodePoint(enc).normalize();
                if (R == null || R.isInfinity()) continue;
                // Q = r⁻¹ (sR - eG)
                BigInteger rInv = r.modInverse(n);
                ECPoint Q =
                        R.multiply(s)
                                .subtract(TestConstants.SECP256K1.getG().multiply(e))
                                .multiply(rInv)
                                .normalize();
                if (Q.isInfinity()) continue;
                byte[] qEnc = Q.getEncoded(true);
                if (Arrays.equals(qEnc, expectedCompressedPub)) return v;
            } catch (Exception ignored) {
                // try next v
            }
        }
        return -1;
    }

    private static byte[] bigIntToFixed(BigInteger n, int len) {
        byte[] raw = n.toByteArray();
        if (raw.length == len) return raw;
        byte[] out = new byte[len];
        if (raw.length > len) System.arraycopy(raw, raw.length - len, out, 0, len);
        else System.arraycopy(raw, 0, out, len - raw.length, raw.length);
        return out;
    }
}
