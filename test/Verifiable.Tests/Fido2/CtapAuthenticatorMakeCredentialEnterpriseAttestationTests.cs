using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The waveep PKG-C matrix for <c>authenticatorMakeCredential</c>'s <c>enterpriseAttestation</c> parameter
/// (CTAP 2.3 §7.1, mc algorithm step 9): the full negative/positive clause tree (R4/R5/R6), the packed
/// CERTIFIED attestation mint (R7), <c>epAtt</c> emission (R9), the none-family discretionary decline
/// (R8), the <c>authenticatorReset</c> interplay (§7.1.3), and R15's personal/enterprise coexistence
/// proofs. Driven over <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/> with the shipped CBOR
/// codecs, mirroring <see cref="CtapAuthenticatorMakeCredentialTests"/>'s and
/// <see cref="CtapAuthenticatorPackedAttestationTests"/>'s own shape.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorMakeCredentialEnterpriseAttestationTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A relying party identifier never present on any fixture's pre-configured RP ID list.</summary>
    private const string UnlistedRpId = "unlisted.example";

    /// <summary>A second relying party identifier, distinct from <see cref="UnlistedRpId"/>, standing in for a platform-vetted (value-2) RP.</summary>
    private const string PlatformVettedRpId = "platform-vetted.example";

    /// <summary>A relying party identifier for R15(b)'s personal (non-enterprise) resident credential.</summary>
    private const string PersonalRpId = "personal.example";


    /// <summary>
    /// The <c>clientDataHash</c> bytes <see cref="CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest"/>
    /// always seeds with, captured independently for the certified-signature verification oracle (the
    /// request's own carrier is disposed once sent).
    /// </summary>
    private static byte[] ExpectedMakeCredentialClientDataHash => BuildFixedBytes(32, 0x10);

    /// <summary>The <c>clientDataHash</c> bytes <see cref="CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest"/> always seeds with — see <see cref="ExpectedMakeCredentialClientDataHash"/>.</summary>
    private static byte[] ExpectedGetAssertionClientDataHash => BuildFixedBytes(32, 0x20);


    /// <summary>
    /// mc Step 9 sub-step 1 (CTAP 2.3 line 3331, waveep R5, trap 5's order-pin): a NON-CAPABLE
    /// authenticator rejects <c>enterpriseAttestation</c> with <c>InvalidParameter</c> REGARDLESS of the
    /// value supplied — including out-of-range values that would otherwise trigger the value-validation
    /// check (sub-step 2.1) IF that check ran first. Value 1 alone is already covered by
    /// <see cref="CtapAuthenticatorMakeCredentialTests.EnterpriseAttestationPresentReturnsInvalidParameter"/>;
    /// this test's own DataRow set proves the SAME code for values that check would otherwise reject
    /// differently, proving sub-step 1 runs STRICTLY BEFORE sub-step 2.1.
    /// </summary>
    [TestMethod]
    [DataRow(0, DisplayName = "value 0 (would be InvalidOption if capable)")]
    [DataRow(2, DisplayName = "value 2 (a legal value if capable)")]
    [DataRow(3, DisplayName = "value 3 (would be InvalidOption if capable)")]
    [DataRow(7, DisplayName = "value 7 (out of range)")]
    public async Task EnterpriseAttestationOnNonCapableAuthenticatorReturnsInvalidParameterRegardlessOfValue(int enterpriseAttestationValue)
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator($"mc-ep-noncapable-{enterpriseAttestationValue}");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, enterpriseAttestation: enterpriseAttestationValue);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// mc Step 9 sub-step 1: a CAPABLE but currently DISABLED authenticator rejects
    /// <c>enterpriseAttestation</c> with <c>InvalidParameter</c> — the same code as the non-capable case,
    /// since sub-step 1's condition is "not capable OR capable-but-disabled" (a single disjunction, one
    /// code either way).
    /// </summary>
    [TestMethod]
    public async Task EnterpriseAttestationOnCapableButDisabledAuthenticatorReturnsInvalidParameter()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = CtapWaveEpFixtures.CreateCapableSimulator("mc-ep-capable-disabled", pool);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, enterpriseAttestation: 1);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// mc Step 9 sub-step 2.1 (CTAP 2.3 line 3336, waveep R5): once capable AND enabled, a value that is
    /// neither 1 nor 2 rejects with <c>InvalidOption</c> — a code this handler could never previously
    /// produce for this parameter (seams §1).
    /// </summary>
    [TestMethod]
    [DataRow(0, DisplayName = "value 0")]
    [DataRow(3, DisplayName = "value 3")]
    public async Task EnterpriseAttestationInvalidValueOnCapableEnabledAuthenticatorReturnsInvalidOption(int enterpriseAttestationValue)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CtapWaveEpFixtures.CreateCapableEnabledSimulatorAsync(
            $"mc-ep-invalid-value-{enterpriseAttestationValue}", pool, preConfiguredRpIds: null, TestContext.CancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, enterpriseAttestation: enterpriseAttestationValue);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// mc Step 9's vendor-facilitated grant (CTAP 2.3 line 3345, waveep R4): <c>enterpriseAttestation: 1</c>
    /// with an <c>rp.id</c> matching the pre-configured list mints a packed CERTIFIED attestation — the
    /// response carries <c>epAtt: true</c>, an <c>attStmt</c> with <c>x5c</c> present (the seeded chain's
    /// own bytes, byte-exact), and keys in ascending order <c>alg</c> &lt; <c>sig</c> &lt; <c>x5c</c>
    /// (trap 14). The signature independently verifies against the SEEDED ATTESTATION public key (trap
    /// 11's positive half) and does NOT verify against the newly minted CREDENTIAL's own public key (trap
    /// 11's negative half — proving the certified mint never signs with the credential key).
    /// </summary>
    [TestMethod]
    public async Task EnterpriseAttestationValueOneWithListedRpIdGrantsCertifiedAttestationSignedByAttestationKey()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        (CtapEnterpriseAttestationProvisioning provisioning, PublicKeyMemory attestationPublicKey) =
            CtapWaveEpFixtures.BuildProvisioningWithAttestationPublicKey(pool);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-ep-value1-listed", enterpriseAttestationProvisioning: provisioning);
        try
        {
            var enableRequest = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.EnableEnterpriseAttestation);
            using PooledMemory enableResponse = await CtapWaveConfigFixtures.SendAuthenticatorConfigAsync(simulator, enableRequest, pool, TestContext.CancellationToken);
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, enableResponse.AsReadOnlySpan()[0]);

            CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
                pool, rpId: CtapWaveEpFixtures.DefaultPreConfiguredRpId, enterpriseAttestation: 1);
            using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

            CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
            Assert.AreEqual(WellKnownWebAuthnAttestationFormats.Packed, decoded.Fmt);
            Assert.IsTrue(decoded.EpAtt.HasValue && decoded.EpAtt.Value, "a granted certified mint must report epAtt: true.");

            AssertAttStmtKeyOrderIsAlgSigX5c(decoded.AttStmt!.Value);

            using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);

            PackedAttestationStatement statement = PackedAttestationStatementCborReader.Parse(decoded.AttStmt!.Value, pool);
            try
            {
                Assert.AreEqual(WellKnownCoseAlgorithms.Es256, statement.Alg);
                Assert.IsNotNull(statement.X5c, "a certified mint must carry x5c.");
                Assert.HasCount(1, statement.X5c!);
                Assert.AreSequenceEqual(
                    provisioning.X5c[0].AsReadOnlySpan().ToArray(), statement.X5c![0].AsReadOnlySpan().ToArray(),
                    "the wire x5c entry must be the seeded chain's own bytes, verbatim.");

                byte[] message = new byte[decoded.AuthData.Length + ExpectedMakeCredentialClientDataHash.Length];
                decoded.AuthData.Span.CopyTo(message);
                ExpectedMakeCredentialClientDataHash.CopyTo(message, decoded.AuthData.Length);

                using ECDsa attestationOracleKey = BuildP256Oracle(attestationPublicKey);
                bool verifiedByAttestationKey = attestationOracleKey.VerifyData(message, statement.Signature.Span, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
                Assert.IsTrue(verifiedByAttestationKey, "the certified signature must verify against the SEEDED attestation public key.");

                using ECDsa credentialOracleKey = BuildP256OracleFromCoseKey(authenticatorData.AttestedCredentialData!.CredentialPublicKey);
                bool verifiedByCredentialKey = credentialOracleKey.VerifyData(message, statement.Signature.Span, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
                Assert.IsFalse(verifiedByCredentialKey, "the certified signature must NOT verify against the newly minted credential's own public key (trap 11).");
            }
            finally
            {
                if(statement.X5c is not null)
                {
                    foreach(PkiCertificateMemory certificate in statement.X5c)
                    {
                        certificate.Dispose();
                    }
                }
            }
        }
        finally
        {
            attestationPublicKey.Dispose();
        }
    }


    /// <summary>
    /// The genuinely reachable "enterprise-attested resident credential with a largeBlobKey also
    /// requested" combination (trap 2/5): granting an enterprise attestation and requesting §12.3's
    /// <c>largeBlobKey</c> extension in the SAME mc call produces a wire response carrying <c>attStmt</c>
    /// (<c>0x03</c>), <c>epAtt</c> (<c>0x04</c>), AND <c>largeBlobKey</c> (<c>0x05</c>) together — proving
    /// the full simulator pipeline (not just the writer in isolation) preserves all three members through
    /// <c>GenerateCredentialAsync</c>'s own largeBlobKey-splice step.
    /// </summary>
    [TestMethod]
    public async Task EnterpriseAttestationGrantedTogetherWithLargeBlobKeyProducesAllThreeOptionalMembers()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CtapWaveEpFixtures.CreateCapableEnabledSimulatorAsync(
            "mc-ep-with-largeblobkey", pool, preConfiguredRpIds: null, TestContext.CancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool, rpId: CtapWaveEpFixtures.DefaultPreConfiguredRpId, enterpriseAttestation: 1,
            options: new CtapCommandOptions(ResidentKey: true), extensions: BuildMakeCredentialExtensionsInput(largeBlobKey: true));
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.IsTrue(decoded.AttStmt.HasValue, "attStmt must be present.");
        Assert.IsTrue(decoded.EpAtt.HasValue && decoded.EpAtt.Value, "epAtt must be present and true.");
        Assert.IsTrue(decoded.LargeBlobKey.HasValue, "largeBlobKey must be present.");
        Assert.HasCount(32, decoded.LargeBlobKey!.Value.ToArray());
    }


    /// <summary>
    /// mc Step 9 sub-step 2.3's fallthrough (CTAP 2.3 line 3350, the row-3339 MUST NOT's own NON-VACUOUS
    /// proof, waveep R4): <c>enterpriseAttestation: 1</c> with an <c>rp.id</c> that does NOT match the
    /// pre-configured list is treated as ABSENT — the request still SUCCEEDS, but with a regular packed
    /// SELF attestation (no <c>x5c</c>) and <c>epAtt</c> absent, never an error.
    /// </summary>
    [TestMethod]
    public async Task EnterpriseAttestationValueOneWithUnlistedRpIdFallsThroughToRegularSelfAttestation()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CtapWaveEpFixtures.CreateCapableEnabledSimulatorAsync(
            "mc-ep-value1-unlisted", pool, preConfiguredRpIds: null, TestContext.CancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, rpId: UnlistedRpId, enterpriseAttestation: 1);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.Packed, decoded.Fmt);
        Assert.IsFalse(decoded.EpAtt.HasValue, "a fallthrough-to-regular-attestation response must never carry epAtt.");

        PackedAttestationStatement statement = PackedAttestationStatementCborReader.Parse(decoded.AttStmt!.Value, pool);
        Assert.IsNull(statement.X5c, "the fallthrough attestation must be a regular self-attestation with no x5c.");
    }


    /// <summary>
    /// mc Step 9's platform-managed grant (CTAP 2.3 line 3347, waveep R4): <c>enterpriseAttestation: 2</c>
    /// grants an enterprise attestation for an <c>rp.id</c> NOT on the pre-configured list at all — "the
    /// authenticator MAY return an enterprise attestation WITHOUT checking whether the request's rp.id
    /// matches an entry on the authenticator's pre-configured RP ID list" — proving value 2's own no-
    /// list-check disposition, independent of value 1's vendor-facilitated gate.
    /// </summary>
    [TestMethod]
    public async Task EnterpriseAttestationValueTwoWithUnlistedRpIdGrantsCertifiedAttestationWithoutListCheck()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CtapWaveEpFixtures.CreateCapableEnabledSimulatorAsync(
            "mc-ep-value2-unlisted", pool, preConfiguredRpIds: null, TestContext.CancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, rpId: PlatformVettedRpId, enterpriseAttestation: 2);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.IsTrue(decoded.EpAtt.HasValue && decoded.EpAtt.Value, "value 2 must grant regardless of the pre-configured list.");

        PackedAttestationStatement statement = PackedAttestationStatementCborReader.Parse(decoded.AttStmt!.Value, pool);
        try
        {
            Assert.IsNotNull(statement.X5c, "a granted value-2 mint must carry x5c.");
        }
        finally
        {
            if(statement.X5c is not null)
            {
                foreach(PkiCertificateMemory certificate in statement.X5c)
                {
                    certificate.Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Waveep R8: a granted request whose OWN <c>attestationFormatsPreference</c> resolves to a
    /// none-family choice declines the grant — the authenticator's ONE adopted sub-step 2.4 discretionary
    /// constraint. <c>enterpriseAttestation: 2</c> (unconditionally grantable) combined with a
    /// single-entry <c>["none"]</c> preference still answers <c>fmt=none</c>, <c>attStmt</c> omitted, and
    /// <c>epAtt</c> absent.
    /// </summary>
    [TestMethod]
    public async Task EnterpriseAttestationValueTwoWithNonePreferenceDeclinesGrant()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CtapWaveEpFixtures.CreateCapableEnabledSimulatorAsync(
            "mc-ep-value2-none-preference", pool, preConfiguredRpIds: null, TestContext.CancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool, rpId: PlatformVettedRpId, enterpriseAttestation: 2, attestationFormatsPreference: [WellKnownWebAuthnAttestationFormats.None]);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.None, decoded.Fmt);
        Assert.IsFalse(decoded.AttStmt.HasValue, "the single-entry [\"none\"] preference must still omit attStmt entirely.");
        Assert.IsFalse(decoded.EpAtt.HasValue, "a none-family-declined grant must never carry epAtt.");
    }


    /// <summary>
    /// CTAP 2.3 §7.1.3 (lines 8276-8278): <c>authenticatorReset</c> disables the enterprise attestation
    /// feature — a subsequent mc with <c>enterpriseAttestation</c> present rejects with
    /// <c>InvalidParameter</c>, the SAME code (and same sub-step 1 reasoning) as a freshly built,
    /// never-enabled capable authenticator, even though the underlying capability (the seeded
    /// provisioning) survives the reset unchanged.
    /// </summary>
    [TestMethod]
    public async Task EnterpriseAttestationAfterFactoryResetReturnsInvalidParameter()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CtapWaveEpFixtures.CreateCapableEnabledSimulatorAsync(
            "mc-ep-reset-then-mc", pool, preConfiguredRpIds: null, TestContext.CancellationToken);

        byte[] resetRequest = [WellKnownCtapCommands.Reset];
        using PooledMemory resetResponse = await simulator.TransceiveAsync(resetRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0]);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, rpId: CtapWaveEpFixtures.DefaultPreConfiguredRpId, enterpriseAttestation: 1);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// R15(a): the personal context on an enterprise-provisioned device. An <c>enterpriseAttestation</c>-
    /// ABSENT mc request against a CAPABLE+ENABLED authenticator returns the regular packed SELF
    /// attestation, <c>epAtt</c> absent — and the response's own SHAPE (fmt, x5c-absence, epAtt-absence)
    /// is indistinguishable from an equivalent request against a NON-CAPABLE authenticator (CTAP 2.3 line
    /// 2974: "attestation's privacy characteristics are unaffected, regardless of whether the enterprise
    /// attestation feature is presently enabled"). This is asserted structurally, not assumed — both
    /// simulators answer the identical request shape and both are checked against the identical
    /// predicates.
    /// </summary>
    [TestMethod]
    public async Task ParameterAbsentOnCapableEnabledAuthenticatorProducesShapeIndistinguishableFromNonCapableAuthenticator()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator capableEnabledSimulator = await CtapWaveEpFixtures.CreateCapableEnabledSimulatorAsync(
            "mc-ep-r15a-capable", pool, preConfiguredRpIds: null, TestContext.CancellationToken);
        using CtapAuthenticatorSimulator nonCapableSimulator = CreateSimulator("mc-ep-r15a-noncapable");

        CtapMakeCredentialResponse capableEnabledDecoded = await SendPlainMakeCredentialAsync(capableEnabledSimulator, pool);
        CtapMakeCredentialResponse nonCapableDecoded = await SendPlainMakeCredentialAsync(nonCapableSimulator, pool);

        AssertRegularSelfAttestationShape(capableEnabledDecoded, pool);
        AssertRegularSelfAttestationShape(nonCapableDecoded, pool);

        Assert.AreEqual(nonCapableDecoded.Fmt, capableEnabledDecoded.Fmt, "the fmt member must match between the two authenticators.");
        Assert.AreEqual(nonCapableDecoded.EpAtt.HasValue, capableEnabledDecoded.EpAtt.HasValue, "epAtt presence must match (both absent).");

        static async Task<CtapMakeCredentialResponse> SendPlainMakeCredentialAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool)
        {
            CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, rpId: CtapWaveEpFixtures.DefaultPreConfiguredRpId);
            using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, default);

            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

            return CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        }

        static void AssertRegularSelfAttestationShape(CtapMakeCredentialResponse decoded, MemoryPool<byte> pool)
        {
            Assert.AreEqual(WellKnownWebAuthnAttestationFormats.Packed, decoded.Fmt);
            Assert.IsFalse(decoded.EpAtt.HasValue, "the personal (param-absent) path must never carry epAtt.");

            PackedAttestationStatement statement = PackedAttestationStatementCborReader.Parse(decoded.AttStmt!.Value, pool);
            Assert.IsNull(statement.X5c, "the personal (param-absent) path must never carry x5c.");
        }
    }


    /// <summary>
    /// R15(b): a personal (non-enterprise) resident credential and an enterprise-attested resident
    /// credential coexist on ONE authenticator; both later assert successfully via
    /// <c>authenticatorGetAssertion</c>, and each assertion's signature verifies ONLY against ITS OWN
    /// credential's public key — never the seeded attestation key — proving the personal path carries no
    /// enterprise material and that even the enterprise-minted credential's own LATER assertions never
    /// touch the attestation key (assertions are always credential-key-signed, independent of how the
    /// credential itself was minted).
    /// </summary>
    [TestMethod]
    public async Task PersonalAndEnterpriseResidentCredentialsCoexistAndBothAssertViaGetAssertionWithoutEnterpriseMaterialOnPersonalPath()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapAuthenticatorSimulator simulator = await CtapWaveEpFixtures.CreateCapableEnabledSimulatorAsync(
            "mc-ep-r15b-coexist", pool, preConfiguredRpIds: null, TestContext.CancellationToken);

        CtapMakeCredentialRequest personalRequest = BuildMakeCredentialRequest(
            pool, rpId: PersonalRpId, userId: BuildFixedBytes(16, 0x71), options: new CtapCommandOptions(ResidentKey: true));
        using PooledMemory personalResponse = await SendMakeCredentialAsync(simulator, personalRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, personalResponse.AsReadOnlySpan()[0]);
        CtapMakeCredentialResponse personalDecoded = CtapMakeCredentialResponseCborReader.Read(personalResponse.AsReadOnlyMemory()[1..]);
        Assert.IsFalse(personalDecoded.EpAtt.HasValue, "the personal credential's own mint must never carry epAtt.");
        using AuthenticatorData personalAuthenticatorData = AuthenticatorDataReader.Read(personalDecoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        CoseKey personalCredentialPublicKey = personalAuthenticatorData.AttestedCredentialData!.CredentialPublicKey;

        CtapMakeCredentialRequest enterpriseRequest = BuildMakeCredentialRequest(
            pool, rpId: CtapWaveEpFixtures.DefaultPreConfiguredRpId, userId: BuildFixedBytes(16, 0x72),
            options: new CtapCommandOptions(ResidentKey: true), enterpriseAttestation: 1);
        using PooledMemory enterpriseResponse = await SendMakeCredentialAsync(simulator, enterpriseRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, enterpriseResponse.AsReadOnlySpan()[0]);
        CtapMakeCredentialResponse enterpriseDecoded = CtapMakeCredentialResponseCborReader.Read(enterpriseResponse.AsReadOnlyMemory()[1..]);
        Assert.IsTrue(enterpriseDecoded.EpAtt.HasValue && enterpriseDecoded.EpAtt.Value, "the enterprise credential's own mint must carry epAtt: true.");
        using AuthenticatorData enterpriseAuthenticatorData = AuthenticatorDataReader.Read(enterpriseDecoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        CoseKey enterpriseCredentialPublicKey = enterpriseAuthenticatorData.AttestedCredentialData!.CredentialPublicKey;

        CtapGetAssertionRequest personalAssertionRequest = BuildGetAssertionRequest(pool, rpId: PersonalRpId);
        using PooledMemory personalAssertionResponse = await SendGetAssertionAsync(simulator, personalAssertionRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, personalAssertionResponse.AsReadOnlySpan()[0]);
        CtapGetAssertionResponse personalAssertionDecoded = CtapGetAssertionResponseCborReader.Read(personalAssertionResponse.AsReadOnlyMemory()[1..], pool);
        try
        {
            AssertAssertionSignatureVerifiesOnlyAgainstOwnCredentialKey(personalAssertionDecoded, personalCredentialPublicKey);
        }
        finally
        {
            personalAssertionDecoded.Credential.Id.Dispose();
            personalAssertionDecoded.User?.Id.Dispose();
        }

        CtapGetAssertionRequest enterpriseAssertionRequest = BuildGetAssertionRequest(pool, rpId: CtapWaveEpFixtures.DefaultPreConfiguredRpId);
        using PooledMemory enterpriseAssertionResponse = await SendGetAssertionAsync(simulator, enterpriseAssertionRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, enterpriseAssertionResponse.AsReadOnlySpan()[0]);
        CtapGetAssertionResponse enterpriseAssertionDecoded = CtapGetAssertionResponseCborReader.Read(enterpriseAssertionResponse.AsReadOnlyMemory()[1..], pool);
        try
        {
            AssertAssertionSignatureVerifiesOnlyAgainstOwnCredentialKey(enterpriseAssertionDecoded, enterpriseCredentialPublicKey);
        }
        finally
        {
            enterpriseAssertionDecoded.Credential.Id.Dispose();
            enterpriseAssertionDecoded.User?.Id.Dispose();
        }

        static void AssertAssertionSignatureVerifiesOnlyAgainstOwnCredentialKey(CtapGetAssertionResponse decoded, CoseKey ownCredentialPublicKey)
        {
            byte[] message = new byte[decoded.AuthData.Length + ExpectedGetAssertionClientDataHash.Length];
            decoded.AuthData.Span.CopyTo(message);
            ExpectedGetAssertionClientDataHash.CopyTo(message, decoded.AuthData.Length);

            using ECDsa ownOracleKey = BuildP256OracleFromCoseKey(ownCredentialPublicKey);
            bool verified = ownOracleKey.VerifyData(message, decoded.Signature.Span, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            Assert.IsTrue(verified, "the assertion signature must verify against its own credential's public key — never any enterprise attestation material.");
        }
    }


    /// <summary>
    /// Reads <paramref name="attStmt"/>'s three CBOR text keys, in wire order, and asserts they are
    /// exactly <c>alg</c>, <c>sig</c>, <c>x5c</c> (waveep R7, trap 14: bytewise ascending on a 3-character
    /// tie).
    /// </summary>
    private static void AssertAttStmtKeyOrderIsAlgSigX5c(ReadOnlyMemory<byte> attStmt)
    {
        var reader = new System.Formats.Cbor.CborReader(attStmt, System.Formats.Cbor.CborConformanceMode.Ctap2Canonical);
        int? entryCount = reader.ReadStartMap();
        Assert.AreEqual(3, entryCount);

        Assert.AreEqual("alg", reader.ReadTextString());
        reader.SkipValue();
        Assert.AreEqual("sig", reader.ReadTextString());
        reader.SkipValue();
        Assert.AreEqual("x5c", reader.ReadTextString());
        reader.SkipValue();

        reader.ReadEndMap();
    }


    /// <summary>
    /// Builds an independent P-256 <see cref="ECDsa"/> verification oracle from a raw, compressed
    /// <see cref="PublicKeyMemory"/> — the same decompress-then-<see cref="ECDsa"/> shape
    /// <c>CtapCredentialSigningBackend.GenerateEs256KeyPairAsync</c> uses to BUILD a COSE_Key view, here
    /// used only to VERIFY, never through this library's own signing/verification seam.
    /// </summary>
    private static ECDsa BuildP256Oracle(PublicKeyMemory publicKey)
    {
        ReadOnlySpan<byte> compressed = publicKey.AsReadOnlySpan();
        EllipticCurveTypes curveType = EllipticCurveUtilities.CurveTypeFor(publicKey.Tag.Get<CryptoAlgorithm>());
        byte[] y = EllipticCurveUtilities.Decompress(compressed, curveType);
        byte[] x = compressed[1..].ToArray();

        //Independent verification oracle (self-consistency firewall): framework ECDsa verifies wire-exported library output, never mints or signs.
        return ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } });
    }


    /// <summary>
    /// Builds an independent P-256 <see cref="ECDsa"/> verification oracle from an already-decompressed
    /// <see cref="CoseKey"/> — mirrors <see cref="CtapAuthenticatorGetAssertionTests.SignCountIncrementsAndEachSignatureVerifiesIndependently"/>'s
    /// own oracle-construction shape.
    /// </summary>
    private static ECDsa BuildP256OracleFromCoseKey(CoseKey coseKey)
    {
        byte[] x = coseKey.X!.Value.ToArray();
        byte[] y = coseKey.Y!.Value.ToArray();

        //Independent verification oracle (self-consistency firewall): framework ECDsa verifies wire-exported library output, never mints or signs.
        return ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } });
    }
}
