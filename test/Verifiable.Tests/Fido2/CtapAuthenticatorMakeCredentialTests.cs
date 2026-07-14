using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapAuthenticatorSimulator"/>'s <c>authenticatorMakeCredential</c> handler,
/// driven over <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/> with the shipped CBOR codecs and
/// the ES256-default credential-signing backend: the full wave-2 error matrix, credential-store
/// semantics (same-user overwrite, different-user key-store-full, non-resident registration), and the
/// <c>authData</c>/attestation byte shape.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorMakeCredentialTests
{
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A non-resident registration with <c>attestationFormatsPreference: ["none"]</c> — CTAP 2.3 section
    /// 6.1.2 step 17's single-entry-<c>"none"</c> case — succeeds with <c>fmt=none</c> and <c>attStmt</c>
    /// omitted entirely from the CTAP wire response (the step's own "omit attestation from the output"
    /// instruction; this <em>preference</em>-specific shape differs from the general <c>none</c>-format
    /// empty-map shape a multi-entry preference resolving to <c>none</c> produces, covered in
    /// <c>CtapAuthenticatorPackedAttestationTests</c>), and byte-faithful <c>authData</c>: correct
    /// <c>rpIdHash</c>, UP/AT set with UV/BE/BS/ED clear, signCount zero, and an EC2/ES256 attested
    /// credential public key — verified by round-tripping the produced <c>authData</c> through the
    /// shipped <see cref="AuthenticatorDataReader"/>, an independent SHA-256 oracle for <c>rpIdHash</c>.
    /// </summary>
    [TestMethod]
    public async Task NonResidentRegistrationWithNonePreferenceSucceedsWithAttStmtOmittedAndFaithfulAuthData()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-success-non-resident");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, attestationFormatsPreference: [WellKnownWebAuthnAttestationFormats.None]);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.None, decoded.Fmt);
        Assert.IsFalse(decoded.AttStmt.HasValue, "A single-entry [\"none\"] preference must omit attStmt from the CTAP wire response.");

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);

        //Independent oracle: rpIdHash computed here via the framework SHA-256 API, not the production
        //ComputeDigest seam the simulator itself used.
        byte[] expectedRpIdHash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(DefaultRpId));
        CollectionAssert.AreEqual(expectedRpIdHash, authenticatorData.RpIdHash.AsReadOnlySpan().ToArray());

        Assert.IsTrue(authenticatorData.Flags.UserPresent);
        Assert.IsFalse(authenticatorData.Flags.UserVerified);
        Assert.IsFalse(authenticatorData.Flags.BackupEligible);
        Assert.IsFalse(authenticatorData.Flags.BackupState);
        Assert.IsTrue(authenticatorData.Flags.AttestedCredentialDataIncluded);
        Assert.IsFalse(authenticatorData.Flags.ExtensionDataIncluded);
        Assert.AreEqual(0u, authenticatorData.SignCount);

        Assert.IsNotNull(authenticatorData.AttestedCredentialData);
        Assert.AreEqual(simulator.Aaguid, authenticatorData.AttestedCredentialData!.Aaguid);
        Assert.AreEqual(CoseKeyTypes.Ec2, authenticatorData.AttestedCredentialData.CredentialPublicKey.Kty);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, authenticatorData.AttestedCredentialData.CredentialPublicKey.Alg);
    }


    /// <summary>A resident (<c>rk: true</c>) registration also succeeds, minting a discoverable credential.</summary>
    [TestMethod]
    public async Task ResidentRegistrationSucceeds()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-success-resident");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte[] credentialId = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x41), TestContext.CancellationToken);

        Assert.HasCount(32, credentialId);
    }


    /// <summary>
    /// A non-zero-length <c>pinUvAuthParam</c> accompanied by a SUPPORTED <c>pinUvAuthProtocol</c>
    /// passes the CTAP 2.3 §6.1.2 step 2 guard; since no PIN is set on this authenticator, it is NOT
    /// protected by some form of user verification, so the junk param is ignored per step 11's own
    /// structure (line 3440) and the registration succeeds with the response authData's <c>uv</c> bit
    /// clear.
    /// </summary>
    [TestMethod]
    public async Task PinUvAuthParamWithSupportedProtocolAndNoPinSetSucceedsWithUvClear()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-pinuv-with-protocol");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> pinUvAuthParamOwner = pool.Rent(16);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, pinUvAuthParam: pinUvAuthParamOwner.Memory[..16], pinUvAuthProtocol: 1);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsFalse(authenticatorData.Flags.UserVerified, "an ignored pinUvAuthParam must never set the uv bit.");
    }


    /// <summary>A non-zero-length <c>pinUvAuthParam</c> accompanied by an UNSUPPORTED <c>pinUvAuthProtocol</c> is rejected with <c>CTAP1_ERR_INVALID_PARAMETER</c> (step 2's reject half).</summary>
    [TestMethod]
    public async Task PinUvAuthParamWithUnsupportedProtocolReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-pinuv-unsupported-protocol");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> pinUvAuthParamOwner = pool.Rent(16);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, pinUvAuthParam: pinUvAuthParamOwner.Memory[..16], pinUvAuthProtocol: 3);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
        Assert.AreEqual(1, response.Length);
    }


    /// <summary>A <c>pinUvAuthParam</c> without an accompanying <c>pinUvAuthProtocol</c> is rejected with <c>CTAP2_ERR_MISSING_PARAMETER</c>.</summary>
    [TestMethod]
    public async Task PinUvAuthParamWithoutProtocolReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-pinuv-without-protocol");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> pinUvAuthParamOwner = pool.Rent(16);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, pinUvAuthParam: pinUvAuthParamOwner.Memory[..16]);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// <c>options.uv = true</c> is rejected with <c>CTAP2_ERR_INVALID_OPTION</c> on a fresh simulator
    /// with zero fingerprint enrollments — the built-in UV method is not yet configured
    /// (<see cref="CtapAuthenticatorBuiltInUvTests.MakeCredentialOptionsUvTrueWithoutEnrollmentReturnsInvalidOption"/>
    /// proves the same gate explicitly; this test's own scope stays "no PIN, no enrollment at all").
    /// </summary>
    [TestMethod]
    public async Task UserVerificationTrueReturnsInvalidOption()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-uv-true");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, options: new CtapCommandOptions(UserVerification: true));
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>options.up = false</c> is rejected with <c>CTAP2_ERR_INVALID_OPTION</c>, unconditionally.</summary>
    [TestMethod]
    public async Task UserPresenceFalseReturnsInvalidOption()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-up-false");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, options: new CtapCommandOptions(UserPresence: false));
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, response.AsReadOnlySpan()[0]);
    }


    /// <summary>An <c>enterpriseAttestation</c> parameter against a non-enterprise-capable authenticator is rejected with <c>CTAP1_ERR_INVALID_PARAMETER</c>.</summary>
    [TestMethod]
    public async Task EnterpriseAttestationPresentReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-enterprise-attestation");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, enterpriseAttestation: 1);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>An <c>excludeList</c> entry matching an already-registered credential for the SAME rp.id is rejected with <c>CTAP2_ERR_CREDENTIAL_EXCLUDED</c>.</summary>
    [TestMethod]
    public async Task ExcludeListMatchForSameRpIdReturnsCredentialExcluded()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-exclude-match");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte[] existingCredentialId = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x42), TestContext.CancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool,
            userId: BuildFixedBytes(16, 0x43),
            excludeList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(existingCredentialId, pool) }]);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.CredentialExcluded, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// An <c>excludeList</c> entry naming a credential ID registered for a DIFFERENT rp.id does not
    /// exclude the request — CTAP 2.3 section 6.1.2 step 12 requires the match to be "bound to the
    /// specified rp.id".
    /// </summary>
    [TestMethod]
    public async Task ExcludeListMatchForDifferentRpIdDoesNotExclude()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-exclude-different-rp");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte[] otherRpCredentialId = await RegisterAndCaptureCredentialIdBytesAsync(
            simulator, pool, BuildFixedBytes(16, 0x44), TestContext.CancellationToken, rpId: "other.example");

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool,
            excludeList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(otherRpCredentialId, pool) }]);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// When no element of <c>pubKeyCredParams</c> names an algorithm the injected backend supports,
    /// the request is rejected with <c>CTAP2_ERR_UNSUPPORTED_ALGORITHM</c>.
    /// </summary>
    [TestMethod]
    public async Task UnsupportedAlgorithmReturnsUnsupportedAlgorithm()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-unsupported-algorithm");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, alg: WellKnownCoseAlgorithms.Rs256);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.UnsupportedAlgorithm, response.AsReadOnlySpan()[0]);
    }


    /// <summary>With no credential-signing backend injected at all, every request answers <c>CTAP2_ERR_UNSUPPORTED_ALGORITHM</c>.</summary>
    [TestMethod]
    public async Task NoBackendInjectedReturnsUnsupportedAlgorithm()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulatorWithBackend("mc-no-backend", backend: null);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.UnsupportedAlgorithm, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A resident registration that would push the resident-credential store past its configured
    /// capacity is rejected with <c>CTAP2_ERR_KEY_STORE_FULL</c> — CTAP 2.3 section 6.1.2's genuine
    /// storage-capacity condition, mandating no specific number: filling a small (2-slot) capacity with
    /// two different accounts at the same rp.id succeeds, and a third different account fails.
    /// </summary>
    [TestMethod]
    public async Task ResidentRegistrationExceedingCapacityReturnsKeyStoreFull()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-key-store-full", residentCredentialCapacity: 2);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x50), TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x60), TestContext.CancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool, userId: BuildFixedBytes(16, 0x70), options: new CtapCommandOptions(ResidentKey: true));
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.KeyStoreFull, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// Multiple different accounts can each hold a resident credential at the SAME rp.id, as long as the
    /// store stays under capacity — the one-resident-per-rp.id bound wave 2 enforced is removed; the
    /// store is now re-keyed by the pair (rp.id, account).
    /// </summary>
    [TestMethod]
    public async Task MultipleDifferentAccountsAtSameRelyingPartySucceedUnderCapacity()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-multi-account", residentCredentialCapacity: 3);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte[] firstCredentialId = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x91), TestContext.CancellationToken);
        byte[] secondCredentialId = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x92), TestContext.CancellationToken);

        CollectionAssert.AreNotEqual(firstCredentialId, secondCredentialId);
    }


    /// <summary>
    /// Filling capacity, then overwriting an EXISTING account's resident credential at the same rp.id,
    /// still succeeds: an overwrite never counts against capacity (CTAP 2.3 section 6.1.2's overwrite
    /// rule is unconditional and independent of the storage-capacity condition).
    /// </summary>
    [TestMethod]
    public async Task OverwriteAtFullCapacityStillSucceeds()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-overwrite-at-capacity", residentCredentialCapacity: 1);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] userId = BuildFixedBytes(16, 0xA1);

        byte[] firstCredentialId = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, userId, TestContext.CancellationToken);
        byte[] secondCredentialId = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, userId, TestContext.CancellationToken);

        CollectionAssert.AreNotEqual(firstCredentialId, secondCredentialId);
    }


    /// <summary>
    /// A resident registration for the SAME rp.id and user overwrites the existing resident credential
    /// (CTAP 2.3, section 6.1.2, step 16): the newly minted credential ID differs from the old one, and
    /// the old credential ID is fully removed from the credential-ID-keyed store — a subsequent
    /// registration whose <c>excludeList</c> names the old (overwritten) ID is no longer excluded.
    /// </summary>
    [TestMethod]
    public async Task ResidentRegistrationForSameUserOverwritesAndRemovesOldCredentialId()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-overwrite");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] userId = BuildFixedBytes(16, 0x70);

        byte[] firstCredentialId = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, userId, TestContext.CancellationToken);
        byte[] secondCredentialId = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, userId, TestContext.CancellationToken);

        CollectionAssert.AreNotEqual(firstCredentialId, secondCredentialId);

        CtapMakeCredentialRequest thirdRequest = BuildMakeCredentialRequest(
            pool,
            userId: BuildFixedBytes(16, 0x80),
            excludeList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(firstCredentialId, pool) }]);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, thirdRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A resident registration for a rp.id that already holds a DIFFERENT user's NON-resident credential
    /// succeeds — only resident credentials count against
    /// <see cref="CtapAuthenticatorState.ResidentCredentialCapacity"/>; a non-resident credential never
    /// contributes to that count and so never triggers <c>CTAP2_ERR_KEY_STORE_FULL</c>.
    /// </summary>
    [TestMethod]
    public async Task ResidentRegistrationForDifferentUserSucceedsWhenExistingCredentialIsNonResident()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("mc-key-store-not-full-non-resident");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x51), TestContext.CancellationToken, resident: false);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool, userId: BuildFixedBytes(16, 0x61), options: new CtapCommandOptions(ResidentKey: true));
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }
}
