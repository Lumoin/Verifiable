using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapAuthenticatorSimulator"/>'s <c>authenticatorMakeCredential</c> attestation
/// format selection (CTAP 2.3, section 6.1.2, step 17) and packed self-attestation emission — driven over
/// <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/> with the shipped CBOR codecs and the
/// ES256-default credential-signing backend.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorPackedAttestationTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// An <c>attestationFormatsPreference</c>-absent registration defaults to packed self-attestation —
    /// the authenticator's own choice per step 17's first bullet. The emitted <c>attStmt</c> is decoded
    /// by the SHIPPED <see cref="PackedAttestationStatementCborReader"/> and verified by the SHIPPED
    /// <see cref="PackedAttestation"/> self-attestation branch against the credential's own minted public
    /// key, over real wire bytes rather than a hand-built statement.
    /// </summary>
    [TestMethod]
    public async Task AbsentPreferenceDefaultsToPackedSelfAttestationAcceptedByShippedVerifier()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("packed-default");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);

        using IMemoryOwner<byte> clientDataHashOwner = pool.Rent(request.ClientDataHash.Length);
        request.ClientDataHash.AsReadOnlySpan().CopyTo(clientDataHashOwner.Memory.Span);
        using DigestValue independentClientDataHash = new(clientDataHashOwner, CryptoTags.Sha256Digest);

        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.Packed, decoded.Fmt);
        Assert.IsTrue(decoded.AttStmt.HasValue, "A packed self-attestation response must carry attStmt.");

        PackedAttestationStatement statement = PackedAttestationStatementCborReader.Parse(decoded.AttStmt!.Value, pool);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, statement.Alg);
        Assert.IsNull(statement.X5c, "Self-attestation must omit x5c entirely.");

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);

        AttestationVerifyDelegate verify = PackedAttestation.Build(
            PackedAttestationStatementCborReader.Parse,
            MicrosoftX509Functions.ValidateChainAsync,
            MicrosoftX509Functions.ReadCertificateProfile,
            MicrosoftX509Functions.ReadCertificateExtensionValue);

        AttestationVerificationRequest verifyRequest = new(
            decoded.AuthData, authenticatorData, independentClientDataHash, decoded.AttStmt.Value, trustAnchors: [], validationTime: TestClock.CanonicalEpoch, pool);

        AttestationResult result = await verify(verifyRequest, TestContext.CancellationToken);

        Assert.IsInstanceOfType<SelfAttestationResult>(result);
    }


    /// <summary>
    /// A single-entry <c>["packed"]</c> preference resolves to packed self-attestation via the general
    /// lowest-index-supported-entry rule (step 17's third bullet) — the same outcome as an absent
    /// preference, but reached by an explicit, non-<c>"none"</c> single-entry list.
    /// </summary>
    [TestMethod]
    public async Task SingleEntryPackedPreferenceResolvesToPackedSelfAttestation()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("packed-single-entry");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, attestationFormatsPreference: [WellKnownWebAuthnAttestationFormats.Packed]);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.Packed, decoded.Fmt);
        Assert.IsTrue(decoded.AttStmt.HasValue);
    }


    /// <summary>
    /// A preference list naming both formats with <c>"packed"</c> at the lower index —
    /// <c>["packed", "none"]</c> — resolves to packed self-attestation: the lowest-index supported entry
    /// wins (step 17's third bullet).
    /// </summary>
    [TestMethod]
    public async Task PackedAtLowerIndexThanNoneResolvesToPackedSelfAttestation()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("packed-lower-index");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool, attestationFormatsPreference: [WellKnownWebAuthnAttestationFormats.Packed, WellKnownWebAuthnAttestationFormats.None]);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.Packed, decoded.Fmt);
        Assert.IsTrue(decoded.AttStmt.HasValue);
    }


    /// <summary>
    /// A preference list naming both formats with <c>"none"</c> at the lower index —
    /// <c>["none", "packed"]</c> — resolves to the STANDARD section 8.7 <c>none</c> shape: <c>fmt=none</c>
    /// with the canonical empty-map <c>attStmt</c> PRESENT. This differs from the single-entry
    /// <c>["none"]</c> case (covered in <c>CtapAuthenticatorMakeCredentialTests</c>), which omits
    /// <c>attStmt</c> entirely — only that exact single-entry list triggers step 17's "omit attestation
    /// from the output" instruction; a multi-entry list resolving to <c>none</c> via the general
    /// lowest-index rule uses the format's own ordinary attStmt shape instead.
    /// </summary>
    [TestMethod]
    public async Task NoneAtLowerIndexThanPackedResolvesToNoneWithEmptyMapStatementPresent()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("packed-none-lower-index");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool, attestationFormatsPreference: [WellKnownWebAuthnAttestationFormats.None, WellKnownWebAuthnAttestationFormats.Packed]);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.None, decoded.Fmt);
        Assert.IsTrue(decoded.AttStmt.HasValue, "A multi-entry preference resolving to none must still carry the standard empty-map attStmt.");
        Assert.HasCount(1, decoded.AttStmt!.Value);
        Assert.AreEqual(NoneAttestation.CanonicalEmptyMap, decoded.AttStmt.Value.Span[0]);
    }


    /// <summary>
    /// A preference list naming no format this authenticator supports falls back to packed
    /// self-attestation — this authenticator's chosen "any other means" (step 17's third bullet's own
    /// fallback for "no supported format identifier appears on the list").
    /// </summary>
    [TestMethod]
    public async Task PreferenceWithNoSupportedFormatFallsBackToPackedSelfAttestation()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("packed-fallback");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, attestationFormatsPreference: [WellKnownWebAuthnAttestationFormats.Tpm]);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.Packed, decoded.Fmt);
        Assert.IsTrue(decoded.AttStmt.HasValue);
    }


    /// <summary>
    /// An empty <c>attestationFormatsPreference</c> list (present but zero entries) is treated the same
    /// as an absent one — packed self-attestation — per step 17's first bullet's own "absent or its value
    /// is the empty list" wording.
    /// </summary>
    [TestMethod]
    public async Task EmptyPreferenceListDefaultsToPackedSelfAttestation()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("packed-empty-list");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, attestationFormatsPreference: []);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.Packed, decoded.Fmt);
        Assert.IsTrue(decoded.AttStmt.HasValue);
    }
}
