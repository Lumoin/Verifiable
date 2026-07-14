using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Edge-case tests for <see cref="AndroidKeyAttestation"/> that sibling formats
/// (<see cref="PackedAttestation"/>, <see cref="FidoU2fAttestation"/>) already pin but
/// <see cref="AndroidKeyAttestationTests"/> does not: an empty trust anchor list, a present-but-empty
/// <c>x5c</c> array, and the shipped <c>requireTeeEnforcedAuthorizations</c> default's actual value.
/// </summary>
/// <remarks>
/// Every fixture mints its certificate chain, key description extension, and attestation signature
/// with an independent oracle — raw <see cref="ECDsa"/>/<see cref="CertificateRequest"/> and
/// BouncyCastle's ASN.1 writer (via <see cref="AndroidKeyAttestationTestVectors"/>), never this
/// package's own signing, chain-building, or ASN.1-reading seams.
/// </remarks>
[TestClass]
internal sealed class AndroidKeyAttestationEdgeCaseTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// An empty trust anchor list is rejected with <see cref="Fido2AttestationErrors.NoTrustAnchors"/>
    /// before any chain building is attempted — the same guarantee
    /// <c>PackedCertifiedAttestationTests.EmptyTrustAnchorsIsRejectedWithNoTrustAnchors</c> and its
    /// <c>fido-u2f</c> sibling already pin, ported onto <c>android-key</c>, which carries the
    /// identical check at <c>AndroidKeyAttestation.cs</c> but had no such test.
    /// </summary>
    [TestMethod]
    public async Task EmptyTrustAnchorsIsRejectedWithNoTrustAnchors()
    {
        Fido2AttestationError? error = await VerifyConformantEcVariantAndGetErrorAsync(trustAnchors: []);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.NoTrustAnchors.Code, error.Code);
    }


    /// <summary>
    /// A statement carrying a present-but-empty <c>x5c</c> array is rejected with
    /// <see cref="Fido2AttestationErrors.MalformedStatement"/>, run through the real
    /// <see cref="AndroidKeyAttestation.Build"/> verifier — <c>android-key</c> has no self-attestation
    /// branch to fall back to (unlike <c>packed</c>), so a present-but-empty <c>x5c</c> is a malformed
    /// statement. Confirmed via grep: the only place this codebase previously constructed a non-null,
    /// empty <c>X5c</c> for either statement type was an equality-test fixture that never called a
    /// verifier at all.
    /// </summary>
    [TestMethod]
    public async Task PresentButEmptyX5cArrayIsRejectedWithMalformedStatement()
    {
        //Independent oracle: raw ECDsa feeds CreateSelfSignedCa's CertificateRequest-based CA minting (cert-factory carve-out).
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //Independent oracle: raw ECDsa signs the to-be-signed transcript below via SignWithEcdsaP256, verified
        //against this same key's public half embedded in authenticatorData (oracle carve-out).
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);

        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        //A non-null, empty X5c: the statement decoded but carried no certificates at all — distinct
        //from a genuinely missing x5c, which android-key's CDDL treats as mandatory syntax.
        var statement = new AndroidKeyAttestationStatement(WellKnownCoseAlgorithms.Es256, signature, X5c: []);

        AttestationVerifyDelegate verify = AndroidKeyAttestation.Build(
            AndroidKeyAttestationTestVectors.CreateStatementParser(statement), MicrosoftX509Functions.ValidateChainAsync, MicrosoftX509Functions.ReadCertificateExtensionValue);
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [rootPki], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        RejectedAttestationResult rejected = Assert.IsInstanceOfType<RejectedAttestationResult>(result);
        Assert.AreEqual(Fido2AttestationErrors.MalformedStatement.Code, rejected.Error.Code);
    }


    /// <summary>
    /// <see cref="AndroidKeyAttestation.Build"/>'s <c>requireTeeEnforcedAuthorizations</c> parameter,
    /// omitted entirely (its shipped default), accepts a key description satisfied ONLY by
    /// <c>softwareEnforced</c> — pinning the default's actual value as union mode, per section 8.4's
    /// baseline. Every existing test that omits this parameter happens to ALSO carry a conformant
    /// <c>teeEnforced</c> list, so flipping the default to <see langword="true"/> would not have
    /// changed any of their outcomes; this fixture's <c>teeEnforced</c> list is deliberately
    /// non-conformant (empty), so only the union-mode default can accept it.
    /// </summary>
    [TestMethod]
    public async Task OmittedRequireTeeEnforcedAuthorizationsParameterDefaultsToUnionModeAcceptingSoftwareEnforcedOnlyKey()
    {
        AttestationResult result = await VerifyEcVariantAsync(
            softwareEnforced: AndroidKeyAttestationTestVectors.ConformantAuthorizationList,
            teeEnforced: AndroidKeyAttestationTestVectors.EmptyAuthorizationList,
            trustAnchors: null,
            omitRequireTeeEnforcedAuthorizations: true);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
    }


    /// <summary>
    /// Builds and runs a conformant, ES256, EC-keyed android-key statement whose authorization lists
    /// and trust anchors are individually controllable, so the fixtures above can isolate exactly the
    /// axis each targets while every other check on the path stays satisfied.
    /// </summary>
    /// <param name="softwareEnforced">The <c>softwareEnforced</c> authorization list. Defaults to the conformant list.</param>
    /// <param name="teeEnforced">The <c>teeEnforced</c> authorization list. Defaults to the conformant list.</param>
    /// <param name="trustAnchors">The trust anchors to verify against. Defaults to the minted root alone.</param>
    /// <param name="omitRequireTeeEnforcedAuthorizations">
    /// When <see langword="true"/>, calls <see cref="AndroidKeyAttestation.Build"/> without supplying
    /// <c>requireTeeEnforcedAuthorizations</c> at all — the shipped-default axis under test — rather
    /// than passing <see langword="false"/> explicitly, which would exercise the same code path but
    /// not pin the parameter's own default value.
    /// </param>
    private async Task<AttestationResult> VerifyEcVariantAsync(
        AndroidKeyAuthorizationList? softwareEnforced = null,
        AndroidKeyAuthorizationList? teeEnforced = null,
        IReadOnlyList<PkiCertificateMemory>? trustAnchors = null,
        bool omitRequireTeeEnforcedAuthorizations = false)
    {
        //Independent oracle: raw ECDsa feeds CreateSelfSignedCa's CertificateRequest-based CA minting (cert-factory carve-out).
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //Independent oracle: raw ECDsa feeds both CreateEcCredCert's CertificateRequest-based leaf minting and
        //SignWithEcdsaP256's attestation signature below (cert-factory and oracle carve-outs).
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        byte[] challenge = clientDataHash.AsReadOnlySpan().ToArray();

        byte[] keyDescriptionBytes = AndroidKeyAttestationTestVectors.EncodeKeyDescriptionExtensionValue(
            challenge,
            softwareEnforced ?? AndroidKeyAttestationTestVectors.ConformantAuthorizationList,
            teeEnforced ?? AndroidKeyAttestationTestVectors.ConformantAuthorizationList);
        using X509Certificate2 credCert = AndroidKeyAttestationTestVectors.CreateEcCredCert(rootCert, credentialKey, keyDescriptionBytes);

        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);

        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        using PkiCertificateMemory credCertPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(credCert.RawData);
        var statement = new AndroidKeyAttestationStatement(WellKnownCoseAlgorithms.Es256, signature, [credCertPki, rootPki]);

        AttestationVerifyDelegate verify = omitRequireTeeEnforcedAuthorizations
            ? AndroidKeyAttestation.Build(
                AndroidKeyAttestationTestVectors.CreateStatementParser(statement), MicrosoftX509Functions.ValidateChainAsync, MicrosoftX509Functions.ReadCertificateExtensionValue)
            : AndroidKeyAttestation.Build(
                AndroidKeyAttestationTestVectors.CreateStatementParser(statement), MicrosoftX509Functions.ValidateChainAsync, MicrosoftX509Functions.ReadCertificateExtensionValue,
                requireTeeEnforcedAuthorizations: false);

        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty,
            trustAnchors: trustAnchors ?? [rootPki], validationTime: TestClock.CanonicalEpoch);

        return await verify(request, TestContext.CancellationToken);
    }


    /// <summary>Runs <see cref="VerifyEcVariantAsync"/> with fully-conformant authorization lists and extracts the rejection error, if any.</summary>
    /// <param name="trustAnchors">The trust anchors to verify against.</param>
    private async Task<Fido2AttestationError?> VerifyConformantEcVariantAndGetErrorAsync(IReadOnlyList<PkiCertificateMemory> trustAnchors)
    {
        AttestationResult result = await VerifyEcVariantAsync(trustAnchors: trustAnchors);

        return result is RejectedAttestationResult rejected ? rejected.Error : null;
    }
}
