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
/// Edge-case tests for the certified (<c>x5c</c>-present) branch of <see cref="PackedAttestation"/>
/// that no existing test in <see cref="PackedCertifiedAttestationTests"/> covers: a present-but-empty
/// <c>x5c</c> array, and a malformed <c>id-fido-gen-ce-aaguid</c> certificate extension value fed
/// through <see cref="PackedAttestation"/>'s own AAGUID-unwrapping fail path.
/// </summary>
/// <remarks>
/// Every fixture mints its certificate chain and attestation signature with an independent oracle —
/// raw <see cref="ECDsa"/>/<see cref="CertificateRequest"/>, never this package's own signing or
/// chain-building seams — so <see cref="PackedAttestation"/> is exercised against genuinely external
/// wire material reconstructed solely from the <see cref="AttestationVerificationRequest"/>'s
/// wire-shaped members, mirroring <see cref="PackedCertifiedAttestationTests"/>'s own convention.
/// </remarks>
[TestClass]
internal sealed class PackedAttestationEdgeCaseTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A statement carrying a present-but-empty <c>x5c</c> array is rejected with
    /// <see cref="Fido2AttestationErrors.MalformedStatement"/>, run through the real
    /// <see cref="PackedAttestation.Build"/> verifier — the CDDL requires at least the attestation
    /// certificate when <c>x5c</c> is present at all, so a non-null-but-empty array does not conform.
    /// Confirmed via grep: the only place this codebase previously constructed a non-null, empty
    /// <c>X5c</c> for a packed statement was an equality-test fixture that never called a verifier.
    /// </summary>
    [TestMethod]
    public async Task PresentButEmptyX5cArrayIsRejectedWithMalformedStatement()
    {
        //Independent-oracle key (owner carve-out): feeds SignWithEcdsaP256's raw ECDsa signing below, never this package's own signing seam.
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);

        //A non-null, empty X5c: the statement decoded but carried no certificates at all — distinct
        //from a null X5c, which dispatches to the self-attestation branch instead.
        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: []);

        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        RejectedAttestationResult rejected = Assert.IsInstanceOfType<RejectedAttestationResult>(result);
        Assert.AreEqual(Fido2AttestationErrors.MalformedStatement.Code, rejected.Error.Code);
    }


    /// <summary>
    /// A leaf certificate whose <c>id-fido-gen-ce-aaguid</c> extension value is a well-formed DER
    /// OCTET STRING of the wrong length (15 bytes, one short of the required 16) is rejected with
    /// <see cref="Fido2AttestationErrors.AaguidMismatch"/> — <c>TryUnwrapAaguid</c>'s explicit length
    /// check, not its <c>catch(AsnContentException)</c> fail path, since the value parses cleanly as
    /// DER.
    /// </summary>
    [TestMethod]
    public async Task AaguidExtensionWithWrongLengthOctetStringIsRejectedWithAaguidMismatch()
    {
        //A well-formed DER OCTET STRING (tag 0x04) carrying 15 content bytes rather than the
        //required 16 — TryUnwrapAaguid's own AaguidByteLength check, not a parse failure.
        byte[] fifteenBytes = [.. Enumerable.Range(1, 15).Select(static i => (byte)i)];
        byte[] malformedExtensionValue = [0x04, checked((byte)fifteenBytes.Length), .. fifteenBytes];

        Fido2AttestationError? error = await VerifyWithMalformedAaguidExtensionAsync(malformedExtensionValue);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.AaguidMismatch.Code, error.Code);
    }


    /// <summary>
    /// A leaf certificate whose <c>id-fido-gen-ce-aaguid</c> extension value carries a well-formed
    /// 16-byte OCTET STRING followed by trailing bytes is rejected with
    /// <see cref="Fido2AttestationErrors.AaguidMismatch"/> — <c>TryUnwrapAaguid</c>'s
    /// <c>reader.HasData</c> check, since the OCTET STRING itself decodes cleanly.
    /// </summary>
    [TestMethod]
    public async Task AaguidExtensionWithTrailingBytesAfterTheOctetStringIsRejectedWithAaguidMismatch()
    {
        byte[] wellFormedValue = Fido2AttestationTestVectors.EncodeAaguidExtensionValue(Guid.NewGuid());
        byte[] malformedExtensionValue = [.. wellFormedValue, 0x00];

        Fido2AttestationError? error = await VerifyWithMalformedAaguidExtensionAsync(malformedExtensionValue);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.AaguidMismatch.Code, error.Code);
    }


    /// <summary>
    /// A leaf certificate whose <c>id-fido-gen-ce-aaguid</c> extension value declares a DER OCTET
    /// STRING length longer than the bytes actually present is rejected with
    /// <see cref="Fido2AttestationErrors.AaguidMismatch"/> — <c>TryUnwrapAaguid</c>'s
    /// <c>catch(AsnContentException)</c> fail path, since the declared length overruns the buffer.
    /// </summary>
    [TestMethod]
    public async Task AaguidExtensionWithAnOverrunLengthByteIsRejectedWithAaguidMismatch()
    {
        //Tag 0x04 (OCTET STRING), declared length 0x10 (16), but only 5 content bytes actually
        //follow: AsnReader.ReadOctetString throws AsnContentException on the overrun.
        byte[] malformedExtensionValue = [0x04, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05];

        Fido2AttestationError? error = await VerifyWithMalformedAaguidExtensionAsync(malformedExtensionValue);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.AaguidMismatch.Code, error.Code);
    }


    /// <summary>
    /// Mints a section 8.2.1-conformant, otherwise-valid packed-certified leaf carrying
    /// <paramref name="malformedAaguidExtensionValue"/> under the <c>id-fido-gen-ce-aaguid</c> OID
    /// (rather than the well-formed value <see cref="Fido2AttestationTestVectors.CreateLeafAttestationCertificate"/>'s
    /// own <c>aaguidExtensionValue</c> parameter would encode), and runs it through the real
    /// <see cref="PackedAttestation.Build"/> verifier.
    /// </summary>
    /// <param name="malformedAaguidExtensionValue">The raw (possibly malformed) extension value bytes.</param>
    /// <returns>The rejection error, if any.</returns>
    private async Task<Fido2AttestationError?> VerifyWithMalformedAaguidExtensionAsync(byte[] malformedAaguidExtensionValue)
    {
        //Cert-factory carve-out (rootKey mints the CA only) and independent-oracle carve-out (leafKey is
        //embedded in the leaf certificate below and signs the attestation transcript further down, so
        //PackedAttestation is exercised against genuinely external wire material).
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);

        //Test-side certificate factory (owner carve-out): X509Extension carries the malformed AAGUID value into the CertificateRequest-minted leaf below.
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert,
            leafKey,
            isCertificateAuthority: false,
            Fido2AttestationTestVectors.RequiredOrganizationalUnit,
            aaguidExtensionValue: null,
            additionalExtensions: [new X509Extension(Fido2AttestationTestVectors.AaguidExtensionOid, malformedAaguidExtensionValue, critical: false)]);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(
            aaguid, Fido2AttestationTestVectors.CreateP256CoseKey(leafKey, WellKnownCoseAlgorithms.Es256), out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        using PkiCertificateMemory leafPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCert.RawData);
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);
        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: [leafPki, rootPki]);

        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [rootPki], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        return result is RejectedAttestationResult rejected ? rejected.Error : null;
    }


    /// <summary>Builds the <see cref="PackedAttestation"/> verifier under a given statement parser.</summary>
    private static AttestationVerifyDelegate BuildVerifier(ParsePackedAttestationStatementDelegate parseStatement) =>
        PackedAttestation.Build(
            parseStatement,
            MicrosoftX509Functions.ValidateChainAsync,
            MicrosoftX509Functions.ReadCertificateProfile,
            MicrosoftX509Functions.ReadCertificateExtensionValue);
}
