using System;
using System.Buffers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Unit tests for <see cref="JAdESSignatureFacts"/>'s own EN 319 102-1 mapping decisions, independent of the full capstone lifecycle <see cref="JAdESCapstoneFirewalledFlowTests"/> exercises.
/// </summary>
[TestClass]
internal sealed class JAdESSignatureFactsTests
{
    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A B-B-conformant JAdES signature extracts successfully, and its <c>alg</c>/<c>iat</c> facts are mapped.
    /// </summary>
    [TestMethod]
    public async Task ExtractFactsSucceedsForAConformantBBSignature()
    {
        using SensitiveMemoryCarrier signedDataObject = await MintBBWireBytesAsync(TestContext.CancellationToken).ConfigureAwait(false);

        SignatureFormatSeam seam = JAdESSignatureFacts.CreateSeam(
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESProtectedHeaderJson.DetectX5tPresence,
            JAdESEtsiUJson.TryParse, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder);

        using SignatureFacts facts = await seam.ExtractFacts(
            new SignatureFactsExtractionContext { SignedDataObject = signedDataObject.Memory },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureFactsStatus.Extracted, facts.Status, "A B-B conformant JAdES signature must extract.");
        Assert.AreEqual(SignatureFormatIdentifier.JAdES, facts.Format);
        Assert.HasCount(1, facts.AlgorithmUses);
        Assert.AreEqual(WellKnownJwaValues.Es256, facts.AlgorithmUses[0].Algorithm.Oid);
        Assert.IsTrue(facts.TryGetAttribute("iat", out SignatureAttributeFacts? iatAttribute), "iat is mandatory from the outset and must be reported as a signed attribute.");
        Assert.IsTrue(iatAttribute!.IsWellFormed);
        Assert.IsNotNull(facts.ClaimedSigningTime);
    }


    /// <summary>
    /// A signing certificate that is not well-formed X.509 at all (a garbage byte string, standing in for
    /// "unsupported/unparseable" alongside an RSA certificate — <see cref="EllipticCurveSigningCertificateResolution.TryResolve"/>
    /// treats both identically, see that method's own remarks) means no verification could even be ATTEMPTED —
    /// <see cref="SignatureCryptographicOutcome.NotVerified"/>, which <see cref="CryptographicVerification"/>'s
    /// own default arm maps to <see cref="BuildingBlockIndication.Indeterminate"/>/<see cref="SignatureValidationSubIndication.Custom"/>,
    /// never <see cref="SignatureCryptographicOutcome.SignatureValueFailure"/>/<see cref="BuildingBlockIndication.Failed"/>.
    /// </summary>
    [TestMethod]
    public async Task VerifyCryptographyReportsIndeterminateNotFailedForAnUnsupportedSigningCertificate()
    {
        using SensitiveMemoryCarrier signedDataObject = await MintBBWireBytesAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory garbageCertificate = ToCarrier(new byte[] { 0x00, 0x01, 0x02, 0x03 });

        SignatureFormatSeam seam = JAdESSignatureFacts.CreateSeam(
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESProtectedHeaderJson.DetectX5tPresence,
            JAdESEtsiUJson.TryParse, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder);
        using SignatureFacts facts = await seam.ExtractFacts(
            new SignatureFactsExtractionContext { SignedDataObject = signedDataObject.Memory },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(SignatureFactsStatus.Extracted, facts.Status, "The wire bytes are B-B conformant; extraction must succeed before cryptographic verification runs.");

        CryptographicVerificationResult result = await CryptographicVerification.VerifyAsync(
            facts, garbageCertificate, validatedCertificateChain: [], signerDocuments: [],
            seam.VerifyCryptography, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureCryptographicOutcome.NotVerified, result.Outcome,
            "An unsupported/unparseable signing certificate means no verification was attempted, not one that was attempted and failed.");
        Assert.AreEqual(BuildingBlockIndication.Indeterminate, result.Conclusion.Indication,
            "Table 15's cannot-process case is INDETERMINATE, never TOTAL-FAILED.");
        Assert.AreEqual(SignatureValidationSubIndication.Custom, result.Conclusion.SubIndications[0],
            "CryptographicVerification's own default (cannot-process) arm reports CUSTOM.");
    }


    /// <summary>
    /// A malformed JAdES JWS structure maps to <see cref="SignatureFactsStatus.FormatFailure"/> — Class 1 of the
    /// mapping discipline (see <see cref="JAdESSignatureFacts"/>'s own remarks): decode failure, never a
    /// downgraded attribute.
    /// </summary>
    [TestMethod]
    public async Task ExtractFactsReportsFormatFailureForMalformedWireBytes()
    {
        using PkiCertificateMemory garbageWireBytes = ToCarrier("not a JWS at all"u8.ToArray());

        SignatureFormatSeam seam = JAdESSignatureFacts.CreateSeam(
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESProtectedHeaderJson.DetectX5tPresence,
            JAdESEtsiUJson.TryParse, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder);

        using SignatureFacts facts = await seam.ExtractFacts(
            new SignatureFactsExtractionContext { SignedDataObject = garbageWireBytes },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureFactsStatus.FormatFailure, facts.Status);
        Assert.AreEqual(SignatureFormatIdentifier.JAdES, facts.Format);
        Assert.IsFalse(string.IsNullOrWhiteSpace(facts.FormatFailureReason));
    }


    /// <summary>Mints a minimal B-B JAdES signature (Compact serialization) and wraps its wire bytes as the engine's Signed Data Object input.</summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into creationResult on a " +
            "successful SignAsync call, which is 'using'-disposed below -- mirroring " +
            "JAdESCapstoneFirewalledFlowTests.MintCapstoneWorldAsync's own identical CA2000 justification.")]
    private static async ValueTask<SensitiveMemoryCarrier> MintBBWireBytesAsync(CancellationToken cancellationToken)
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var headers = new JAdESProtectedHeaders(
            WellKnownJwaValues.Es256, issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch), x5tHashS256: TestDigest());

        using JAdESSignatureCreationResult creationResult = await JAdESSignatureCreation.SignAsync(
            headers, new JAdESAttachedPayloadInput(new byte[] { 0x01, 0x02, 0x03 }), unsignedHeaders: null,
            JAdESProtectedHeaderJson.Encode, JAdESEtsiUJson.Encode, TestSetup.Base64UrlEncoder,
            privateKey, MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);

        byte[] wireBytes = JAdESSignatureCreation.Serialize(creationResult, JoseSerializationFormat.Compact, TestSetup.Base64UrlEncoder, JsonSerialize);

        return new SensitiveMemoryCarrier(ToCarrier(wireBytes));
    }


    /// <summary>Serializes <paramref name="value"/> to UTF-8 JSON bytes.</summary>
    private static byte[] JsonSerialize(object value) => JsonSerializer.SerializeToUtf8Bytes(value);


    private static DigestValue TestDigest()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(32);
        new byte[32].CopyTo(owner.Memory);

        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }


    /// <summary>Copies bytes into a pooled, X.509-tagged carrier — the tag is irrelevant to this file's assertions (only decodability matters for the certificate cases).</summary>
    /// <param name="bytes">The bytes to copy.</param>
    /// <returns>The owned carrier.</returns>
    private static PkiCertificateMemory ToCarrier(byte[] bytes)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>Wraps a <see cref="PkiCertificateMemory"/> so it can stand in for the engine's <see cref="SensitiveMemory"/> Signed Data Object slot.</summary>
    /// <param name="carrier">The owned carrier.</param>
    private sealed class SensitiveMemoryCarrier(PkiCertificateMemory carrier): IDisposable
    {
        /// <summary>Gets the carrier as the engine's own Signed Data Object type.</summary>
        public SensitiveMemory Memory => carrier;

        /// <inheritdoc/>
        public void Dispose() => carrier.Dispose();
    }
}
