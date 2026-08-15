using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Unit tests for <see cref="CBAdESSignatureFacts"/>'s own EN 319 102-1 mapping decisions, independent of the full capstone lifecycle
/// <see cref="CBAdESCapstoneFirewalledFlowTests"/> exercises.
/// </summary>
[TestClass]
internal sealed class CBAdESSignatureFactsTests
{
    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A signing certificate that is not well-formed X.509 at all (a garbage byte string, standing in
    /// for "unsupported/unparseable" alongside an RSA certificate — <see cref="EllipticCurveSigningCertificateResolution.TryResolve"/>
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

        SignatureFormatSeam seam = CBAdESSignatureFacts.CreateSeam(CBAdESSignatureSerialization.ParseCBAdESSign1, CoseSerialization.BuildSigStructure);
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


    /// <summary>Mints a minimal B-B CB-AdES <c>COSE_Sign1</c> and wraps its wire bytes as the engine's Signed Data Object input.</summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "thumbprintDigest's ownership transfers into thumbprint, then into headers, then into " +
            "creationResult on a successful SignAsync call, which is 'using'-disposed below -- mirroring " +
            "CBAdESCapstoneFirewalledFlowTests.MintCapstoneWorldAsync's own identical CA2000 justification.")]
    private static async ValueTask<SensitiveMemoryCarrier> MintBBWireBytesAsync(CancellationToken cancellationToken)
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        //thumbprintDigest is deliberately not using-scoped: its ownership transfers into the AdESCertificateThumbprint
        //below, then into headers (the x5t parameter), then into creationResult on a successful SignAsync call --
        //mirroring CBAdESCapstoneFirewalledFlowTests.MintCapstoneWorldAsync's own identical CA2000 justification.
        DigestValue thumbprintDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            "not-a-real-certificate"u8.ToArray(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), thumbprintDigest);

        using var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);

        using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
            headers, new CBAdESAttachedPayloadInput(new byte[] { 0x01 }), unsignedHeaders: null,
            CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
            CoseSerialization.BuildSigStructure, privateKey, MicrosoftCryptographicFunctions.SignP256Async,
            dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);

        using EncodedCoseSign1 wireBytes = CBAdESSignatureSerialization.SerializeCBAdESSign1(creationResult.Message, payloadIsDetached: false, BaseMemoryPool.Shared);

        return new SensitiveMemoryCarrier(ToCarrier(wireBytes.AsReadOnlySpan().ToArray()));
    }


    /// <summary>Copies bytes into a pooled, X.509-tagged carrier — the tag is irrelevant to this file's assertions (only decodability matters).</summary>
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
