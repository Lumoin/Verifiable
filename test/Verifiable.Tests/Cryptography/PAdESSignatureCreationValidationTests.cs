using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="PAdESSignatureCreation"/> and <see cref="PAdESSignatureValidation"/>:
/// PAdES-B-B and PAdES-B-T creation and validation composing the shipped CAdES
/// creation/augmentation/verification surfaces over the <see cref="PdfIncrementalUpdateWriter"/> byte surface,
/// round-tripped over both fixture shapes the arc's own oracle-independence discipline expects — a fresh
/// single-signature document this suite builds directly (not through <c>PdfFixtureBuilder</c>, the reader's own
/// independent test-only oracle) and a second, layered incremental-update signature over the first.
/// </summary>
[TestClass]
internal sealed class PAdESSignatureCreationValidationTests
{
    /// <summary>The address handed to the TSA transport delegate; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.pades.example.test/";

    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;

    private static DateTimeOffset SignatureTimestampTime { get; } = TestClock.CanonicalEpoch.AddHours(1);


    public required TestContext TestContext { get; set; }


    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">ETSI EN 319 142-1 V1.2.1</see>
    /// PA-4.1-01, PA-4.1-03, PA-5.4.2.2-04, PA-6.1-DEF-a, PA-6.3-g, PA-6.3-h, PA-6.3-j.
    /// </remarks>
    [TestMethod]
    public async Task CreatesAndValidatesARoundTripPAdESBaselineSignature()
    {
        using PAdESScenario scenario = PAdESScenario.Create();

        PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
            scenario.BuildRequest(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AdESBaselineLevel.BB, signed.Level);

        using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
            signed.Bytes, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        Assert.HasCount(1, validation.Signatures!);
        PAdESSignatureValidationResult result = validation.Signatures![0];
        Assert.IsTrue(result.IsValid, $"Expected Valid, was {result.Status}.");
        Assert.AreEqual(AdESBaselineLevel.BB, result.Level);
        Assert.AreEqual(SigningTime, result.SigningTime);
        Assert.IsNull(result.TimestampTime, "A PAdES-B-B signature carries no signature-time-stamp.");
        Assert.IsNotNull(result.SignerCertificate);
        Assert.IsTrue(result.SignerCertificate!.AsReadOnlySpan().SequenceEqual(scenario.SignerCertificate.AsReadOnlySpan()));
    }


    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">ETSI EN 319 142-1 V1.2.1</see>
    /// PA-6.1-DEF-b, PA-6.3-T23, PA-6.3-T24, PA-6.3-n.
    /// </remarks>
    [TestMethod]
    public async Task CreatesAndValidatesARoundTripPAdESTimestampSignature()
    {
        using PAdESScenario scenario = PAdESScenario.Create();
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority, scenario.Root], SignatureTimestampTime);

        PAdESSigningRequest request = scenario.BuildRequest() with
        {
            ContentsCapacityBytes = 16384,
            SignatureTimestamp = new PAdESSignatureTimestampRequest
            {
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync
            }
        };

        PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
            request, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AdESBaselineLevel.BT, signed.Level);

        using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
            signed.Bytes, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        PAdESSignatureValidationResult result = validation.Signatures![0];
        Assert.IsTrue(result.IsValid, $"Expected Valid, was {result.Status}.");
        Assert.AreEqual(AdESBaselineLevel.BT, result.Level);
        Assert.AreEqual(SignatureTimestampTime, result.TimestampTime);
    }


    [TestMethod]
    public async Task ValidatesBothSignaturesOfALayeredIncrementalUpdate()
    {
        using PAdESScenario scenario = PAdESScenario.Create();

        PAdESSignedDocument first = await PAdESSignatureCreation.SignAsync(
            scenario.BuildRequest(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using PAdESValidationResult firstLocated = await PAdESSignatureValidation.ValidateAsync(
            first.Bytes, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        PdfIncrementalUpdateAnchor secondAnchor = LocatePlaceholderAnchor(first.Bytes);

        PAdESSigningRequest secondRequest = scenario.BuildRequest() with
        {
            PriorDocument = first.Bytes,
            Anchor = secondAnchor,
            SigningTime = SigningTime.AddHours(2),
            Name = "Second Signer"
        };

        PAdESSignedDocument second = await PAdESSignatureCreation.SignAsync(
            secondRequest, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
            second.Bytes, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        Assert.HasCount(2, validation.Signatures!);
        Assert.IsTrue(validation.Signatures![0].IsValid, $"First signature: expected Valid, was {validation.Signatures[0].Status}.");
        Assert.IsTrue(validation.Signatures![1].IsValid, $"Second signature: expected Valid, was {validation.Signatures[1].Status}.");
        Assert.AreEqual(SigningTime, validation.Signatures[0].SigningTime);
        Assert.AreEqual(SigningTime.AddHours(2), validation.Signatures[1].SigningTime);

        //PA-6.3-k: a legitimately multi-signed document is not a coverage violation -- the earlier signature's
        //own, shorter coverage is expected and exposed as a fact, not folded into a failure.
        Assert.IsFalse(validation.Signatures[0].CoversDocumentEnd, "The earlier signature's own ByteRange must stop at its own, shorter revision's length.");
        Assert.IsTrue(validation.Signatures[1].CoversDocumentEnd, "The newest signature's own ByteRange must cover the whole final document.");
    }


    /// <summary>
    /// (the shadow attack): content appended after the newest signature's own <c>ByteRange</c> coverage never
    /// touches the signed bytes themselves, so cryptographic verification alone does not catch it -- only
    /// PA-6.3-k's own coverage gate does. Regression (a).
    /// </summary>
    [TestMethod]
    public async Task ContentAppendedAfterTheNewestSignaturesByteRangeCoverageIsRejected()
    {
        using PAdESScenario scenario = PAdESScenario.Create();
        PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
            scenario.BuildRequest(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        int xrefOffset = FindLastXrefOffset(signed.Bytes);
        byte[] shadowed = PdfFixtureBuilder.AppendUnsignedIncrementalUpdate(signed.Bytes, xrefOffset);

        using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
            shadowed, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        Assert.HasCount(1, validation.Signatures!);
        Assert.AreEqual(PAdESSignatureStatus.IncompleteByteRangeCoverage, validation.Signatures![0].Status,
            "Content appended after the newest (and only) signature's own coverage must be rejected (PA-6.3-k).");
        Assert.IsFalse(validation.Signatures[0].CoversDocumentEnd);
    }


    /// <summary>
    /// <c>Contents</c>' own reserved-capacity padding (ISO 32000-1 clause 7.3.4) must be all-zero octets; a single non-zero trailing octet
    /// — well inside the <c>ByteRange</c>-covered, signed bytes, so cryptographic verification alone never sees it either — is the
    /// smuggling vector <see cref="PAdESSignatureFacts.TryTrimToDerLength"/> exists to close.
    /// </summary>
    [TestMethod]
    public async Task NonZeroTrailingContentInContentsPaddingIsRejected()
    {
        using PAdESScenario scenario = PAdESScenario.Create();
        PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
            scenario.BuildRequest(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] corrupted = CorruptFirstPaddingHexDigit(signed.Bytes, (byte)'1');

        using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
            corrupted, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        Assert.HasCount(1, validation.Signatures!);
        Assert.AreEqual(PAdESSignatureStatus.InvalidContentsPadding, validation.Signatures![0].Status,
            "A non-zero octet past the DER-encoded SignedData's own end must be rejected, never silently trimmed away.");
    }


    /// <summary>a second, well-formed DER TLV spliced into <c>Contents</c>' own reserved-capacity padding is rejected the same way a single stray non-zero octet is — the padding convention tolerates only all-zero filler, never a second structure.</summary>
    [TestMethod]
    public async Task ASecondSignedDataAppendedInTheContentsPaddingIsRejected()
    {
        using PAdESScenario scenario = PAdESScenario.Create();
        PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
            scenario.BuildRequest(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //A plausible-looking, well-formed DER fragment (an INTEGER TLV) spliced right at the padding's own start
        //-- not random noise, the shape a smuggled second structure would actually take.
        byte[] smuggledFragment = [0x02, 0x01, 0x2A];
        byte[] corrupted = SpliceIntoContentsPadding(signed.Bytes, smuggledFragment);

        using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
            corrupted, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        Assert.HasCount(1, validation.Signatures!);
        Assert.AreEqual(PAdESSignatureStatus.InvalidContentsPadding, validation.Signatures![0].Status,
            "A second DER structure smuggled into the reserved Contents capacity must be rejected.");
    }


    /// <summary>Overwrites the first zero-padding hexadecimal digit past the real DER SignedData's own end with a single non-zero hex digit.</summary>
    private static byte[] CorruptFirstPaddingHexDigit(byte[] document, byte nonZeroHexDigit)
    {
        byte[] mutated = (byte[])document.Clone();
        int paddingHexStart = LocateContentsPaddingHexStart(document);
        mutated[paddingHexStart] = nonZeroHexDigit;

        return mutated;
    }


    /// <summary>Overwrites the zero-padding hex digits past the real DER SignedData's own end with <paramref name="fragment"/>'s own hex rendering, leaving whatever padding remains after it all-zero.</summary>
    private static byte[] SpliceIntoContentsPadding(byte[] document, byte[] fragment)
    {
        byte[] mutated = (byte[])document.Clone();
        int paddingHexStart = LocateContentsPaddingHexStart(document);
        string fragmentHex = Convert.ToHexString(fragment);
        for(int i = 0; i < fragmentHex.Length; ++i)
        {
            mutated[paddingHexStart + i] = (byte)fragmentHex[i];
        }

        return mutated;
    }


    /// <summary>Decodes a signed document's own located <c>Contents</c>, reads the real DER SignedData TLV's own encoded length, and returns the document byte offset of the first hexadecimal digit of the all-zero padding that follows it.</summary>
    private static int LocateContentsPaddingHexStart(byte[] document)
    {
        using PdfByteSurfaceParseResult located = PdfByteSurfaceReader.Locate(document, BaseMemoryPool.Shared);
        PdfSignatureDictionary signature = located.SignatureDictionaries![0];

        System.Formats.Asn1.AsnDecoder.ReadEncodedValue(
            signature.Contents.AsReadOnlySpan(), System.Formats.Asn1.AsnEncodingRules.DER, out _, out _, out int consumed);

        int hexStart = signature.ByteRange.GapStart + 1;

        return hexStart + (consumed * 2);
    }


    [TestMethod]
    public async Task TamperingWithADocumentByteInsideTheSignedRangeIsDetected()
    {
        using PAdESScenario scenario = PAdESScenario.Create();
        PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
            scenario.BuildRequest(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] tampered = (byte[])signed.Bytes.Clone();
        int catalogByte = Array.IndexOf(tampered, (byte)'C', 0); //Somewhere inside "/Type /Catalog", well within the first signed segment.
        tampered[catalogByte] = (byte)'X';

        using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
            tampered, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        Assert.AreEqual(PAdESSignatureStatus.InvalidSignature, validation.Signatures![0].Status);
    }


    /// <summary>
    /// Shrinking a lone signature's own declared coverage away from the document's actual end of file is caught by
    /// PA-6.3-k's own coverage gate (<see cref="PAdESSignatureStatus.IncompleteByteRangeCoverage"/>), reached
    /// before cryptographic verification is ever attempted -- NOT evidence that a byte-mismatch inside the
    /// declared segments is detected; <see cref="TamperingWithADocumentByteInsideTheSignedRangeIsDetected"/> and
    /// <see cref="TamperingWithAContentsHexDigitIsDetected"/> are that evidence.
    /// </summary>
    [TestMethod]
    public async Task ShrinkingTheDeclaredByteRangeCoverageIsDetected()
    {
        using PAdESScenario scenario = PAdESScenario.Create();
        PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
            scenario.BuildRequest(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] tampered = (byte[])signed.Bytes.Clone();
        PdfByteRange original = GetByteRange(signed.Bytes);

        //Shrinks the second segment by two bytes -- the ByteRange itself stays internally well-formed (in
        //bounds, non-overlapping), so the byte-surface reader still locates the signature; its own declared
        //coverage now falls two bytes short of the document's actual end of file.
        string corrupted = $"[{Pad(0)} {Pad(original.FirstLength)} {Pad(original.SecondOffset)} {Pad(original.SecondLength - 2)}]";
        int byteRangeArrayOffset = FindByteRangeArrayOffset(tampered);
        Encoding.ASCII.GetBytes(corrupted).CopyTo(tampered, byteRangeArrayOffset);

        using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
            tampered, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        Assert.AreEqual(PAdESSignatureStatus.IncompleteByteRangeCoverage, validation.Signatures![0].Status);
        Assert.IsFalse(validation.Signatures[0].CoversDocumentEnd);
    }


    [TestMethod]
    public async Task TamperingWithAContentsHexDigitIsDetected()
    {
        using PAdESScenario scenario = PAdESScenario.Create();
        PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
            scenario.BuildRequest(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] tampered = (byte[])signed.Bytes.Clone();
        int contentsStart = FindContentsHexStart(tampered);
        //Flips a hex digit well inside the real signature bytes (past the DER SEQUENCE header) rather than the
        //zero-padding tail, so the corruption lands on real CMS content, not an already-zero pad byte.
        tampered[contentsStart + 20] = tampered[contentsStart + 20] == (byte)'0' ? (byte)'1' : (byte)'0';

        using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
            tampered, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        Assert.IsFalse(validation.Signatures![0].IsValid, "A single flipped Contents hex digit must not still validate.");
    }


    [TestMethod]
    public async Task SigningWithAMismatchedPrivateKeyFailsValidation()
    {
        using PAdESScenario scenario = PAdESScenario.Create();
        using PrivateKeyMemory wrongKey = PAdESScenario.MintUnrelatedPrivateKey();

        PAdESSigningRequest request = scenario.BuildRequest() with { SignerPrivateKey = wrongKey };

        PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
            request, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
            signed.Bytes, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        Assert.AreEqual(PAdESSignatureStatus.InvalidSignature, validation.Signatures![0].Status);
    }


    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">ETSI EN 319 142-1 V1.2.1</see>
    /// PA-6.3-T13.
    /// </remarks>
    [TestMethod]
    public async Task TheProducedSignatureCarriesNoCmsSigningTimeAttribute()
    {
        using PAdESScenario scenario = PAdESScenario.Create();
        PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
            scenario.BuildRequest(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
            signed.Bytes, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        PAdESSignatureValidationResult result = validation.Signatures![0];
        Assert.IsTrue(result.IsValid, $"Expected Valid, was {result.Status}.");

        //A genuinely successful detached CAdES verification reads the CMS signed attributes for real (unlike a
        //failure path, which always carries a null SigningTime by construction): a non-null value here would
        //mean the composed CAdES creation surface leaked the signing-time attribute PA-6.3-T13 forbids.
        Assert.IsNull(result.CryptographicResult!.SigningTime, "PA-6.3-T13 (cardinality 0): the CMS signing-time attribute shall not be present.");
        Assert.AreEqual(SigningTime, result.SigningTime, "The claimed signing time is carried by the Signature Dictionary's own M entry instead (PA-6.3-T12/g).");
    }


    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">ETSI EN 319 142-1 V1.2.1</see>
    /// PA-4.1-04, PA-5.2-01, PA-6.3-T19, PA-6.3-d1, PA-6.3-d2, PA-6.3-m1.
    /// </remarks>
    [TestMethod]
    public async Task RefusesReasonAlongsideCommitmentTypeIndication()
    {
        using PAdESScenario scenario = PAdESScenario.Create();
        PAdESSigningRequest request = scenario.BuildRequest() with
        {
            Reason = "Approval",
            OptionalAttributes = new CAdESOptionalSignedAttributes
            {
                CommitmentType = new CAdESCommitmentType { CommitmentTypeId = "1.2.840.113549.1.9.16.6.1" }
            }
        };

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
        {
            _ = await PAdESSignatureCreation.SignAsync(request, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">ETSI EN 319 142-1 V1.2.1</see>
    /// PA-6.3-m2.
    /// </remarks>
    [TestMethod]
    public async Task RefusesReasonAlongsideSignaturePolicyIdentifier()
    {
        using PAdESScenario scenario = PAdESScenario.Create();
        PAdESSigningRequest request = scenario.BuildRequest() with
        {
            Reason = "Approval",
            OptionalAttributes = new CAdESOptionalSignedAttributes
            {
                SignaturePolicyIdentifier = new CAdESSignaturePolicyIdentifier
                {
                    SigPolicyId = "1.2.3.4.5",
                    HashAlgorithm = PkiDigestAlgorithm.Sha256,
                    SigPolicyHash = new byte[32]
                }
            }
        };

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
        {
            _ = await PAdESSignatureCreation.SignAsync(request, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    /// <summary>PA-6.3-l: a Signature Dictionary whose <c>SubFilter</c> is not <c>ETSI.CAdES.detached</c> fails before any cryptographic verification is attempted (arbitrary <c>Contents</c> bytes are enough to prove the gate runs first).</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">ETSI EN 319 142-1 V1.2.1</see>
    /// PA-6.3-i.
    /// </remarks>
    [TestMethod]
    public async Task SignatureDictionaryWithAnUnsupportedSubFilterFailsValidationWithoutReachingCryptography()
    {
        PdfFixtureBuilder.SingleUpdateFixture fixture = PdfFixtureBuilder.BuildSingleUpdateSignedPdf(
            [0xDE, 0xAD, 0xBE, 0xEF], subFilter: "adbe.pkcs7.detached");

        using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
            fixture.Bytes, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        Assert.AreEqual(PAdESSignatureStatus.UnsupportedSubFilter, validation.Signatures![0].Status);
    }


    /// <summary>PA-6.3-T12/g): a Signature Dictionary with no <c>M</c> entry fails before any cryptographic verification is attempted.</summary>
    [TestMethod]
    public async Task SignatureDictionaryWithNoSigningTimeFailsValidationWithoutReachingCryptography()
    {
        PdfFixtureBuilder.SingleUpdateFixture fixture = PdfFixtureBuilder.BuildSingleUpdateSignedPdf(
            [0xDE, 0xAD, 0xBE, 0xEF], signingTime: null);

        using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
            fixture.Bytes, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        Assert.AreEqual(PAdESSignatureStatus.MissingSigningTime, validation.Signatures![0].Status);
    }


    /// <summary>
    /// PA-6.3-T13 at validation: a signature whose composed CMS carries the (PAdES-forbidden) <c>signing-time</c>
    /// attribute is built directly through <see cref="PdfIncrementalUpdateWriter"/> and
    /// <see cref="CAdESSignatureCreation.SignAsync(PkiCertificateMemory, PrivateKeyMemory, ReadOnlyMemory{byte}?, ReadOnlyMemory{byte}?, DateTimeOffset, IReadOnlyList{PkiCertificateMemory}?, CryptographicConstraints?, bool, BaseMemoryPool, CancellationToken, CAdESOptionalSignedAttributes?, bool)"/>
    /// with <c>shouldIncludeSigningTimeAttribute: true</c> — bypassing <see cref="PAdESSignatureCreation"/>'s own
    /// <c>shouldIncludeSigningTimeAttribute: false</c> call, the one production path this library never takes — so the
    /// signature is otherwise genuinely valid and the failure is provably PA-6.3-T13's own gate, not a
    /// cryptographic one.
    /// </summary>
    [TestMethod]
    public async Task SignatureCarryingTheProhibitedCmsSigningTimeAttributeIsDetectedAtValidation()
    {
        using PAdESScenario scenario = PAdESScenario.Create();

        PdfSignaturePlaceholder placeholder = PdfIncrementalUpdateWriter.AppendPlaceholderSignature(
            scenario.UnsignedDocument,
            scenario.Anchor,
            new PdfSignatureFieldValues { SigningTime = SigningTime },
            contentsCapacityBytes: 4096);

        using DigestValue contentDigest = await ComputeByteRangeDigestAsync(placeholder, TestContext.CancellationToken).ConfigureAwait(false);

        using CmsSignedData signature = await CAdESSignatureCreation.SignAsync(
            scenario.SignerCertificate,
            scenario.SignerPrivateKey,
            content: null,
            detachedContentDigest: contentDigest.AsReadOnlyMemory(),
            signingTime: SigningTime,
            additionalCertificates: null,
            algorithmConstraints: null,
            includeCmsAlgorithmProtection: false,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken,
            optionalAttributes: null,
            shouldIncludeSigningTimeAttribute: true).ConfigureAwait(false);

        byte[] document = PdfIncrementalUpdateWriter.CompleteSignature(placeholder, signature.AsReadOnlyMemory());

        using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
            document, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        Assert.AreEqual(PAdESSignatureStatus.ProhibitedSigningTimeAttribute, validation.Signatures![0].Status);
    }


    /// <summary>
    /// <c>VerifyAttributesAsync</c> resolves <see cref="VerifyCmsSignedDataDelegate"/> lazily, only where a
    /// signature-time-stamp actually needs it. A PAdES-B-B signature carries no signature-time-stamp, so <see
    /// cref="CAdESVerification.VerifyDetachedAsync"/>'s own documented registry-with-fallback must hold even with
    /// NOTHING registered for the encapsulating (non-detached) delegate. Mutates the process-wide default
    /// registration for the duration (the extension architecture, not a test seam — mirrors
    /// <c>CBAdESLevelValidationNegativeTests</c>'s own established pattern), so parallel execution is disabled and
    /// the original registration is always restored.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public async Task ValidatesAPAdESBaselineSignatureWithNoVerifyCmsSignedDataDelegateRegistered()
    {
        using PAdESScenario scenario = PAdESScenario.Create();
        PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
            scenario.BuildRequest(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        VerifyCmsSignedDataDelegate? original = CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate));
        try
        {
            CryptographicKeyFactory.RegisterFunction(typeof(VerifyCmsSignedDataDelegate), (VerifyCmsSignedDataDelegate)null!);

            using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
                signed.Bytes, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
            Assert.IsTrue(validation.Signatures![0].IsValid, $"Expected Valid, was {validation.Signatures[0].Status}.");
        }
        finally
        {
            if(original is not null)
            {
                CryptographicKeyFactory.RegisterFunction(typeof(VerifyCmsSignedDataDelegate), original);
            }
        }
    }


    /// <summary>Mirrors <see cref="PAdESSignatureCreation"/>'s own private byte-range digest computation, so this test file can build a signature outside that surface's own <c>shouldIncludeSigningTimeAttribute: false</c> call.</summary>
    private static async ValueTask<DigestValue> ComputeByteRangeDigestAsync(PdfSignaturePlaceholder placeholder, CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> document = placeholder.Document;
        int firstLength = placeholder.ByteRange.FirstLength;
        int secondOffset = placeholder.ByteRange.SecondOffset;
        int secondLength = placeholder.ByteRange.SecondLength;
        int total = firstLength + secondLength;

        using IMemoryOwner<byte> concatenation = BaseMemoryPool.Shared.Rent(total);
        document[..firstLength].CopyTo(concatenation.Memory);
        document.Slice(secondOffset, secondLength).CopyTo(concatenation.Memory[firstLength..]);

        return await CryptographicKeyEvents.ComputeDigestAsync(
            concatenation.Memory[..total], PkiDigestAlgorithm.Sha256.OutputByteLength, PkiDigestAlgorithm.Sha256.DigestTag, BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task CreationAndValidationAreMeteredPoolBalanced()
    {
        using var metered = new MeteredHousePool();
        using PAdESScenario scenario = PAdESScenario.Create();

        PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
            scenario.BuildRequest(), metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);

        using(PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
            signed.Bytes, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
            Assert.IsTrue(validation.Signatures![0].IsValid);
        }

        Assert.AreEqual(metered.RentedCount, metered.ReturnedCount, "Every carrier rented across creation and validation must be returned once every owning result is disposed.");
        Assert.AreEqual(0, metered.OutstandingCount);
    }


    private static PdfByteRange GetByteRange(byte[] document)
    {
        using PdfByteSurfaceParseResult located = PdfByteSurfaceReader.Locate(document, BaseMemoryPool.Shared);

        return located.SignatureDictionaries![0].ByteRange;
    }


    private static PdfIncrementalUpdateAnchor LocatePlaceholderAnchor(byte[] document)
    {
        using PdfByteSurfaceParseResult located = PdfByteSurfaceReader.Locate(document, BaseMemoryPool.Shared);

        //The document's own second signed segment ends with this revision's xref/trailer/startxref tail; the
        //new anchor's PriorXrefOffset is this revision's own startxref target, and PriorObjectCount is one past
        //the signature object this scenario always numbers 2 (the fixture builder always starts at object 2).
        int xrefOffset = FindLastXrefOffset(document);

        return new PdfIncrementalUpdateAnchor
        {
            PriorXrefOffset = xrefOffset,
            PriorObjectCount = 3,
            RootObjectNumber = 1,
            RootGeneration = 0
        };
    }


    private static int FindLastXrefOffset(byte[] document)
    {
        string text = Encoding.ASCII.GetString(document);
        int index = text.LastIndexOf("startxref", StringComparison.Ordinal);
        int numberStart = index + "startxref".Length;
        while(document[numberStart] is (byte)'\n' or (byte)'\r')
        {
            numberStart++;
        }

        int numberEnd = numberStart;
        while(document[numberEnd] is >= (byte)'0' and <= (byte)'9')
        {
            numberEnd++;
        }

        return int.Parse(text[numberStart..numberEnd], System.Globalization.CultureInfo.InvariantCulture);
    }


    private static int FindByteRangeArrayOffset(byte[] document)
    {
        string text = Encoding.ASCII.GetString(document);

        return text.IndexOf("/ByteRange [", StringComparison.Ordinal) + "/ByteRange ".Length;
    }


    private static int FindContentsHexStart(byte[] document)
    {
        string text = Encoding.ASCII.GetString(document);

        return text.IndexOf("/Contents <", StringComparison.Ordinal) + "/Contents <".Length;
    }


    private static string Pad(int value) => value.ToString("D10", System.Globalization.CultureInfo.InvariantCulture);


    /// <summary>Mints the signer identity and the unsigned base PDF one <see cref="PAdESSigningRequest"/> is built against.</summary>
    private sealed class PAdESScenario: IDisposable
    {
        internal required X509ChainTestRingNode Root { get; init; }

        internal required X509ChainTestRingNode Authority { get; init; }

        internal required PkiCertificateMemory SignerCertificate { get; init; }

        internal required PrivateKeyMemory SignerPrivateKey { get; init; }

        internal required byte[] UnsignedDocument { get; init; }

        internal required PdfIncrementalUpdateAnchor Anchor { get; init; }


        internal static PAdESScenario Create()
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintSigner();
            (byte[] document, PdfIncrementalUpdateAnchor anchor) = BuildUnsignedBasePdf();

            return new PAdESScenario
            {
                Root = root,
                Authority = authority,
                SignerCertificate = certificate,
                SignerPrivateKey = privateKey,
                UnsignedDocument = document,
                Anchor = anchor
            };
        }


        internal PAdESSigningRequest BuildRequest() => new()
        {
            PriorDocument = UnsignedDocument,
            Anchor = Anchor,
            ContentsCapacityBytes = 4096,
            SignerCertificate = SignerCertificate,
            SignerPrivateKey = SignerPrivateKey,
            SigningTime = SigningTime,
            Location = "Helsinki",
            ContactInfo = "test@example.com",
            Name = "Test Signer"
        };


        /// <summary>Builds a minimal unsigned PDF: a catalog object plus a classic xref/trailer, independently of any reader/writer this library ships.</summary>
        private static (byte[] Bytes, PdfIncrementalUpdateAnchor Anchor) BuildUnsignedBasePdf()
        {
            var writer = new List<byte>();
            void Ascii(string s) => writer.AddRange(Encoding.ASCII.GetBytes(s));

            Ascii("%PDF-1.7\n");
            int obj1Offset = writer.Count;
            Ascii("1 0 obj\n<< /Type /Catalog >>\nendobj\n");
            int xrefOffset = writer.Count;
            Ascii("xref\n0 2\n");
            Ascii("0000000000 65535 f \n");
            Ascii($"{obj1Offset:D10} 00000 n \n");
            Ascii("trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n");
            Ascii(xrefOffset.ToString(System.Globalization.CultureInfo.InvariantCulture));
            Ascii("\n%%EOF\n");

            byte[] bytes = [.. writer];
            var anchor = new PdfIncrementalUpdateAnchor
            {
                PriorXrefOffset = xrefOffset,
                PriorObjectCount = 2,
                RootObjectNumber = 1,
                RootGeneration = 0
            };

            return (bytes, anchor);
        }


        /// <summary>Mints a P-256 signer: key material through <see cref="BouncyCastleKeyMaterialCreator"/>, and a self-signed certificate over the same public point through a platform <see cref="ECDsa"/> reconstructed from it.</summary>
        private static (PkiCertificateMemory Certificate, PrivateKeyMemory PrivateKey) MintSigner()
        {
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
            using(keys.PublicKey)
            {
                byte[] uncompressedPoint = EllipticCurveUtilities.NormalizeToUncompressed(keys.PublicKey.AsReadOnlySpan(), EllipticCurveTypes.P256);
                var ecParameters = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    D = keys.PrivateKey.AsReadOnlySpan().ToArray(),
                    Q = new ECPoint
                    {
                        X = EllipticCurveUtilities.SliceXCoordinate(uncompressedPoint).ToArray(),
                        Y = EllipticCurveUtilities.SliceYCoordinate(uncompressedPoint).ToArray()
                    }
                };

                using ECDsa platformKey = ECDsa.Create(ecParameters);
                using X509Certificate2 platformCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(platformKey, NotBefore, NotAfter);

                return (ToCertificateCarrier(platformCertificate.RawData), keys.PrivateKey);
            }
        }


        /// <summary>Mints a fresh, unrelated P-256 private key — a signer that signs under a different key than <see cref="SignerCertificate"/>'s own public point, for the wrong-key negative.</summary>
        internal static PrivateKeyMemory MintUnrelatedPrivateKey()
        {
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
            keys.PublicKey.Dispose();

            return keys.PrivateKey;
        }


        private static PkiCertificateMemory ToCertificateCarrier(byte[] certificate)
        {
            IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(certificate.Length);
            certificate.CopyTo(owner.Memory.Span);

            return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
        }


        public void Dispose()
        {
            SignerPrivateKey.Dispose();
            SignerCertificate.Dispose();
            Authority.Dispose();
            Root.Dispose();
        }
    }
}
