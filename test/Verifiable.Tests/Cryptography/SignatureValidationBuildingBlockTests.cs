using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Validates the seven basic building blocks of ETSI EN 319 102-1 V1.4.1 clause 5.2, the format-facts seam of
/// clause 5.1.1 that keeps them format neutral, its CAdES binding, and the RFC 3161 time-stamp token surface the
/// blocks and the CAdES verification share.
/// </summary>
/// <remarks>
/// The material under test is minted independently of the library: CAdES signatures come from the framework's
/// own CMS signer through <see cref="CmsSignedDataTestFactory"/>, certificate chains from
/// <see cref="X509ChainTestRing"/>'s platform certificate requests, and the RFC 3161 <c>TSTInfo</c> vectors are
/// written straight with <see cref="AsnWriter"/> here, so a block that agrees with them agrees with something
/// the library did not produce. Every digest the assertions rely on is taken by the library through the
/// registered digest seam; nothing here hashes directly.
/// </remarks>
[TestClass]
internal sealed class SignatureValidationBuildingBlockTests
{
    /// <summary>The validity window start of every certificate minted for these tests.</summary>
    private static DateTimeOffset NotBefore { get; } = SyntheticPassportFactory.NotBefore;

    /// <summary>The validity window end of every certificate minted for these tests.</summary>
    private static DateTimeOffset NotAfter { get; } = SyntheticPassportFactory.NotAfter;

    /// <summary>The claimed signing time every CAdES signature minted for these tests declares.</summary>
    private static DateTimeOffset SigningTime { get; } = new(2025, 3, 14, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The content-type signed attribute, mandatory in a CAdES-B-B signature.</summary>
    private const string ContentTypeOid = "1.2.840.113549.1.9.3";

    /// <summary>The signing-certificate-v2 signed attribute, mandatory in a CAdES-B-B signature.</summary>
    private const string SigningCertificateV2Oid = "1.2.840.113549.1.9.16.2.47";

    /// <summary>The commitment-type-indication signed attribute, absent from every signature minted here.</summary>
    private const string CommitmentTypeIndicationOid = "1.2.840.113549.1.9.16.2.16";

    /// <summary>The SHA-1 digest algorithm object identifier, which the digest seam is not asked to dispatch on.</summary>
    private const string Sha1Oid = "1.3.14.3.2.26";

    /// <summary>The SHA-256 digest algorithm object identifier.</summary>
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Every field the data extraction of step 3) of clause 5.4.4 asks a time-stamp validation to return, and the
    /// optional <c>TSTInfo</c> fields the ordering rules of RFC 3161 §2.4.2 need, surface from a minted token.
    /// </summary>
    [TestMethod]
    public async Task ReadsEveryFieldOfAMintedTimestampTokenInfo()
    {
        using DigestValue imprint = await ComputeSha256Async("timestamped octets"u8.ToArray()).ConfigureAwait(false);
        DateTimeOffset generationTime = new(2025, 6, 1, 12, 0, 0, TimeSpan.Zero);
        byte[] tstInfo = WriteTstInfo(Sha256Oid, imprint.AsReadOnlySpan().ToArray(), generationTime, includeOptionalFields: true);

        using TimestampTokenInfo info = TimestampTokenInfo.Read(tstInfo, BaseMemoryPool.Shared);

        Assert.AreEqual(TimestampTokenInfoStatus.Read, info.Status, "A well-formed TSTInfo must read.");
        Assert.AreEqual(1, info.Version, "RFC 3161 §2.4.2 defines version 1.");
        Assert.AreEqual("1.2.3.4.1", info.PolicyOid, "The policy identifier must surface verbatim.");
        Assert.AreEqual(AlgorithmIdentifier.Sha256, info.MessageImprintAlgorithm, "The message imprint algorithm must be the one the token names.");
        Assert.AreEqual(generationTime, info.GenerationTime, "The generation time must surface.");
        Assert.AreEqual(TimeSpan.FromSeconds(1) + TimeSpan.FromMilliseconds(500), info.Accuracy, "The accuracy components must add up to one interval.");
        Assert.IsTrue(info.IsOrdered, "The ordering flag must surface.");
        Assert.AreEqual("2A", info.SerialNumber, "The serial number must surface as upper-case hexadecimal.");
        Assert.AreEqual("0102", info.Nonce, "The nonce must surface as upper-case hexadecimal.");
        Assert.AreEqual("CN=Test TSA", info.TimestampAuthorityName, "The TSA name hint must surface as a rendered directory name.");
    }


    /// <summary>
    /// A time-stamp token reaches the engine as the value of a signature attribute, which for the unsigned
    /// attributes is arbitrary DER anyone who can rewrite the Signed Data Object chose. Opening such a token goes
    /// through the registered CMS verification seam, and the shipped backends raise different exception types for
    /// octets that are not a CMS SignedData at all. The read reports a status for it, so nothing escapes into the
    /// validation process the token was found by.
    /// </summary>
    [TestMethod]
    public async Task ReportsATokenTheCmsSeamCannotOpenRatherThanThrowing()
    {
        using PkiCertificateMemory notATokenAtAll = MintPlaceholder(PkiCertificateTags.TimestampToken, [0x04, 0x02, 0x00, 0x00]);

        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(
            notATokenAtAll, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TimestampTokenInfoStatus.TokenNotVerified, info.Status,
            "Octets that are not a CMS SignedData cannot be opened, and that is a status of the read, not an exception the caller has to catch.");
        Assert.IsFalse(info.IsRead, "Nothing was read, so no field of the token carries data.");
    }


    /// <summary>
    /// The read rejects octets appended after the <c>TSTInfo</c> SEQUENCE rather than ignoring them, so that a
    /// differently-written parser cannot be led to read something else.
    /// </summary>
    [TestMethod]
    public async Task RejectsDataTrailingTheTimestampTokenInfo()
    {
        using DigestValue imprint = await ComputeSha256Async("timestamped octets"u8.ToArray()).ConfigureAwait(false);
        byte[] tstInfo = WriteTstInfo(Sha256Oid, imprint.AsReadOnlySpan().ToArray(), SigningTime, includeOptionalFields: false);
        byte[] withTrailingData = new byte[tstInfo.Length + 1];
        tstInfo.CopyTo(withTrailingData, 0);

        using TimestampTokenInfo info = TimestampTokenInfo.Read(withTrailingData, BaseMemoryPool.Shared);

        Assert.AreEqual(TimestampTokenInfoStatus.Malformed, info.Status, "Octets beyond the TSTInfo SEQUENCE must be rejected, not ignored.");
    }


    /// <summary>
    /// A <c>messageImprint.hashAlgorithm</c> this library cannot compute is reported as such rather than treated
    /// as an imprint that matched, so no check downstream can pass on an algorithm nothing evaluated.
    /// </summary>
    [TestMethod]
    public void ReportsAMessageImprintAlgorithmThatCannotBeComputed()
    {
        byte[] tstInfo = WriteTstInfo(Sha1Oid, new byte[20], SigningTime, includeOptionalFields: false);

        using TimestampTokenInfo info = TimestampTokenInfo.Read(tstInfo, BaseMemoryPool.Shared);

        Assert.AreEqual(TimestampTokenInfoStatus.UnsupportedMessageImprintAlgorithm, info.Status,
            "A message imprint under an algorithm the digest seam is not asked to dispatch on must fail closed with its own status.");
    }


    /// <summary>
    /// A <c>hashedMessage</c> whose length contradicts the algorithm the token names is not a message imprint at
    /// all, which keeps the later imprint comparison total.
    /// </summary>
    [TestMethod]
    public async Task RejectsAMessageImprintWhoseLengthContradictsItsAlgorithm()
    {
        using DigestValue imprint = await ComputeSha256Async("timestamped octets"u8.ToArray()).ConfigureAwait(false);
        byte[] truncated = imprint.AsReadOnlySpan()[..16].ToArray();
        byte[] tstInfo = WriteTstInfo(Sha256Oid, truncated, SigningTime, includeOptionalFields: false);

        using TimestampTokenInfo info = TimestampTokenInfo.Read(tstInfo, BaseMemoryPool.Shared);

        Assert.AreEqual(TimestampTokenInfoStatus.Malformed, info.Status, "A hashedMessage shorter than its algorithm's output is not a message imprint.");
    }


    /// <summary>
    /// The imprint verification of step 2) of clause 5.2.8.4.2.5 holds only for the octets the token was computed
    /// over, and fails for any other octets.
    /// </summary>
    [TestMethod]
    public async Task VerifiesTheMessageImprintOnlyAgainstTheTimestampedOctets()
    {
        byte[] timestamped = "timestamped octets"u8.ToArray();
        using DigestValue imprint = await ComputeSha256Async(timestamped).ConfigureAwait(false);
        byte[] tstInfo = WriteTstInfo(Sha256Oid, imprint.AsReadOnlySpan().ToArray(), SigningTime, includeOptionalFields: false);

        using TimestampTokenInfo info = TimestampTokenInfo.Read(tstInfo, BaseMemoryPool.Shared);

        Assert.IsTrue(await info.VerifyMessageImprintAsync(timestamped, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "The imprint must bind the octets it was taken over.");
        Assert.IsFalse(await info.VerifyMessageImprintAsync("other octets"u8.ToArray(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "The imprint must not bind octets it was not taken over.");
    }


    /// <summary>
    /// The CAdES binding of the format-facts seam surfaces everything the format-neutral building blocks of
    /// clause 5.2 read about a CAdES-B-B signature.
    /// </summary>
    [TestMethod]
    public async Task ExtractsTheFactsOfACAdESBaselineSignature()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cades content"u8, signerCertificate, SigningTime);

        using SignatureFacts facts = await ExtractAsync(carrier).ConfigureAwait(false);

        Assert.AreEqual(SignatureFactsStatus.Extracted, facts.Status, "A CAdES-B-B signature's facts must extract.");
        Assert.AreEqual(SignatureFormatIdentifier.CAdES, facts.Format, "The binding must declare the format it speaks.");
        Assert.IsTrue(facts.TryGetAttribute(ContentTypeOid, out _), "The content-type signed attribute must surface.");
        Assert.IsTrue(facts.TryGetAttribute(SigningCertificateV2Oid, out SignatureAttributeFacts? signingCertificateAttribute), "The signing-certificate-v2 attribute must surface.");
        Assert.AreEqual(SignatureAttributeScope.Signed, signingCertificateAttribute!.Scope, "The signing-certificate-v2 attribute is covered by the signature.");
        Assert.IsTrue(signingCertificateAttribute.IsWellFormed, "A decodable attribute must not be reported as malformed.");
        Assert.AreEqual(SigningTime, facts.ClaimedSigningTime, "The claimed signing time must surface from the signing-time attribute.");
        Assert.HasCount(1, facts.SigningCertificateReferences, "One ESSCertIDv2 is one signing certificate reference.");
        Assert.IsTrue(facts.SigningCertificateReferences[0].IsSignerReference, "RFC 5035 §3 makes the first certificate identifier the signer's.");
        Assert.IsNotNull(facts.SigningCertificate, "The signer's certificate must be matched from the SignerInfo identifier.");
        Assert.IsTrue(facts.SigningCertificate!.AsReadOnlyMemory().Span.SequenceEqual(signerCertificate.RawData), "The matched certificate must be the one that signed.");
        Assert.IsNotNull(facts.SignedContent, "An encapsulating signature carries its signed content.");
        Assert.IsEmpty(facts.Timestamps, "A baseline signature embeds no time-stamp token.");
    }


    /// <summary>
    /// The binding classifies the signature-time-stamp-token unsigned attribute of a CAdES-B-T signature as the
    /// signature time-stamp class clause 5.5.4 determines best-signature-time from.
    /// </summary>
    [TestMethod]
    public async Task ClassifiesTheSignatureTimestampOfACAdESTSignature()
    {
        DateTimeOffset timestampTime = new(2025, 6, 1, 12, 0, 0, TimeSpan.Zero);

        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using ECDsa tsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var tsaCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(tsaKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdEST("the cades content"u8, signerCertificate, SigningTime, tsaCertificate, timestampTime);

        using SignatureFacts facts = await ExtractAsync(carrier).ConfigureAwait(false);

        IReadOnlyList<EmbeddedTimestamp> signatureTimestamps = facts.TimestampsOfClass(SignatureTimestampClass.SignatureTimestamp);
        Assert.HasCount(1, signatureTimestamps, "The signature-time-stamp-token unsigned attribute is one signature time-stamp.");
        Assert.AreEqual(SignatureAttributeScope.Unsigned, FindScope(facts, signatureTimestamps[0].Identifier), "A signature time-stamp is not covered by the signature.");
        Assert.IsTrue(signatureTimestamps[0].Token.IsTimestampToken, "The token carrier must declare its kind.");

        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(
            signatureTimestamps[0].Token, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TimestampTokenInfoStatus.Read, info.Status, "The embedded token must open through the registered CMS seam.");
        Assert.AreEqual(timestampTime, info.GenerationTime, "The token's generation time must be the one it was minted with.");
    }


    /// <summary>
    /// The format checking building block of clause 5.2.2 reports <c>FAILED</c>/<c>FORMAT_FAILURE</c> for octets
    /// that are not a processable CMS SignedData, rather than letting the parse escape as an exception.
    /// </summary>
    [TestMethod]
    public async Task FormatCheckingFailsForBytesThatAreNotACmsSignedData()
    {
        using CmsSignedData notCms = CmsSignedData.FromBytes("not a signed data object"u8, BaseMemoryPool.Shared);

        FormatCheckingResult result = await FormatChecking.CheckAsync(
            new SignatureFactsExtractionContext { SignedDataObject = notCms },
            CAdESSignatureFacts.Seam.Format,
            CAdESSignatureFacts.Seam.ExtractFacts,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        using(result.Facts)
        {
            Assert.AreEqual(BuildingBlockIndication.Failed, result.Conclusion.Indication, "Clause 5.2.2.3 makes a non-conformant signature FAILED.");
            Assert.Contains(SignatureValidationSubIndication.FormatFailure, result.Conclusion.SubIndications, "The sub-indication must be FORMAT_FAILURE.");
            Assert.IsInstanceOfType<FormatFailureReportData>(result.Conclusion.ReportData[0], "Table 6 mandates information on why parsing failed.");
        }
    }


    /// <summary>
    /// The identification of the signing certificate building block of clause 5.2.3 finds the signer's
    /// certificate from the ESS signing-certificate reference the signature carries.
    /// </summary>
    [TestMethod]
    public async Task IdentifiesTheSigningCertificateFromTheEssReference()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cades content"u8, signerCertificate, SigningTime);
        using SignatureFacts facts = await ExtractAsync(carrier).ConfigureAwait(false);

        SigningCertificateIdentificationResult result = await SigningCertificateIdentification.IdentifyAsync(
            facts, signingCertificate: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Passed, result.Conclusion.Indication, "A reference whose hash matches identifies the signing certificate.");
        Assert.IsNotNull(result.SigningCertificate, "Clause 5.2.3.3 makes the signing certificate the success output.");
        Assert.IsFalse(result.HasIssuerSerialMismatchWarning, "The minted reference omits IssuerSerial, so step 3) reports nothing.");
    }


    /// <summary>
    /// Clause 5.2.3.4: a reference whose digest binds a different certificate identifies no signing certificate,
    /// which is the <c>NO_SIGNING_CERTIFICATE_FOUND</c> outcome rather than an accepted candidate.
    /// </summary>
    [TestMethod]
    public async Task ReportsNoSigningCertificateFoundWhenTheReferenceBindsAnotherCertificate()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cades content"u8, signerCertificate, SigningTime, bindWrongCertificate: true);
        using SignatureFacts facts = await ExtractAsync(carrier).ConfigureAwait(false);

        SigningCertificateIdentificationResult result = await SigningCertificateIdentification.IdentifyAsync(
            facts, signingCertificate: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Indeterminate, result.Conclusion.Indication, "A reference matching no candidate leaves the identification indeterminate.");
        Assert.Contains(SignatureValidationSubIndication.NoSigningCertificateFound, result.Conclusion.SubIndications, "Clause 5.2.3.4 names NO_SIGNING_CERTIFICATE_FOUND.");
        Assert.IsNull(result.SigningCertificate, "No certificate may be reported when none was identified.");
    }


    /// <summary>
    /// The cryptographic verification building block of clause 5.2.7 passes a signature whose data items hash as
    /// declared and whose signature value verifies under the signing certificate's public key.
    /// </summary>
    [TestMethod]
    public async Task VerifiesTheCryptographyOfAValidCAdESSignature()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cades content"u8, signerCertificate, SigningTime);
        using SignatureFacts facts = await ExtractAsync(carrier).ConfigureAwait(false);

        CryptographicVerificationResult result = await CryptographicVerification.VerifyAsync(
            facts, facts.SigningCertificate!, [], [], CAdESSignatureFacts.Seam.VerifyCryptography, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Passed, result.Conclusion.Indication, "A signature whose value and content digest verify is PASSED.");
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, result.Outcome, "The binding must report the verification it performed.");
    }


    /// <summary>
    /// Step 2) of clause 5.2.7.4: content whose hash does not match the corresponding value in the signature is
    /// the <c>FAILED</c>/<c>HASH_FAILURE</c> row of Table 15, named with the object that failed.
    /// </summary>
    [TestMethod]
    public async Task ReportsHashFailureWhenTheContentDoesNotMatchItsDigestAttribute()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cades content"u8, signerCertificate, SigningTime);
        using CmsSignedData tampered = CmsSignedDataTestFactory.TamperContent(carrier, "the cades content"u8);
        using SignatureFacts facts = await ExtractAsync(tampered).ConfigureAwait(false);

        CryptographicVerificationResult result = await CryptographicVerification.VerifyAsync(
            facts, facts.SigningCertificate!, [], [], CAdESSignatureFacts.Seam.VerifyCryptography, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Failed, result.Conclusion.Indication, "Table 15 makes a hash failure FAILED, not INDETERMINATE.");
        Assert.Contains(SignatureValidationSubIndication.HashFailure, result.Conclusion.SubIndications,
            "Content that does not match its message-digest attribute is HASH_FAILURE, distinct from SIG_CRYPTO_FAILURE.");
        Assert.IsInstanceOfType<HashFailureReportData>(result.Conclusion.ReportData[0], "Table 15 asks for the identifiers of the signed data that failed.");
    }


    /// <summary>
    /// Clause 5.2.4.4: a signature that declares no signature policy identifier leaves the validation context
    /// initialization building block with the default set of constraints the caller supplied.
    /// </summary>
    [TestMethod]
    public async Task SelectsTheDefaultConstraintsWhenTheSignatureDeclaresNoPolicy()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cades content"u8, signerCertificate, SigningTime);
        using SignatureFacts facts = await ExtractAsync(carrier).ConfigureAwait(false);
        SignatureValidationConstraints constraints = EmptyConstraints();

        ValidationContextInitializationResult result = await ValidationContextInitialization.InitializeAsync(
            facts, constraints, [], UnmappedSignaturePolicyHandling.TerminateValidation, resolveSignaturePolicy: null, [],
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Passed, result.Conclusion.Indication, "Clause 5.2.4.4 selects a default policy when the signature declares none.");
        Assert.AreSame(constraints, result.Constraints, "The selected constraints must be the ones supplied, not a copy.");
        Assert.IsNotEmpty(result.CertificateValidationData, "The certificates the signature carries are certificate validation data.");
    }


    /// <summary>
    /// Step 1) of clause 5.2.5.4: the maximum accepted revocation freshness the X.509 validation constraints
    /// state takes precedence over the <c>nextUpdate</c> interval of the revocation data.
    /// </summary>
    [TestMethod]
    public async Task UsesTheConstraintValueForRevocationFreshnessWhenOneIsStated()
    {
        DateTimeOffset validationTime = new(2026, 1, 10, 0, 0, 0, TimeSpan.Zero);
        using PkiCertificateMemory certificate = MintPlaceholder(PkiCertificateTags.X509Certificate, [0x01]);
        using PkiCertificateMemory revocationData = MintPlaceholder(PkiCertificateTags.X509Crl, [0x02]);

        RevocationFreshnessResult fresh = await RunFreshnessAsync(
            revocationData, certificate, validationTime, validationTime.AddDays(-1), nextUpdate: null, TimeSpan.FromDays(2), TestContext.CancellationToken).ConfigureAwait(false);
        RevocationFreshnessResult stale = await RunFreshnessAsync(
            revocationData, certificate, validationTime, validationTime.AddDays(-5), nextUpdate: null, TimeSpan.FromDays(2), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Passed, fresh.Conclusion.Indication, "Status information issued after validation time minus the freshness is fresh.");
        Assert.AreEqual(TimeSpan.FromDays(2), fresh.AcceptedFreshness, "The constraint value takes precedence over the nextUpdate interval.");
        Assert.AreEqual(BuildingBlockIndication.Failed, stale.Conclusion.Indication, "Status information issued before that instant is not fresh.");
    }


    /// <summary>
    /// Step 1) of clause 5.2.5.4 and its NOTE 1: without a stated maximum accepted freshness the checker uses the
    /// <c>nextUpdate</c>-minus-<c>thisUpdate</c> interval, and revocation data setting no <c>nextUpdate</c> fails.
    /// </summary>
    [TestMethod]
    public async Task FallsBackToTheNextUpdateIntervalAndFailsWithoutIt()
    {
        DateTimeOffset validationTime = new(2026, 1, 10, 0, 0, 0, TimeSpan.Zero);
        using PkiCertificateMemory certificate = MintPlaceholder(PkiCertificateTags.X509Certificate, [0x01]);
        using PkiCertificateMemory revocationData = MintPlaceholder(PkiCertificateTags.X509Crl, [0x02]);

        RevocationFreshnessResult fallback = await RunFreshnessAsync(
            revocationData, certificate, validationTime, validationTime.AddDays(-1), validationTime.AddDays(2), maximumAcceptedFreshness: null, TestContext.CancellationToken).ConfigureAwait(false);
        RevocationFreshnessResult withoutNextUpdate = await RunFreshnessAsync(
            revocationData, certificate, validationTime, validationTime.AddDays(-1), nextUpdate: null, maximumAcceptedFreshness: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Passed, fallback.Conclusion.Indication, "The thisUpdate-to-nextUpdate interval is the fallback freshness of step 1).");
        Assert.AreEqual(TimeSpan.FromDays(3), fallback.AcceptedFreshness, "The fallback freshness is nextUpdate minus thisUpdate.");
        Assert.AreEqual(BuildingBlockIndication.Failed, withoutNextUpdate.Conclusion.Indication, "NOTE 1 makes an absent nextUpdate a FAILED, never an unbounded acceptance.");
        Assert.IsNull(withoutNextUpdate.AcceptedFreshness, "No freshness could be determined at all.");
    }


    /// <summary>
    /// Step 1) of clause 5.2.6.4: a signing certificate that is itself a trust anchor passes, and the same anchor
    /// at or after the sunset date the constraints associate with it is
    /// <c>INDETERMINATE</c>/<c>NO_CERTIFICATE_CHAIN_FOUND_NO_POE</c>.
    /// </summary>
    [TestMethod]
    public async Task PassesWhenTheSigningCertificateIsATrustAnchorAndFailsAfterItsSunsetDate()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("trust-anchor.example.test", timeProvider);
        DateTimeOffset validationTime = timeProvider.GetUtcNow();
        IReadOnlyList<PkiCertificateMemory> anchors = MicrosoftX509Functions.ParseX5c(ring.RootX5c, BaseMemoryPool.Shared);
        try
        {
            X509CertificateValidationResult trusted = await X509CertificateValidation.ValidateAsync(
                anchors[0], Anchors(anchors, sunsetDate: null), EllipticCurveSignatureAlgorithms(), [], [],
                NoCompletion, MicrosoftX509Functions.ValidateChainAsync, checkRevocation: null,
                validationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            X509CertificateValidationResult sunset = await X509CertificateValidation.ValidateAsync(
                anchors[0], Anchors(anchors, validationTime.AddDays(-1)), EllipticCurveSignatureAlgorithms(), [], [],
                NoCompletion, MicrosoftX509Functions.ValidateChainAsync, checkRevocation: null,
                validationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(BuildingBlockIndication.Passed, trusted.Conclusion.Indication, "Step 1)b): a trust anchor is trusted at a validation time before its sunset date.");
            Assert.AreEqual(CertificateChainReportKind.Validated, trusted.ChainKind, "Table 13's PASSED row reports the chain used in the successful validation.");
            Assert.AreEqual(BuildingBlockIndication.Indeterminate, sunset.Conclusion.Indication, "Step 1)a): a trust anchor past its sunset date yields no chain.");
            Assert.Contains(SignatureValidationSubIndication.NoCertificateChainFoundNoProofOfExistence, sunset.Conclusion.SubIndications,
                "Step 1)a) names NO_CERTIFICATE_CHAIN_FOUND_NO_POE.");
        }
        finally
        {
            DisposeAll(anchors);
        }
    }


    /// <summary>
    /// The X.509 certificate validation building block over a real three-level chain: <c>PASSED</c> with the
    /// chain when nothing is revoked, and the <c>REVOKED_NO_POE</c> and <c>REVOKED_CA_NO_POE</c> outcomes of
    /// steps 4)b) and 4)d) with the revocation particulars Table 6 mandates.
    /// </summary>
    [TestMethod]
    public async Task ValidatesAThreeLevelChainAndReportsRevocationOutcomes()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("chain-validation.example.test", timeProvider);
        DateTimeOffset validationTime = timeProvider.GetUtcNow();
        IReadOnlyList<PkiCertificateMemory> chain = MicrosoftX509Functions.ParseX5c(ring.X5cValues, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> anchors = MicrosoftX509Functions.ParseX5c(ring.RootX5c, BaseMemoryPool.Shared);
        try
        {
            var completer = new CertificateChainCompleter([chain[1], chain[2]]);
            X509ValidationConstraints constraints = Anchors(anchors, sunsetDate: null);
            CryptographicConstraints algorithms = EllipticCurveSignatureAlgorithms();
            using PkiCertificateMemory revocationData = MintPlaceholder(PkiCertificateTags.X509Crl, [0x02]);

            X509CertificateValidationResult good = await X509CertificateValidation.ValidateAsync(
                chain[0], constraints, algorithms, [chain[1], chain[2]],
                [Status(revocationData, chain[0], CertificateRevocationStatus.Good, validationTime), Status(revocationData, chain[1], CertificateRevocationStatus.Good, validationTime)],
                completer.CompleteAsync, MicrosoftX509Functions.ValidateChainAsync, checkRevocation: null,
                validationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            X509CertificateValidationResult revokedLeaf = await X509CertificateValidation.ValidateAsync(
                chain[0], constraints, algorithms, [chain[1], chain[2]],
                [Status(revocationData, chain[0], CertificateRevocationStatus.Revoked, validationTime, revocationReason: 1)],
                completer.CompleteAsync, MicrosoftX509Functions.ValidateChainAsync, checkRevocation: null,
                validationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            X509CertificateValidationResult revokedIntermediate = await X509CertificateValidation.ValidateAsync(
                chain[0], constraints, algorithms, [chain[1], chain[2]],
                [Status(revocationData, chain[0], CertificateRevocationStatus.Good, validationTime), Status(revocationData, chain[1], CertificateRevocationStatus.Revoked, validationTime, revocationReason: 4)],
                completer.CompleteAsync, MicrosoftX509Functions.ValidateChainAsync, checkRevocation: null,
                validationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            X509CertificateValidationResult noStatus = await X509CertificateValidation.ValidateAsync(
                chain[0], constraints, algorithms, [chain[1], chain[2]], [],
                completer.CompleteAsync, MicrosoftX509Functions.ValidateChainAsync, checkRevocation: null,
                validationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(BuildingBlockIndication.Passed, good.Conclusion.Indication, "Step 9): a chain that validates with fresh good status is PASSED.");
            Assert.Contains(SignatureValidationSubIndication.RevokedNoProofOfExistence, revokedLeaf.Conclusion.SubIndications, "Step 4)b) names REVOKED_NO_POE for the signing certificate.");
            Assert.IsInstanceOfType<CertificateRevocationReportData>(revokedLeaf.Conclusion.ReportData[0], "Table 6 mandates the chain, the revocation date and the reason.");
            Assert.Contains(SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence, revokedIntermediate.Conclusion.SubIndications,
                "Step 4)d) names REVOKED_CA_NO_POE for an intermediate.");
            Assert.Contains(SignatureValidationSubIndication.TryLater, noStatus.Conclusion.SubIndications,
                "With no revocation status information and no checker, nothing is established and fresher data may arrive.");
        }
        finally
        {
            DisposeAll(chain);
            DisposeAll(anchors);
        }
    }


    /// <summary>
    /// The signature acceptance validation building block of clause 5.2.8 passes a signature that satisfies every
    /// signature elements constraint it was given, reporting each constraint it evaluated.
    /// </summary>
    [TestMethod]
    public async Task AcceptsASignatureThatSatisfiesEveryElementsConstraint()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cades content"u8, signerCertificate, SigningTime);
        using SignatureFacts facts = await ExtractAsync(carrier).ConfigureAwait(false);

        SignatureAcceptanceValidationResult result = await SignatureAcceptanceValidation.ValidateAsync(
            facts,
            [],
            new SignatureElementsConstraints
            {
                MandatedSignedAttributeOids = [ContentTypeOid, SigningCertificateV2Oid],
                ForbiddenSignedAttributeOids = [CommitmentTypeIndicationOid]
            },
            ReliableAlgorithms(facts),
            validateTimestampToken: null,
            SigningTime,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Passed, result.Conclusion.Indication, "A signature carrying every mandated and no forbidden attribute is PASSED.");
        Assert.AreEqual(SigningTime, result.ClaimedSigningTime, "Clause 5.2.8.4.2.2 makes the claimed signing time available to the Driving Application.");
    }


    /// <summary>
    /// Clause 5.2.8.4.1: a signed attribute the constraints mandate but the signature does not carry is
    /// <c>INDETERMINATE</c>/<c>SIG_CONSTRAINTS_FAILURE</c>, reported with the constraint that was not met.
    /// </summary>
    [TestMethod]
    public async Task ReportsSignatureConstraintsFailureForAMissingMandatedAttribute()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cades content"u8, signerCertificate, SigningTime);
        using SignatureFacts facts = await ExtractAsync(carrier).ConfigureAwait(false);

        SignatureAcceptanceValidationResult result = await SignatureAcceptanceValidation.ValidateAsync(
            facts,
            [],
            new SignatureElementsConstraints { MandatedSignedAttributeOids = [CommitmentTypeIndicationOid] },
            ReliableAlgorithms(facts),
            validateTimestampToken: null,
            SigningTime,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Indeterminate, result.Conclusion.Indication, "Table 17 makes an unmet constraint INDETERMINATE.");
        Assert.Contains(SignatureValidationSubIndication.SignatureConstraintsFailure, result.Conclusion.SubIndications, "The sub-indication is SIG_CONSTRAINTS_FAILURE.");
        Assert.IsInstanceOfType<UnsatisfiedSignatureConstraintsReportData>(result.Conclusion.ReportData[0], "Table 17 mandates the set of constraints not verified.");
        Assert.IsNotEmpty(result.Conclusion.ConstraintEvaluations, "Clause 5.1.3 requires the per-constraint outcome for an indeterminate result.");
    }


    /// <summary>
    /// The signed signing-certificate binding constraint of ETSI TS 119 172-4 REQ-4.2-03 h): a plain CMS
    /// signature carries no signing certificate identifier attribute, so under
    /// <see cref="SignatureElementsConstraints.RequireSignedSigningCertificateBinding"/> the acceptance is
    /// <c>INDETERMINATE</c>/<c>SIG_CONSTRAINTS_FAILURE</c> with the signing-certificate-references
    /// constraint reported unmet.
    /// </summary>
    [TestMethod]
    public async Task RequiredSignedSigningCertificateBindingFailsASignatureCarryingNone()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCms("the plain cms content"u8, signerCertificate);
        using SignatureFacts facts = await ExtractAsync(carrier).ConfigureAwait(false);

        SignatureAcceptanceValidationResult result = await SignatureAcceptanceValidation.ValidateAsync(
            facts,
            [],
            new SignatureElementsConstraints { RequireSignedSigningCertificateBinding = true },
            ReliableAlgorithms(facts),
            validateTimestampToken: null,
            SigningTime,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Indeterminate, result.Conclusion.Indication, "A missing signed signing-certificate binding is an unmet constraint (INDETERMINATE).");
        Assert.Contains(SignatureValidationSubIndication.SignatureConstraintsFailure, result.Conclusion.SubIndications, "The sub-indication is SIG_CONSTRAINTS_FAILURE.");
        Assert.Contains(
            evaluation => evaluation.Identifier == ValidationConstraintIdentifier.SigningCertificateReferences,
            result.Conclusion.ConstraintEvaluations,
            "The unmet constraint is reported under the signing-certificate-references identity.");
    }


    /// <summary>
    /// The same plain CMS signature is accepted when no constraint requires the signed binding — the
    /// clause 5.2.3.4 branch that accepts the carried copy of the signing certificate stays the default —
    /// and a CAdES signature, which carries the signing-certificate-v2 attribute, satisfies the constraint
    /// when it is required.
    /// </summary>
    [TestMethod]
    public async Task SignedSigningCertificateBindingIsNotRequiredByDefaultAndACAdESSignatureSatisfiesIt()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);

        using CmsSignedData plainCarrier = CmsSignedDataTestFactory.SignAsCms("the plain cms content"u8, signerCertificate);
        using SignatureFacts plainFacts = await ExtractAsync(plainCarrier).ConfigureAwait(false);
        SignatureAcceptanceValidationResult defaultResult = await SignatureAcceptanceValidation.ValidateAsync(
            plainFacts, [], new SignatureElementsConstraints(), ReliableAlgorithms(plainFacts),
            validateTimestampToken: null, SigningTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Passed, defaultResult.Conclusion.Indication,
            "Without the constraint, a signature with no signed binding stays accepted — the specification's own no-constraint branch.");

        using CmsSignedData cadesCarrier = CmsSignedDataTestFactory.SignAsCAdES("the cades content"u8, signerCertificate, SigningTime);
        using SignatureFacts cadesFacts = await ExtractAsync(cadesCarrier).ConfigureAwait(false);
        SignatureAcceptanceValidationResult constrainedResult = await SignatureAcceptanceValidation.ValidateAsync(
            cadesFacts, [], new SignatureElementsConstraints { RequireSignedSigningCertificateBinding = true }, ReliableAlgorithms(cadesFacts),
            validateTimestampToken: null, SigningTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Passed, constrainedResult.Conclusion.Indication,
            "A CAdES signature carries the signing-certificate-v2 signed attribute, which satisfies the required binding.");
    }


    /// <summary>
    /// An algorithm the dated reliability table does not list is never reliable, so the signature acceptance
    /// validation reports <c>INDETERMINATE</c>/<c>CRYPTO_CONSTRAINTS_FAILURE_NO_POE</c> with the assessment.
    /// </summary>
    [TestMethod]
    public async Task ReportsCryptoConstraintsFailureNoProofOfExistenceForAnUnlistedAlgorithm()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cades content"u8, signerCertificate, SigningTime);
        using SignatureFacts facts = await ExtractAsync(carrier).ConfigureAwait(false);

        SignatureAcceptanceValidationResult result = await SignatureAcceptanceValidation.ValidateAsync(
            facts, [], new SignatureElementsConstraints(), CryptographicConstraints.Empty,
            validateTimestampToken: null, SigningTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Indeterminate, result.Conclusion.Indication, "An algorithm no table asserts reliable leaves the acceptance indeterminate.");
        Assert.Contains(SignatureValidationSubIndication.CryptographicConstraintsFailureNoProofOfExistence, result.Conclusion.SubIndications,
            "Clause 5.2.8.4.1 names CRYPTO_CONSTRAINTS_FAILURE_NO_POE.");
        Assert.IsInstanceOfType<CryptographicConstraintsFailureReportData>(result.Conclusion.ReportData[0], "Table 17 mandates the list of algorithms concerned.");
    }


    /// <summary>
    /// Runs the CAdES binding's fact extraction over a signed data carrier.
    /// </summary>
    /// <param name="carrier">The CMS SignedData carrier.</param>
    /// <returns>The extracted facts, which the caller disposes.</returns>
    private async ValueTask<SignatureFacts> ExtractAsync(CmsSignedData carrier) =>
        await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = carrier }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// Computes a SHA-256 digest through the registered digest seam, so the vectors the tests mint are bound to
    /// the same digest the library takes.
    /// </summary>
    /// <param name="input">The bytes to hash.</param>
    /// <returns>The digest, which the caller disposes.</returns>
    private async ValueTask<DigestValue> ComputeSha256Async(byte[] input) =>
        await CryptographicKeyEvents.ComputeDigestAsync(
            input, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// Runs the revocation freshness checker over a synthesised instance of revocation status information.
    /// </summary>
    /// <param name="revocationData">The revocation data carrier.</param>
    /// <param name="certificate">The certificate the status is about.</param>
    /// <param name="validationTime">The instant the freshness is judged at.</param>
    /// <param name="thisUpdate">The issuance time of the status information.</param>
    /// <param name="nextUpdate">The instant newer status information is expected, when the issuer set one.</param>
    /// <param name="maximumAcceptedFreshness">The freshness the X.509 validation constraints state, when they state one.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The block's result.</returns>
    private static async ValueTask<RevocationFreshnessResult> RunFreshnessAsync(
        PkiCertificateMemory revocationData,
        PkiCertificateMemory certificate,
        DateTimeOffset validationTime,
        DateTimeOffset thisUpdate,
        DateTimeOffset? nextUpdate,
        TimeSpan? maximumAcceptedFreshness,
        System.Threading.CancellationToken cancellationToken)
    {
        var information = new RevocationStatusInformation
        {
            RevocationData = revocationData,
            SubjectCertificate = certificate,
            Status = CertificateRevocationStatus.Good,
            ThisUpdate = thisUpdate,
            NextUpdate = nextUpdate
        };
        var constraints = new X509ValidationConstraints
        {
            TrustAnchors = [],
            MaximumAcceptedRevocationFreshness = maximumAcceptedFreshness
        };

        return await RevocationFreshnessChecker.CheckAsync(information, certificate, validationTime, constraints, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds one instance of revocation status information about a certificate.
    /// </summary>
    /// <param name="revocationData">The revocation data carrier.</param>
    /// <param name="certificate">The certificate the status is about.</param>
    /// <param name="status">The status stated.</param>
    /// <param name="validationTime">The instant the status is anchored around.</param>
    /// <param name="revocationReason">The CRLReason value, when the status is a revocation.</param>
    /// <returns>The status information.</returns>
    private static RevocationStatusInformation Status(
        PkiCertificateMemory revocationData,
        PkiCertificateMemory certificate,
        CertificateRevocationStatus status,
        DateTimeOffset validationTime,
        int? revocationReason = null) => new()
        {
            RevocationData = revocationData,
            SubjectCertificate = certificate,
            Status = status,
            ThisUpdate = validationTime.AddHours(-1),
            NextUpdate = validationTime.AddDays(1),
            RevocationTime = status == CertificateRevocationStatus.Revoked ? validationTime.AddDays(-2) : null,
            RevocationReason = revocationReason
        };


    /// <summary>
    /// Builds X.509 validation constraints naming a set of trust anchors, optionally with a sunset date.
    /// </summary>
    /// <param name="anchors">The trust anchors.</param>
    /// <param name="sunsetDate">The sunset date to associate with every anchor, or <see langword="null"/> for none.</param>
    /// <returns>The constraints.</returns>
    private static X509ValidationConstraints Anchors(IReadOnlyList<PkiCertificateMemory> anchors, DateTimeOffset? sunsetDate)
    {
        List<TrustAnchorConstraint> constraints = [];
        for(int i = 0; i < anchors.Count; ++i)
        {
            constraints.Add(new TrustAnchorConstraint(anchors[i], sunsetDate));
        }

        return new X509ValidationConstraints { TrustAnchors = constraints, MaximumAcceptedRevocationFreshness = TimeSpan.FromDays(7) };
    }


    /// <summary>
    /// Builds a cryptographic constraints table asserting every algorithm a signature's facts name reliable,
    /// so a test about attribute rules is not decided by the algorithm table.
    /// </summary>
    /// <param name="facts">The signature's facts.</param>
    /// <returns>The table.</returns>
    private static CryptographicConstraints ReliableAlgorithms(SignatureFacts facts)
    {
        List<AlgorithmReliabilityEntry> entries = [];
        for(int i = 0; i < facts.AlgorithmUses.Count; ++i)
        {
            entries.Add(new AlgorithmReliabilityEntry(facts.AlgorithmUses[i].Algorithm, MinimumKeySizeBits: null, TrustedUntil: null));
        }

        return new CryptographicConstraints { Entries = entries };
    }


    /// <summary>
    /// Builds a cryptographic constraints table asserting the elliptic-curve signature algorithms the minted
    /// certificate chains are signed with reliable without expiry, so a chain-validation test is decided by the
    /// step under test and not by an empty algorithm table.
    /// </summary>
    /// <returns>The table.</returns>
    private static CryptographicConstraints EllipticCurveSignatureAlgorithms() => new()
    {
        Entries =
        [
            new AlgorithmReliabilityEntry(new AlgorithmIdentifier("1.2.840.10045.4.3.2"), MinimumKeySizeBits: 256, TrustedUntil: null),
            new AlgorithmReliabilityEntry(new AlgorithmIdentifier("1.2.840.10045.4.3.3"), MinimumKeySizeBits: 256, TrustedUntil: null),
            new AlgorithmReliabilityEntry(AlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, TrustedUntil: null)
        ]
    };


    /// <summary>
    /// Builds validation constraints that state nothing beyond an empty trust anchor set — the shape a caller
    /// supplies when its own configuration, not a policy artefact, drives the run.
    /// </summary>
    /// <returns>The constraints.</returns>
    private static SignatureValidationConstraints EmptyConstraints() => new()
    {
        Identifier = SignatureValidationPolicyIdentifier.CallerSuppliedConstraints,
        X509 = new X509ValidationConstraints { TrustAnchors = [] },
        Cryptographic = CryptographicConstraints.Empty,
        SignatureElements = new SignatureElementsConstraints()
    };


    /// <summary>
    /// A chain completion seam that returns the partial chain unchanged — the behaviour every completer has for
    /// a chain that already reaches a trust anchor, and the only behaviour a single trust anchor needs.
    /// </summary>
    /// <param name="partialChain">The chain as supplied.</param>
    /// <param name="trustAnchors">The trust anchors, unused.</param>
    /// <param name="pool">The memory pool, unused.</param>
    /// <param name="cancellationToken">A cancellation token, unused.</param>
    /// <returns>The chain as supplied.</returns>
    private static ValueTask<IReadOnlyList<PkiCertificateMemory>> NoCompletion(
        IReadOnlyList<PkiCertificateMemory> partialChain,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        MemoryPool<byte> pool,
        System.Threading.CancellationToken cancellationToken) => ValueTask.FromResult(partialChain);


    /// <summary>
    /// Finds the scope a signature's facts report for one attribute identity.
    /// </summary>
    /// <param name="facts">The signature's facts.</param>
    /// <param name="identifier">The attribute's identity.</param>
    /// <returns>The scope, or <see cref="SignatureAttributeScope.Unknown"/> when the attribute is absent.</returns>
    private static SignatureAttributeScope FindScope(SignatureFacts facts, string identifier) =>
        facts.TryGetAttribute(identifier, out SignatureAttributeFacts? attribute) ? attribute.Scope : SignatureAttributeScope.Unknown;


    /// <summary>
    /// Wraps a few bytes in a PKI carrier, for a test that needs a distinguishable non-owning reference rather
    /// than a parsable structure.
    /// </summary>
    /// <param name="tag">The tag declaring the carrier's kind.</param>
    /// <param name="bytes">The bytes.</param>
    /// <returns>The carrier, which the caller disposes.</returns>
    private static PkiCertificateMemory MintPlaceholder(Tag tag, byte[] bytes)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }


    /// <summary>
    /// Disposes every carrier of a list.
    /// </summary>
    /// <param name="carriers">The carriers.</param>
    private static void DisposeAll(IReadOnlyList<PkiCertificateMemory> carriers)
    {
        for(int i = 0; i < carriers.Count; ++i)
        {
            carriers[i].Dispose();
        }
    }


    /// <summary>
    /// Writes an RFC 3161 <c>TSTInfo</c> straight with <see cref="AsnWriter"/> — the independent oracle the
    /// promoted time-stamp surface is read against.
    /// </summary>
    /// <param name="hashOid">The <c>messageImprint.hashAlgorithm</c> object identifier.</param>
    /// <param name="imprint">The <c>messageImprint.hashedMessage</c> value.</param>
    /// <param name="generationTime">The <c>genTime</c>.</param>
    /// <param name="includeOptionalFields">Whether the accuracy, ordering, nonce and TSA fields are written.</param>
    /// <returns>The DER encoding.</returns>
    private static byte[] WriteTstInfo(string hashOid, byte[] imprint, DateTimeOffset generationTime, bool includeOptionalFields)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteInteger(1);
            writer.WriteObjectIdentifier("1.2.3.4.1");
            using(writer.PushSequence())
            {
                using(writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(hashOid);
                    writer.WriteNull();
                }

                writer.WriteOctetString(imprint);
            }

            writer.WriteInteger(0x2A);
            writer.WriteGeneralizedTime(generationTime);

            if(includeOptionalFields)
            {
                using(writer.PushSequence())
                {
                    writer.WriteInteger(1);
                    writer.WriteInteger(500, new Asn1Tag(TagClass.ContextSpecific, 0));
                }

                writer.WriteBoolean(true);
                writer.WriteInteger(0x0102);
                using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4)))
                    {
                        using(writer.PushSequence())
                        {
                            using(writer.PushSetOf())
                            {
                                using(writer.PushSequence())
                                {
                                    writer.WriteObjectIdentifier(WellKnownOids.CommonName);
                                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, "Test TSA");
                                }
                            }
                        }
                    }
                }
            }
        }

        return writer.Encode();
    }
}
