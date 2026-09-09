using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The <c>certificates</c> field of a CMS SignedData
/// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">RFC 5652 §5.1</see>) is not covered by
/// the signer's signature — only the encapsulated content and, when present, the signed attributes feed
/// the message digest calculation
/// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.4">RFC 5652 §5.4</see>) — so a member that
/// fails to parse is a fact about that member, not about the structure's authenticity. These tests exercise
/// <see cref="ManagedCmsVerification"/> and <see cref="BouncyCastleCmsFunctions"/> directly (no registry
/// indirection), matching <c>CmsBackendEquivalenceTests</c>'s own idiom for invoking both backends as
/// statics, over a plain CAdES-B-B <see cref="CmsSignedData"/> minted by <see cref="CmsSignedDataTestFactory"/>
/// and doctored by <see cref="CmsCertificatesFieldSpliceTestFactory"/>.
/// </summary>
[TestClass]
internal sealed class CmsCertificatesSetToleranceTests
{
    private static DateTimeOffset NotBefore { get; } = SyntheticPassportFactory.NotBefore;
    private static DateTimeOffset NotAfter { get; } = SyntheticPassportFactory.NotAfter;
    private static DateTimeOffset SigningTime { get; } = new(2025, 3, 14, 0, 0, 0, TimeSpan.Zero);


    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A member that is a well-formed TLV — a tag-valid untagged <c>SEQUENCE</c>, the shape of the untagged
    /// <c>Certificate</c> <c>CertificateChoices</c> alternative — but whose content fails
    /// <see cref="ManagedCertificate.Parse"/>, appended alongside the genuine signer certificate, does not
    /// fail verification: the field carrying it is not covered by the signature
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.4">RFC 5652 §5.4</see>'s message digest
    /// runs over the content or signed attributes), so an unparseable non-signer member is a
    /// verification-denial lever rather than evidence against the signature, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">§5.1</see>'s "there may be more
    /// certificates than necessary" makes the set's contents a convenience no verifier may rely on
    /// member-by-member. The verified content surfaces the signer and no other, intact, member.
    /// </summary>
    [TestMethod]
    [DataRow(false, DisplayName = "Managed")]
    [DataRow(true, DisplayName = "BouncyCastle")]
    public async Task AppendingAWellFormedTlvGarbledCertificatesSetMemberStillVerifiesAndSurfacesOnlyIntactMembers(bool useBouncyCastle)
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData bareCarrier = CmsSignedDataTestFactory.SignAsCAdES("the certificates-set tolerance content"u8, signerCertificate, SigningTime);

        byte[] brokenMember = CmsCertificatesFieldSpliceTestFactory.BuildBrokenCertificateMember();
        using CmsSignedData carrier = CmsCertificatesFieldSpliceTestFactory.RebuildWithCertificatesField(bareCarrier, signerCertificate.RawData, brokenMember);

        using var metered = new MeteredHousePool();
        VerifyCmsSignedDataDelegate verify = ResolveBackend(useBouncyCastle);
        using CmsVerifiedContent verified = await verify(carrier, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, verified.Certificates, "The broken member never parses to a certificate, so only the genuine signer certificate is surfaced.");
        Assert.IsTrue(verified.SignerCertificate.AsReadOnlyMemory().Span.SequenceEqual(signerCertificate.RawData), "The surfaced signer certificate is the genuine one, byte-identical to the minted certificate.");

        verified.Dispose();
        Assert.AreEqual(0, metered.OutstandingCount, "Every carrier the verify call rented is disposed once the verified content is disposed; the skipped broken member never reached the pool.");
    }


    /// <summary>
    /// When the SIGNER's own certificates-set member is the one that fails to parse — its bytes replaced
    /// entirely, so nothing in the field can resolve the <c>SignerInfo</c>'s <c>sid</c> — verification fails
    /// with the same failure an entirely absent field produces.
    /// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">RFC 5652 §5.1</see> makes embedding
    /// the signer's certificate optional ("The signer's certificate MAY be included") and §5.6 lets a
    /// recipient obtain the key "by any means"; requiring the signer to resolve from the embedded field is
    /// this library's own stricter policy, shared by both shipped backends. Under it an unresolvable signer
    /// is refused — while the parse failure of one member alone never fails the whole structure's signature.
    /// </summary>
    [TestMethod]
    [DataRow(false, DisplayName = "Managed")]
    [DataRow(true, DisplayName = "BouncyCastle")]
    public async Task AGarbledSignerCertificateStillFailsWithTheSignerNotEmbeddedFailure(bool useBouncyCastle)
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData bareCarrier = CmsSignedDataTestFactory.SignAsCAdES("the garbled-signer content"u8, signerCertificate, SigningTime);

        byte[] brokenMember = CmsCertificatesFieldSpliceTestFactory.BuildBrokenCertificateMember();
        using CmsSignedData carrier = CmsCertificatesFieldSpliceTestFactory.RebuildWithCertificatesField(bareCarrier, brokenMember);

        using var metered = new MeteredHousePool();
        VerifyCmsSignedDataDelegate verify = ResolveBackend(useBouncyCastle);
        CryptographicException refusal = await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () =>
            {
                using CmsVerifiedContent _ = await verify(carrier, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            },
            "The signer's own certificate never parses, so no embedded member can be attributed as the signer.").ConfigureAwait(false);

        Assert.Contains("does not embed the signer certificate", refusal.Message, StringComparison.Ordinal);
        Assert.AreEqual(0, metered.OutstandingCount, "A refused verify leaves nothing outstanding in the pool.");
    }


    /// <summary>
    /// A tagged <c>CertificateChoices</c> alternative sitting alongside the genuine signer certificate — the
    /// <c>v1AttrCert [1]</c> shape of
    /// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-10.2.2">RFC 5652 §10.2.2</see>'s
    /// <c>CertificateChoices ::= CHOICE { certificate Certificate, extendedCertificate [0] …, v1AttrCert
    /// [1] …, v2AttrCert [2] …, other [3] … }</c> — is a legal <c>CertificateChoices</c> alternative shape:
    /// verification succeeds and the alternative is skipped rather than surfaced as one of
    /// <see cref="CmsVerifiedContent.Certificates"/>. The splice keeps the carrier's original
    /// <c>CMSVersion</c>, so the rebuilt structure does not restate §5.1's version rules for
    /// attribute-certificate members — a producer requirement neither backend polices.
    /// </summary>
    [TestMethod]
    [DataRow(false, DisplayName = "Managed")]
    [DataRow(true, DisplayName = "BouncyCastle")]
    public async Task ATaggedCertificateChoicesAlternativeIsSkippedAndNeverSurfacedAsACertificate(bool useBouncyCastle)
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData bareCarrier = CmsSignedDataTestFactory.SignAsCAdES("the tagged-alternative content"u8, signerCertificate, SigningTime);

        byte[] decoy = CmsCertificatesFieldSpliceTestFactory.BuildTaggedCertificateChoice(signerCertificate.RawData, tagNumber: 1);
        using CmsSignedData carrier = CmsCertificatesFieldSpliceTestFactory.RebuildWithCertificatesField(bareCarrier, signerCertificate.RawData, decoy);

        using var metered = new MeteredHousePool();
        VerifyCmsSignedDataDelegate verify = ResolveBackend(useBouncyCastle);
        using CmsVerifiedContent verified = await verify(carrier, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, verified.Certificates, "The v1AttrCert [1] alternative is skipped, never counted alongside the genuine signer certificate.");
        Assert.IsTrue(verified.SignerCertificate.AsReadOnlyMemory().Span.SequenceEqual(signerCertificate.RawData), "The signer certificate is still attributed despite the tagged alternative sharing its certificates SET.");

        verified.Dispose();
        Assert.AreEqual(0, metered.OutstandingCount, "The skipped tagged alternative never reached the pool; the surfaced signer certificate is disposed with the verified content.");
    }


    /// <summary>
    /// A structure minted with its <c>certificates</c> field entirely absent —
    /// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">RFC 5652 §5.1</see> makes the field
    /// <c>OPTIONAL</c> — still fails with the same signer-not-embedded failure the garbled-signer case
    /// produces: member-tolerant parsing of a present field never loosens this library's own requirement
    /// (stricter than §5.1/§5.6, which allow obtaining the certificate by other means) that the signer be
    /// resolvable from SOME embedded certificate.
    /// </summary>
    [TestMethod]
    [DataRow(false, DisplayName = "Managed")]
    [DataRow(true, DisplayName = "BouncyCastle")]
    public async Task AnAbsentCertificatesFieldStillFailsWithTheSignerNotEmbeddedFailure(bool useBouncyCastle)
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCmsWithoutCertificates("the absent-field content"u8, signerCertificate);

        using var metered = new MeteredHousePool();
        VerifyCmsSignedDataDelegate verify = ResolveBackend(useBouncyCastle);
        CryptographicException refusal = await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () =>
            {
                using CmsVerifiedContent _ = await verify(carrier, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            },
            "With no certificates field at all, no embedded member can be attributed as the signer.").ConfigureAwait(false);

        Assert.Contains("does not embed the signer certificate", refusal.Message, StringComparison.Ordinal);
        Assert.AreEqual(0, metered.OutstandingCount, "A refused verify leaves nothing outstanding in the pool.");
    }


    /// <summary>
    /// The same appended-garbage <c>certificates</c> field that
    /// <see cref="AppendingAWellFormedTlvGarbledCertificatesSetMemberStillVerifiesAndSurfacesOnlyIntactMembers"/>
    /// proves signature-verifiable still collapses <see cref="CmsEmbeddedMaterial"/>'s independent
    /// re-parse to <see cref="CmsEmbeddedMaterialStatus.Malformed"/> — the ratified whole-structure
    /// observation-channel behavior member-tolerant signature verification never leaks into. The two seams
    /// disagree by design: one authenticates a signature the field never covered
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.4">RFC 5652 §5.4</see>), the other
    /// reports facts about the structure's own bytes.
    /// </summary>
    [TestMethod]
    public async Task TheAppendedGarbageMemberStillReportsMalformedThroughTheEmbeddedMaterialObservationChannel()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData bareCarrier = CmsSignedDataTestFactory.SignAsCAdES("the lenient-channel-guard content"u8, signerCertificate, SigningTime);

        byte[] brokenMember = CmsCertificatesFieldSpliceTestFactory.BuildBrokenCertificateMember();
        using CmsSignedData carrier = CmsCertificatesFieldSpliceTestFactory.RebuildWithCertificatesField(bareCarrier, signerCertificate.RawData, brokenMember);

        using var metered = new MeteredHousePool();
        using CmsEmbeddedMaterial material = CmsEmbeddedMaterial.Parse(carrier.AsReadOnlyMemory(), metered.Pool);

        Assert.AreEqual(CmsEmbeddedMaterialStatus.Malformed, material.Status, "The broken member's tag-valid-but-unparseable content collapses the whole embedded-material read, exactly as a signature-verifying backend's separate tolerance does not.");
        Assert.IsEmpty(material.Certificates, "A Malformed read surfaces no certificates, not even the intact signer member the tolerant verification path still resolves.");

        Assert.AreEqual(0, metered.OutstandingCount, "A Malformed parse disposes anything it rented before returning; nothing is outstanding once the material itself is disposed.");
    }


    /// <summary>
    /// Resolves the CMS SignedData verification backend under test, invoked directly as a static — never
    /// through the <see cref="CryptographicKeyFactory"/> registry — so a test exercises the named backend's
    /// own behavior regardless of what a host has registered as the default.
    /// </summary>
    /// <param name="useBouncyCastle"><see langword="true"/> for <see cref="BouncyCastleCmsFunctions"/>; <see langword="false"/> for <see cref="ManagedCmsVerification"/>.</param>
    private static VerifyCmsSignedDataDelegate ResolveBackend(bool useBouncyCastle) =>
        useBouncyCastle
            ? BouncyCastleCmsFunctions.VerifyCmsSignedDataAsync
            : ManagedCmsVerification.VerifyCmsSignedDataAsync;
}
