using System;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The <c>id-aa-CMSAlgorithmProtection</c> signed attribute
/// (<see href="https://www.rfc-editor.org/rfc/rfc6211#section-2">RFC 6211 §2</see>) binds a copy of the
/// <c>SignerInfo</c>'s <c>digestAlgorithm</c> and <c>signatureAlgorithm</c> fields inside the signature's
/// own coverage, closing the algorithm-substitution gap RFC 6211 §1 describes for CMS. These tests exercise
/// <see cref="ManagedCmsVerification"/> directly (Managed-only: BouncyCastle performs its own
/// algorithm-protection processing inside <c>signer.Verify</c>), over fixtures
/// <see cref="CmsAlgorithmProtectionTestFactory"/> mints with a caller-controlled attribute value signed
/// over the mismatch itself, so a negative fixture's signature verifies and only the algorithm-protection
/// compare rejects it.
/// </summary>
[TestClass]
internal sealed class CmsAlgorithmProtectionVerificationTests
{
    private static DateTimeOffset NotBefore { get; } = SyntheticPassportFactory.NotBefore;
    private static DateTimeOffset NotAfter { get; } = SyntheticPassportFactory.NotAfter;

    /// <summary>The digest algorithm the framework's <c>CmsSigner</c>-backed minting defaults to (SHA-256), which every fixture below signs its RSA certificate's <c>SignerInfo</c> under.</summary>
    private const string ActualDigestAlgorithmOid = WellKnownOids.Sha256;

    /// <summary>
    /// The bare <c>rsaEncryption</c> signature algorithm object identifier an RSA <c>CmsSigner</c> states in
    /// <c>SignerInfo.signatureAlgorithm</c>, carrying the hash in the digest algorithm instead of naming one
    /// itself (RFC 3370 §3.2) — see <c>CmsSignedDataTestFactory.BuildCAdES</c>'s own remark on the same
    /// shape.
    /// </summary>
    private const string ActualSignatureAlgorithmOid = WellKnownOids.RsaEncryption;


    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A <c>CMSAlgorithmProtection</c> attribute whose <c>digestAlgorithm</c> and <c>signatureAlgorithm</c>
    /// genuinely agree with the <c>SignerInfo</c> fields it was minted beside verifies exactly as a
    /// structure carrying no such attribute would: RFC 6211 §3.1 gates on the fields being "not the same",
    /// never on the attribute's mere presence.
    /// </summary>
    [TestMethod]
    public async Task ACmsAlgorithmProtectionAttributeAgreeingWithSignerInfoVerifies()
    {
        using RSA signingKey = RSA.Create(2048);
        using X509Certificate2 signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsAlgorithmProtectionTestFactory.SignWithCmsAlgorithmProtection(
            "the agreeing algorithm-protection content"u8, signerCertificate, ActualDigestAlgorithmOid, ActualSignatureAlgorithmOid);

        using var metered = new MeteredHousePool();
        using CmsVerifiedContent verified = await ManagedCmsVerification.VerifyCmsSignedDataAsync(carrier, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verified.TryGetSignedAttribute(CmsAlgorithmProtectionTestFactory.CmsAlgorithmProtectionOid, out _), "The signed attribute the fixture minted is surfaced among the verified signed attributes.");

        verified.Dispose();
        Assert.AreEqual(0, metered.OutstandingCount, "Every carrier the verify call rented returns to the pool once the verified content is disposed.");
    }


    /// <summary>
    /// A <c>CMSAlgorithmProtection</c> attribute whose <c>digestAlgorithm</c> disagrees with the
    /// <c>SignerInfo.digestAlgorithm</c> field it was signed beside fails verification: RFC 6211 §3.1 item 1
    /// states "The SignerInfo.digestAlgorithm field MUST be compared to the digestAlgorithm field in the
    /// attribute. If the fields are not the same (modulo encoding), then signature validation MUST fail."
    /// The fixture signs over the mismatched value itself, so the signature mathematics verify and only this
    /// compare rejects it.
    /// </summary>
    [TestMethod]
    public async Task ACmsAlgorithmProtectionDigestAlgorithmDisagreeingWithSignerInfoFailsVerification()
    {
        using RSA signingKey = RSA.Create(2048);
        using X509Certificate2 signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsAlgorithmProtectionTestFactory.SignWithCmsAlgorithmProtection(
            "the digest-mismatch content"u8, signerCertificate, WellKnownOids.Sha384, ActualSignatureAlgorithmOid);

        using var metered = new MeteredHousePool();
        CryptographicException refusal = await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () =>
            {
                using CmsVerifiedContent _ = await ManagedCmsVerification.VerifyCmsSignedDataAsync(carrier, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            },
            "The attribute names SHA-384 while the SignerInfo digest algorithm is SHA-256; RFC 6211 §3.1 item 1 requires the compare to reject rather than resolve in either field's favor.").ConfigureAwait(false);

        //The §3.1 item 1 compare's own refusal — not the multiplicity guard, the malformed-DER wrapper, or
        //any other failure sharing the exception type.
        Assert.Contains("digest algorithm does not match", refusal.Message, StringComparison.Ordinal);
        Assert.AreEqual(0, metered.OutstandingCount, "A refused verify leaves nothing outstanding in the pool.");
    }


    /// <summary>
    /// A <c>CMSAlgorithmProtection</c> attribute whose <c>signatureAlgorithm</c> disagrees with the
    /// <c>SignerInfo.signatureAlgorithm</c> field it was signed beside fails verification: RFC 6211 §3.1
    /// item 2 states "The SignerInfo.signatureAlgorithm field MUST be compared to the signatureAlgorithm
    /// field in the attribute. If the fields are not the same (modulo encoding), then the signature
    /// validation MUST fail." The fixture's <c>digestAlgorithm</c> agrees, isolating the signature-algorithm
    /// compare as the sole cause of the failure.
    /// </summary>
    [TestMethod]
    public async Task ACmsAlgorithmProtectionSignatureAlgorithmDisagreeingWithSignerInfoFailsVerification()
    {
        using RSA signingKey = RSA.Create(2048);
        using X509Certificate2 signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsAlgorithmProtectionTestFactory.SignWithCmsAlgorithmProtection(
            "the signature-algorithm-mismatch content"u8, signerCertificate, ActualDigestAlgorithmOid, WellKnownOids.Sha256WithRsaEncryption);

        using var metered = new MeteredHousePool();
        CryptographicException refusal = await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () =>
            {
                using CmsVerifiedContent _ = await ManagedCmsVerification.VerifyCmsSignedDataAsync(carrier, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            },
            "The attribute names the combined sha256WithRSAEncryption identifier while the SignerInfo signature algorithm is the bare rsaEncryption RFC 3370 §3.2 shape; RFC 6211 §3.1 item 2 requires the compare to reject.").ConfigureAwait(false);

        //The §3.1 item 2 compare's own refusal, distinguishable from every other failure on the path.
        Assert.Contains("signature algorithm does not match", refusal.Message, StringComparison.Ordinal);
        Assert.AreEqual(0, metered.OutstandingCount, "A refused verify leaves nothing outstanding in the pool.");
    }


    /// <summary>
    /// A <c>CMSAlgorithmProtection</c> attribute carrying two <c>AttributeValue</c>s under the one signed
    /// attribute type fails verification outright, independent of whether either value itself agrees with
    /// the <c>SignerInfo</c> fields: RFC 6211 §2 states "An algorithm protection attribute MUST have a
    /// single attribute value, even though the syntax is defined as a SET OF AttributeValue. There MUST NOT
    /// be zero or multiple instances of AttributeValue present."
    /// </summary>
    [TestMethod]
    public async Task TwoAttributeValuesUnderTheOneCmsAlgorithmProtectionAttributeFailVerification()
    {
        using RSA signingKey = RSA.Create(2048);
        using X509Certificate2 signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsAlgorithmProtectionTestFactory.SignWithCmsAlgorithmProtection(
            "the duplicate-attribute-value content"u8, signerCertificate, ActualDigestAlgorithmOid, ActualSignatureAlgorithmOid, duplicateAttributeValue: true);

        using var metered = new MeteredHousePool();
        CryptographicException refusal = await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () =>
            {
                using CmsVerifiedContent _ = await ManagedCmsVerification.VerifyCmsSignedDataAsync(carrier, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            },
            "Two AttributeValues under the one algorithm-protection attribute type is the shape RFC 6211 §2 forbids outright, even though both values here agree with the SignerInfo fields.").ConfigureAwait(false);

        //The §2 multiplicity guard's own refusal — the values agree with the SignerInfo, so no compare fires.
        Assert.Contains("exactly once with exactly one attribute value", refusal.Message, StringComparison.Ordinal);
        Assert.AreEqual(0, metered.OutstandingCount, "A refused verify leaves nothing outstanding in the pool.");
    }


    /// <summary>
    /// A mismatching <c>CMSAlgorithmProtection</c> value carried ONLY as an unsigned attribute never gates
    /// verification: RFC 6211 §2 states the attribute "MUST be a signed attribute or an authenticated
    /// attribute; it MUST NOT be an unsigned attribute", so an unsigned instance is unauthenticated data this
    /// verifier is never required to consult, and its mismatching content is not itself an error the
    /// verifier invents.
    /// </summary>
    [TestMethod]
    public async Task AMismatchingCmsAlgorithmProtectionValueOnlyInUnsignedAttrsIsNeverConsulted()
    {
        using RSA signingKey = RSA.Create(2048);
        using X509Certificate2 signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsAlgorithmProtectionTestFactory.SignWithCmsAlgorithmProtection(
            "the unsigned-mismatch content"u8, signerCertificate, WellKnownOids.Sha384, WellKnownOids.Sha256WithRsaEncryption, asSignedAttribute: false);

        using var metered = new MeteredHousePool();
        using CmsVerifiedContent verified = await ManagedCmsVerification.VerifyCmsSignedDataAsync(carrier, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(verified.TryGetSignedAttribute(CmsAlgorithmProtectionTestFactory.CmsAlgorithmProtectionOid, out _), "The attribute was added only as unsigned, so it never appears among the signed attributes this verifier surfaces.");

        verified.Dispose();
        Assert.AreEqual(0, metered.OutstandingCount, "Every carrier the verify call rented returns to the pool once the verified content is disposed.");
    }


    /// <summary>
    /// A <c>CMSAlgorithmProtection</c> attribute whose value is not the RFC 6211 §2
    /// <c>CMSAlgorithmProtection ::= SEQUENCE</c> shape at all fails verification with the
    /// <see cref="CryptographicException"/> the verification surface documents — never a raw ASN.1 parse
    /// exception — even though the signature over the malformed value itself verifies. The fixture carries a
    /// DER <c>NULL</c> where the SEQUENCE belongs.
    /// </summary>
    [TestMethod]
    public async Task AMalformedCmsAlgorithmProtectionValueFailsVerificationWithACryptographicException()
    {
        using RSA signingKey = RSA.Create(2048);
        using X509Certificate2 signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsAlgorithmProtectionTestFactory.SignWithCmsAlgorithmProtection(
            "the malformed-attribute-value content"u8, signerCertificate, ActualDigestAlgorithmOid, ActualSignatureAlgorithmOid,
            rawAttributeValue: [0x05, 0x00]);

        using var metered = new MeteredHousePool();
        CryptographicException refusal = await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () =>
            {
                using CmsVerifiedContent _ = await ManagedCmsVerification.VerifyCmsSignedDataAsync(carrier, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            },
            "A DER NULL where RFC 6211 §2's CMSAlgorithmProtection SEQUENCE belongs is a malformed attribute; the documented failure surface is CryptographicException, not the parser's own exception type.").ConfigureAwait(false);

        //The malformed-encoding wrapper's own refusal, distinguishable from the semantic compares.
        Assert.Contains("not well-formed DER", refusal.Message, StringComparison.Ordinal);
        Assert.AreEqual(0, metered.OutstandingCount, "A refused verify leaves nothing outstanding in the pool.");
    }


    /// <summary>
    /// A <c>CMSAlgorithmProtection</c> value carrying content beyond the fields RFC 6211 §2 defines fails
    /// verification: the §2 <c>WITH COMPONENTS</c> constraint admits exactly <c>digestAlgorithm</c> with
    /// <c>signatureAlgorithm</c> present and <c>macAlgorithm</c> absent in a <c>SignerInfo</c> placement, so
    /// a trailing element after <c>signatureAlgorithm</c> is not a <c>CMSAlgorithmProtection</c> and is
    /// refused rather than ignored.
    /// </summary>
    [TestMethod]
    public async Task ACmsAlgorithmProtectionValueWithTrailingContentFailsVerification()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            using(writer.PushSequence())
            {
                writer.WriteObjectIdentifier(ActualDigestAlgorithmOid);
            }

            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                writer.WriteObjectIdentifier(ActualSignatureAlgorithmOid);
            }

            writer.WriteInteger(0);
        }

        using RSA signingKey = RSA.Create(2048);
        using X509Certificate2 signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsAlgorithmProtectionTestFactory.SignWithCmsAlgorithmProtection(
            "the trailing-content attribute value"u8, signerCertificate, ActualDigestAlgorithmOid, ActualSignatureAlgorithmOid,
            rawAttributeValue: writer.Encode());

        using var metered = new MeteredHousePool();
        CryptographicException refusal = await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () =>
            {
                using CmsVerifiedContent _ = await ManagedCmsVerification.VerifyCmsSignedDataAsync(carrier, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            },
            "An INTEGER after signatureAlgorithm is content RFC 6211 §2 gives no field for; the value is refused as malformed rather than the extra content being skipped.").ConfigureAwait(false);

        //The strict-emptiness refusal surfaces through the malformed-encoding wrapper.
        Assert.Contains("not well-formed DER", refusal.Message, StringComparison.Ordinal);
        Assert.AreEqual(0, metered.OutstandingCount, "A refused verify leaves nothing outstanding in the pool.");
    }


    /// <summary>
    /// A <c>CMSAlgorithmProtection</c> value carrying both <c>signatureAlgorithm [1]</c> and
    /// <c>macAlgorithm [2]</c> fails verification: RFC 6211 §2 gives the type as
    /// <c>(WITH COMPONENTS { signatureAlgorithm PRESENT, macAlgorithm ABSENT } | WITH COMPONENTS
    /// { signatureAlgorithm ABSENT, macAlgorithm PRESENT })</c>, and states "Exactly one of signatureAlgorithm
    /// or macAlgorithm SHALL be present." A <c>SignerInfo.signedAttrs</c> placement takes the first
    /// alternative — <c>signatureAlgorithm</c> "populated only if the attribute is placed in a
    /// SignerInfo.signedAttrs sequence" — so a value stating both satisfies neither alternative.
    /// </summary>
    [TestMethod]
    public async Task ACmsAlgorithmProtectionValueCarryingAMacAlgorithmFailsVerification()
    {
        const string HmacWithSha256Oid = "1.2.840.113549.2.9";

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            using(writer.PushSequence())
            {
                writer.WriteObjectIdentifier(ActualDigestAlgorithmOid);
            }

            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                writer.WriteObjectIdentifier(ActualSignatureAlgorithmOid);
            }

            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                writer.WriteObjectIdentifier(HmacWithSha256Oid);
            }
        }

        using RSA signingKey = RSA.Create(2048);
        using X509Certificate2 signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsAlgorithmProtectionTestFactory.SignWithCmsAlgorithmProtection(
            "the mac-algorithm-carrying attribute value"u8, signerCertificate, ActualDigestAlgorithmOid, ActualSignatureAlgorithmOid,
            rawAttributeValue: writer.Encode());

        using var metered = new MeteredHousePool();
        CryptographicException refusal = await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () =>
            {
                using CmsVerifiedContent _ = await ManagedCmsVerification.VerifyCmsSignedDataAsync(carrier, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            },
            "A macAlgorithm alongside a signatureAlgorithm is the WITH COMPONENTS shape RFC 6211 §2 forbids for a SignerInfo.signedAttrs placement, which admits only signatureAlgorithm PRESENT with macAlgorithm ABSENT.").ConfigureAwait(false);

        //The §2 WITH COMPONENTS constraint's own refusal, distinguishable from the multiplicity and malformed-encoding guards.
        Assert.Contains("must not carry a macAlgorithm", refusal.Message, StringComparison.Ordinal);
        Assert.AreEqual(0, metered.OutstandingCount, "A refused verify leaves nothing outstanding in the pool.");
    }


    /// <summary>
    /// A <c>CMSAlgorithmProtection</c> value omitting <c>signatureAlgorithm [1]</c> entirely fails
    /// verification: RFC 6211 §2 gives the type as <c>(WITH COMPONENTS { signatureAlgorithm PRESENT,
    /// macAlgorithm ABSENT } | WITH COMPONENTS { signatureAlgorithm ABSENT, macAlgorithm PRESENT })</c>, and
    /// <c>signatureAlgorithm</c> is "populated only if the attribute is placed in a SignerInfo.signedAttrs
    /// sequence" — the placement every fixture in this file uses. A value stating <c>digestAlgorithm</c> alone
    /// satisfies neither WITH COMPONENTS alternative for that placement.
    /// </summary>
    [TestMethod]
    public async Task ACmsAlgorithmProtectionValueOmittingTheSignatureAlgorithmFailsVerification()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            using(writer.PushSequence())
            {
                writer.WriteObjectIdentifier(ActualDigestAlgorithmOid);
            }
        }

        using RSA signingKey = RSA.Create(2048);
        using X509Certificate2 signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsAlgorithmProtectionTestFactory.SignWithCmsAlgorithmProtection(
            "the signature-algorithm-omitting attribute value"u8, signerCertificate, ActualDigestAlgorithmOid, ActualSignatureAlgorithmOid,
            rawAttributeValue: writer.Encode());

        using var metered = new MeteredHousePool();
        CryptographicException refusal = await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () =>
            {
                using CmsVerifiedContent _ = await ManagedCmsVerification.VerifyCmsSignedDataAsync(carrier, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            },
            "digestAlgorithm alone satisfies neither RFC 6211 §2 WITH COMPONENTS alternative for a SignerInfo.signedAttrs placement, which requires signatureAlgorithm present.").ConfigureAwait(false);

        //The §2 WITH COMPONENTS constraint's own refusal for the missing signatureAlgorithm.
        Assert.Contains("must carry a signatureAlgorithm", refusal.Message, StringComparison.Ordinal);
        Assert.AreEqual(0, metered.OutstandingCount, "A refused verify leaves nothing outstanding in the pool.");
    }


    /// <summary>
    /// A <c>CMSAlgorithmProtection</c> attribute stating an explicit DER <c>NULL</c> <c>parameters</c> field on
    /// both <c>digestAlgorithm</c> and <c>signatureAlgorithm</c> verifies against a <c>SignerInfo</c> whose own
    /// fields carry whichever of the two encodings the platform signer emitted: RFC 6211 §3 notes "the
    /// parameter value of NULL can be included in the ASN.1 encoding by some implementations and be omitted by
    /// other implementations. It is left to the implementer of this attribute to decide the comparison for
    /// equality is satisfied in this case." This library decides an absent field and an explicit DER
    /// <c>NULL</c> compare equal, so the attribute agrees "modulo encoding" with the §3.1 compare regardless of
    /// which of the two shapes the SignerInfo fields take.
    /// </summary>
    [TestMethod]
    public async Task ACmsAlgorithmProtectionWithExplicitNullParametersVerifiesModuloEncoding()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            using(writer.PushSequence())
            {
                writer.WriteObjectIdentifier(ActualDigestAlgorithmOid);
                writer.WriteNull();
            }

            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                writer.WriteObjectIdentifier(ActualSignatureAlgorithmOid);
                writer.WriteNull();
            }
        }

        using RSA signingKey = RSA.Create(2048);
        using X509Certificate2 signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsAlgorithmProtectionTestFactory.SignWithCmsAlgorithmProtection(
            "the explicit-null-parameters content"u8, signerCertificate, ActualDigestAlgorithmOid, ActualSignatureAlgorithmOid,
            rawAttributeValue: writer.Encode());

        using var metered = new MeteredHousePool();
        using CmsVerifiedContent verified = await ManagedCmsVerification.VerifyCmsSignedDataAsync(carrier, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verified.TryGetSignedAttribute(CmsAlgorithmProtectionTestFactory.CmsAlgorithmProtectionOid, out _), "The signed attribute the fixture minted is surfaced among the verified signed attributes.");

        verified.Dispose();
        Assert.AreEqual(0, metered.OutstandingCount, "Every carrier the verify call rented returns to the pool once the verified content is disposed.");
    }
}
