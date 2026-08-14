using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Construction and validation-surface tests for the JAdES clause 5.2 signed-component MODELS —
/// <c>x5t#o</c>/<c>sigX5ts</c> (<see cref="AdESCertificateThumbprint"/>/<see cref="AdESCertificateThumbprints"/>),
/// <c>srCms</c> (<see cref="AdESSignerCommitments"/>/<see cref="AdESCommitment"/>), <c>sigPl</c>
/// (<see cref="AdESSignatureProductionPlace"/>), <c>srAts</c> (<see cref="AdESSignerAttributes"/> and its
/// closed/open sub-shapes), <c>sigPId</c> (<see cref="AdESSignaturePolicyIdentifier"/> and its qualifier closed
/// sum), and the shared <c>iat</c>/<c>sigT</c> value carrier (<see cref="JAdESClaimedSigningTime"/>), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, clause 5.2. <c>sigD</c> is covered separately in
/// <c>JAdESDetachedDataObjectReferenceTests</c>; the aggregate itself in <c>JAdESProtectedHeadersTests</c>.
/// </summary>
/// <remarks>
/// These MODELS are serialization-free — this suite
/// exercises construction, fail-closed validation of every constructor-enforced invariant, and (for the
/// disposable carriers) ownership/dispose semantics; a JSON codec is a separate concern.
/// </remarks>
[TestClass]
internal sealed class JAdESSignedComponentModelsTests
{
    /// <summary>Builds a fixture <see cref="DigestValue"/> over <paramref name="bytes"/> — content is irrelevant, only carriage matters here.</summary>
    private static DigestValue CreateDigest(byte[] bytes)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.AsSpan().CopyTo(owner.Memory.Span);

        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }


    //x5t#o / sigX5ts (clause 5.2.2)


    /// <summary>A thumbprint carries its algorithm identifier and digest through unchanged.</summary>
    [TestMethod]
    public void CertificateThumbprintCarriesAlgorithmAndDigest()
    {
        using DigestValue digest = CreateDigest([0x01, 0x02, 0x03]);

        using var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-256"), digest);

        Assert.AreEqual(new AdESDigestAlgorithmTextIdentifier("sha-256"), thumbprint.HashAlgorithm);
        Assert.IsTrue(digest.AsReadOnlySpan().SequenceEqual(thumbprint.Digest.AsReadOnlySpan()));
    }


    /// <summary><c>digAlg</c> is required (JA-5.2.2.2-05); a <see langword="null"/>/empty value fails closed.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-A.1.1-07, JA-A.1.2-13, JA-A.1.2-31.
    /// </remarks>
    [TestMethod]
    public void ConstructingCertificateThumbprintWithEmptyHashAlgorithmThrows()
    {
        using DigestValue digest = CreateDigest([0x01]);

        Assert.ThrowsExactly<ArgumentException>(() => new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier(string.Empty), digest));
    }


    /// <summary><c>digVal</c> is required (JA-5.2.2.2-07); a <see langword="null"/> digest fails closed.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-A.1.1-09, JA-A.1.2-15, JA-A.1.2-33.
    /// </remarks>
    [TestMethod]
    public void ConstructingCertificateThumbprintWithNullDigestThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-256"), null!));
    }


    /// <summary>Two thumbprints carrying the same algorithm and digest bytes compare equal.</summary>
    [TestMethod]
    public void CertificateThumbprintEqualityIsByAlgorithmAndDigestBytes()
    {
        using DigestValue digestA = CreateDigest([0xAA, 0xBB]);
        using DigestValue digestB = CreateDigest([0xAA, 0xBB]);
        using var thumbprintA = new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-256"), digestA);
        using var thumbprintB = new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-256"), digestB);

        Assert.AreEqual(thumbprintA, thumbprintB);
        Assert.IsTrue(thumbprintA == thumbprintB);
        Assert.AreEqual(thumbprintA.GetHashCode(), thumbprintB.GetHashCode());
    }


    /// <summary>Index 0 of a constructed <see cref="AdESCertificateThumbprints"/> is the signing certificate (JA-5.2.2.3-03).</summary>
    [TestMethod]
    public void CertificateThumbprintsExposesSigningCertificateThumbprintAtIndexZero()
    {
        using DigestValue signingDigest = CreateDigest([0x01]);
        using DigestValue pathDigest = CreateDigest([0x02]);
        using var signing = new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-256"), signingDigest);
        using var path = new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-384"), pathDigest);

        //CA2000: ownership of 'signing'/'path' transfers into the array-literal argument below; disposing
        //'thumbprints' (via 'using') disposes them too. Both the 'using' locals above and this instance's own
        //Dispose are safe together — every owned Dispose here is idempotent.
        using var thumbprints = new AdESCertificateThumbprints([signing, path]);

        Assert.AreSame(signing, thumbprints.SigningCertificateThumbprint);
        Assert.HasCount(2, thumbprints.Thumbprints);
    }


    /// <summary>The schema's <c>minItems: 2</c> constraint (JA-5.2.2.3-05) requires at least two entries; a single entry fails closed.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.2.3-02.
    /// </remarks>
    [TestMethod]
    public void ConstructingCertificateThumbprintsBelowMinimumCountThrows()
    {
        using DigestValue digest = CreateDigest([0x01]);
        var single = new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-256"), digest);
        try
        {
            Assert.ThrowsExactly<ArgumentException>(() => new AdESCertificateThumbprints([single]));
        }
        finally
        {
            single.Dispose();
        }
    }


    /// <summary>A <see langword="null"/> <paramref name="thumbprints"/>-equivalent argument fails closed.</summary>
    [TestMethod]
    public void ConstructingCertificateThumbprintsWithNullListThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new AdESCertificateThumbprints(null!));
    }


    //srCms (clause 5.2.3)


    /// <summary>A commitment carries its identifier and, when supplied, its qualifiers through unchanged.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.3-03, JA-5.2.3-M1, JA-5.2.3-M2, JA-5.2.3-07.
    /// </remarks>
    [TestMethod]
    public void CommitmentCarriesIdAndQualifiers()
    {
        var commitmentId = new AdESObjectIdentifier("https://example.org/jades/commitment/proof-of-origin");
        object[] qualifiers = ["a qualifier"];

        var commitment = new AdESCommitment(commitmentId, qualifiers);

        Assert.AreSame(commitmentId, commitment.CommitmentId);
        Assert.AreSame(qualifiers, commitment.CommitmentQualifiers);
    }


    /// <summary>A <see langword="null"/> <c>commId</c> fails closed.</summary>
    [TestMethod]
    public void ConstructingCommitmentWithNullIdThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new AdESCommitment(null!));
    }


    /// <summary>The schema's <c>minItems: 1</c> constraint on <c>commQuals</c> requires non-empty when present.</summary>
    [TestMethod]
    public void ConstructingCommitmentWithEmptyQualifiersThrows()
    {
        var commitmentId = new AdESObjectIdentifier("https://example.org/jades/commitment/proof-of-origin");

        Assert.ThrowsExactly<ArgumentException>(() => new AdESCommitment(commitmentId, []));
    }


    /// <summary>A non-empty commitments array constructs and carries through in wire order.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.3-06.
    /// </remarks>
    [TestMethod]
    public void SignerCommitmentsConstructsWithMultipleCommitmentsInOrder()
    {
        var first = new AdESCommitment(new AdESObjectIdentifier("https://example.org/commitments/1"));
        var second = new AdESCommitment(new AdESObjectIdentifier("https://example.org/commitments/2"));

        var model = new AdESSignerCommitments([first, second]);

        Assert.HasCount(2, model.Commitments);
        Assert.AreSame(first, model.Commitments[0]);
        Assert.AreSame(second, model.Commitments[1]);
    }


    /// <summary><c>srCms</c> shall indicate at least one commitment (JA-5.2.3-01/-02); an empty array fails closed.</summary>
    [TestMethod]
    public void ConstructingSignerCommitmentsWithEmptyArrayThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new AdESSignerCommitments([]));
    }


    /// <summary>A <see langword="null"/> commitments argument fails closed.</summary>
    [TestMethod]
    public void ConstructingSignerCommitmentsWithNullArrayThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new AdESSignerCommitments(null!));
    }


    //sigPl (clause 5.2.4)


    /// <summary>Every <c>sigPl</c> member carries through when supplied.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.4-02, JA-5.2.4-05.
    /// </remarks>
    [TestMethod]
    public void SignatureProductionPlaceCarriesEverySuppliedMember()
    {
        var model = new AdESSignatureProductionPlace
        {
            AddressCountry = "FI",
            AddressLocality = "Espoo",
            AddressRegion = "Uusimaa",
            PostOfficeBoxNumber = "12",
            PostalCode = "02150",
            StreetAddress = "Otakaari 1"
        };

        Assert.AreEqual("FI", model.AddressCountry);
        Assert.AreEqual("Espoo", model.AddressLocality);
        Assert.AreEqual("Uusimaa", model.AddressRegion);
        Assert.AreEqual("12", model.PostOfficeBoxNumber);
        Assert.AreEqual("02150", model.PostalCode);
        Assert.AreEqual("Otakaari 1", model.StreetAddress);
    }


    /// <summary>Every member is individually optional — a fully-empty instance constructs without throwing (the schema's <c>minProperties: 1</c> is a documented, not constructor-enforced, invariant — see the type remarks).</summary>
    [TestMethod]
    public void SignatureProductionPlaceConstructsWithNoMembers()
    {
        var model = new AdESSignatureProductionPlace();

        Assert.IsNull(model.AddressCountry);
        Assert.IsNull(model.StreetAddress);
    }


    //srAts (clause 5.2.5)


    /// <summary>Certified/signed-assertions/claimed all carry through when supplied together.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.5-02, JA-5.2.5-M1, JA-5.2.5-M2.
    /// </remarks>
    [TestMethod]
    public void SignerAttributesCarriesAllThreeMembersWhenSupplied()
    {
        var certified = new AdESX509AttributeCertificate(new AdESPkiObject { Val = new byte[] { 0x30 } });
        var signedAssertion = new JAdESQualifyingAttribute("application/vc+jwt", "base64url", ["assertion-value"]);
        var claimed = new JAdESQualifyingAttribute("text/plain", "base64", ["role=admin"]);

        var model = new AdESSignerAttributes([certified], [signedAssertion], [claimed]);

        Assert.HasCount(1, model.Certified!);
        Assert.HasCount(1, model.SignedAssertions!);
        Assert.HasCount(1, model.Claimed!);
    }


    /// <summary>The schema requires <c>certified</c>, when present, to be non-empty (JA-5.2.5-05).</summary>
    [TestMethod]
    public void ConstructingSignerAttributesWithEmptyCertifiedThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new AdESSignerAttributes(certified: []));
    }


    /// <summary>The schema requires <c>signedAssertions</c>, when present, to be non-empty (JA-5.2.5-07).</summary>
    [TestMethod]
    public void ConstructingSignerAttributesWithEmptySignedAssertionsThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new AdESSignerAttributes(signedAssertions: []));
    }


    /// <summary>The schema requires <c>claimed</c>, when present, to be non-empty (JA-5.2.5-08).</summary>
    [TestMethod]
    public void ConstructingSignerAttributesWithEmptyClaimedThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new AdESSignerAttributes(claimed: []));
    }


    /// <summary>The <c>x509AttrCert</c>/<c>otherAttrCert</c> arms carry their encapsulated <see cref="AdESPkiObject"/> through unchanged.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.5-06.
    /// </remarks>
    [TestMethod]
    public void CertifiedAttributeArmsCarryEncapsulatedPkiObject()
    {
        var pkiObject = new AdESPkiObject { Val = new byte[] { 0x30, 0x03 } };

        var x509 = new AdESX509AttributeCertificate(pkiObject);
        var other = new AdESOtherAttributeCertificate(pkiObject);

        Assert.AreSame(pkiObject, x509.Certificate);
        Assert.AreSame(pkiObject, other.Certificate);
    }


    /// <summary>All three <c>qArrays</c> item members (<c>mediaType</c>/<c>encoding</c>/<c>qVals</c>) carry through unchanged.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.5-11.
    /// </remarks>
    [TestMethod]
    public void QualifyingAttributeCarriesAllRequiredMembers()
    {
        object[] values = ["value-one", "value-two"];

        var model = new JAdESQualifyingAttribute("application/vc+jwt", "base64url", values);

        Assert.AreEqual("application/vc+jwt", model.MediaType);
        Assert.AreEqual("base64url", model.Encoding);
        Assert.AreSame(values, model.QualifyingValues);
    }


    /// <summary><c>mediaType</c> is required (JA-5.2.5-12); a <see langword="null"/>/empty value fails closed.</summary>
    [TestMethod]
    public void ConstructingQualifyingAttributeWithEmptyMediaTypeThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new JAdESQualifyingAttribute(string.Empty, "base64url", ["value"]));
    }


    /// <summary><c>encoding</c> is required (JA-5.2.5-14); a <see langword="null"/>/empty value fails closed.</summary>
    [TestMethod]
    public void ConstructingQualifyingAttributeWithEmptyEncodingThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new JAdESQualifyingAttribute("application/vc+jwt", string.Empty, ["value"]));
    }


    /// <summary>The schema's <c>minItems: 1</c> constraint on <c>qVals</c> (JA-5.2.5-16) requires non-empty; an empty array fails closed.</summary>
    [TestMethod]
    public void ConstructingQualifyingAttributeWithEmptyQualifyingValuesThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new JAdESQualifyingAttribute("application/vc+jwt", "base64url", []));
    }


    //sigPId (clause 5.2.7.1/5.2.7.2)


    /// <summary>Constructing with only the required <c>id</c> member leaves every optional member at its default.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.7.1-05, JA-5.2.7.1-10.
    /// </remarks>
    [TestMethod]
    public void SignaturePolicyIdentifierConstructsWithIdOnly()
    {
        var id = new AdESObjectIdentifier("https://example.org/jades/policy/1");

        using var model = new AdESSignaturePolicyIdentifier(id);

        Assert.AreSame(id, model.Id);
        Assert.IsNull(model.HashAlgorithm);
        Assert.IsNull(model.Digest);
        Assert.IsFalse(model.DigestIsPerSpecification);
        Assert.IsNull(model.Qualifiers);
    }


    /// <summary>A <see langword="null"/> <c>id</c> fails closed.</summary>
    [TestMethod]
    public void ConstructingSignaturePolicyIdentifierWithNullIdThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new AdESSignaturePolicyIdentifier(null!));
    }


    /// <summary>The schema's <c>minItems: 1</c> constraint on <c>sigPQuals</c> (JA-5.2.7.1-13) requires non-empty when present.</summary>
    [TestMethod]
    public void ConstructingSignaturePolicyIdentifierWithEmptyQualifiersThrows()
    {
        var id = new AdESObjectIdentifier("https://example.org/jades/policy/1");

        Assert.ThrowsExactly<ArgumentException>(() =>
            new AdESSignaturePolicyIdentifier(id, qualifiers: []));
    }


    /// <summary>
    /// JA-5.2.7.1-11/-12: when <c>digPSp</c> is <see langword="true"/>, an <c>spDSpec</c> qualifier shall be
    /// present; its absence fails closed.
    /// </summary>
    [TestMethod]
    public void ConstructingSignaturePolicyIdentifierWithDigestPerSpecificationButNoDocumentSpecificationThrows()
    {
        var id = new AdESObjectIdentifier("https://example.org/jades/policy/1");
        IReadOnlyList<AdESSignaturePolicyQualifier> qualifiers = [new AdESSignaturePolicyUri("https://example.org/policy.pdf")];

        Assert.ThrowsExactly<ArgumentException>(() =>
            new AdESSignaturePolicyIdentifier(id, digestIsPerSpecification: true, qualifiers: qualifiers));
    }


    /// <summary>
    /// JA-5.2.7.1-11/-12's coupling is satisfied when an <c>spDSpec</c> qualifier is present alongside
    /// <c>digPSp: true</c> — the digest and every optional member carry through.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.7.1-07, JA-5.2.7.1-08, JA-5.2.7.1-09.
    /// </remarks>
    [TestMethod]
    public void SignaturePolicyIdentifierConstructsWithDigestPerSpecificationAndDocumentSpecification()
    {
        var id = new AdESObjectIdentifier("https://example.org/jades/policy/1");
        using DigestValue digest = CreateDigest([0x01, 0x02]);
        var specification = new AdESSignaturePolicyDocumentSpecification(
            new AdESObjectIdentifier("https://example.org/specs/policy-syntax"));
        IReadOnlyList<AdESSignaturePolicyQualifier> qualifiers = [specification];

        using var model = new AdESSignaturePolicyIdentifier(id, new AdESDigestAlgorithmTextIdentifier("sha-256"), digest, true, qualifiers);

        Assert.AreEqual(new AdESDigestAlgorithmTextIdentifier("sha-256"), model.HashAlgorithm);
        Assert.IsTrue(digest.AsReadOnlySpan().SequenceEqual(model.Digest!.AsReadOnlySpan()));
        Assert.IsTrue(model.DigestIsPerSpecification);
        Assert.AreSame(specification, model.Qualifiers![0]);
    }


    /// <summary><see cref="AdESSignaturePolicyIdentifier.Dispose"/> is idempotent and safe to call any number of times.</summary>
    [TestMethod]
    public void SignaturePolicyIdentifierDisposeIsIdempotent()
    {
        var id = new AdESObjectIdentifier("https://example.org/jades/policy/1");

        //CA2000: ownership of 'digest' transfers into the constructor below; 'model.Dispose()' disposes it.
        //Both calls below are exercising this test's own idempotency claim, not a leak.
#pragma warning disable CA2000 // Dispose objects before losing scope
        var model = new AdESSignaturePolicyIdentifier(id, new AdESDigestAlgorithmTextIdentifier("sha-256"), CreateDigest([0x01]));
#pragma warning restore CA2000 // Dispose objects before losing scope

        model.Dispose();
        model.Dispose();
    }


    /// <summary>The <c>spURI</c> qualifier carries its location through unchanged.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.7.2-02.
    /// </remarks>
    [TestMethod]
    public void SignaturePolicyUriCarriesLocation()
    {
        var location = "https://example.org/policy.pdf";

        var qualifier = new AdESSignaturePolicyUri(location);

        Assert.AreEqual(location, qualifier.Location);
    }


    /// <summary>A <c>spUserNotice</c> with only <c>explText</c> constructs.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.7.2-03, JA-5.2.7.2-04.
    /// </remarks>
    [TestMethod]
    public void SignaturePolicyUserNoticeConstructsWithExplicitTextOnly()
    {
        var qualifier = new AdESSignaturePolicyUserNotice(explicitText: "Please read before signing.");

        Assert.IsNull(qualifier.NoticeReference);
        Assert.AreEqual("Please read before signing.", qualifier.ExplicitText);
    }


    /// <summary>A <c>spUserNotice</c> with only <c>noticeRef</c> constructs.</summary>
    [TestMethod]
    public void SignaturePolicyUserNoticeConstructsWithNoticeReferenceOnly()
    {
        var reference = new AdESSignaturePolicyNoticeReference("Example Org", [1, 2]);

        var qualifier = new AdESSignaturePolicyUserNotice(reference);

        Assert.AreSame(reference, qualifier.NoticeReference);
        Assert.IsNull(qualifier.ExplicitText);
    }


    /// <summary>The schema's <c>minProperties: 1</c> constraint requires at least one of <c>noticeRef</c>/<c>explText</c>; both absent fails closed.</summary>
    [TestMethod]
    public void ConstructingSignaturePolicyUserNoticeWithNeitherMemberThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new AdESSignaturePolicyUserNotice());
    }


    /// <summary><c>noticeRef</c>'s <c>organization</c> and <c>noticeNumbers</c> members are both required.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.7.2-05, JA-5.2.7.2-06.
    /// </remarks>
    [TestMethod]
    public void NoticeReferenceCarriesOrganizationAndNoticeNumbers()
    {
        var reference = new AdESSignaturePolicyNoticeReference("Example Org", [1, 2, 3]);

        Assert.AreEqual("Example Org", reference.Organization);
        Assert.HasCount(3, reference.NoticeNumbers);
    }


    /// <summary>A <see langword="null"/>/empty <c>organization</c> fails closed.</summary>
    [TestMethod]
    public void ConstructingNoticeReferenceWithEmptyOrganizationThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new AdESSignaturePolicyNoticeReference(string.Empty, [1]));
    }


    /// <summary>The schema's <c>minItems: 1</c> constraint on <c>noticeNumbers</c> requires non-empty.</summary>
    [TestMethod]
    public void ConstructingNoticeReferenceWithEmptyNoticeNumbersThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new AdESSignaturePolicyNoticeReference("Example Org", []));
    }


    /// <summary>The <c>spDSpec</c> qualifier carries its identifying <c>oId</c> through unchanged.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.7.2-07.
    /// </remarks>
    [TestMethod]
    public void SignaturePolicyDocumentSpecificationCarriesSpecification()
    {
        var specification = new AdESObjectIdentifier("https://example.org/specs/policy-syntax");

        var qualifier = new AdESSignaturePolicyDocumentSpecification(specification);

        Assert.AreSame(specification, qualifier.Specification);
    }


    //Shared iat/sigT carrier (JAdESClaimedSigningTime)


    /// <summary>A whole-second UTC value constructs, carries through unchanged, and reports as conformant on both facts.</summary>
    [TestMethod]
    public void ClaimedSigningTimeConstructsWithWholeSecondUtcValue()
    {
        var value = new DateTimeOffset(2026, 8, 6, 12, 0, 0, TimeSpan.Zero);

        var model = new JAdESClaimedSigningTime(value);

        Assert.AreEqual(value, model.Value);
        Assert.IsTrue(model.IsUtc);
        Assert.IsFalse(model.HasFractionalSeconds);
    }


    /// <summary>
    /// JA-5.1.11-04/JA-5.2.1-05: this carrier represents any RFC 3339-parseable instant permissively — a
    /// non-zero offset constructs successfully and is reported as a fact via <see cref="JAdESClaimedSigningTime.IsUtc"/>
    /// rather than rejected at construction (a validator-reported forward obligation; see the
    /// type's own remarks). Minting enforcement belongs to the not-yet-built creation orchestrator.
    /// </summary>
    [TestMethod]
    public void ClaimedSigningTimeConstructsWithNonZeroOffsetAndReportsNonUtc()
    {
        var value = new DateTimeOffset(2026, 8, 6, 12, 0, 0, TimeSpan.FromHours(2));

        var model = new JAdESClaimedSigningTime(value);

        Assert.AreEqual(value, model.Value);
        Assert.IsFalse(model.IsUtc);
    }


    /// <summary>
    /// JA-5.1.11-05/JA-5.2.1-06: this carrier represents a sub-second component permissively — it constructs
    /// successfully and is reported as a fact via <see cref="JAdESClaimedSigningTime.HasFractionalSeconds"/>
    /// rather than rejected at construction (a validator-reported forward obligation; see the
    /// type's own remarks). Minting enforcement belongs to the not-yet-built creation orchestrator.
    /// </summary>
    [TestMethod]
    public void ClaimedSigningTimeConstructsWithFractionalSecondsAndReportsSubSecondPrecision()
    {
        var value = new DateTimeOffset(2026, 8, 6, 12, 0, 0, 500, TimeSpan.Zero);

        var model = new JAdESClaimedSigningTime(value);

        Assert.AreEqual(value, model.Value);
        Assert.IsTrue(model.HasFractionalSeconds);
    }
}
