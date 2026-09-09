using System.Text;
using Verifiable.Cryptography.Pki;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESDigestAlgorithmPosture"/> against clause 6.2.1's MD5 digest-algorithm ban of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>, checked at every digest-algorithm URI position the XAdES surface carries.
/// </summary>
[TestClass]
internal sealed class XAdESDigestAlgorithmPostureTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string V141 = "http://uri.etsi.org/01903/v1.4.1#";

    private const string Sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";

    private const string Md5 = "http://www.w3.org/2001/04/xmldsig-more#md5";


    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves <see cref="XAdESDigestAlgorithmPosture.Md5DigestUri"/>/<see cref="XAdESDigestAlgorithmPosture.Md5DigestUriUtf8"/> stay in bijection with <see
    /// cref="XmlSignatureWellKnown.Md5DigestUri"/> — the leaf's own literal, kept crypto-free, restates rather than reuses the Pki-side identifier, and this test is what
    /// keeps the two from silently drifting apart, the bijection-pinning precedent, for the URI clause 6.2.1's XA-6.2.1-02 bans. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.2.1.
    /// </summary>
    [TestMethod]
    public void LeafLiteralStaysInBijectionWithThePkiLiteral()
    {
        Assert.AreEqual(XmlSignatureWellKnown.Md5DigestUri, XAdESDigestAlgorithmPosture.Md5DigestUri);
        Assert.AreSequenceEqual(Encoding.UTF8.GetBytes(XmlSignatureWellKnown.Md5DigestUri), XAdESDigestAlgorithmPosture.Md5DigestUriUtf8.ToArray());
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.2.1's XA-6.2.1-02 at a
    /// <see cref="XAdESDigestAlgAndValue"/> site — <c>CertDigest</c>, read through
    /// <see cref="XAdESSigningCertificateV2"/>: an MD5 <c>ds:DigestMethod</c> is recognized, a SHA-256 one is
    /// not.
    /// </summary>
    [TestMethod]
    [DataRow(Md5, true)]
    [DataRow(Sha256, false)]
    public void CertDigestSiteIsCheckable(string digestAlgorithmUri, bool expectedIsMd5)
    {
        string document = $"""
            <SigningCertificateV2 xmlns="{V132}" xmlns:ds="{DsNamespace}">
              <Cert>
                <CertDigest>
                  <ds:DigestMethod Algorithm="{digestAlgorithmUri}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </CertDigest>
              </Cert>
            </SigningCertificateV2>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSigningCertificateV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSigningCertificateV2? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.AreEqual(expectedIsMd5, XAdESDigestAlgorithmPosture.IsMd5DigestUri(value!.Certs[0].CertDigest.DigestMethodAlgorithm));
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.2.1's XA-6.2.1-02 at a second
    /// <see cref="XAdESDigestAlgAndValue"/> site — <c>SigPolicyHash</c>, read through <see cref="XAdESSignaturePolicyIdentifier"/>: the SAME shared digest-carrier type is checkable regardless
    /// of the wrapping element's own name.
    /// </summary>
    [TestMethod]
    public void SigPolicyHashSiteIsCheckable()
    {
        string document = $"""
            <SignaturePolicyIdentifier xmlns="{V132}" xmlns:ds="{DsNamespace}">
              <SignaturePolicyId>
                <SigPolicyId><Identifier>urn:oid:1.2.3.4</Identifier></SigPolicyId>
                <SigPolicyHash>
                  <ds:DigestMethod Algorithm="{Md5}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </SigPolicyHash>
              </SignaturePolicyId>
            </SignaturePolicyIdentifier>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyIdentifier.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSignaturePolicyIdentifier? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(XAdESDigestAlgorithmPosture.IsMd5DigestUri(value!.SignaturePolicyId!.SigPolicyHash.DigestMethodAlgorithm));
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.2.1's XA-6.2.1-02 at the "timestamp
    /// imprint digest method" position — <c>OtherTimeStampType</c>'s own <c>ReferenceInfo</c> list, via
    /// <see cref="XAdESReferenceInfo.Digest"/>.
    /// </summary>
    [TestMethod]
    public void ReferenceInfoDigestSiteIsCheckable()
    {
        string document = $"""
            <OtherTimeStamp xmlns="{V132}" xmlns:ds="{DsNamespace}">
              <ReferenceInfo Id="r1">
                <ds:DigestMethod Algorithm="{Md5}"/>
                <ds:DigestValue>AQ==</ds:DigestValue>
              </ReferenceInfo>
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </OtherTimeStamp>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        //owned is a collection of disposables, not one disposable value: a using declaration disposes one
        //variable's own value, not a collection's elements, so the foreach below in the finally block is
        //the release point.
        var owned = new List<PooledMemory>();
        try
        {
            bool isRead = XAdESOtherTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, owned, out XAdESOtherTimeStamp value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.IsTrue(XAdESDigestAlgorithmPosture.IsMd5DigestUri(value.ReferenceInfos[0].Digest.DigestMethodAlgorithm));
        }
        finally
        {
            foreach(PooledMemory buffer in owned)
            {
                buffer.Dispose();
            }
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.2.1's XA-6.2.1-02 at
    /// <see cref="XAdESRenewedDigestsV2.DigestMethodAlgorithm"/> — clause 5.5.3's own, non-shared
    /// <c>ds:DigestMethod</c>, distinct from the <see cref="XAdESDigestAlgAndValue"/> family.
    /// </summary>
    [TestMethod]
    public void RenewedDigestsV2SiteIsCheckable()
    {
        const string ExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
        string document = $"""
            <RenewedDigestsV2 xmlns="{V141}" xmlns:ds="{DsNamespace}">
              <ds:CanonicalizationMethod Algorithm="{ExclusiveC14N}"/>
              <ds:DigestMethod Algorithm="{Md5}"/>
              <RecomputedDigestValue><NewSDODigestValue>AQ==</NewSDODigestValue><OriginalRefDigest>Ag==</OriginalRefDigest></RecomputedDigestValue>
            </RenewedDigestsV2>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESRenewedDigestsV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESRenewedDigestsV2? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(XAdESDigestAlgorithmPosture.IsMd5DigestUri(value!.DigestMethodAlgorithm));
        }
    }
}
