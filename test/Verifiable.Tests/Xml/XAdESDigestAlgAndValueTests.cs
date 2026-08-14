using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESDigestAlgAndValue.TryRead"/> against the <c>DigestAlgAndValueType</c> data type
/// of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> (first declared at clause 5.2.2 as <c>CertDigest</c>'s content, reused
/// unchanged for <c>SigPolicyHash</c>/<c>DigestAlgAndValue</c>, per the "one shared digest-carrier
/// reader"). This reader does not itself dispose <see cref="XAdESDigestAlgAndValue.DigestValueOctets"/>;
/// the shared custody-list convention means a refusal reached AFTER the digest value already decoded still
/// leaves the buffer in the caller's custody list for release, proven explicitly below.
/// </summary>
[TestClass]
internal sealed class XAdESDigestAlgAndValueTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2, the minimal shape: <c>ds:DigestMethod</c> then <c>ds:DigestValue</c>, and nothing else, reads —
    /// the digest method's <c>Algorithm</c> and the decoded digest value both surface exactly. Custody is
    /// proven balanced once the caller disposes the decoded value, via <see cref="MeteredHousePool"/>.
    /// </summary>
    [TestMethod]
    public void MinimalShapeReadsAndCustodyIsBalancedAfterDispose()
    {
        byte[] digest = [0xAA, 0xBB, 0xCC];
        string document = $"""
            <CertDigest xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
              <ds:DigestValue>{Convert.ToBase64String(digest)}</ds:DigestValue>
            </CertDigest>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            var owned = new List<PooledMemory>();
            bool isRead = XAdESDigestAlgAndValue.TryRead(table, table.DocumentElementIndex, metered.Pool, owned, out XAdESDigestAlgAndValue value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.AreEqual("http://www.w3.org/2001/04/xmlenc#sha256", Encoding.UTF8.GetString(value.DigestMethodAlgorithm));
            Assert.AreSequenceEqual(digest, value.DigestValueOctets.AsReadOnlySpan().ToArray());

            foreach(PooledMemory buffer in owned)
            {
                buffer.Dispose();
            }

            Assert.AreEqual(0L, metered.OutstandingCount, "The decoded digest value buffer must be returned once the caller disposes it.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2, a missing <c>ds:DigestMethod</c> is refused.
    /// </summary>
    [TestMethod]
    public void MissingDigestMethodIsRefused()
    {
        using XmlNodeTable table = Parse($"""<CertDigest xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}"/>""", BaseMemoryPool.Shared);
        bool isRead = XAdESDigestAlgAndValue.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, [], out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A CertDigest without a DigestMethod child must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2, a <c>ds:DigestMethod</c> without its mandatory <c>Algorithm</c> attribute is refused.
    /// </summary>
    [TestMethod]
    public void MissingAlgorithmAttributeIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <CertDigest xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              <ds:DigestMethod/>
              <ds:DigestValue>QQ==</ds:DigestValue>
            </CertDigest>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESDigestAlgAndValue.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, [], out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A DigestMethod without Algorithm must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredAttribute, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2, a missing <c>ds:DigestValue</c> (only <c>ds:DigestMethod</c> present) is refused.
    /// </summary>
    [TestMethod]
    public void MissingDigestValueIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <CertDigest xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            </CertDigest>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESDigestAlgAndValue.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, [], out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A CertDigest without a DigestValue child must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2, an unrecognized attribute on the wrapping element is refused — <c>DigestAlgAndValueType</c>
    /// declares no attribute of its own, unlike <c>ReferenceInfoType</c>'s <c>Id</c>/<c>URI</c>.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeOnWrappingElementIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <CertDigest xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}" unexpected="value">
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
              <ds:DigestValue>QQ==</ds:DigestValue>
            </CertDigest>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESDigestAlgAndValue.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, [], out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute on the wrapping element must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2, invalid base64 content in <c>ds:DigestValue</c> is refused through the same shared decoder
    /// every base64-typed field of this leaf uses.
    /// </summary>
    [TestMethod]
    public void InvalidBase64DigestValueIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <CertDigest xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
              <ds:DigestValue>Q!Q=</ds:DigestValue>
            </CertDigest>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESDigestAlgAndValue.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, [], out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "Non-alphabet base64 content must be refused.");
        Assert.AreEqual(XAdESReadFailure.InvalidBase64Content, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2, a trailing, unrecognized element after <c>ds:DigestValue</c> is refused — AND that because the
    /// refusal is determined only after the digest value already decoded successfully, the decoded buffer is
    /// still present in the caller's custody list, not silently dropped: the caller (here, standing in for
    /// an aggregate type such as <see cref="XAdESSigningCertificateV2"/>) must dispose it itself, exactly the
    /// shared custody convention <c>XmlSignature.TryRead</c>'s own outer <c>try</c>/<c>finally</c> exists for.
    /// </summary>
    [TestMethod]
    public void TrailingElementRefusalStillLeavesTheDecodedValueInTheCustodyListForTheCallerToRelease()
    {
        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse($"""
                <CertDigest xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <ds:DigestValue>QQ==</ds:DigestValue>
                  <TrailingUnknown/>
                </CertDigest>
                """, BaseMemoryPool.Shared);

            var owned = new List<PooledMemory>();
            bool isRead = XAdESDigestAlgAndValue.TryRead(table, table.DocumentElementIndex, metered.Pool, owned, out _, out XAdESReadError error);
            Assert.IsFalse(isRead, "A trailing unrecognized element must be refused.");
            Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
            Assert.HasCount(1, owned, "The DigestValue decode already succeeded before the trailing-element refusal was determined, so its buffer sits in the custody list.");

            foreach(PooledMemory buffer in owned)
            {
                buffer.Dispose();
            }

            Assert.AreEqual(0L, metered.OutstandingCount, "Disposing the custody list the caller was handed must balance the rent even on this refusal path.");
        }
    }
}
