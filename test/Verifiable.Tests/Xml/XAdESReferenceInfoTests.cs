using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESReferenceInfo.TryRead"/> against the <c>ReferenceInfoType</c> data type of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.3: the fixed <c>ds:DigestMethod</c>/<c>ds:DigestValue</c>
/// sequence shared with <see cref="XAdESDigestAlgAndValue"/> via
/// <see cref="XAdESDigestAlgAndValue.TryReadDigestMethodAndValue"/>, together with the wrapping element's
/// own optional <c>Id</c>/<c>URI</c> attributes — the very shape <c>DigestAlgAndValueType</c> lacks.
/// </summary>
[TestClass]
internal sealed class XAdESReferenceInfoTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.3, the minimal shape reads: <c>ds:DigestMethod</c> then <c>ds:DigestValue</c>, neither <c>Id</c>
    /// nor <c>URI</c> present. Custody is proven balanced once the caller disposes the decoded value, via
    /// <see cref="MeteredHousePool"/>.
    /// </summary>
    [TestMethod]
    public void MinimalShapeReadsAndCustodyIsBalancedAfterDispose()
    {
        byte[] digest = [0x01, 0x02, 0x03, 0x04];
        string document = $"""
            <ReferenceInfo xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
              <ds:DigestValue>{Convert.ToBase64String(digest)}</ds:DigestValue>
            </ReferenceInfo>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            var owned = new List<PooledMemory>();
            bool isRead = XAdESReferenceInfo.TryRead(table, table.DocumentElementIndex, metered.Pool, owned, out XAdESReferenceInfo value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.IsFalse(value.HasId);
            Assert.IsFalse(value.HasUri);
            Assert.AreEqual("http://www.w3.org/2001/04/xmlenc#sha256", Encoding.UTF8.GetString(value.Digest.DigestMethodAlgorithm));
            Assert.AreSequenceEqual(digest, value.Digest.DigestValueOctets.AsReadOnlySpan().ToArray());

            foreach(PooledMemory buffer in owned)
            {
                buffer.Dispose();
            }

            Assert.AreEqual(0L, metered.OutstandingCount, "The decoded digest value buffer must be returned once the caller disposes it.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.3, the optional <c>Id</c> and <c>URI</c> attributes both read when present — the shape
    /// <c>DigestAlgAndValueType</c>'s own wrapping elements never carry, so <see cref="XAdESReferenceInfo"/>
    /// needs its own attribute handling rather than delegating whole-element reading to
    /// <see cref="XAdESDigestAlgAndValue.TryRead"/>.
    /// </summary>
    [TestMethod]
    public void OptionalIdAndUriAttributesReadWhenPresent()
    {
        string document = $"""
            <ReferenceInfo xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}" Id="ri1" URI="http://example.com/data">
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
              <ds:DigestValue>QQ==</ds:DigestValue>
            </ReferenceInfo>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        var owned = new List<PooledMemory>();
        bool isRead = XAdESReferenceInfo.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, owned, out XAdESReferenceInfo value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value.Digest.DigestValueOctets)
        {
            Assert.IsTrue(value.HasId);
            Assert.AreEqual("ri1", Encoding.UTF8.GetString(value.Id));
            Assert.IsTrue(value.HasUri);
            Assert.AreEqual("http://example.com/data", Encoding.UTF8.GetString(value.Uri));
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.3, a missing <c>ds:DigestMethod</c> is refused, through the same shared core
    /// <see cref="XAdESDigestAlgAndValue"/> uses.
    /// </summary>
    [TestMethod]
    public void MissingDigestMethodIsRefused()
    {
        using XmlNodeTable table = Parse($"""<ReferenceInfo xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}"/>""", BaseMemoryPool.Shared);
        bool isRead = XAdESReferenceInfo.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, [], out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A ReferenceInfo without a DigestMethod child must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.3, an attribute beyond <c>Id</c>/<c>URI</c> is refused fail-closed.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeIsRefused()
    {
        string document = $"""
            <ReferenceInfo xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}" unexpected="value">
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
              <ds:DigestValue>QQ==</ds:DigestValue>
            </ReferenceInfo>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESReferenceInfo.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, [], out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }
}
