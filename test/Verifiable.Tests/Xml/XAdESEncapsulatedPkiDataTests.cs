using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESEncapsulatedPkiData.TryRead"/> against clause 5.1.3's
/// <c>EncapsulatedPKIDataType</c> data type of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: the <c>Encoding</c> default-to-DER rule, the closed five-URI enumeration,
/// and reuse of the shared strict <c>base64Binary</c> decoder rather than a
/// property-local re-implementation.
/// </summary>
[TestClass]
internal sealed class XAdESEncapsulatedPkiDataTests
{
    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.3's default rule (XA-5.1.3-5): an absent <c>Encoding</c> attribute is reported as
    /// <see cref="XAdESPkiDataEncoding.Der"/>, and the base64 content decodes to the exact original octets.
    /// Custody is proven balanced once the caller disposes the decoded content, via
    /// <see cref="MeteredHousePool"/>.
    /// </summary>
    [TestMethod]
    public void AbsentEncodingDefaultsToDerAndContentDecodes()
    {
        byte[] plaintext = [0xDE, 0xAD, 0xBE, 0xEF];
        string document = $"""<EncapsulatedX509Certificate xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">{Convert.ToBase64String(plaintext)}</EncapsulatedX509Certificate>""";

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            var owned = new List<PooledMemory>();
            bool isRead = XAdESEncapsulatedPkiData.TryRead(table, table.DocumentElementIndex, metered.Pool, owned, out XAdESEncapsulatedPkiData value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.AreEqual(XAdESPkiDataEncoding.Der, value.Encoding);
            Assert.IsFalse(value.HasId);
            Assert.AreSequenceEqual(plaintext, value.Content.AsReadOnlySpan().ToArray());

            foreach(PooledMemory buffer in owned)
            {
                buffer.Dispose();
            }

            Assert.AreEqual(0L, metered.OutstandingCount, "The decoded content buffer must be returned once the caller disposes it.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.3's <c>Id</c> attribute reads when present.
    /// </summary>
    [TestMethod]
    public void IdAttributeReadsWhenPresent()
    {
        using XmlNodeTable table = Parse($"""<EncapsulatedCRLValue xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" Id="crl1">QQ==</EncapsulatedCRLValue>""", BaseMemoryPool.Shared);
        var owned = new List<PooledMemory>();
        bool isRead = XAdESEncapsulatedPkiData.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, owned, out XAdESEncapsulatedPkiData value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value.Content)
        {
            Assert.IsTrue(value.HasId);
            Assert.AreEqual("crl1", Encoding.UTF8.GetString(value.Id));
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.3's closed five-value <c>Encoding</c> enumeration: each of <c>DER</c>/<c>BER</c>/
    /// <c>CER</c>/<c>PER</c>/<c>XER</c> is recognized and mapped to its own <see cref="XAdESPkiDataEncoding"/>
    /// member.
    /// </summary>
    [TestMethod]
    public void EachOfTheFiveEncodingUrisIsRecognized()
    {
        (string Uri, XAdESPkiDataEncoding Expected)[] cases =
        [
            (XAdESIdentifiers.DerEncodingUri, XAdESPkiDataEncoding.Der),
            (XAdESIdentifiers.BerEncodingUri, XAdESPkiDataEncoding.Ber),
            (XAdESIdentifiers.CerEncodingUri, XAdESPkiDataEncoding.Cer),
            (XAdESIdentifiers.PerEncodingUri, XAdESPkiDataEncoding.Per),
            (XAdESIdentifiers.XerEncodingUri, XAdESPkiDataEncoding.Xer)
        ];

        foreach((string uri, XAdESPkiDataEncoding expected) in cases)
        {
            using XmlNodeTable table = Parse($"""<EncapsulatedOCSPValue xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" Encoding="{uri}">QQ==</EncapsulatedOCSPValue>""", BaseMemoryPool.Shared);
            var owned = new List<PooledMemory>();
            bool isRead = XAdESEncapsulatedPkiData.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, owned, out XAdESEncapsulatedPkiData value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Encoding '{uri}' must read but was refused with {error.Failure}.");
            using(value.Content)
            {
                Assert.AreEqual(expected, value.Encoding, $"Encoding '{uri}' must map to {expected}.");
            }
        }
    }


    /// <summary>
    /// Proves an <c>Encoding</c> value outside the closed five-URI enumeration is refused, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.3's
    /// "the following URIs shall be used".
    /// </summary>
    [TestMethod]
    public void UnrecognizedEncodingValueIsRefused()
    {
        using XmlNodeTable table = Parse($"""<EncapsulatedX509Certificate xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" Encoding="http://example.com/not-a-real-encoding">QQ==</EncapsulatedX509Certificate>""", BaseMemoryPool.Shared);
        bool isRead = XAdESEncapsulatedPkiData.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, [], out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized Encoding value must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnrecognizedPkiDataEncoding, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.3, an unrecognized attribute is refused fail-closed — the type declares only <c>Id</c> and
    /// <c>Encoding</c>.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeIsRefused()
    {
        using XmlNodeTable table = Parse($"""<EncapsulatedX509Certificate xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" unexpected="value">QQ==</EncapsulatedX509Certificate>""", BaseMemoryPool.Shared);
        bool isRead = XAdESEncapsulatedPkiData.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, [], out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.3, the simple content is decoded through the same strict <c>base64Binary</c> lexical decoder every
    /// base64-typed field of this leaf shares, rather than a property-local re-implementation: a non-alphabet
    /// character is refused exactly as <see cref="XmlBase64ContentTests"/> proves for the decoder directly,
    /// bridged to <see cref="XAdESReadFailure.InvalidBase64Content"/>.
    /// </summary>
    [TestMethod]
    public void InvalidBase64ContentIsRefused()
    {
        using XmlNodeTable table = Parse($"""<EncapsulatedX509Certificate xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">Q!Q=</EncapsulatedX509Certificate>""", BaseMemoryPool.Shared);
        bool isRead = XAdESEncapsulatedPkiData.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, [], out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "Non-alphabet base64 content must be refused.");
        Assert.AreEqual(XAdESReadFailure.InvalidBase64Content, error.Failure);
    }
}
