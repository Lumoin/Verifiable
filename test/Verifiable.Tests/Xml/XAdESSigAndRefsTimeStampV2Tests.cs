using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESSigAndRefsTimeStampV2.TryRead"/> against clause A.1.5.1's <c>SigAndRefsTimeStampV2</c>
/// qualifying property "defined in the namespace whose URI is <c>http://uri.etsi.org/01903/v1.4.1#</c>" of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>. The anchor here is A.1.5.1 — the TRUE defining clause — never Annex D item 6's
/// misprinted "clause A.1.3".
/// </summary>
[TestClass]
internal sealed class XAdESSigAndRefsTimeStampV2Tests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string V141 = "http://uri.etsi.org/01903/v1.4.1#";


    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves the v1.4.1-namespace <c>SigAndRefsTimeStampV2</c> reads through the shared <see cref="XAdESTimeStamp"/>
    /// grammar with zero <c>Include</c> elements — the not-distributed (Implicit-mechanism) shape of clause
    /// A.1.5.1.2.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.1.
    /// </summary>
    [TestMethod]
    public void NoIncludesReadsAsNotDistributedShape()
    {
        string document = $"""
            <root xmlns="{V132}" xmlns:xadesv2="{V141}">
              <xadesv2:SigAndRefsTimeStampV2 Id="sarts1"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></xadesv2:SigAndRefsTimeStampV2>
            </root>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isFound = table.TryFindElementById("sarts1"u8, out int elementIndex, out _);
        Assert.IsTrue(isFound, "The fixture SigAndRefsTimeStampV2 must resolve by Id.");
        bool isRead = XAdESSigAndRefsTimeStampV2.TryRead(table, elementIndex, BaseMemoryPool.Shared, out XAdESSigAndRefsTimeStampV2? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.HasCount(0, value!.TimeStamp.Includes);
        }
    }


    /// <summary>
    /// Proves this reader imposes NO Implicit-mechanism lock: an instance carrying <c>Include</c> elements (the
    /// distributed case's Explicit mechanism, clause A.1.5.1.3) is accepted at read time, since clause A.1.5.1.2's
    /// Implicit-mechanism requirement is scoped to the not-distributed case only.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.1.
    /// </summary>
    [TestMethod]
    public void IncludesArePermitted()
    {
        string document = $"""
            <root xmlns="{V132}" xmlns:xadesv2="{V141}">
              <Target Id="t1"/>
              <xadesv2:SigAndRefsTimeStampV2 Id="sarts1">
                <Include URI="#t1"/>
                <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
              </xadesv2:SigAndRefsTimeStampV2>
            </root>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isFound = table.TryFindElementById("sarts1"u8, out int elementIndex, out _);
        Assert.IsTrue(isFound, "The fixture SigAndRefsTimeStampV2 must resolve by Id.");
        bool isRead = XAdESSigAndRefsTimeStampV2.TryRead(table, elementIndex, BaseMemoryPool.Shared, out XAdESSigAndRefsTimeStampV2? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.HasCount(1, value!.TimeStamp.Includes);
        }
    }


    /// <summary>
    /// Proves this reader's own identity check is scoped to the v1.4.1 namespace and the exact local name
    /// <c>SigAndRefsTimeStampV2</c> — the deprecated v1.3.2-namespace <c>SigAndRefsTimeStamp</c> (Annex D item 6)
    /// is a different, unrelated element this type never accepts.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.1.
    /// </summary>
    [TestMethod]
    public void DeprecatedV132NamespacedElementIsRefused()
    {
        string document = $"""<SigAndRefsTimeStamp xmlns="{V132}"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></SigAndRefsTimeStamp>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSigAndRefsTimeStampV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "The deprecated v1.3.2-namespace element must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves custody is balanced on the success path via <see cref="MeteredHousePool"/>: the decoded
    /// <c>EncapsulatedTimeStamp</c> content is released once the caller disposes the returned value.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.1.5.1.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnSuccess()
    {
        string document = $"""
            <root xmlns="{V132}" xmlns:xadesv2="{V141}">
              <xadesv2:SigAndRefsTimeStampV2 Id="sarts1"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></xadesv2:SigAndRefsTimeStampV2>
            </root>
            """;
        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isFound = table.TryFindElementById("sarts1"u8, out int elementIndex, out _);
            Assert.IsTrue(isFound, "The fixture SigAndRefsTimeStampV2 must resolve by Id.");
            bool isRead = XAdESSigAndRefsTimeStampV2.TryRead(table, elementIndex, metered.Pool, out XAdESSigAndRefsTimeStampV2? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");

            value!.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "The decoded EncapsulatedTimeStamp buffer must be released on Dispose.");
        }
    }
}
