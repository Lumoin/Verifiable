using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESIndividualDataObjectsTimeStamp.TryRead"/> against clause 5.2.8.2's
/// <c>IndividualDataObjectsTimeStamp</c> qualifying property of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>. Message-imprint computation itself is <see
/// cref="XAdESIndividualDataObjectsTimeStampImprint"/>'s own job; these proofs cover the structural read and
/// the <c>referencedData="true"</c> rule only.
/// </summary>
[TestClass]
internal sealed class XAdESIndividualDataObjectsTimeStampTests
{
    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.2, the minimal Explicit-mechanism
    /// shape — one <c>Include referencedData="true"</c>, one <c>EncapsulatedTimeStamp</c> — reads, and custody
    /// balances to zero once the caller disposes the returned value.
    /// </summary>
    [TestMethod]
    public void MinimalExplicitShapeReadsAndCustodyBalancesAfterDispose()
    {
        string document = $"""
            <IndividualDataObjectsTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <Include URI="#data1" referencedData="true"/>
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </IndividualDataObjectsTimeStamp>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESIndividualDataObjectsTimeStamp.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESIndividualDataObjectsTimeStamp? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.HasCount(1, value!.TimeStamp.Includes);
            Assert.IsTrue(value.TimeStamp.Includes[0].ReferencedData);

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer rented must be returned once the caller disposes the value.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.2, multiple <c>Include</c>
    /// elements — each carrying <c>referencedData="true"</c> — read together, with document order preserved.
    /// </summary>
    [TestMethod]
    public void MultipleIncludesAllReferencedDataTrueRead()
    {
        string document = $"""
            <IndividualDataObjectsTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <Include URI="#first" referencedData="true"/>
              <Include URI="#second" referencedData="true"/>
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </IndividualDataObjectsTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESIndividualDataObjectsTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESIndividualDataObjectsTimeStamp? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.HasCount(2, value!.TimeStamp.Includes);
            Assert.AreEqual("#first", Encoding.UTF8.GetString(value.TimeStamp.Includes[0].Uri));
            Assert.AreEqual("#second", Encoding.UTF8.GetString(value.TimeStamp.Includes[1].Uri));
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.2's "The <c>referencedData</c>
    /// attribute shall be present in each and every <c>Include</c> element, and set to <c>"true"</c>" — an
    /// <c>Include</c> whose <c>referencedData</c> is present but literally <c>"false"</c> is refused, even
    /// though <c>IncludeType</c>'s own schema (clause 5.1.4.4.2.1) permits any of the four <c>xsd:boolean</c>
    /// lexical forms.
    /// </summary>
    [TestMethod]
    public void IncludeWithReferencedDataFalseIsRefused()
    {
        string document = $"""
            <IndividualDataObjectsTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <Include URI="#data1" referencedData="false"/>
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </IndividualDataObjectsTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESIndividualDataObjectsTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An Include with referencedData=\"false\" must be refused.");
        Assert.AreEqual(XAdESReadFailure.IndividualDataObjectsTimeStampIncludeReferencedDataNotTrue, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.2's "shall be present" half of
    /// the rule: an <c>Include</c> with no <c>referencedData</c> attribute at all — legal under
    /// <c>IncludeType</c>'s own schema, where the attribute is optional — is refused for THIS property
    /// specifically.
    /// </summary>
    [TestMethod]
    public void IncludeWithAbsentReferencedDataIsRefused()
    {
        string document = $"""
            <IndividualDataObjectsTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <Include URI="#data1"/>
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </IndividualDataObjectsTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESIndividualDataObjectsTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An Include with no referencedData attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.IndividualDataObjectsTimeStampIncludeReferencedDataNotTrue, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.2's "each and every" wording,
    /// checked per-<c>Include</c>: with two <c>Include</c> elements, the FIRST carrying
    /// <c>referencedData="true"</c> and the SECOND lacking it, the whole read is refused — a single compliant
    /// <c>Include</c> does not excuse a later non-compliant one.
    /// </summary>
    [TestMethod]
    public void OneNonCompliantIncludeAmongCompliantOnesIsRefused()
    {
        string document = $"""
            <IndividualDataObjectsTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <Include URI="#first" referencedData="true"/>
              <Include URI="#second"/>
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </IndividualDataObjectsTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESIndividualDataObjectsTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A later Include lacking referencedData=\"true\" must still refuse the whole read.");
        Assert.AreEqual(XAdESReadFailure.IndividualDataObjectsTimeStampIncludeReferencedDataNotTrue, error.Failure);
    }


    /// <summary>
    /// Records, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.2, this reader's adjudication of
    /// a point the clause's prose leaves open: nothing in the clause states an
    /// <c>IndividualDataObjectsTimeStamp</c> instance must carry AT LEAST ONE <c>Include</c> — "The
    /// <c>Include</c> elements shall be composed to refer to those <c>ds:Reference</c> elements referencing
    /// the data objects that have to be time-stamped" describes how any <c>Include</c> present must be
    /// composed, not a floor on their count. Zero <c>Include</c> elements is therefore NOT refused by this
    /// reader — the "each and every" rule holds vacuously — leaving the (degenerate, empty-selection) case to
    /// whichever generation-side policy chooses whether to ever emit such an instance.
    /// </summary>
    [TestMethod]
    public void ZeroIncludesIsNotRefused()
    {
        string document = $"""
            <IndividualDataObjectsTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </IndividualDataObjectsTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESIndividualDataObjectsTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESIndividualDataObjectsTimeStamp? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Zero Include elements must not be refused, but was refused with {error.Failure}.");
        using(value)
        {
            Assert.HasCount(0, value!.TimeStamp.Includes);
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.8.2 and the pooling
    /// discipline, custody is balanced even on a refusal path: when the <c>referencedData</c> rule refuses AFTER the underlying <see cref="XAdESTimeStamp"/> already decoded an
    /// <c>EncapsulatedTimeStamp</c> buffer, <see cref="XAdESIndividualDataObjectsTimeStamp.TryRead"/>'s own outer <c>try</c>/<c>finally</c> releases it.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedWhenReferencedDataRefusalFollowsSuccessfulDecoding()
    {
        string document = $"""
            <IndividualDataObjectsTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <Include URI="#data1"/>
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </IndividualDataObjectsTimeStamp>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESIndividualDataObjectsTimeStamp.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESIndividualDataObjectsTimeStamp? value, out XAdESReadError error);
            using(value)
            {
                Assert.IsFalse(isRead, "Must refuse due to the missing referencedData attribute.");
                Assert.IsNull(value);
                Assert.AreEqual(XAdESReadFailure.IndividualDataObjectsTimeStampIncludeReferencedDataNotTrue, error.Failure);
                Assert.AreEqual(0L, metered.OutstandingCount, "The EncapsulatedTimeStamp buffer decoded before the referencedData check must already be released.");
            }
        }
    }
}
