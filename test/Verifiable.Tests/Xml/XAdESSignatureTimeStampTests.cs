using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESSignatureTimeStamp.TryRead"/> against clause 5.3's <c>SignatureTimeStamp</c>
/// qualifying property of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>. Message-imprint computation is proven separately by
/// <see cref="XAdESSignatureTimeStampImprintTests"/>.
/// </summary>
[TestClass]
internal sealed class XAdESSignatureTimeStampTests
{
    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.3, the minimal Implicit-mechanism
    /// shape — no <c>Include</c>, one <c>EncapsulatedTimeStamp</c> — reads, and custody balances to zero once
    /// the caller disposes the returned value.
    /// </summary>
    [TestMethod]
    public void MinimalImplicitShapeReadsAndCustodyBalancesAfterDispose()
    {
        string document = $"""
            <SignatureTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </SignatureTimeStamp>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESSignatureTimeStamp.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESSignatureTimeStamp? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.HasCount(0, value!.TimeStamp.Includes);
            Assert.HasCount(1, value.TimeStamp.TimeStamps);
            Assert.AreEqual(XAdESTimeStampEntryKind.EncapsulatedTimeStamp, value.TimeStamp.TimeStamps[0].Kind);

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer rented must be returned once the caller disposes the value.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clauses 5.1.4.4.1 and 5.3 together — "The
    /// Implicit mechanism (see clause 5.1.4.4.1) shall be used for generating this qualifying property," and
    /// clause 5.1.4.4.1 defines <c>Include</c> as the Explicit mechanism's own exclusive marker — a
    /// <c>SignatureTimeStamp</c> instance carrying an <c>Include</c> element is refused, even though the
    /// shared <c>XAdESTimeStampType</c> schema itself permits <c>Include*</c>. Adjudicated identically to
    /// <see cref="XAdESAllDataObjectsTimeStampTests.PresenceOfIncludeIsRefused"/>'s clause 5.2.8.1 precedent.
    /// </summary>
    [TestMethod]
    public void PresenceOfIncludeIsRefused()
    {
        string document = $"""
            <SignatureTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <Include URI="#data1"/>
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </SignatureTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignatureTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A SignatureTimeStamp carrying an Include element must be refused.");
        Assert.AreEqual(XAdESReadFailure.SignatureTimeStampIncludeNotPermitted, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.1, the underlying
    /// <see cref="XAdESTimeStamp.TryRead"/> refusals surface unchanged: zero time-stamp entries at all is
    /// refused per the shared <c>XAdESTimeStampType</c> grammar's own one-or-more requirement.
    /// </summary>
    [TestMethod]
    public void ZeroTimeStampEntriesIsRefused()
    {
        using XmlNodeTable table = Parse($"""<SignatureTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}"/>""", BaseMemoryPool.Shared);
        bool isRead = XAdESSignatureTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "Zero time-stamp entries must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.3 and the pooling discipline,
    /// custody is balanced even on a refusal path: when the Include-presence rule refuses AFTER the underlying <see cref="XAdESTimeStamp"/> already decoded an <c>EncapsulatedTimeStamp</c> buffer, <see
    /// cref="XAdESSignatureTimeStamp.TryRead"/>'s own outer <c>try</c>/<c>finally</c> releases it.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedWhenIncludeRefusalFollowsSuccessfulDecoding()
    {
        string document = $"""
            <SignatureTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <Include URI="#data1"/>
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </SignatureTimeStamp>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESSignatureTimeStamp.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESSignatureTimeStamp? value, out XAdESReadError error);
            using(value)
            {
                Assert.IsFalse(isRead, "Must refuse due to the Include element.");
                Assert.IsNull(value);
                Assert.AreEqual(XAdESReadFailure.SignatureTimeStampIncludeNotPermitted, error.Failure);
                Assert.AreEqual(0L, metered.OutstandingCount, "The EncapsulatedTimeStamp buffer decoded before the Include check must already be released.");
            }
        }
    }
}
