using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESValidationData.TryReadTimeStampValidationData"/> against clause 5.5.1.1's
/// <c>TimeStampValidationData</c> qualifying property of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>, the second binding of the shared <c>ValidationDataType</c> core
/// <see cref="XAdESValidationData"/> exposes alongside <see cref="XAdESValidationData.TryReadAnyValidationData"/>.
/// </summary>
[TestClass]
internal sealed class XAdESTimeStampValidationDataTests
{
    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static string Document(string body, bool includeUri = true) => $$"""
        <TimeStampValidationData xmlns="{{XAdESIdentifiers.XAdESNamespaceV141}}" xmlns:xades="{{XAdESIdentifiers.XAdESNamespaceV132}}"{{(includeUri ? " URI=\"#ts1\"" : "")}}>
          {{body}}
        </TimeStampValidationData>
        """;


    /// <summary>
    /// Proves clause 5.5.1.1's own permission — "the <c>TimeStampValidationData</c> qualifying property may
    /// have the <c>URI</c> attribute" — contrasted by clause 5.4.6's prohibition on the same attribute for
    /// <c>AnyValidationData</c>: a <c>URI</c>-bearing instance reads successfully here, where
    /// <see cref="XAdESValidationData.TryReadAnyValidationData"/> would refuse it with
    /// <see cref="XAdESReadFailure.AnyValidationDataUriNotPermitted"/>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.1.1.
    /// </summary>
    [TestMethod]
    public void UriAttributeIsPermitted()
    {
        string document = Document("""<xades:CertificateValues><xades:EncapsulatedX509Certificate>AQ==</xades:EncapsulatedX509Certificate></xades:CertificateValues>""", includeUri: true);
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESValidationData.TryReadTimeStampValidationData(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESValidationData? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.HasUri);
            Assert.AreSequenceEqual("#ts1"u8.ToArray(), value.Uri.ToArray());
        }
    }


    /// <summary>
    /// Proves clause 5.5.1.1 states no "shall contain at least one of <c>CertificateValues</c>/
    /// <c>RevocationValues</c>" floor the way clause 5.4.6 does for <c>AnyValidationData</c> — "may contain
    /// all [...] or may contain only some, if the rest are present elsewhere" contemplates a
    /// <c>TimeStampValidationData</c> instance whose own children are both absent; this reader accepts it,
    /// unlike <see cref="XAdESValidationData.TryReadAnyValidationData"/>'s
    /// <see cref="XAdESReadFailure.EmptyAnyValidationData"/> refusal for the analogous shape.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.1.1.
    /// </summary>
    [TestMethod]
    public void EmptyChildrenAreNotRefused()
    {
        string document = Document(string.Empty, includeUri: true);
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESValidationData.TryReadTimeStampValidationData(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESValidationData? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsFalse(value!.HasCertificateValues);
            Assert.IsFalse(value.HasRevocationValues);
        }
    }


    /// <summary>
    /// Proves clause 5.5.1.1's XA-5.5.1-6/-9 both children read through the shared
    /// <see cref="XAdESCertificateValues"/>/<see cref="XAdESRevocationValues"/> readers, exactly as
    /// <c>AnyValidationData</c>'s own shared core does, and custody balances to zero on disposal.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.1.1.
    /// </summary>
    [TestMethod]
    public void BothChildrenReadAndCustodyBalances()
    {
        string document = Document(
            """
            <xades:CertificateValues><xades:EncapsulatedX509Certificate>AQ==</xades:EncapsulatedX509Certificate></xades:CertificateValues>
            <xades:RevocationValues><xades:CRLValues><xades:EncapsulatedCRLValue>AQ==</xades:EncapsulatedCRLValue></xades:CRLValues></xades:RevocationValues>
            """,
            includeUri: true);

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESValidationData.TryReadTimeStampValidationData(table, table.DocumentElementIndex, metered.Pool, out XAdESValidationData? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.IsTrue(value!.HasCertificateValues);
            Assert.IsTrue(value.HasRevocationValues);

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "Every decoded field must be released on Dispose.");
        }
    }
}
