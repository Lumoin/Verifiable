using System.Diagnostics;
using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Growth-bound hardening proofs: every list-shaped qualifying-property reader this leaf bounds (<see
/// cref="XAdESUnsignedSignatureProperties.MaximumPropertyCount"/>, <see
/// cref="XAdESSigningCertificateV2.MaximumCertIdListEntryCount"/>, <see
/// cref="XAdESCompleteRevocationRefs.MaximumRevocationRefEntryCount"/>, <see cref="XAdESCertificateValues.MaximumEntryCount"/>, <see
/// cref="XAdESRevocationValues.MaximumEncapsulatedEntryCount"/>/<see cref="XAdESRevocationValues.MaximumUnmodeledEntryCount"/>, <see
/// cref="XAdESTimeStamp.MaximumIncludeCount"/>) refuses a hostile document carrying one more entry than its bound with <see
/// cref="XAdESReadFailure.EntryCountLimitExceeded"/>, and does so inside a loose wall-clock ceiling — proving the reader's own work
/// is bounded by the CONSTANT, not by the attacker's chosen count — mirroring <see cref="XmlCanonicalizationCostTests"/>'s
/// stopwatch-and-ceiling idiom. Every fixture is built programmatically (no corpora); every refusal path is proven to return its
/// pooled buffers via <see cref="MeteredHousePool"/> accounting.
/// </summary>
[TestClass]
internal sealed class XAdESGrowthBoundsCostTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

    private static readonly TimeSpan ResourceCaseCeiling = TimeSpan.FromSeconds(10);


    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static void DisposeOwned(List<PooledMemory> owned)
    {
        for(int i = 0; i < owned.Count; ++i)
        {
            owned[i].Dispose();
        }
    }


    /// <summary>
    /// Proves <see cref="XAdESUnsignedSignatureProperties.MaximumPropertyCount"/>: a flood of unrecognized foreign-namespace children one past the bound is refused with
    /// <see cref="XAdESReadFailure.EntryCountLimitExceeded"/> inside the loose ceiling, over clause 4.3.6's (XA-4.3.6-3) own unbounded <c>xsd:choice
    /// maxOccurs="unbounded"</c> content model of <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319
    /// 132-1 V1.3.1</see>.
    /// </summary>
    [TestMethod]
    public void UnsignedSignaturePropertiesFloodIsRefusedWithinTheCeiling()
    {
        int count = XAdESUnsignedSignatureProperties.MaximumPropertyCount + 1;
        var builder = new StringBuilder(count * 24);
        builder.Append($"""<UnsignedSignatureProperties xmlns="{V132}" xmlns:f="urn:filler">""");
        for(int i = 0; i < count; ++i)
        {
            builder.Append("<f:Filler/>");
        }

        builder.Append("</UnsignedSignatureProperties>");

        using var metered = new MeteredHousePool();
        var stopwatch = Stopwatch.StartNew();
        using XmlNodeTable table = Parse(builder.ToString(), metered.Pool);
        bool isRead = XAdESUnsignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        stopwatch.Stop();

        Assert.IsFalse(isRead, "A flood past the bound must be refused.");
        Assert.AreEqual(XAdESReadFailure.EntryCountLimitExceeded, error.Failure);
        Assert.IsLessThan(ResourceCaseCeiling, stopwatch.Elapsed, $"Took {stopwatch.Elapsed}, exceeding the loose ceiling {ResourceCaseCeiling}.");
    }


    /// <summary>
    /// Proves <see cref="XAdESSigningCertificateV2.MaximumCertIdListEntryCount"/>, shared by
    /// <c>SigningCertificateV2</c>/<c>CompleteCertificateRefsV2</c>/<c>AttributeCertificateRefsV2</c>: a flood of <c>Cert</c> entries one past the bound is refused inside
    /// the loose ceiling, with every buffer decoded before the refusal released, per clause 5.2.2's own unbounded <c>CertIDListV2Type</c> content model of <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>.
    /// </summary>
    [TestMethod]
    public void CertIdListV2FloodIsRefusedWithinTheCeiling()
    {
        int count = XAdESSigningCertificateV2.MaximumCertIdListEntryCount + 1;
        var builder = new StringBuilder(count * 160);
        builder.Append($"""<Wrapper xmlns="{V132}" xmlns:ds="{DsNamespace}">""");
        for(int i = 0; i < count; ++i)
        {
            builder.Append($"""
                <Cert><CertDigest><ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/><ds:DigestValue>AQ==</ds:DigestValue></CertDigest></Cert>
                """);
        }

        builder.Append("</Wrapper>");

        using var metered = new MeteredHousePool();
        var owned = new List<PooledMemory>();
        var stopwatch = Stopwatch.StartNew();
        XmlNodeTable table = Parse(builder.ToString(), metered.Pool);
        bool isRead = XAdESSigningCertificateV2.TryReadCertIdListV2(table, table.DocumentElementIndex, metered.Pool, owned, out _, out XAdESReadError error);
        stopwatch.Stop();
        DisposeOwned(owned);
        table.Dispose();

        Assert.IsFalse(isRead, "A Cert flood past the bound must be refused.");
        Assert.AreEqual(XAdESReadFailure.EntryCountLimitExceeded, error.Failure);
        Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer decoded before the refusal must be released.");
        Assert.IsLessThan(ResourceCaseCeiling, stopwatch.Elapsed, $"Took {stopwatch.Elapsed}, exceeding the loose ceiling {ResourceCaseCeiling}.");
    }


    /// <summary>
    /// Proves <see cref="XAdESCompleteRevocationRefs.MaximumRevocationRefEntryCount"/>: a flood of <c>CRLRef</c> entries one past the bound, under
    /// <c>CompleteRevocationRefs</c>'s own <c>CRLRefs</c> list, is refused inside the loose ceiling, per Annex A.1.2's own unbounded content model of <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>.
    /// </summary>
    [TestMethod]
    public void CrlRefFloodIsRefusedWithinTheCeiling()
    {
        int count = XAdESCompleteRevocationRefs.MaximumRevocationRefEntryCount + 1;
        var builder = new StringBuilder(count * 200);
        builder.Append($"""<CompleteRevocationRefs xmlns="{V132}" xmlns:ds="{DsNamespace}"><CRLRefs>""");
        for(int i = 0; i < count; ++i)
        {
            builder.Append($"""
                <CRLRef><DigestAlgAndValue><ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/><ds:DigestValue>AQ==</ds:DigestValue></DigestAlgAndValue></CRLRef>
                """);
        }

        builder.Append("</CRLRefs></CompleteRevocationRefs>");

        using var metered = new MeteredHousePool();
        var stopwatch = Stopwatch.StartNew();
        XmlNodeTable table = Parse(builder.ToString(), metered.Pool);
        bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, metered.Pool, out XAdESCompleteRevocationRefs? value, out XAdESReadError error);
        stopwatch.Stop();
        value?.Dispose();
        table.Dispose();

        Assert.IsFalse(isRead, "A CRLRef flood past the bound must be refused.");
        Assert.AreEqual(XAdESReadFailure.EntryCountLimitExceeded, error.Failure);
        Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer decoded before the refusal must be released.");
        Assert.IsLessThan(ResourceCaseCeiling, stopwatch.Elapsed, $"Took {stopwatch.Elapsed}, exceeding the loose ceiling {ResourceCaseCeiling}.");
    }


    /// <summary>
    /// Proves <see cref="XAdESCertificateValues.MaximumEntryCount"/>: a flood of <c>OtherCertificate</c> entries one past the bound is refused inside the loose ceiling,
    /// per clause 5.4.2's own unbounded content model of <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI
    /// EN 319 132-1 V1.3.1</see>.
    /// </summary>
    [TestMethod]
    public void CertificateValuesFloodIsRefusedWithinTheCeiling()
    {
        int count = XAdESCertificateValues.MaximumEntryCount + 1;
        var builder = new StringBuilder(count * 24);
        builder.Append($"""<CertificateValues xmlns="{V132}">""");
        for(int i = 0; i < count; ++i)
        {
            builder.Append("<OtherCertificate/>");
        }

        builder.Append("</CertificateValues>");

        using var metered = new MeteredHousePool();
        var stopwatch = Stopwatch.StartNew();
        XmlNodeTable table = Parse(builder.ToString(), metered.Pool);
        bool isRead = XAdESCertificateValues.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESCertificateValues? value, out XAdESReadError error);
        stopwatch.Stop();
        value?.Dispose();
        table.Dispose();

        Assert.IsFalse(isRead, "An OtherCertificate flood past the bound must be refused.");
        Assert.AreEqual(XAdESReadFailure.EntryCountLimitExceeded, error.Failure);
        Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer decoded before the refusal must be released.");
        Assert.IsLessThan(ResourceCaseCeiling, stopwatch.Elapsed, $"Took {stopwatch.Elapsed}, exceeding the loose ceiling {ResourceCaseCeiling}.");
    }


    /// <summary>
    /// Proves <see cref="XAdESRevocationValues.MaximumEncapsulatedEntryCount"/>: a flood of <c>EncapsulatedCRLValue</c> entries one past the bound, under
    /// <c>RevocationValues</c>'s own <c>CRLValues</c> list, is refused inside the loose ceiling, per clause 5.4.3's own unbounded content model of <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>.
    /// </summary>
    [TestMethod]
    public void RevocationValuesEncapsulatedFloodIsRefusedWithinTheCeiling()
    {
        int count = XAdESRevocationValues.MaximumEncapsulatedEntryCount + 1;
        var builder = new StringBuilder(count * 40);
        builder.Append($"""<RevocationValues xmlns="{V132}"><CRLValues>""");
        for(int i = 0; i < count; ++i)
        {
            builder.Append("<EncapsulatedCRLValue>AQ==</EncapsulatedCRLValue>");
        }

        builder.Append("</CRLValues></RevocationValues>");

        using var metered = new MeteredHousePool();
        var stopwatch = Stopwatch.StartNew();
        XmlNodeTable table = Parse(builder.ToString(), metered.Pool);
        bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESRevocationValues? value, out XAdESReadError error);
        stopwatch.Stop();
        value?.Dispose();
        table.Dispose();

        Assert.IsFalse(isRead, "An EncapsulatedCRLValue flood past the bound must be refused.");
        Assert.AreEqual(XAdESReadFailure.EntryCountLimitExceeded, error.Failure);
        Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer decoded before the refusal must be released.");
        Assert.IsLessThan(ResourceCaseCeiling, stopwatch.Elapsed, $"Took {stopwatch.Elapsed}, exceeding the loose ceiling {ResourceCaseCeiling}.");
    }


    /// <summary>
    /// Proves <see cref="XAdESRevocationValues.MaximumUnmodeledEntryCount"/>, shared by <c>RevocationValues</c>'s own <c>OtherValues</c> and <see
    /// cref="XAdESCompleteRevocationRefs"/>'s <c>OtherRefs</c>: a flood of <c>OtherValue</c> entries one past the bound is refused inside the loose ceiling, per clause
    /// 5.4.3's own unbounded content model of <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1
    /// V1.3.1</see>.
    /// </summary>
    [TestMethod]
    public void RevocationValuesUnmodeledFloodIsRefusedWithinTheCeiling()
    {
        int count = XAdESRevocationValues.MaximumUnmodeledEntryCount + 1;
        var builder = new StringBuilder(count * 24);
        builder.Append($"""<RevocationValues xmlns="{V132}"><OtherValues>""");
        for(int i = 0; i < count; ++i)
        {
            builder.Append("<OtherValue/>");
        }

        builder.Append("</OtherValues></RevocationValues>");

        using var metered = new MeteredHousePool();
        var stopwatch = Stopwatch.StartNew();
        using XmlNodeTable table = Parse(builder.ToString(), metered.Pool);
        bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESRevocationValues? value, out XAdESReadError error);
        stopwatch.Stop();
        value?.Dispose();

        Assert.IsFalse(isRead, "An OtherValue flood past the bound must be refused.");
        Assert.AreEqual(XAdESReadFailure.EntryCountLimitExceeded, error.Failure);
        Assert.IsLessThan(ResourceCaseCeiling, stopwatch.Elapsed, $"Took {stopwatch.Elapsed}, exceeding the loose ceiling {ResourceCaseCeiling}.");
    }


    /// <summary>
    /// Proves <see cref="XAdESTimeStamp.MaximumIncludeCount"/>: a flood of <c>Include</c> children one past the bound is refused inside the loose ceiling — dangling
    /// <c>URI</c> targets are irrelevant, since <see cref="XAdESTimeStamp.TryRead"/> is a structural read that never dereferences them. Anchored to clause 5.1.4.4.2.1's
    /// (XA-5.1.4.4.1-2) own unbounded content model of <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN
    /// 319 132-1 V1.3.1</see>.
    /// </summary>
    [TestMethod]
    public void IncludeFloodIsRefusedWithinTheCeiling()
    {
        int count = XAdESTimeStamp.MaximumIncludeCount + 1;
        var builder = new StringBuilder(count * 24);
        builder.Append($"""<Wrapper xmlns="{V132}">""");
        for(int i = 0; i < count; ++i)
        {
            builder.Append("""<Include URI="#nonexistent"/>""");
        }

        builder.Append("</Wrapper>");

        using var metered = new MeteredHousePool();
        var owned = new List<PooledMemory>();
        var stopwatch = Stopwatch.StartNew();
        XmlNodeTable table = Parse(builder.ToString(), metered.Pool);
        bool isRead = XAdESTimeStamp.TryRead(table, table.DocumentElementIndex, metered.Pool, owned, out _, out XAdESReadError error);
        stopwatch.Stop();
        DisposeOwned(owned);
        table.Dispose();

        Assert.IsFalse(isRead, "An Include flood past the bound must be refused.");
        Assert.AreEqual(XAdESReadFailure.EntryCountLimitExceeded, error.Failure);
        Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer decoded before the refusal must be released.");
        Assert.IsLessThan(ResourceCaseCeiling, stopwatch.Elapsed, $"Took {stopwatch.Elapsed}, exceeding the loose ceiling {ResourceCaseCeiling}.");
    }
}
