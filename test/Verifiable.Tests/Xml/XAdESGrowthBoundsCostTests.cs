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
/// cref="XAdESReadFailure.EntryCountLimitExceeded"/> — proving the reader's own work is bounded by the CONSTANT, not by the
/// attacker's chosen count. Every table is parsed on a plain pool so a reader-only <see cref="MeteredHousePool"/> observes only the
/// reader's own rents: each case that reads through a pooled API asserts an exact per-entry rent count (a real decode precedes
/// the bound check), or exactly zero rents, and also asserts the balance — nothing decoded before the refusal is leaked. The
/// zero-rent cases split two ways: <see cref="RevocationValuesEncapsulatedFloodIsRefusedBeforeAnyEntryDecodes"/>'s own reader
/// decodes real pooled content once past the bound, so its zero rents prove the count check runs BEFORE any per-entry decode;
/// <see cref="CertificateValuesFloodIsRefusedWithNoPooledRent"/>, <see cref="RevocationValuesUnmodeledFloodIsRefusedWithNoPooledRent"/>
/// and <see cref="IncludeFloodIsRefusedWithNoPooledRent"/> instead prove the entry itself carries no pooled content on any path, so
/// the metered pool has nothing to observe regardless of flood size. One case
/// (<see cref="UnsignedSignaturePropertiesFloodIsRefused"/>) reads through a pool-free API that takes no
/// <see cref="BaseMemoryPool"/> at all, so it asserts only the refusal code; the throughput characterisation of
/// this shape lives in <c>Verifiable.Benchmarks</c>'s <c>XAdESGrowthBoundsBenchmarks</c>. Every
/// fixture is built programmatically (no corpora); every case that touches the pool is proven to return its buffers via
/// <see cref="MeteredHousePool"/> accounting. Each case's owned carrier (<c>owned</c> or <c>value</c>) is disposed
/// explicitly, via <see cref="DisposeOwned(List{PooledMemory})"/> or a direct <c>value?.Dispose()</c> call, rather than
/// a <see langword="using"/> declaration, because the <see cref="MeteredHousePool.OutstandingCount"/> assertion right
/// after it must see the carrier already released.
/// </summary>
[TestClass]
internal sealed class XAdESGrowthBoundsCostTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";


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
    /// <see cref="XAdESReadFailure.EntryCountLimitExceeded"/>, over clause 4.3.6's (XA-4.3.6-3) own unbounded <c>xsd:choice
    /// maxOccurs="unbounded"</c> content model of <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319
    /// 132-1 V1.3.1</see>. Asserts only the refusal code: <c>XAdESUnsignedSignatureProperties.TryRead</c> takes no pool parameter at all — the
    /// foreign-namespace flood is a pure structural walk with nothing pooled to observe. The throughput characterisation of this walk lives in
    /// <c>Verifiable.Benchmarks</c>'s <c>XAdESGrowthBoundsBenchmarks.UnsignedSignaturePropertiesFloodIsRefused</c>.
    /// </summary>
    [TestMethod]
    public void UnsignedSignaturePropertiesFloodIsRefused()
    {
        int count = XAdESUnsignedSignatureProperties.MaximumPropertyCount + 1;
        var builder = new StringBuilder(count * 24);
        builder.Append($"""<UnsignedSignatureProperties xmlns="{V132}" xmlns:f="urn:filler">""");
        for(int i = 0; i < count; ++i)
        {
            builder.Append("<f:Filler/>");
        }

        builder.Append("</UnsignedSignatureProperties>");

        using XmlNodeTable table = Parse(builder.ToString(), BaseMemoryPool.Shared);
        bool isRead = XAdESUnsignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "A flood past the bound must be refused.");
        Assert.AreEqual(XAdESReadFailure.EntryCountLimitExceeded, error.Failure);
    }


    /// <summary>
    /// Proves <see cref="XAdESSigningCertificateV2.MaximumCertIdListEntryCount"/>, shared by
    /// <c>SigningCertificateV2</c>/<c>CompleteCertificateRefsV2</c>/<c>AttributeCertificateRefsV2</c>: a flood of <c>Cert</c> entries one past the bound is refused, with
    /// every buffer decoded before the refusal released, per clause 5.2.2's own unbounded <c>CertIDListV2Type</c> content model of <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>. Counted, not timed: each
    /// <c>Cert</c> is fully decoded before the count check trips (<c>certs.Add</c> precedes the bound comparison), and each decode is exactly three pool rents —
    /// <see cref="XmlBase64Content.TryDecode"/>'s <c>significant</c> scratch list (sized to the four-character <c>"AQ=="</c> content), its <c>output</c> scratch list
    /// (one decoded octet), and <see cref="PooledMemory.FromBytes"/>'s own copy (the same one octet) — so a reader-only <see cref="MeteredHousePool"/> observes exactly
    /// <c>3 &#215; count</c> rents, deterministically, independent of machine speed.
    /// </summary>
    [TestMethod]
    public void CertIdListV2FloodIsRefusedAfterExactlyThreeRentsPerEntry()
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

        using XmlNodeTable table = Parse(builder.ToString(), BaseMemoryPool.Shared);
        using var metered = new MeteredHousePool();
        var owned = new List<PooledMemory>();
        bool isRead = XAdESSigningCertificateV2.TryReadCertIdListV2(table, table.DocumentElementIndex, metered.Pool, owned, out _, out XAdESReadError error);
        DisposeOwned(owned);

        Assert.IsFalse(isRead, "A Cert flood past the bound must be refused.");
        Assert.AreEqual(XAdESReadFailure.EntryCountLimitExceeded, error.Failure);
        Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer decoded before the refusal must be released.");
        Assert.AreEqual(3L * count, metered.RentedCount, "Each Cert decodes its digest in exactly three pool rents; the reader must process exactly count entries before refusing, not fewer or more.");
    }


    /// <summary>
    /// Proves <see cref="XAdESCompleteRevocationRefs.MaximumRevocationRefEntryCount"/>: a flood of <c>CRLRef</c> entries one past the bound, under
    /// <c>CompleteRevocationRefs</c>'s own <c>CRLRefs</c> list, is refused, per Annex A.1.2's own unbounded content model of <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>. Counted, not timed: each
    /// <c>CRLRef</c> decodes its <c>DigestAlgAndValue</c> through the same three-rent shape
    /// <see cref="CertIdListV2FloodIsRefusedAfterExactlyThreeRentsPerEntry"/>'s doc comment derives, before the count check trips — a reader-only
    /// <see cref="MeteredHousePool"/> observes exactly <c>3 &#215; count</c> rents.
    /// </summary>
    [TestMethod]
    public void CrlRefFloodIsRefusedAfterExactlyThreeRentsPerEntry()
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

        using XmlNodeTable table = Parse(builder.ToString(), BaseMemoryPool.Shared);
        using var metered = new MeteredHousePool();
        bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, metered.Pool, out XAdESCompleteRevocationRefs? value, out XAdESReadError error);
        value?.Dispose();

        Assert.IsFalse(isRead, "A CRLRef flood past the bound must be refused.");
        Assert.AreEqual(XAdESReadFailure.EntryCountLimitExceeded, error.Failure);
        Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer decoded before the refusal must be released.");
        Assert.AreEqual(3L * count, metered.RentedCount, "Each CRLRef decodes its digest in exactly three pool rents; the reader must process exactly count entries before refusing.");
    }


    /// <summary>
    /// Proves <see cref="XAdESCertificateValues.MaximumEntryCount"/>: a flood of <c>OtherCertificate</c> entries one past the bound is refused, per clause 5.4.2's own
    /// unbounded content model of <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1
    /// V1.3.1</see>. Counted, not timed: an <c>OtherCertificate</c> entry reads through <c>XAdESUnmodeledContent.Read</c>, which takes no pool at all — a reader-only
    /// <see cref="MeteredHousePool"/> observes exactly zero rents regardless of the flood size, proving the per-entry cost carries no pooled allocation to bound in the
    /// first place.
    /// </summary>
    [TestMethod]
    public void CertificateValuesFloodIsRefusedWithNoPooledRent()
    {
        int count = XAdESCertificateValues.MaximumEntryCount + 1;
        var builder = new StringBuilder(count * 24);
        builder.Append($"""<CertificateValues xmlns="{V132}">""");
        for(int i = 0; i < count; ++i)
        {
            builder.Append("<OtherCertificate/>");
        }

        builder.Append("</CertificateValues>");

        using XmlNodeTable table = Parse(builder.ToString(), BaseMemoryPool.Shared);
        using var metered = new MeteredHousePool();
        bool isRead = XAdESCertificateValues.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESCertificateValues? value, out XAdESReadError error);
        value?.Dispose();

        Assert.IsFalse(isRead, "An OtherCertificate flood past the bound must be refused.");
        Assert.AreEqual(XAdESReadFailure.EntryCountLimitExceeded, error.Failure);
        Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer decoded before the refusal must be released.");
        Assert.AreEqual(0L, metered.RentedCount, "OtherCertificate entries carry no pooled content; the reader must rent nothing regardless of the flood size.");
    }


    /// <summary>
    /// Proves <see cref="XAdESRevocationValues.MaximumEncapsulatedEntryCount"/>: a flood of <c>EncapsulatedCRLValue</c> entries one past the bound, under
    /// <c>RevocationValues</c>'s own <c>CRLValues</c> list, is refused, per clause 5.4.3's own unbounded content model of <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>. Counted, not timed: the
    /// reader collects every <c>CRLValues</c> child into a plain list FIRST and compares its count against the bound BEFORE decoding a single entry — a reader-only
    /// <see cref="MeteredHousePool"/> observes exactly zero rents, proving the refusal is structural, not a decode-then-discard walk of the flood.
    /// </summary>
    [TestMethod]
    public void RevocationValuesEncapsulatedFloodIsRefusedBeforeAnyEntryDecodes()
    {
        int count = XAdESRevocationValues.MaximumEncapsulatedEntryCount + 1;
        var builder = new StringBuilder(count * 40);
        builder.Append($"""<RevocationValues xmlns="{V132}"><CRLValues>""");
        for(int i = 0; i < count; ++i)
        {
            builder.Append("<EncapsulatedCRLValue>AQ==</EncapsulatedCRLValue>");
        }

        builder.Append("</CRLValues></RevocationValues>");

        using XmlNodeTable table = Parse(builder.ToString(), BaseMemoryPool.Shared);
        using var metered = new MeteredHousePool();
        bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESRevocationValues? value, out XAdESReadError error);
        value?.Dispose();

        Assert.IsFalse(isRead, "An EncapsulatedCRLValue flood past the bound must be refused.");
        Assert.AreEqual(XAdESReadFailure.EntryCountLimitExceeded, error.Failure);
        Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer decoded before the refusal must be released.");
        Assert.AreEqual(0L, metered.RentedCount, "The bound is checked before any entry is decoded; the reader must rent nothing regardless of the flood size.");
    }


    /// <summary>
    /// Proves <see cref="XAdESRevocationValues.MaximumUnmodeledEntryCount"/>, shared by <c>RevocationValues</c>'s own <c>OtherValues</c> and <see
    /// cref="XAdESCompleteRevocationRefs"/>'s <c>OtherRefs</c>: a flood of <c>OtherValue</c> entries one past the bound is refused, per clause 5.4.3's own unbounded
    /// content model of <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>.
    /// Counted, not timed: <c>TryReadNonEmptyUnmodeledList</c> takes no pool parameter at all — an <c>OtherValue</c> entry carries no pooled content on any path, so a
    /// reader-only <see cref="MeteredHousePool"/> observes exactly zero rents regardless of the flood size.
    /// </summary>
    [TestMethod]
    public void RevocationValuesUnmodeledFloodIsRefusedWithNoPooledRent()
    {
        int count = XAdESRevocationValues.MaximumUnmodeledEntryCount + 1;
        var builder = new StringBuilder(count * 24);
        builder.Append($"""<RevocationValues xmlns="{V132}"><OtherValues>""");
        for(int i = 0; i < count; ++i)
        {
            builder.Append("<OtherValue/>");
        }

        builder.Append("</OtherValues></RevocationValues>");

        using XmlNodeTable table = Parse(builder.ToString(), BaseMemoryPool.Shared);
        using var metered = new MeteredHousePool();
        bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESRevocationValues? value, out XAdESReadError error);
        value?.Dispose();

        Assert.IsFalse(isRead, "An OtherValue flood past the bound must be refused.");
        Assert.AreEqual(XAdESReadFailure.EntryCountLimitExceeded, error.Failure);
        Assert.AreEqual(0L, metered.RentedCount, "OtherValue entries carry no pooled content; the reader must rent nothing regardless of the flood size.");
    }


    /// <summary>
    /// Proves <see cref="XAdESTimeStamp.MaximumIncludeCount"/>: a flood of <c>Include</c> children one past the bound is refused — dangling <c>URI</c> targets are
    /// irrelevant, since <see cref="XAdESTimeStamp.TryRead"/> is a structural read that never dereferences them. Anchored to clause 5.1.4.4.2.1's (XA-5.1.4.4.1-2) own
    /// unbounded content model of <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1
    /// V1.3.1</see>. Counted, not timed: <c>XAdESInclude.TryRead</c> takes no pool at all — an <c>Include</c> entry (a bare <c>URI</c> attribute) carries no pooled
    /// content, so a reader-only <see cref="MeteredHousePool"/> observes exactly zero rents regardless of the flood size.
    /// </summary>
    [TestMethod]
    public void IncludeFloodIsRefusedWithNoPooledRent()
    {
        int count = XAdESTimeStamp.MaximumIncludeCount + 1;
        var builder = new StringBuilder(count * 24);
        builder.Append($"""<Wrapper xmlns="{V132}">""");
        for(int i = 0; i < count; ++i)
        {
            builder.Append("""<Include URI="#nonexistent"/>""");
        }

        builder.Append("</Wrapper>");

        using XmlNodeTable table = Parse(builder.ToString(), BaseMemoryPool.Shared);
        using var metered = new MeteredHousePool();
        var owned = new List<PooledMemory>();
        bool isRead = XAdESTimeStamp.TryRead(table, table.DocumentElementIndex, metered.Pool, owned, out _, out XAdESReadError error);
        DisposeOwned(owned);

        Assert.IsFalse(isRead, "An Include flood past the bound must be refused.");
        Assert.AreEqual(XAdESReadFailure.EntryCountLimitExceeded, error.Failure);
        Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer decoded before the refusal must be released.");
        Assert.AreEqual(0L, metered.RentedCount, "Include entries carry no pooled content; the reader must rent nothing regardless of the flood size.");
    }
}
