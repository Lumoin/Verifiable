using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESRenewedDigestsV2.TryRead"/> against clause 5.5.3's <c>RenewedDigestsV2</c>
/// qualifying property of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
[TestClass]
internal sealed class XAdESRenewedDigestsV2Tests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string V141 = "http://uri.etsi.org/01903/v1.4.1#";

    private const string ExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

    private const string Sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";


    private static string RecomputedDigestValue(string newValue = "AQ==", string originalValue = "Ag==") => $"""
        <RecomputedDigestValue><NewSDODigestValue>{newValue}</NewSDODigestValue><OriginalRefDigest>{originalValue}</OriginalRefDigest></RecomputedDigestValue>
        """;


    private static string Document(string canonicalizationMethodElement, string digestMethodElement, string recomputedDigestValues) => $$"""
        <RenewedDigestsV2 xmlns="{{V141}}" xmlns:ds="{{DsNamespace}}">
          {{canonicalizationMethodElement}}
          {{digestMethodElement}}
          {{recomputedDigestValues}}
        </RenewedDigestsV2>
        """;


    private static string DefaultCanonicalizationMethod { get; } = $"""<ds:CanonicalizationMethod Algorithm="{ExclusiveC14N}"/>""";

    private static string DefaultDigestMethod { get; } = $"""<ds:DigestMethod Algorithm="{Sha256}"/>""";


    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves the fixed sequence — <c>ds:CanonicalizationMethod</c>, <c>ds:DigestMethod</c>, one-or-more
    /// <c>RecomputedDigestValue</c> — reads, each <c>RecomputedDigestValue</c>'s two base64 fields decode, and
    /// custody balances to zero on disposal.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3.
    /// </summary>
    [TestMethod]
    public void WellFormedInstanceReadsAndCustodyBalances()
    {
        string document = Document(DefaultCanonicalizationMethod, DefaultDigestMethod, RecomputedDigestValue());
        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESRenewedDigestsV2.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESRenewedDigestsV2? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.AreSequenceEqual(Encoding.UTF8.GetBytes(ExclusiveC14N), value!.CanonicalizationMethod.Algorithm.ToArray());
            Assert.AreSequenceEqual(Encoding.UTF8.GetBytes(Sha256), value.DigestMethodAlgorithm.ToArray());
            Assert.HasCount(1, value.RecomputedDigestValues);

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "Every decoded field must be released on Dispose.");
        }
    }


    /// <summary>
    /// Proves multiple <c>RecomputedDigestValue</c> entries — the schema's own
    /// <c>maxOccurs="unbounded"</c> — all read, in document order.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3.
    /// </summary>
    [TestMethod]
    public void MultipleRecomputedDigestValuesRead()
    {
        string document = Document(DefaultCanonicalizationMethod, DefaultDigestMethod, RecomputedDigestValue("AQ==", "Ag==") + RecomputedDigestValue("Aw==", "BA=="));
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESRenewedDigestsV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESRenewedDigestsV2? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.HasCount(2, value!.RecomputedDigestValues);
        }
    }


    /// <summary>
    /// Proves <c>ds:CanonicalizationMethod</c> is MANDATORY here — unlike every optional
    /// <c>ds:CanonicalizationMethod</c> elsewhere in this leg (<see cref="XAdESTimeStamp.HasCanonicalizationMethod"/>):
    /// its absence refuses.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3.
    /// </summary>
    [TestMethod]
    public void AbsentCanonicalizationMethodIsRefused()
    {
        string document = Document(string.Empty, DefaultDigestMethod, RecomputedDigestValue());
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESRenewedDigestsV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An absent ds:CanonicalizationMethod must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves <c>ds:DigestMethod</c>'s own absence refuses.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3.
    /// </summary>
    [TestMethod]
    public void AbsentDigestMethodIsRefused()
    {
        string document = Document(DefaultCanonicalizationMethod, string.Empty, RecomputedDigestValue());
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESRenewedDigestsV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An absent ds:DigestMethod must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves <c>ds:DigestMethod</c>'s own mandatory <c>Algorithm</c> attribute must be present.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3.
    /// </summary>
    [TestMethod]
    public void AbsentDigestMethodAlgorithmIsRefused()
    {
        string document = Document(DefaultCanonicalizationMethod, "<ds:DigestMethod/>", RecomputedDigestValue());
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESRenewedDigestsV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An absent ds:DigestMethod Algorithm must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredAttribute, error.Failure);
    }


    /// <summary>
    /// Proves the schema's <c>maxOccurs="unbounded"</c> child carries a default <c>minOccurs="1"</c>: zero
    /// <c>RecomputedDigestValue</c> entries refuses.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3.
    /// </summary>
    [TestMethod]
    public void ZeroRecomputedDigestValuesIsRefused()
    {
        string document = Document(DefaultCanonicalizationMethod, DefaultDigestMethod, string.Empty);
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESRenewedDigestsV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "Zero RecomputedDigestValue entries must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves this reader's own identity check: an element that is not the v1.4.1-namespace
    /// <c>RenewedDigestsV2</c> is refused rather than accepted.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3.
    /// </summary>
    [TestMethod]
    public void WrongElementNameIsRefused()
    {
        string document = $$"""<NotRenewedDigestsV2 xmlns="{{V141}}"/>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESRenewedDigestsV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A differently-named element must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves the v1.3.2-namespace form of this local name — never declared by the schema — is refused too,
    /// since this reader's identity check requires the v1.4.1 namespace exactly.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3.
    /// </summary>
    [TestMethod]
    public void V132NamespacedFormIsRefused()
    {
        string document = $$"""<RenewedDigestsV2 xmlns="{{V132}}"/>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESRenewedDigestsV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "The v1.3.2-namespace element must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves custody is balanced even on a mid-read refusal: the first <c>RecomputedDigestValue</c>'s two
    /// fields decode before the second entry's malformed base64 refuses, and every buffer accumulated so far is
    /// released by the outer <c>try</c>/<c>finally</c>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnAMidReadRefusal()
    {
        string malformedSecondEntry = """<RecomputedDigestValue><NewSDODigestValue>not-base64!!</NewSDODigestValue><OriginalRefDigest>Ag==</OriginalRefDigest></RecomputedDigestValue>""";
        string document = Document(DefaultCanonicalizationMethod, DefaultDigestMethod, RecomputedDigestValue() + malformedSecondEntry);
        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESRenewedDigestsV2.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESRenewedDigestsV2? value, out XAdESReadError error);
            using(value)
            {
                Assert.IsFalse(isRead, "The malformed second entry must be refused.");
                Assert.AreEqual(XAdESReadFailure.InvalidBase64Content, error.Failure);
                Assert.IsNull(value);
                Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer decoded before the refusal must be released.");
            }
        }
    }
}
