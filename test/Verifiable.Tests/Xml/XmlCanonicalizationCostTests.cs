using System.Globalization;
using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Canonicalization-side correctness proofs over <see cref="XmlCanonicalization.TryCanonicalize"/> and
/// <see cref="XmlCanonicalization.TryCanonicalizeExclusive"/>: a wide-attribute document, a
/// wide-namespace document and a sibling-spread document canonicalize to non-empty correct output under
/// both entry points, and a declaration-heavy start-tag parses to the correct shape, with every buffer
/// rented from the caller's pool and returned on disposal, observed through <see cref="MeteredHousePool"/>
/// accounting. The "no quadratic behavior" throughput obligation for these same shapes lives in
/// <c>Verifiable.Benchmarks</c>'s <c>XmlCanonicalizationBenchmarks</c>, a unit test proving cost by
/// counting rather than by timing itself against a wall-clock ceiling.
/// </summary>
[TestClass]
internal sealed class XmlCanonicalizationCostTests
{
    /// <summary>How many attributes the wide-attribute document carries on its one element.</summary>
    private const int WideAttributeCount = 40_000;

    /// <summary>How many namespace declarations the wide-namespace document carries on its root.</summary>
    private const int WideNamespaceDeclarationCount = 4_000;

    /// <summary>How many child elements the wide-namespace document places under its root.</summary>
    private const int WideNamespaceChildCount = 200;

    /// <summary>How many namespace declarations, each with a prefixed attribute, the parse case carries on one start-tag.</summary>
    private const int ParseDeclarationCount = 32_000;

    /// <summary>How many sibling elements, each declaring and using a distinct prefix, the sibling-spread document carries.</summary>
    private const int SiblingSpreadCount = 64_000;


    /// <summary>
    /// One element carrying <see cref="WideAttributeCount"/> attributes whose names descend
    /// lexicographically, the order adverse to the attribute-axis sort of Canonical XML section 2.2.
    /// </summary>
    /// <returns>The document octets.</returns>
    private static byte[] BuildWideAttributeDocument()
    {
        var builder = new StringBuilder(WideAttributeCount * 16);
        builder.Append("<doc");
        for(int i = WideAttributeCount - 1; i >= 0; --i)
        {
            builder.Append(CultureInfo.InvariantCulture, $" a{i:D5}=\"v{i}\"");
        }

        builder.Append("/>");

        return Encoding.UTF8.GetBytes(builder.ToString());
    }


    /// <summary>
    /// A root carrying <see cref="WideNamespaceDeclarationCount"/> namespace declarations with
    /// <see cref="WideNamespaceChildCount"/> prefixed children, so every child renders its namespace axis
    /// against the full in-scope set: the inclusive families suppress each binding against the rendered
    /// parent and the exclusive family decides visible utilization of the child's own prefix.
    /// </summary>
    /// <returns>The document octets.</returns>
    private static byte[] BuildWideNamespaceDocument()
    {
        var builder = new StringBuilder(WideNamespaceDeclarationCount * 40);
        builder.Append("<root");
        for(int i = 0; i < WideNamespaceDeclarationCount; ++i)
        {
            builder.Append(CultureInfo.InvariantCulture, $" xmlns:p{i:D4}=\"urn:cost:ns:{i}\"");
        }

        builder.Append('>');
        for(int i = 0; i < WideNamespaceChildCount; ++i)
        {
            builder.Append(CultureInfo.InvariantCulture, $"<p{i % WideNamespaceDeclarationCount:D4}:c/>");
        }

        builder.Append("</root>");

        return Encoding.UTF8.GetBytes(builder.ToString());
    }


    /// <summary>
    /// A root with <see cref="SiblingSpreadCount"/> sibling elements, each declaring a distinct prefix on
    /// itself and using it in its own name, so every prefix goes out of scope when the walk ascends past
    /// its declaring sibling: an element's namespace axis holds at most one binding beyond the root's,
    /// and only retiring out-of-scope prefix slots keeps the per-element axis work independent of how
    /// many prefixes earlier siblings declared.
    /// </summary>
    /// <returns>The document octets.</returns>
    private static byte[] BuildSiblingSpreadDocument()
    {
        var builder = new StringBuilder(SiblingSpreadCount * 44);
        builder.Append("<root>");
        for(int i = 0; i < SiblingSpreadCount; ++i)
        {
            builder.Append(CultureInfo.InvariantCulture, $"<p{i:D5}:c xmlns:p{i:D5}=\"urn:cost:sibling:{i}\"/>");
        }

        builder.Append("</root>");

        return Encoding.UTF8.GetBytes(builder.ToString());
    }


    /// <summary>
    /// Parses a document and canonicalizes its whole-document node-set through the given entry point,
    /// asserting success, non-empty canonical octets, and that every pooled buffer returns after disposal.
    /// </summary>
    /// <param name="document">The document octets.</param>
    /// <param name="isExclusive">Whether <see cref="XmlCanonicalization.TryCanonicalizeExclusive"/> runs
    /// instead of <see cref="XmlCanonicalization.TryCanonicalize"/>.</param>
    private static void AssertCanonicalizesWithBalancedPool(byte[] document, bool isExclusive)
    {
        using var metered = new MeteredHousePool();
        bool isParsed = XmlNodeTable.TryParse(document, metered.Pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The cost document must parse but was refused with {readError.Failure} at {readError.ByteOffset}.");

        XmlNodeSet nodeSet = XmlNodeSet.WholeDocument(table!);
        PooledMemory? canonicalOctets;
        XmlCanonicalizationError error;
        bool isCanonicalized = isExclusive
            ? XmlCanonicalization.TryCanonicalizeExclusive(table!, nodeSet, isWithComments: false, [], metered.Pool, out canonicalOctets, out error)
            : XmlCanonicalization.TryCanonicalize(table!, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10, metered.Pool, out canonicalOctets, out error);

        Assert.IsTrue(isCanonicalized, $"The cost document must canonicalize but was refused with {error.Failure}.");
        Assert.IsGreaterThan(0, canonicalOctets!.AsReadOnlySpan().Length, "The canonical form must be non-empty.");
        canonicalOctets.Dispose();
        table!.Dispose();
        Assert.IsGreaterThan(0L, metered.RentedCount, "The work must rent from the supplied pool.");
        Assert.AreEqual(0L, metered.OutstandingCount, "Every pooled buffer must be returned after disposal.");
    }


    /// <summary>
    /// Proves the attribute axis under <see cref="XmlCanonicalization.TryCanonicalize"/>: forty thousand
    /// descending-named attributes on one element sort into the (namespace URI, local name) order of
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.2,
    /// with the pool balanced after disposal. The no-quadratic-behavior throughput obligation for this
    /// shape lives in <c>Verifiable.Benchmarks</c>'s <c>XmlCanonicalizationBenchmarks</c>.
    /// </summary>
    [TestMethod]
    public void WideAttributeDocumentCanonicalizesWithABalancedPool()
    {
        AssertCanonicalizesWithBalancedPool(BuildWideAttributeDocument(), isExclusive: false);
    }


    /// <summary>
    /// Proves the attribute axis under <see cref="XmlCanonicalization.TryCanonicalizeExclusive"/>: forty
    /// thousand descending-named attributes on one element sort into the (namespace URI, local name)
    /// order of <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML
    /// Canonicalization 1.0</see> section 3, with the pool balanced after disposal. The
    /// no-quadratic-behavior throughput obligation for this shape lives in
    /// <c>Verifiable.Benchmarks</c>'s <c>XmlCanonicalizationBenchmarks</c>.
    /// </summary>
    [TestMethod]
    public void WideAttributeDocumentCanonicalizesExclusivelyWithABalancedPool()
    {
        AssertCanonicalizesWithBalancedPool(BuildWideAttributeDocument(), isExclusive: true);
    }


    /// <summary>
    /// Proves the namespace axis under <see cref="XmlCanonicalization.TryCanonicalize"/>: a root with
    /// four thousand namespace declarations and two hundred prefixed children renders every child's axis
    /// with the superfluous-declaration suppression of
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.3 —
    /// the in-scope axis is carried down the walk, not re-derived per element — with the pool balanced
    /// after disposal. The no-quadratic-behavior throughput obligation for this shape lives in
    /// <c>Verifiable.Benchmarks</c>'s <c>XmlCanonicalizationBenchmarks</c>.
    /// </summary>
    [TestMethod]
    public void WideNamespaceDocumentCanonicalizesWithABalancedPool()
    {
        AssertCanonicalizesWithBalancedPool(BuildWideNamespaceDocument(), isExclusive: false);
    }


    /// <summary>
    /// Proves the namespace axis under <see cref="XmlCanonicalization.TryCanonicalizeExclusive"/>: a root
    /// with four thousand namespace declarations and two hundred prefixed children decides the
    /// visibly-utilizes conditions of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 3 for every binding of every child, with the pool balanced after disposal. The
    /// no-quadratic-behavior throughput obligation for this shape lives in
    /// <c>Verifiable.Benchmarks</c>'s <c>XmlCanonicalizationBenchmarks</c>.
    /// </summary>
    [TestMethod]
    public void WideNamespaceDocumentCanonicalizesExclusivelyWithABalancedPool()
    {
        AssertCanonicalizesWithBalancedPool(BuildWideNamespaceDocument(), isExclusive: true);
    }


    /// <summary>
    /// Proves the namespace axis over the sibling-spread shape under
    /// <see cref="XmlCanonicalization.TryCanonicalize"/> and
    /// <see cref="XmlCanonicalization.TryCanonicalizeExclusive"/>: sixty-four thousand siblings, each
    /// declaring and using a distinct prefix, render the namespace axes of
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.3
    /// and <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML
    /// Canonicalization 1.0</see> section 3 — a prefix slot retires when the walk ascends past its
    /// declaring element, so an element's axis iteration covers only the prefixes in scope at that
    /// element, never every prefix declared earlier in the document — with the pool balanced after
    /// disposal. The no-quadratic-behavior throughput obligation for this shape lives in
    /// <c>Verifiable.Benchmarks</c>'s <c>XmlCanonicalizationBenchmarks</c>.
    /// </summary>
    [TestMethod]
    public void SiblingSpreadDocumentCanonicalizesWithABalancedPoolUnderBothEntryPoints()
    {
        byte[] document = BuildSiblingSpreadDocument();

        AssertCanonicalizesWithBalancedPool(document, isExclusive: false);
        AssertCanonicalizesWithBalancedPool(document, isExclusive: true);
    }


    /// <summary>
    /// Proves parsing at the parse surface: one start-tag carrying thirty-two thousand namespace
    /// declarations and thirty-two thousand prefixed attributes resolves every name against the in-scope
    /// declarations per <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML
    /// 1.0 (Third Edition)</see> section 5 — prefix resolution walks a hash chain, not the whole scope
    /// stack — with the pool balanced after disposal. The no-quadratic-behavior throughput obligation for
    /// this shape lives in <c>Verifiable.Benchmarks</c>'s
    /// <c>XmlCanonicalizationBenchmarks.DeclarationHeavyStartTagParses</c>.
    /// </summary>
    [TestMethod]
    public void DeclarationHeavyStartTagParses()
    {
        var builder = new StringBuilder(ParseDeclarationCount * 48);
        builder.Append("<root");
        for(int i = 0; i < ParseDeclarationCount; ++i)
        {
            builder.Append(CultureInfo.InvariantCulture, $" xmlns:p{i:D5}=\"urn:cost:parse:{i}\"");
        }

        for(int i = 0; i < ParseDeclarationCount; ++i)
        {
            builder.Append(CultureInfo.InvariantCulture, $" p{i:D5}:a=\"v\"");
        }

        builder.Append("/>");
        byte[] document = Encoding.UTF8.GetBytes(builder.ToString());

        using var metered = new MeteredHousePool();
        bool isParsed = XmlNodeTable.TryParse(document, metered.Pool, out XmlNodeTable? table, out XmlReadError error);

        Assert.IsTrue(isParsed, $"The declaration-heavy document must parse but was refused with {error.Failure} at {error.ByteOffset}.");
        Assert.AreEqual(ParseDeclarationCount, table!.NamespaceDeclarationCountOf(table.DocumentElementIndex));
        Assert.AreEqual(ParseDeclarationCount, table.AttributeCountOf(table.DocumentElementIndex));
        Assert.IsGreaterThan(0L, metered.RentedCount, "Parsing must rent from the supplied pool.");
        table.Dispose();
        Assert.AreEqual(0L, metered.OutstandingCount, "Every pooled buffer must be returned after disposal.");
    }
}
