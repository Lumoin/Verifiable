using System.Globalization;
using System.Text;
using BenchmarkDotNet.Attributes;
using Verifiable.Xml;

namespace Verifiable.Benchmarks.Xml;

/// <summary>
/// The document shape <see cref="XmlCanonicalizationBenchmarks"/> canonicalizes for one benchmark run.
/// </summary>
internal enum XmlCanonicalizationShape
{
    /// <summary>One element carrying forty thousand descending-named attributes.</summary>
    WideAttribute,

    /// <summary>A root with four thousand namespace declarations and two hundred prefixed children.</summary>
    WideNamespace,

    /// <summary>A root with sixty-four thousand siblings, each declaring and using a distinct prefix.</summary>
    SiblingSpread
}


/// <summary>
/// Throughput and allocation benchmarks for <see cref="XmlCanonicalization.TryCanonicalize"/> and
/// <see cref="XmlCanonicalization.TryCanonicalizeExclusive"/> over the wide-attribute, wide-namespace and
/// sibling-spread document shapes, and for parsing a declaration-heavy start-tag — the
/// cost-characterisation counterpart to <c>Verifiable.Tests.Xml.XmlCanonicalizationCostTests</c>, whose
/// unit tests keep only the canonical-output-shape and pooled-custody assertions.
/// </summary>
[MemoryDiagnoser]
internal class XmlCanonicalizationBenchmarks
{
    private const int WideAttributeCount = 40_000;

    private const int WideNamespaceDeclarationCount = 4_000;

    private const int WideNamespaceChildCount = 200;

    private const int ParseDeclarationCount = 32_000;

    private const int SiblingSpreadCount = 64_000;

    private byte[] document = null!;

    private byte[] declarationHeavyDocument = null!;


    /// <summary>The document shape this run's <see cref="WideDocumentCanonicalizesUnderTheChosenEntryPoint"/> canonicalizes.</summary>
    [ParamsAllValues]
    public XmlCanonicalizationShape Shape { get; set; }

    /// <summary>Whether <see cref="XmlCanonicalization.TryCanonicalizeExclusive"/> runs instead of <see cref="XmlCanonicalization.TryCanonicalize"/>.</summary>
    [Params(false, true)]
    public bool IsExclusive { get; set; }


    /// <summary>One element carrying <see cref="WideAttributeCount"/> attributes whose names descend lexicographically.</summary>
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


    /// <summary>A root carrying <see cref="WideNamespaceDeclarationCount"/> namespace declarations with <see cref="WideNamespaceChildCount"/> prefixed children.</summary>
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


    /// <summary>A root with <see cref="SiblingSpreadCount"/> sibling elements, each declaring and using a distinct prefix on itself.</summary>
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


    /// <summary>Builds the document for the current <see cref="Shape"/> and the declaration-heavy parse fixture.</summary>
    [GlobalSetup]
    public void Setup()
    {
        document = Shape switch
        {
            XmlCanonicalizationShape.WideAttribute => BuildWideAttributeDocument(),
            XmlCanonicalizationShape.WideNamespace => BuildWideNamespaceDocument(),
            XmlCanonicalizationShape.SiblingSpread => BuildSiblingSpreadDocument(),
            _ => throw new ArgumentOutOfRangeException(nameof(Shape), Shape, "Unknown canonicalization shape.")
        };

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
        declarationHeavyDocument = Encoding.UTF8.GetBytes(builder.ToString());
    }


    /// <summary>Measures parsing and canonicalizing <see cref="Shape"/> under <see cref="IsExclusive"/>'s entry point.</summary>
    [Benchmark]
    public void WideDocumentCanonicalizesUnderTheChosenEntryPoint()
    {
        XmlNodeTable.TryParse(document, BaseMemoryPool.Shared, out XmlNodeTable? table, out _);
        using(table)
        {
            if(table is null)
            {
                return;
            }

            XmlNodeSet nodeSet = XmlNodeSet.WholeDocument(table);
            PooledMemory? canonicalOctets;
            bool isCanonicalized = IsExclusive
                ? XmlCanonicalization.TryCanonicalizeExclusive(table, nodeSet, isWithComments: false, [], BaseMemoryPool.Shared, out canonicalOctets, out _)
                : XmlCanonicalization.TryCanonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10, BaseMemoryPool.Shared, out canonicalOctets, out _);
            using(canonicalOctets)
            {
            }
        }
    }


    /// <summary>Measures parsing one start-tag carrying <see cref="ParseDeclarationCount"/> namespace declarations and as many prefixed attributes.</summary>
    [Benchmark]
    public void DeclarationHeavyStartTagParses()
    {
        XmlNodeTable.TryParse(declarationHeavyDocument, BaseMemoryPool.Shared, out XmlNodeTable? table, out _);
        using(table)
        {
        }
    }
}
