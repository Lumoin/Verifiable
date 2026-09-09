using System.Globalization;
using System.Text;
using BenchmarkDotNet.Attributes;
using Verifiable.Xml;

namespace Verifiable.Benchmarks.Xml;

/// <summary>
/// Throughput and allocation benchmarks for <see cref="XmlNodeTable.TryParse"/> over a single oversized
/// attribute value, a single oversized element name, and an adversarial attribute count with a trailing
/// duplicate — the cost-characterisation counterpart to
/// <c>Verifiable.Tests.Xml.XmlReaderAdversarialLimitsTests</c>, whose unit tests keep only the
/// parsed-shape, refusal-code and pooled-custody assertions.
/// </summary>
[MemoryDiagnoser]
internal class XmlReaderAdversarialLimitsBenchmarks
{
    private const int ValueLength = 8 * 1024 * 1024;

    private const int NameLength = 8 * 1024 * 1024;

    private const int AttributeCount = 20_000;

    private byte[] eightMebibyteAttributeValueDocument = null!;

    private byte[] eightMebibyteElementNameDocument = null!;

    private byte[] twentyThousandAttributesDocument = null!;


    /// <summary>Builds every oversized and adversarial-count fixture this class's benchmarks measure, once per run.</summary>
    [GlobalSetup]
    public void Setup()
    {
        byte[] prefix = "<a x=\""u8.ToArray();
        byte[] suffix = "\"/>"u8.ToArray();
        eightMebibyteAttributeValueDocument = new byte[prefix.Length + ValueLength + suffix.Length];
        prefix.CopyTo(eightMebibyteAttributeValueDocument, 0);
        eightMebibyteAttributeValueDocument.AsSpan(prefix.Length, ValueLength).Fill((byte)'v');
        suffix.CopyTo(eightMebibyteAttributeValueDocument, prefix.Length + ValueLength);

        eightMebibyteElementNameDocument = new byte[1 + NameLength + 2];
        eightMebibyteElementNameDocument[0] = (byte)'<';
        eightMebibyteElementNameDocument.AsSpan(1, NameLength).Fill((byte)'n');
        eightMebibyteElementNameDocument[1 + NameLength] = (byte)'/';
        eightMebibyteElementNameDocument[2 + NameLength] = (byte)'>';

        var builder = new StringBuilder(AttributeCount * 16);
        builder.Append("<a");
        for(int i = 0; i < AttributeCount; ++i)
        {
            builder.Append(CultureInfo.InvariantCulture, $" a{i}=\"v\"");
        }

        builder.Append(" a0=\"duplicate\"/>");
        twentyThousandAttributesDocument = Encoding.UTF8.GetBytes(builder.ToString());
    }


    /// <summary>Measures parsing a single eight-mebibyte attribute value.</summary>
    [Benchmark]
    public void EightMebibyteAttributeValueParses()
    {
        XmlNodeTable.TryParse(eightMebibyteAttributeValueDocument, BaseMemoryPool.Shared, out XmlNodeTable? table, out _);
        using(table)
        {
        }
    }


    /// <summary>Measures parsing a single eight-mebibyte element name.</summary>
    [Benchmark]
    public void EightMebibyteElementNameParses()
    {
        XmlNodeTable.TryParse(eightMebibyteElementNameDocument, BaseMemoryPool.Shared, out XmlNodeTable? table, out _);
        using(table)
        {
        }
    }


    /// <summary>Measures duplicate-attribute detection over twenty thousand attributes whose duplicate sits last.</summary>
    [Benchmark]
    public void TwentyThousandAttributesWithTrailingDuplicateAreRefused()
    {
        XmlNodeTable.TryParse(twentyThousandAttributesDocument, BaseMemoryPool.Shared, out XmlNodeTable? table, out _);
        using(table)
        {
        }
    }
}
