using System.Text;
using BenchmarkDotNet.Attributes;
using Verifiable.Xml;

namespace Verifiable.Benchmarks.Xml;

/// <summary>
/// Throughput benchmark for the pool-free foreign-namespace-flood walk in
/// <see cref="XAdESUnsignedSignatureProperties.TryRead"/> — the cost-characterisation counterpart to
/// <c>Verifiable.Tests.Xml.XAdESGrowthBoundsCostTests</c>, whose unit test keeps only the refusal-code
/// assertion.
/// </summary>
[MemoryDiagnoser]
internal class XAdESGrowthBoundsBenchmarks
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private byte[] document = null!;


    /// <summary>Builds a foreign-namespace-child flood one past <see cref="XAdESUnsignedSignatureProperties.MaximumPropertyCount"/>.</summary>
    [GlobalSetup]
    public void Setup()
    {
        int count = XAdESUnsignedSignatureProperties.MaximumPropertyCount + 1;
        var builder = new StringBuilder(count * 24);
        builder.Append($"""<UnsignedSignatureProperties xmlns="{V132}" xmlns:f="urn:filler">""");
        for(int i = 0; i < count; ++i)
        {
            builder.Append("<f:Filler/>");
        }

        builder.Append("</UnsignedSignatureProperties>");
        document = Encoding.UTF8.GetBytes(builder.ToString());
    }


    /// <summary>Measures parsing the flood document and walking it to refusal past the bound.</summary>
    [Benchmark]
    public void UnsignedSignaturePropertiesFloodIsRefused()
    {
        XmlNodeTable.TryParse(document, BaseMemoryPool.Shared, out XmlNodeTable? table, out _);
        using(table)
        {
            if(table is not null)
            {
                _ = XAdESUnsignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out _, out _);
            }
        }
    }
}
