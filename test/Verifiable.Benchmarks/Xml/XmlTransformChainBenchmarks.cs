using System.Globalization;
using System.Text;
using BenchmarkDotNet.Attributes;
using Verifiable.Xml;

namespace Verifiable.Benchmarks.Xml;

/// <summary>
/// Throughput and allocation benchmarks for the reference-processing/transform-chain engine over
/// megabyte-scale base64 and canonicalization content, and over a wide same-document reference list —
/// the cost-characterisation counterpart to <c>Verifiable.Tests.Xml.XmlTransformChainCostTests</c>, whose
/// unit tests keep only the correctness and pooled-custody assertions.
/// </summary>
[MemoryDiagnoser]
internal class XmlTransformChainBenchmarks
{
    private const string SignatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

    /// <summary>How many repeated child elements the megabyte-scale decoded payload document carries.</summary>
    private const int PayloadElementCount = 40_000;

    /// <summary>How many distinct bare-name-Id references the wide-reference-list document carries.</summary>
    private const int WideReferenceCount = 300;

    /// <summary>How many base64 quantums ("AAAA\n") the noise payload repeats.</summary>
    private const int QuantumCount = 300_000;

    private XmlNodeTable noiseTable = null!;

    private XmlSignature noiseSignature = null!;

    private XmlReferenceResolver noiseResolver = null!;

    private XmlNodeTable mixedTable = null!;

    private XmlSignature mixedSignature = null!;

    private XmlNodeTable wideReferenceTable = null!;

    private XmlSignature wideReferenceSignature = null!;


    /// <summary>Parses a document and reads its first <c>Signature</c> element, the fixture shape every benchmark in this class shares.</summary>
    /// <param name="document">The document text.</param>
    /// <param name="pool">The pool the parse and read rent scratch buffers from.</param>
    /// <returns>The parsed table and its first signature.</returns>
    private static (XmlNodeTable Table, XmlSignature Signature) ReadFirstSignature(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        if(!isParsed)
        {
            throw new InvalidOperationException($"The benchmark fixture document must parse but was refused with {readError.Failure}.");
        }

        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
        bool isRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError readSignatureError);
        if(!isRead)
        {
            throw new InvalidOperationException($"The benchmark fixture Signature must read but was refused with {readSignatureError.Failure}.");
        }

        return (table!, signature!);
    }


    /// <summary>A reference resolver that hands back the same pooled octets on every call, regardless of the requested URI.</summary>
    /// <param name="octets">The fixed content every resolution returns a pooled copy of.</param>
    /// <returns>The resolver delegate.</returns>
    private static XmlReferenceResolver CreateFixedResolver(byte[] octets)
    {
        return (ReadOnlySpan<byte> uri, BaseMemoryPool pool, out PooledMemory? result) =>
        {
            result = PooledMemory.FromBytes(octets, pool, BufferTags.XmlDigestInput);

            return true;
        };
    }


    /// <summary>A well-formed document of roughly a megabyte, built from <see cref="PayloadElementCount"/> repeated child elements.</summary>
    /// <returns>The document octets.</returns>
    private static byte[] BuildMegabyteScalePayloadDocument()
    {
        var builder = new StringBuilder(PayloadElementCount * 24);
        builder.Append("<Root>");
        for(int i = 0; i < PayloadElementCount; ++i)
        {
            builder.Append("<Item>content</Item>");
        }

        builder.Append("</Root>");

        return Encoding.UTF8.GetBytes(builder.ToString());
    }


    /// <summary>A document carrying <see cref="WideReferenceCount"/> distinct bare-name-<c>Id</c> targets, one same-document <c>Reference</c> per target.</summary>
    /// <returns>The document text.</returns>
    private static string BuildWideReferenceListDocument()
    {
        var targets = new StringBuilder(WideReferenceCount * 40);
        var references = new StringBuilder(WideReferenceCount * 128);
        for(int i = 0; i < WideReferenceCount; ++i)
        {
            targets.Append(CultureInfo.InvariantCulture, $"<Target Id=\"target{i:D4}\">content{i}</Target>");
            references.Append(CultureInfo.InvariantCulture,
                $"""<Reference URI="#target{i:D4}"><DigestMethod Algorithm="{DigestMethodAlgorithm}"/><DigestValue>AQ==</DigestValue></Reference>""");
        }

        return $$"""
            <Document>
              {{targets}}
              <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                  <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                  {{references}}
                </SignedInfo>
                <SignatureValue>AQ==</SignatureValue>
              </Signature>
            </Document>
            """;
    }


    /// <summary>Parses every fixture this class's benchmarks measure, once per run.</summary>
    [GlobalSetup]
    public void Setup()
    {
        var noiseBuilder = new StringBuilder((QuantumCount * 5) + 16);
        for(int i = 0; i < QuantumCount; ++i)
        {
            noiseBuilder.Append("AAAA\n");
        }

        byte[] noiseOctets = Encoding.ASCII.GetBytes(noiseBuilder.ToString());
        noiseResolver = CreateFixedResolver(noiseOctets);
        string noiseDocument = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                <Reference URI="http://example.com/noise.b64">
                  <Transforms><Transform Algorithm="{{XmlSignatureIdentifiers.Base64TransformUri}}"/></Transforms>
                  <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;
        (noiseTable, noiseSignature) = ReadFirstSignature(noiseDocument, BaseMemoryPool.Shared);

        byte[] decodedPayload = BuildMegabyteScalePayloadDocument();
        string base64Payload = Convert.ToBase64String(decodedPayload);
        string mixedDocument = $$"""
            <Document>
              <Data Id="target">{{base64Payload}}</Data>
              <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                  <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                  <Reference URI="#target">
                    <Transforms>
                      <Transform Algorithm="{{XmlSignatureIdentifiers.Base64TransformUri}}"/>
                      <Transform Algorithm="{{XmlSignatureIdentifiers.CanonicalXml10Uri}}"/>
                      <Transform Algorithm="{{XmlSignatureIdentifiers.CanonicalXml10Uri}}"/>
                    </Transforms>
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>AQ==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>AQ==</SignatureValue>
              </Signature>
            </Document>
            """;
        (mixedTable, mixedSignature) = ReadFirstSignature(mixedDocument, BaseMemoryPool.Shared);

        (wideReferenceTable, wideReferenceSignature) = ReadFirstSignature(BuildWideReferenceListDocument(), BaseMemoryPool.Shared);
    }


    /// <summary>Releases every fixture this class's benchmarks parsed.</summary>
    [GlobalCleanup]
    public void Cleanup()
    {
        noiseSignature.Dispose();
        noiseTable.Dispose();
        mixedSignature.Dispose();
        mixedTable.Dispose();
        wideReferenceSignature.Dispose();
        wideReferenceTable.Dispose();
    }


    /// <summary>Measures decoding several megabytes of base64 noise through the base64 transform branch of the chain engine.</summary>
    [Benchmark]
    public void MegabyteScaleBase64NoiseDecodesThroughTheTransformChain()
    {
        XmlReferenceProcessing.TryComputeDigestInput(noiseTable, noiseSignature, 0, noiseResolver, BaseMemoryPool.Shared, out PooledMemory? digestInput, out _);
        using(digestInput)
        {
        }
    }


    /// <summary>Measures a chain mixing a base64 decode with two canonicalization re-parses over a megabyte-scale payload.</summary>
    [Benchmark]
    public void MixedBase64AndCanonicalizationChainOverMegabyteText()
    {
        XmlReferenceProcessing.TryComputeDigestInput(mixedTable, mixedSignature, 0, resolver: null, BaseMemoryPool.Shared, out PooledMemory? digestInput, out _);
        using(digestInput)
        {
        }
    }


    /// <summary>Measures computing every reference's digest input over a <see cref="WideReferenceCount"/>-reference same-document list.</summary>
    [Benchmark]
    public void WideReferenceListComputesEveryReferencesDigestInput()
    {
        for(int i = 0; i < WideReferenceCount; ++i)
        {
            XmlReferenceProcessing.TryComputeDigestInput(wideReferenceTable, wideReferenceSignature, i, resolver: null, BaseMemoryPool.Shared, out PooledMemory? digestInput, out _);
            using(digestInput)
            {
            }
        }
    }
}
