using System.Globalization;
using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Correctness proofs for the reference-processing/transform-chain engine over megabyte-scale content and
/// a wide same-document reference list: each case decodes/computes the correct output and returns every
/// buffer rented from the caller's pool, proven through <see cref="MeteredHousePool"/> accounting. The
/// throughput characterisation of these same shapes — whether the engine stays linear rather than
/// quadratic — lives in <c>Verifiable.Benchmarks</c>'s <c>XmlTransformChainBenchmarks</c>, a unit test
/// proving cost by counting rather than by timing itself against a wall-clock ceiling.
/// </summary>
[TestClass]
internal sealed class XmlTransformChainCostTests
{
    private const string SignatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

    /// <summary>How many repeated child elements the megabyte-scale decoded payload document carries.</summary>
    private const int PayloadElementCount = 40_000;

    /// <summary>How many distinct bare-name-Id references the wide-reference-list document carries.</summary>
    private const int WideReferenceCount = 300;


    private static (XmlNodeTable Table, XmlSignature Signature) ReadFirstSignature(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
        Assert.HasCount(1, signatureIndices, "The fixture must carry exactly one Signature element.");

        bool isRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError readSignatureError);
        Assert.IsTrue(isRead, $"The fixture Signature must read but was refused with {readSignatureError.Failure}.");

        return (table!, signature!);
    }


    private static XmlReferenceResolver CreateFixedResolver(byte[] octets)
    {
        return (ReadOnlySpan<byte> uri, BaseMemoryPool pool, out PooledMemory? result) =>
        {
            result = PooledMemory.FromBytes(octets, pool, BufferTags.XmlDigestInput);

            return true;
        };
    }


    /// <summary>
    /// A well-formed XML document of roughly a megabyte, built from <see cref="PayloadElementCount"/>
    /// repeated child elements — large enough that a quadratic base64-decode or a quadratic re-parse shows
    /// in the benchmark that characterises this shape, small enough to build and canonicalize quickly when
    /// the engine behaves linearly.
    /// </summary>
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


    /// <summary>
    /// Proves that several megabytes of valid, XML-whitespace-interspersed base64 text — octets arriving
    /// directly at the base64 transform, the branch that calls <see cref="XmlBase64Content.TryDecode"/>
    /// over the whole buffer at once — decode to the correct octets with every pooled buffer returned. This
    /// is the DoS posture named by <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML
    /// Signature Syntax and Processing (Second Edition)</see> section 8.3: "even there perverse parameters
    /// might cause unacceptable processing or memory demand"; the throughput characterisation of this shape
    /// lives in <c>Verifiable.Benchmarks</c>'s <c>XmlTransformChainBenchmarks.MegabyteScaleBase64NoiseDecodesThroughTheTransformChain</c>.
    /// </summary>
    [TestMethod]
    public void MegabyteScaleBase64NoiseDecodesThroughTheTransformChainWithABalancedPool()
    {
        const int QuantumCount = 300_000;
        var builder = new StringBuilder((QuantumCount * 5) + 16);
        for(int i = 0; i < QuantumCount; ++i)
        {
            builder.Append("AAAA\n");
        }

        byte[] noise = Encoding.ASCII.GetBytes(builder.ToString());
        string document = $$"""
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
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            using var metered = new MeteredHousePool();
            bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, 0, CreateFixedResolver(noise), metered.Pool, out PooledMemory? digestInput, out XmlSignatureProcessingError error);

            Assert.IsTrue(isComputed, $"Megabyte-scale base64 noise must decode but was refused with {error.Failure}.");
            using(digestInput)
            {
                Assert.HasCount(QuantumCount * 3, digestInput!.AsReadOnlySpan().ToArray(), "Each 'AAAA' quantum decodes to three zero octets.");
            }

            Assert.AreEqual(0L, metered.OutstandingCount, "Every pooled buffer must be returned after disposal.");
        }
    }


    /// <summary>
    /// Proves a chain mixing both transform families the engine executes over a megabyte-scale payload: a
    /// base64-encoded XML payload decodes (base64, node-set-arriving text selection), re-parses into a
    /// node-set (the section 4.3.3.2 default), then canonicalizes twice more in a row — two further
    /// octets-to-node-set re-parses, staying within <see cref="XmlReferenceProcessing.MaximumReparseDepth"/>
    /// — computing the correct digest input with the pool balanced after disposal. This is the
    /// practically-realizable form of "alternating c14n/base64" this data model admits: Canonical XML's
    /// octet output always carries element markup, so a base64 transform can only re-enter a chain by
    /// arriving at a node-set (its own text-selection rule strips the markup), never by re-decoding
    /// already-canonicalized octets. Same DoS posture as the sibling cases: <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 8.3's "even there perverse parameters might cause unacceptable
    /// processing or memory demand," now over a chain mixing both transform families; the throughput
    /// characterisation of this shape lives in <c>Verifiable.Benchmarks</c>'s
    /// <c>XmlTransformChainBenchmarks.MixedBase64AndCanonicalizationChainOverMegabyteText</c>.
    /// </summary>
    [TestMethod]
    public void MixedBase64AndCanonicalizationChainOverMegabyteTextComputesWithABalancedPool()
    {
        byte[] decodedPayload = BuildMegabyteScalePayloadDocument();
        string base64Payload = Convert.ToBase64String(decodedPayload);
        string document = $$"""
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
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            using var metered = new MeteredHousePool();
            bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, 0, resolver: null, metered.Pool, out PooledMemory? digestInput, out XmlSignatureProcessingError error);

            Assert.IsTrue(isComputed, $"The mixed megabyte-scale chain must compute but was refused with {error.Failure}.");
            using(digestInput)
            {
                Assert.Contains("<Item>content</Item>", Encoding.UTF8.GetString(digestInput!.AsReadOnlySpan()));
            }

            Assert.AreEqual(0L, metered.OutstandingCount, "Every pooled buffer and every re-parsed table must be returned after disposal.");
        }
    }


    /// <summary>
    /// A document carrying <see cref="WideReferenceCount"/> distinct target elements, each identified by its
    /// own bare-name <c>Id</c>, and one <c>SignedInfo</c> with one same-document <c>Reference</c> per target.
    /// </summary>
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


    /// <summary>
    /// Proves a hardening gap: the contract names "maximum transforms per reference" and
    /// "maximum re-parse depth" as the chain engine's documented bounds, but states no bound on how many
    /// <c>Reference</c>s one <c>SignedInfo</c> may declare, and each same-document dereference costs a document-wide
    /// <c>Id</c> scan (<see cref="XmlNodeTable.TryFindElementById"/>). <see cref="WideReferenceCount"/> references
    /// over as many distinct bare-name <c>Id</c> targets each compute the correct digest input through <see
    /// cref="XmlReferenceProcessing.TryComputeDigestInput"/> — every reference in the list, not a sample — with the
    /// pool balanced after disposal. This scale is intentionally far below the security lens's adversarial
    /// ~20 000-reference concrete input; it proves the per-reference behavior is correct at a CI-safe size without
    /// asserting anything about the unbounded reference-count axis itself, which the contract does not bound. The
    /// throughput characterisation of this shape — whether the per-reference cost stays well-behaved rather than
    /// quadratic — lives in <c>Verifiable.Benchmarks</c>'s
    /// <c>XmlTransformChainBenchmarks.WideReferenceListComputesEveryReferencesDigestInput</c>. Grounded in the same
    /// DoS posture as the sibling cases in this file: <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/"> XML Signature Syntax and Processing (Second
    /// Edition)</see> section 8.3's "even there perverse parameters might cause unacceptable processing or memory
    /// demand."
    /// </summary>
    [TestMethod]
    public void WideReferenceListComputesEveryReferencesDigestInputWithABalancedPool()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(BuildWideReferenceListDocument(), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            Assert.HasCount(WideReferenceCount, signature.SignedInfo.References);

            using var metered = new MeteredHousePool();
            for(int i = 0; i < WideReferenceCount; ++i)
            {
                bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, i, resolver: null, metered.Pool, out PooledMemory? digestInput, out XmlSignatureProcessingError error);
                Assert.IsTrue(isComputed, $"Reference #{i} must compute but was refused with {error.Failure}.");
                digestInput!.Dispose();
            }

            Assert.AreEqual(0L, metered.OutstandingCount, "Every pooled buffer across all references must be returned after disposal.");
        }
    }
}
