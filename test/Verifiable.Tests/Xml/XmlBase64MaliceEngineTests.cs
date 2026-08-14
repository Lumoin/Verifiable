using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of base64 malice against the section 6.6.2 transform, exercised through the full <see
/// cref="XmlReferenceProcessing.TryComputeDigestInput"/> transform-chain engine rather than <see
/// cref="XmlBase64Content"/> directly — the octets-arriving path AND the node-set-arriving
/// <c>self::text</c> collection path both feed the same lexical decoder: whitespace tricks, alphabet abuse,
/// and truncation. Every refusal path is observed through <see
/// cref="MeteredHousePool"/> accounting.
/// </summary>
[TestClass]
internal sealed class XmlBase64MaliceEngineTests
{
    private const string SignatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";


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


    private static string BuildOctetsSourcedDocument()
    {
        return $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                <Reference URI="http://example.com/raw.b64">
                  <Transforms><Transform Algorithm="{{XmlSignatureIdentifiers.Base64TransformUri}}"/></Transforms>
                  <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;
    }


    private static string BuildNodeSetSourcedDocument(string targetText)
    {
        return $$"""
            <Document>
              <Data Id="target">{{targetText}}</Data>
              <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                  <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                  <Reference URI="#target">
                    <Transforms><Transform Algorithm="{{XmlSignatureIdentifiers.Base64TransformUri}}"/></Transforms>
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>AQ==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>AQ==</SignatureValue>
              </Signature>
            </Document>
            """;
    }


    /// <summary>
    /// Proves the XSD <c>base64Binary</c> lexical space, applied at the <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 6.6.2 transform: interior XML white space inside octets arriving at
    /// the base64 transform decodes fine, per the fixed <c>collapse</c> <c>whiteSpace</c> facet — an
    /// external resolver's octets, pretty-printed with tabs and newlines threaded through the base64
    /// alphabet characters, decode to exactly the same bytes as the compact encoding.
    /// </summary>
    [TestMethod]
    public void InteriorWhitespaceInOctetsArrivingAtTheBase64TransformDecodesFine()
    {
        byte[] plaintext = [0xDE, 0xAD, 0xBE, 0xEF, 0x01];
        string compact = Convert.ToBase64String(plaintext);
        string interspersed = " \t" + string.Join("\r\n", compact.ToCharArray()) + " ";

        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(BuildOctetsSourcedDocument(), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, 0, CreateFixedResolver(Encoding.ASCII.GetBytes(interspersed)), BaseMemoryPool.Shared, out PooledMemory? digestInput, out XmlSignatureProcessingError error);
            Assert.IsTrue(isComputed, $"Whitespace-interspersed base64 octets must decode through the transform chain but were refused with {error.Failure}.");
            using(digestInput)
            {
                Assert.AreSequenceEqual(plaintext, digestInput!.AsReadOnlySpan().ToArray());
            }
        }
    }


    /// <summary>
    /// Proves the strict <c>base64Binary</c> lexical-space decode rule at the <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 6.6.2 transform: an illegal alphabet character arriving as OCTETS at
    /// the base64 transform refuses as <see cref="XmlSignatureProcessingFailure.InvalidBase64Content"/> —
    /// the transform-execution-time analogue of the read-time refusal, produced because the malice surfaces
    /// mid-chain rather than while the model reads.
    /// </summary>
    [TestMethod]
    public void IllegalAlphabetCharacterInOctetsArrivingAtTheBase64TransformRefuses()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(BuildOctetsSourcedDocument(), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            using var metered = new MeteredHousePool();
            bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, 0, CreateFixedResolver("AB,C"u8.ToArray()), metered.Pool, out PooledMemory? digestInput, out XmlSignatureProcessingError error);

            Assert.IsFalse(isComputed, "An illegal alphabet character must refuse rather than decode.");
            Assert.IsNull(digestInput);
            Assert.AreEqual(XmlSignatureProcessingFailure.InvalidBase64Content, error.Failure);
            Assert.AreEqual(0L, metered.OutstandingCount, "The refusal must not leave any rented buffer outstanding.");
        }
    }


    /// <summary>
    /// Proves the decode rule holds on the node-set path too, per <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing (Second
    /// Edition)</see> section 6.6.2's own node-set-to-octets rule: an illegal alphabet character hidden inside a
    /// NODE-SET's collected text — reachable only through <c>self::text</c> string-value selection — is still
    /// caught, refusing as <see cref="XmlSignatureProcessingFailure.InvalidBase64Content"/> rather than being
    /// silently accepted because it arrived via the node-set path instead of raw octets.
    /// </summary>
    [TestMethod]
    public void IllegalAlphabetCharacterInANodeSetsCollectedTextRefuses()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(BuildNodeSetSourcedDocument("AB,C"), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            using var metered = new MeteredHousePool();
            bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, 0, resolver: null, metered.Pool, out PooledMemory? digestInput, out XmlSignatureProcessingError error);

            Assert.IsFalse(isComputed, "An illegal alphabet character reached via node-set text collection must still refuse.");
            Assert.IsNull(digestInput);
            Assert.AreEqual(XmlSignatureProcessingFailure.InvalidBase64Content, error.Failure);
            Assert.AreEqual(0L, metered.OutstandingCount, "The refusal must not leave any rented buffer outstanding.");
        }
    }


    /// <summary>
    /// Proves the <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#base64Binary"> XML Schema
    /// Part 2: Datatypes</see> section 3.2.16 <c>Base64Binary</c> production quantum rule holds through the
    /// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 6.6.2 transform chain on both data-flow shapes: truncated content — a
    /// significant-character count that is not a multiple of four — refuses rather than being padded, wrapped
    /// or silently accepted, for both the octets-arriving and node-set-arriving paths.
    /// </summary>
    [TestMethod]
    public void TruncatedBase64ContentRefusesThroughTheTransformChainOnBothPaths()
    {
        (XmlNodeTable octetsTable, XmlSignature octetsSignature) = ReadFirstSignature(BuildOctetsSourcedDocument(), BaseMemoryPool.Shared);
        using(octetsTable)
        using(octetsSignature)
        {
            using var metered = new MeteredHousePool();
            bool isOctetsComputed = XmlReferenceProcessing.TryComputeDigestInput(octetsTable, octetsSignature, 0, CreateFixedResolver("QQ"u8.ToArray()), metered.Pool, out PooledMemory? octetsDigestInput, out XmlSignatureProcessingError octetsError);
            Assert.IsFalse(isOctetsComputed, "Truncated octets-sourced base64 must refuse.");
            Assert.IsNull(octetsDigestInput);
            Assert.AreEqual(XmlSignatureProcessingFailure.InvalidBase64Content, octetsError.Failure);
            Assert.AreEqual(0L, metered.OutstandingCount, "The refusal must not leave any rented buffer outstanding.");
        }

        (XmlNodeTable nodeSetTable, XmlSignature nodeSetSignature) = ReadFirstSignature(BuildNodeSetSourcedDocument("QQ"), BaseMemoryPool.Shared);
        using(nodeSetTable)
        using(nodeSetSignature)
        {
            using var metered = new MeteredHousePool();
            bool isNodeSetComputed = XmlReferenceProcessing.TryComputeDigestInput(nodeSetTable, nodeSetSignature, 0, resolver: null, metered.Pool, out PooledMemory? nodeSetDigestInput, out XmlSignatureProcessingError nodeSetError);
            Assert.IsFalse(isNodeSetComputed, "Truncated node-set-sourced base64 must refuse.");
            Assert.IsNull(nodeSetDigestInput);
            Assert.AreEqual(XmlSignatureProcessingFailure.InvalidBase64Content, nodeSetError.Failure);
            Assert.AreEqual(0L, metered.OutstandingCount, "The refusal must not leave any rented buffer outstanding.");
        }
    }
}
