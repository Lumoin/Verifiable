using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Exact byte-diff cross-checks of the enveloped-signature transform's nearest-ancestor exclusion over
/// sibling AND nested multi-signature documents: for nested + sibling signatures, each signature's
/// enveloped processing removes only itself, cross-checked by verifying both digest inputs differ exactly by
/// the other signature's octets. Where <see cref="XmlReferenceProcessingTests"/> proves nearest-ancestor
/// exclusion qualitatively (a <c>Contains</c>/<c>DoesNotContain</c> substring check), these tests prove it
/// quantitatively: each digest input is asserted EQUAL, byte for byte, to an independently composed
/// expectation built from the same public <see cref="XmlNodeSet"/>/<see cref="XmlCanonicalization"/>
/// primitives the engine itself uses internally, so the only degree of freedom between the two digest
/// inputs is exactly which sibling's own markup fills the excluded slot.
/// </summary>
[TestClass]
internal sealed class XmlMultiSignatureDigestExclusionTests
{
    private static (XmlNodeTable Table, XmlSignature[] Signatures) ReadAllSignaturesInDocumentOrder(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
        var signatures = new XmlSignature[signatureIndices.Length];
        for(int i = 0; i < signatureIndices.Length; ++i)
        {
            bool isRead = XmlSignature.TryRead(table!, signatureIndices[i], pool, out XmlSignature? signature, out XmlSignatureReadError readSignatureError);
            Assert.IsTrue(isRead, $"Signature #{i} must read but was refused with {readSignatureError.Failure}.");
            signatures[i] = signature!;
        }

        return (table!, signatures);
    }


    private static string ComputeDigestInputText(XmlNodeTable table, XmlSignature signature)
    {
        bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, 0, resolver: null, BaseMemoryPool.Shared, out PooledMemory? digestInput, out XmlSignatureProcessingError error);
        Assert.IsTrue(isComputed, $"Digest input must compute but was refused with {error.Failure}.");
        using(digestInput)
        {
            return Encoding.UTF8.GetString(digestInput!.AsReadOnlySpan());
        }
    }


    private static string CanonicalizeExcluding(XmlNodeTable table, int excludedElementIndex)
    {
        XmlNodeSet nodeSet = XmlNodeSet.WholeDocument(table).Excluding(excludedElementIndex);
        bool isCanonicalized = XmlCanonicalization.TryCanonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10, BaseMemoryPool.Shared, out PooledMemory? canonicalOctets, out XmlCanonicalizationError error);
        Assert.IsTrue(isCanonicalized, $"The oracle canonicalization must succeed but was refused with {error.Failure}.");
        using(canonicalOctets)
        {
            return Encoding.UTF8.GetString(canonicalOctets!.AsReadOnlySpan());
        }
    }


    private static string BuildEnvelopedSignature(string signatureValueMarker)
    {
        return $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}"><SignedInfo><CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI=""><Transforms><Transform Algorithm="{{XmlSignatureIdentifiers.EnvelopedSignatureTransformUri}}"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>AQ==</DigestValue></Reference></SignedInfo><SignatureValue>{{signatureValueMarker}}</SignatureValue></Signature>
            """.Trim();
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 6.6.4's "necessary to exclude the second signature element
    /// from the digest calculations of the first signature so that adding the second signature does not
    /// break the first signature" QUANTITATIVELY over two structurally-identical siblings differing only by
    /// their own <c>SignatureValue</c> marker: signature A's digest input is byte-exact to the wrapper
    /// canonicalized with exactly A excluded (leaving B's own octets in place), and signature B's is
    /// byte-exact to the wrapper with exactly B excluded (leaving A's own octets) — the two digest inputs
    /// therefore differ by exactly, and only, the swapped-in sibling's own markup.
    /// </summary>
    [TestMethod]
    public void SiblingSignaturesDigestInputsDifferExactlyByTheOtherSignaturesOwnCanonicalOctets()
    {
        string sigA = BuildEnvelopedSignature("QQ==");
        string sigB = BuildEnvelopedSignature("Qg==");
        string document = $"<Root>{sigA}{sigB}</Root>";

        (XmlNodeTable table, XmlSignature[] signatures) = ReadAllSignaturesInDocumentOrder(document, BaseMemoryPool.Shared);
        Assert.HasCount(2, signatures);
        using(table)
        using(signatures[0])
        using(signatures[1])
        {
            string digestInputA = ComputeDigestInputText(table, signatures[0]);
            string digestInputB = ComputeDigestInputText(table, signatures[1]);

            string expectedA = CanonicalizeExcluding(table, signatures[0].ElementIndex);
            string expectedB = CanonicalizeExcluding(table, signatures[1].ElementIndex);

            Assert.AreEqual(expectedA, digestInputA, "Signature A's digest input must equal the wrapper canonicalized with exactly A excluded.");
            Assert.AreEqual(expectedB, digestInputB, "Signature B's digest input must equal the wrapper canonicalized with exactly B excluded.");
            Assert.AreNotEqual(digestInputA, digestInputB, "The two digest inputs must differ.");
            Assert.Contains("Qg==", digestInputA, "A's digest input, with A excluded, must still carry B's own markup.");
            Assert.Contains("QQ==", digestInputB, "B's digest input, with B excluded, must still carry A's own markup.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 6.6.4's nearest-ancestor rule QUANTITATIVELY, the nested
    /// mirror of <see cref="SiblingSignaturesDigestInputsDifferExactlyByTheOtherSignaturesOwnCanonicalOctets"/>,
    /// over an outer signature whose <c>Object</c> carries a whole nested inner signature (section 9's
    /// "Recorded misc. facts" shape): the OUTER signature's digest input is
    /// byte-exact to the wrapper with the outer's WHOLE subtree excluded (dropping the inner signature
    /// along with it, since it lives inside the excluded subtree), while the INNER signature's digest input
    /// is byte-exact to the wrapper with only the inner's own subtree excluded — the outer's own surrounding
    /// markup (its <c>SignedInfo</c>, its own <c>SignatureValue</c>, its <c>Object</c> wrapper) survives,
    /// proving "nearest," not "outermost," quantitatively.
    /// </summary>
    [TestMethod]
    public void NestedSignatureDigestInputsMatchExclusionOfExactlyTheirOwnSubtree()
    {
        string inner = BuildEnvelopedSignature("Qg==");
        string document = $$"""
            <Root><Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}" Id="outer"><SignedInfo><CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI=""><Transforms><Transform Algorithm="{{XmlSignatureIdentifiers.EnvelopedSignatureTransformUri}}"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>AQ==</DigestValue></Reference></SignedInfo><SignatureValue>QQ==</SignatureValue><Object>{{inner}}</Object></Signature></Root>
            """.Trim();

        (XmlNodeTable table, XmlSignature[] signatures) = ReadAllSignaturesInDocumentOrder(document, BaseMemoryPool.Shared);
        Assert.HasCount(2, signatures, "The document-order scan must find both the outer and the nested inner Signature.");
        using(table)
        using(signatures[0])
        using(signatures[1])
        {
            string outerDigestInput = ComputeDigestInputText(table, signatures[0]);
            string innerDigestInput = ComputeDigestInputText(table, signatures[1]);

            string expectedOuter = CanonicalizeExcluding(table, signatures[0].ElementIndex);
            string expectedInner = CanonicalizeExcluding(table, signatures[1].ElementIndex);

            Assert.AreEqual(expectedOuter, outerDigestInput, "The outer signature's digest input must equal the wrapper with exactly the outer's whole subtree excluded.");
            Assert.AreEqual(expectedInner, innerDigestInput, "The inner signature's digest input must equal the wrapper with exactly the inner's own subtree excluded.");
            Assert.DoesNotContain("QQ==", outerDigestInput, "Excluding the outer's own whole subtree removes its own SignatureValue too.");
            Assert.DoesNotContain("Qg==", outerDigestInput, "Excluding the outer's whole subtree drops the nested inner signature too.");
            Assert.Contains("QQ==", innerDigestInput, "The inner's own exclusion leaves the surrounding outer markup — including the outer's own SignatureValue — intact.");
            Assert.DoesNotContain("Qg==", innerDigestInput, "The inner's own exclusion removes its own SignatureValue along with the rest of its subtree.");
        }
    }
}
