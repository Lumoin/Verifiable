using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="XmlSignatureWellKnown"/>: the digest algorithm identifiers a
/// <c>ds:DigestMethod</c> element names an algorithm by, and the mapping onto the registry the digest seam
/// dispatches on.
/// </summary>
[TestClass]
internal sealed class XmlSignatureWellKnownTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The identifiers are the ones the registries state, letter for letter — including that SHA-384 sits in
    /// the <c>xmldsig-more</c> space while SHA-256 and SHA-512 sit in the XML Encryption one, which is the
    /// asymmetry a hand-written URI most often gets wrong.
    /// </summary>
    [TestMethod]
    public void TheIdentifiersAreTheOnesTheRegistriesState()
    {
        Assert.AreEqual("http://www.w3.org/2000/09/xmldsig#", XmlSignatureWellKnown.XmlSignatureNamespace);
        Assert.AreEqual("http://www.w3.org/2001/04/xmlenc#sha256", XmlSignatureWellKnown.Sha256DigestUri);
        Assert.AreEqual("http://www.w3.org/2001/04/xmldsig-more#sha384", XmlSignatureWellKnown.Sha384DigestUri);
        Assert.AreEqual("http://www.w3.org/2001/04/xmlenc#sha512", XmlSignatureWellKnown.Sha512DigestUri);
        Assert.AreEqual("http://www.w3.org/2000/09/xmldsig#sha1", XmlSignatureWellKnown.Sha1DigestUri);
        Assert.AreEqual("http://www.w3.org/2001/04/xmldsig-more#md5", XmlSignatureWellKnown.Md5DigestUri);
    }


    /// <summary>
    /// Each supported identifier resolves to its algorithm and back, so a manifest read and written again
    /// names the same algorithm.
    /// </summary>
    [TestMethod]
    public void EachSupportedIdentifierResolvesToItsAlgorithmAndBack()
    {
        Assert.AreEqual(PkiDigestAlgorithm.Sha256, XmlSignatureWellKnown.DigestAlgorithmFromUri(XmlSignatureWellKnown.Sha256DigestUri));
        Assert.AreEqual(PkiDigestAlgorithm.Sha384, XmlSignatureWellKnown.DigestAlgorithmFromUri(XmlSignatureWellKnown.Sha384DigestUri));
        Assert.AreEqual(PkiDigestAlgorithm.Sha512, XmlSignatureWellKnown.DigestAlgorithmFromUri(XmlSignatureWellKnown.Sha512DigestUri));

        Assert.AreEqual(XmlSignatureWellKnown.Sha256DigestUri, XmlSignatureWellKnown.DigestUriFromAlgorithm(PkiDigestAlgorithm.Sha256));
        Assert.AreEqual(XmlSignatureWellKnown.Sha384DigestUri, XmlSignatureWellKnown.DigestUriFromAlgorithm(PkiDigestAlgorithm.Sha384));
        Assert.AreEqual(XmlSignatureWellKnown.Sha512DigestUri, XmlSignatureWellKnown.DigestUriFromAlgorithm(PkiDigestAlgorithm.Sha512));
    }


    /// <summary>
    /// The XML form reaches exactly the algorithms the object-identifier form reaches, so a caller cannot
    /// widen or narrow what this library computes by stating an algorithm in XML rather than in DER.
    /// </summary>
    [TestMethod]
    public void TheXmlFormReachesExactlyTheAlgorithmsTheObjectIdentifierFormReaches()
    {
        foreach(PkiDigestAlgorithm algorithm in new[] { PkiDigestAlgorithm.Sha256, PkiDigestAlgorithm.Sha384, PkiDigestAlgorithm.Sha512 })
        {
            string? uri = XmlSignatureWellKnown.DigestUriFromAlgorithm(algorithm);
            Assert.IsNotNull(uri);
            Assert.AreEqual(algorithm, XmlSignatureWellKnown.DigestAlgorithmFromUri(uri));
            Assert.AreEqual(algorithm, PkiDigestAlgorithm.FromOid(algorithm.Identifier.Oid));
        }
    }


    /// <summary>
    /// The two identifiers this library refuses are recognised by name so a refusal can say which algorithm
    /// was asked for, and neither resolves.
    /// </summary>
    [TestMethod]
    public void TheRefusedIdentifiersAreRecognisedByNameAndResolveToNothing()
    {
        Assert.IsTrue(XmlSignatureWellKnown.IsRefusedDigestUri(XmlSignatureWellKnown.Sha1DigestUri));
        Assert.IsTrue(XmlSignatureWellKnown.IsRefusedDigestUri(XmlSignatureWellKnown.Md5DigestUri));
        Assert.IsNull(XmlSignatureWellKnown.DigestAlgorithmFromUri(XmlSignatureWellKnown.Sha1DigestUri));
        Assert.IsNull(XmlSignatureWellKnown.DigestAlgorithmFromUri(XmlSignatureWellKnown.Md5DigestUri));
        Assert.IsFalse(XmlSignatureWellKnown.IsSupportedDigestUri(XmlSignatureWellKnown.Sha1DigestUri));
        Assert.IsFalse(XmlSignatureWellKnown.IsRefusedDigestUri(XmlSignatureWellKnown.Sha256DigestUri));
        Assert.IsFalse(XmlSignatureWellKnown.IsRefusedDigestUri("http://example.test/hash"));
    }


    /// <summary>
    /// Comparison is ordinal, unlike the media types of <see cref="AsicWellKnown"/>: an identifier differing
    /// only in case is a different identifier, because the part of the URI that distinguishes the algorithms
    /// is the path and the fragment, which IETF RFC 3986 clause 6.2.2.1 leaves case-sensitive.
    /// </summary>
    [TestMethod]
    public void ComparisonIsOrdinalUnlikeAMediaType()
    {
        Assert.IsNull(XmlSignatureWellKnown.DigestAlgorithmFromUri("HTTP://WWW.W3.ORG/2001/04/XMLENC#SHA256"));
        Assert.IsFalse(XmlSignatureWellKnown.IsSha256DigestUri("http://www.w3.org/2001/04/xmlenc#SHA256"));
        Assert.IsFalse(XmlSignatureWellKnown.IsSha512DigestUri(XmlSignatureWellKnown.Sha256DigestUri));
        Assert.IsNull(XmlSignatureWellKnown.DigestAlgorithmFromUri(null));
        Assert.IsFalse(XmlSignatureWellKnown.IsSupportedDigestUri(null));
    }


    /// <summary>
    /// The canonicalization identifiers are the ones IETF RFC 3275 clause 6.5.1, IETF RFC 4051 clause 2.4 and
    /// Canonical XML Version 1.1 state, letter for letter — including that the exclusive one's plain form ends
    /// in a fragment separator while the Canonical XML 1.0 one does not, which is the difference a hand-written
    /// identifier most often gets wrong.
    /// </summary>
    [TestMethod]
    public void TheCanonicalizationIdentifiersAreTheOnesTheRegistriesState()
    {
        Assert.AreEqual("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", XmlSignatureWellKnown.CanonicalXml10Uri);
        Assert.AreEqual("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments", XmlSignatureWellKnown.CanonicalXml10WithCommentsUri);
        Assert.AreEqual("http://www.w3.org/2001/10/xml-exc-c14n#", XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri);
        Assert.AreEqual("http://www.w3.org/2001/10/xml-exc-c14n#WithComments", XmlSignatureWellKnown.ExclusiveCanonicalXml10WithCommentsUri);
        Assert.AreEqual("http://www.w3.org/2006/12/xml-c14n11", XmlSignatureWellKnown.CanonicalXml11Uri);
        Assert.AreEqual("http://www.w3.org/2006/12/xml-c14n11#WithComments", XmlSignatureWellKnown.CanonicalXml11WithCommentsUri);
    }


    /// <summary>
    /// Each canonicalization identifier is recognised as its own algorithm's, and an identifier of no registry
    /// is recognised as none — which is what IETF RFC 6283 clause 4.1.2's "algorithm identifiers MUST be used as
    /// defined in [RFC3275] and [RFC4051]" makes a parse able to enforce.
    /// </summary>
    [TestMethod]
    public void EachCanonicalizationIdentifierIsRecognisedAsItsOwnAlgorithms()
    {
        Assert.IsTrue(XmlSignatureWellKnown.IsCanonicalXml10Uri(XmlSignatureWellKnown.CanonicalXml10Uri));
        Assert.IsTrue(XmlSignatureWellKnown.IsCanonicalXml10Uri(XmlSignatureWellKnown.CanonicalXml10WithCommentsUri));
        Assert.IsFalse(XmlSignatureWellKnown.IsCanonicalXml10Uri(XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri));

        Assert.IsTrue(XmlSignatureWellKnown.IsExclusiveCanonicalXml10Uri(XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri));
        Assert.IsTrue(XmlSignatureWellKnown.IsExclusiveCanonicalXml10Uri(XmlSignatureWellKnown.ExclusiveCanonicalXml10WithCommentsUri));
        Assert.IsFalse(XmlSignatureWellKnown.IsExclusiveCanonicalXml10Uri(XmlSignatureWellKnown.CanonicalXml11Uri));

        Assert.IsTrue(XmlSignatureWellKnown.IsCanonicalXml11Uri(XmlSignatureWellKnown.CanonicalXml11Uri));
        Assert.IsTrue(XmlSignatureWellKnown.IsCanonicalXml11Uri(XmlSignatureWellKnown.CanonicalXml11WithCommentsUri));

        Assert.IsTrue(XmlSignatureWellKnown.IsRecognizedCanonicalizationUri(XmlSignatureWellKnown.CanonicalXml10Uri));
        Assert.IsFalse(XmlSignatureWellKnown.IsRecognizedCanonicalizationUri("urn:example:my-own-canonicalization"));
        Assert.IsFalse(XmlSignatureWellKnown.IsRecognizedCanonicalizationUri(null));
        Assert.IsFalse(XmlSignatureWellKnown.IsRecognizedCanonicalizationUri(XmlSignatureWellKnown.Sha256DigestUri),
            "A digest identifier is not a canonicalization identifier, however alike the two spaces look.");
    }


    /// <summary>
    /// The comment-preserving form of each algorithm is distinguished from the plain one, which is the
    /// distinction an Evidence Record's renewal linkage rests on: the canonical octets of an element carrying a
    /// comment are not the same under the two.
    /// </summary>
    [TestMethod]
    public void TheCommentPreservingFormsAreDistinguishedFromThePlainOnes()
    {
        Assert.IsTrue(XmlSignatureWellKnown.IsCanonicalizationWithComments(XmlSignatureWellKnown.CanonicalXml10WithCommentsUri));
        Assert.IsTrue(XmlSignatureWellKnown.IsCanonicalizationWithComments(XmlSignatureWellKnown.ExclusiveCanonicalXml10WithCommentsUri));
        Assert.IsTrue(XmlSignatureWellKnown.IsCanonicalizationWithComments(XmlSignatureWellKnown.CanonicalXml11WithCommentsUri));

        Assert.IsFalse(XmlSignatureWellKnown.IsCanonicalizationWithComments(XmlSignatureWellKnown.CanonicalXml10Uri));
        Assert.IsFalse(XmlSignatureWellKnown.IsCanonicalizationWithComments(XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri));
        Assert.IsFalse(XmlSignatureWellKnown.IsCanonicalizationWithComments(XmlSignatureWellKnown.CanonicalXml11Uri));
        Assert.IsFalse(XmlSignatureWellKnown.IsCanonicalizationWithComments(null));
    }
}
