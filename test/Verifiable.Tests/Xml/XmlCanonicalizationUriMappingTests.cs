using Verifiable.Cryptography.Pki;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// The composition-layer statement of the mapping between the canonicalization algorithm identifiers
/// <see cref="XmlSignatureWellKnown.IsRecognizedCanonicalizationUri"/> accepts and the members of
/// <see cref="XmlCanonicalizationAlgorithm"/>. The <c>Verifiable.Xml</c> leaf does not restate the URIs —
/// recognition stays with <see cref="XmlSignatureWellKnown"/> — so the mapping lives here, in the layer
/// that composes the two, and these proofs pin it as total and bijective.
/// </summary>
[TestClass]
internal sealed class XmlCanonicalizationUriMappingTests
{
    /// <summary>
    /// The mapping itself: each identifier <see cref="XmlSignatureWellKnown"/> recognises as a
    /// canonicalization algorithm paired with the <see cref="XmlCanonicalizationAlgorithm"/> member that
    /// implements it.
    /// </summary>
    private static (string AlgorithmUri, XmlCanonicalizationAlgorithm Algorithm)[] UriToAlgorithm =>
    [
        (XmlSignatureWellKnown.CanonicalXml10Uri, XmlCanonicalizationAlgorithm.CanonicalXml10),
        (XmlSignatureWellKnown.CanonicalXml10WithCommentsUri, XmlCanonicalizationAlgorithm.CanonicalXml10WithComments),
        (XmlSignatureWellKnown.CanonicalXml11Uri, XmlCanonicalizationAlgorithm.CanonicalXml11),
        (XmlSignatureWellKnown.CanonicalXml11WithCommentsUri, XmlCanonicalizationAlgorithm.CanonicalXml11WithComments),
        (XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri, XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10),
        (XmlSignatureWellKnown.ExclusiveCanonicalXml10WithCommentsUri, XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments)
    ];


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI
    /// EN 319 132-1 V1.3.1</see> clause 6.3(d) — the <c>Algorithm</c> attribute "shall have one of the
    /// following values", six identifiers in all — as totality of the mapping over the recognized set:
    /// every identifier <see cref="XmlSignatureWellKnown.IsRecognizedCanonicalizationUri"/> accepts, which
    /// by its definition is exactly the six canonicalization identifiers
    /// <see cref="XmlSignatureWellKnown"/> names, appears in the mapping exactly once.
    /// </summary>
    [TestMethod]
    public void EveryRecognizedUriMapsToExactlyOneAlgorithmMember()
    {
        string[] recognizedUris =
        [
            XmlSignatureWellKnown.CanonicalXml10Uri,
            XmlSignatureWellKnown.CanonicalXml10WithCommentsUri,
            XmlSignatureWellKnown.CanonicalXml11Uri,
            XmlSignatureWellKnown.CanonicalXml11WithCommentsUri,
            XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri,
            XmlSignatureWellKnown.ExclusiveCanonicalXml10WithCommentsUri
        ];
        foreach(string uri in recognizedUris)
        {
            Assert.IsTrue(XmlSignatureWellKnown.IsRecognizedCanonicalizationUri(uri), $"The identifier '{uri}' must be recognized as a canonicalization algorithm.");
        }

        string[] mappedUris = [.. UriToAlgorithm.Select(pair => pair.AlgorithmUri)];
        Assert.AreSequenceEqual(recognizedUris, mappedUris, SequenceOrder.InAnyOrder, "The mapping's domain must be exactly the recognized identifiers, each appearing once.");
    }


    /// <summary>
    /// Proves the mapping is a bijection onto <see cref="XmlCanonicalizationAlgorithm"/> per
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI
    /// EN 319 132-1 V1.3.1</see> clause 6.3(d), whose six bullets each pair one identifier with one
    /// algorithm that "shall be supported": every member of the enumeration is reached by exactly one
    /// recognized identifier, and no member exists outside the mapping's range.
    /// </summary>
    [TestMethod]
    public void EveryAlgorithmMemberIsNamedByExactlyOneRecognizedUri()
    {
        XmlCanonicalizationAlgorithm[] mappedAlgorithms = [.. UriToAlgorithm.Select(pair => pair.Algorithm)];
        int mappedMemberCount = mappedAlgorithms.Length;
        int distinctMemberCount = mappedAlgorithms.Distinct().Count();

        Assert.AreEqual(mappedMemberCount, distinctMemberCount, "No two recognized identifiers may name the same algorithm member.");
        Assert.AreSequenceEqual(Enum.GetValues<XmlCanonicalizationAlgorithm>(), mappedAlgorithms, SequenceOrder.InAnyOrder, "The mapping's range must be exactly the members of the enumeration.");
    }


    /// <summary>
    /// Proves the comment-stance agreement the clause 6.3(d) bullets of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI
    /// EN 319 132-1 V1.3.1</see> encode — three identifiers name a "(with comments)" algorithm and three
    /// an "(omits comments)" one — across the seam:
    /// <see cref="XmlSignatureWellKnown.IsCanonicalizationWithComments"/> answers <see langword="true"/>
    /// for an identifier exactly when the mapping pairs it with a comment-preserving member of
    /// <see cref="XmlCanonicalizationAlgorithm"/>.
    /// </summary>
    [TestMethod]
    public void WithCommentsRecognitionAgreesWithTheWithCommentsMembers()
    {
        foreach((string uri, XmlCanonicalizationAlgorithm algorithm) in UriToAlgorithm)
        {
            bool isWithCommentsMember = algorithm is XmlCanonicalizationAlgorithm.CanonicalXml10WithComments
                or XmlCanonicalizationAlgorithm.CanonicalXml11WithComments
                or XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments;

            Assert.AreEqual(isWithCommentsMember, XmlSignatureWellKnown.IsCanonicalizationWithComments(uri), $"The comment stance of '{uri}' must agree with the member '{algorithm}' it maps to.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/xmldsig-core1/#sec-AlgID">XML Signature clause 6.1</see>,
    /// which identifies an algorithm by the URI as written, at the recognition seam the mapping composes
    /// with: an identifier that differs from a recognized one in case, in fragment presence or in trailing
    /// characters names no algorithm, is not recognized and carries no comment stance, so nothing maps it
    /// onto a member of <see cref="XmlCanonicalizationAlgorithm"/>.
    /// </summary>
    [TestMethod]
    public void NearMissIdentifiersAreNotRecognizedAndCarryNoCommentStance()
    {
        string[] nearMisses =
        [
            "http://www.w3.org/TR/2001/REC-XML-C14N-20010315",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#withcomments",
            "http://www.w3.org/2001/10/xml-exc-c14n",
            "http://www.w3.org/2006/12/xml-c14n11#",
            "http://www.w3.org/2006/12/xml-c14n11 "
        ];
        foreach(string uri in nearMisses)
        {
            Assert.IsFalse(XmlSignatureWellKnown.IsRecognizedCanonicalizationUri(uri), $"The near-miss identifier '{uri}' must not be recognized.");
            Assert.IsFalse(XmlSignatureWellKnown.IsCanonicalizationWithComments(uri), $"The near-miss identifier '{uri}' must carry no comment stance.");
        }
    }
}
