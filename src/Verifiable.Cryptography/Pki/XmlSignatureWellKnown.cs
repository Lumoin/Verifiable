using System;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The XML Signature wire names this library recognises — the core namespace, the digest algorithm identifiers
/// a <c>ds:DigestMethod</c> element names an algorithm by, and the canonicalization algorithm identifiers a
/// <c>CanonicalizationMethod</c> element names one by — together with the mapping onto
/// <see cref="PkiDigestAlgorithm"/>, which is what the registered digest seam dispatches on.
/// </summary>
/// <remarks>
/// <para>
/// Two shipped structures state a digest algorithm as a URI rather than as an object identifier: the
/// <c>ASiCManifest</c> element of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> Annex A.4.2, whose <c>DataObjectReferenceType</c> carries
/// <c>ds:DigestMethod</c> and <c>ds:DigestValue</c>, and the XML form of an Evidence Record per
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-4">IETF RFC 6283 clause 4</see>. Both reach the
/// same registry through this one mapping, so an algorithm this library can compute is named the same way
/// wherever it appears.
/// </para>
/// <para>
/// <strong>The canonicalization identifiers are recognised, never resolved to an implementation.</strong>
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-4.1.2">RFC 6283 clause 4.1.2</see> makes a
/// <c>CanonicalizationMethod</c> a required element of every <c>ArchiveTimeStampChain</c> and requires its
/// identifier to be one of those
/// <see href="https://www.rfc-editor.org/rfc/rfc3275#section-6.5">IETF RFC 3275 clause 6.5</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc4051#section-2.4">IETF RFC 4051 clause 2.4</see> define. This
/// library ships no XML canonicalizer — the algorithm is carried out by the canonicalization seam a caller
/// supplies — so what these members offer is recognition: whether an identifier names a canonicalization
/// algorithm at all, and whether the one it names preserves comments. Which of the recognised ones a caller's
/// seam actually implements is that seam's own statement, reported back as a status.
/// </para>
/// <para>
/// <strong>Comparison is ordinal and case-sensitive</strong>, unlike the media types of
/// <see cref="AsicWellKnown"/>. These values are URIs whose scheme and host would be case-insensitive but whose
/// path and fragment — which is where every one of them differs from the others — are not
/// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">IETF RFC 3986 clause 6.2.2.1</see>), and
/// <see href="https://www.w3.org/TR/xmldsig-core1/#sec-AlgID">XML Signature clause 6.1</see> identifies an
/// algorithm by the URI as written.
/// </para>
/// <para>
/// <strong>Recognised is not the same as supported.</strong> <see cref="Sha1DigestUri"/> and
/// <see cref="Md5DigestUri"/> are named so that a document using them is refused with a reason rather than
/// with "unknown algorithm", and <see cref="DigestAlgorithmFromUri"/> resolves neither — the same stance
/// <see cref="PkiDigestAlgorithm.FromOid"/> takes for the object-identifier form.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
    Justification = "An algorithm identifier is compared as written: XML Signature clause 6.1 identifies an algorithm by the URI string, and System.Uri normalises case, escaping and default ports, which would make two identifiers that name different algorithms compare equal.")]
[SuppressMessage("Design", "CA1055:URI-like return values should not be strings",
    Justification = "The value is written into a ds:DigestMethod Algorithm attribute verbatim; a System.Uri round trip would re-serialise it and the octets a signature commits to would change.")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "These are registered algorithm identifiers compared as strings, never dereferenced; nothing here fetches a URI.")]
public static class XmlSignatureWellKnown
{
    /// <summary>
    /// The XML Signature core namespace, <c>http://www.w3.org/2000/09/xmldsig#</c>
    /// (<see href="https://www.w3.org/TR/xmldsig-core1/#sec-Schema">XML Signature Appendix A</see>), which the
    /// ASiC schema of EN 319 162-1 Annex A.3 imports to reach <c>ds:DigestMethod</c> and <c>ds:DigestValue</c>.
    /// </summary>
    public static string XmlSignatureNamespace { get; } = "http://www.w3.org/2000/09/xmldsig#";

    /// <summary>
    /// The local name of the element carrying a digest algorithm identifier, <c>DigestMethod</c>
    /// (<see href="https://www.w3.org/TR/xmldsig-core1/#sec-DigestMethod">XML Signature clause 4.4.3.5</see>).
    /// </summary>
    public static string DigestMethodElementName { get; } = "DigestMethod";

    /// <summary>
    /// The local name of the element carrying a digest value, <c>DigestValue</c>
    /// (<see href="https://www.w3.org/TR/xmldsig-core1/#sec-DigestValue">XML Signature clause 4.4.4</see>). Its
    /// content is the base64 encoding of the digest octets.
    /// </summary>
    public static string DigestValueElementName { get; } = "DigestValue";

    /// <summary>
    /// The name of the attribute a <c>ds:DigestMethod</c> states its algorithm in, <c>Algorithm</c>
    /// (<see href="https://www.w3.org/TR/xmldsig-core1/#sec-DigestMethod">XML Signature clause 4.4.3.5</see>).
    /// </summary>
    public static string AlgorithmAttributeName { get; } = "Algorithm";

    /// <summary>
    /// SHA-256, <c>http://www.w3.org/2001/04/xmlenc#sha256</c>
    /// (<see href="https://www.w3.org/TR/xmlenc-core1/#sec-SHA256">XML Encryption clause 5.7.2</see>).
    /// </summary>
    public static string Sha256DigestUri { get; } = "http://www.w3.org/2001/04/xmlenc#sha256";

    /// <summary>
    /// SHA-384, <c>http://www.w3.org/2001/04/xmldsig-more#sha384</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6931#section-2.1">IETF RFC 6931 clause 2.1</see>). It sits
    /// in the <c>xmldsig-more</c> space rather than the XML Encryption one because it was registered later.
    /// </summary>
    public static string Sha384DigestUri { get; } = "http://www.w3.org/2001/04/xmldsig-more#sha384";

    /// <summary>
    /// SHA-512, <c>http://www.w3.org/2001/04/xmlenc#sha512</c>
    /// (<see href="https://www.w3.org/TR/xmlenc-core1/#sec-SHA512">XML Encryption clause 5.7.4</see>).
    /// </summary>
    public static string Sha512DigestUri { get; } = "http://www.w3.org/2001/04/xmlenc#sha512";

    /// <summary>
    /// SHA-1, <c>http://www.w3.org/2000/09/xmldsig#sha1</c>
    /// (<see href="https://www.w3.org/TR/xmldsig-core1/#sec-SHA1">XML Signature clause 6.2.1</see>). Recognised
    /// so that a document naming it is refused for the algorithm rather than for being unreadable; never
    /// resolved by <see cref="DigestAlgorithmFromUri"/>.
    /// </summary>
    public static string Sha1DigestUri { get; } = "http://www.w3.org/2000/09/xmldsig#sha1";

    /// <summary>
    /// MD5, <c>http://www.w3.org/2001/04/xmldsig-more#md5</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6931#section-2.1">IETF RFC 6931 clause 2.1</see>).
    /// Recognised for the same reason as <see cref="Sha1DigestUri"/> and resolved for no purpose whatsoever.
    /// </summary>
    public static string Md5DigestUri { get; } = "http://www.w3.org/2001/04/xmldsig-more#md5";

    /// <summary>
    /// Canonical XML 1.0 omitting comments, <c>http://www.w3.org/TR/2001/REC-xml-c14n-20010315</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3275#section-6.5.1">IETF RFC 3275 clause 6.5.1</see>). RFC
    /// 6283 clause 4.1.2 recommends this one outright: "Although alternative canonicalization methods may be
    /// used, it is recommended to use c14n-20010315."
    /// </summary>
    public static string CanonicalXml10Uri { get; } = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    /// <summary>
    /// Canonical XML 1.0 preserving comments,
    /// <c>http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3275#section-6.5.1">IETF RFC 3275 clause 6.5.1</see>).
    /// </summary>
    public static string CanonicalXml10WithCommentsUri { get; } = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";

    /// <summary>
    /// Exclusive XML Canonicalization 1.0 omitting comments, <c>http://www.w3.org/2001/10/xml-exc-c14n#</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc4051#section-2.4">IETF RFC 4051 clause 2.4</see>).
    /// </summary>
    public static string ExclusiveCanonicalXml10Uri { get; } = "http://www.w3.org/2001/10/xml-exc-c14n#";

    /// <summary>
    /// Exclusive XML Canonicalization 1.0 preserving comments,
    /// <c>http://www.w3.org/2001/10/xml-exc-c14n#WithComments</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc4051#section-2.4">IETF RFC 4051 clause 2.4</see>).
    /// </summary>
    public static string ExclusiveCanonicalXml10WithCommentsUri { get; } = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

    /// <summary>
    /// Canonical XML 1.1 omitting comments, <c>http://www.w3.org/2006/12/xml-c14n11</c>
    /// (<see href="https://www.w3.org/TR/xml-c14n11/">Canonical XML Version 1.1</see>).
    /// </summary>
    public static string CanonicalXml11Uri { get; } = "http://www.w3.org/2006/12/xml-c14n11";

    /// <summary>
    /// Canonical XML 1.1 preserving comments, <c>http://www.w3.org/2006/12/xml-c14n11#WithComments</c>
    /// (<see href="https://www.w3.org/TR/xml-c14n11/">Canonical XML Version 1.1</see>).
    /// </summary>
    public static string CanonicalXml11WithCommentsUri { get; } = "http://www.w3.org/2006/12/xml-c14n11#WithComments";


    /// <summary>
    /// Resolves the digest algorithm a <c>ds:DigestMethod</c> URI names.
    /// </summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns>The resolved algorithm, or <see langword="null"/> when this library will not compute it.</returns>
    /// <remarks>
    /// Exactly the three algorithms <see cref="PkiDigestAlgorithm"/> resolves from an object identifier resolve
    /// here, so a caller cannot reach a stronger or a weaker set by stating an algorithm in XML rather than in
    /// DER.
    /// </remarks>
    public static PkiDigestAlgorithm? DigestAlgorithmFromUri(string? algorithmUri) => algorithmUri switch
    {
        null => null,
        _ when IsSha256DigestUri(algorithmUri) => PkiDigestAlgorithm.Sha256,
        _ when IsSha384DigestUri(algorithmUri) => PkiDigestAlgorithm.Sha384,
        _ when IsSha512DigestUri(algorithmUri) => PkiDigestAlgorithm.Sha512,
        _ => null
    };


    /// <summary>
    /// States the <c>ds:DigestMethod</c> URI for a digest algorithm — the inverse of
    /// <see cref="DigestAlgorithmFromUri"/>, used when a manifest is written rather than read.
    /// </summary>
    /// <param name="algorithm">The algorithm to name.</param>
    /// <returns>The URI, or <see langword="null"/> when the algorithm has no registered XML identifier here.</returns>
    public static string? DigestUriFromAlgorithm(PkiDigestAlgorithm algorithm) => algorithm.Identifier.Oid switch
    {
        WellKnownOids.Sha256 => Sha256DigestUri,
        WellKnownOids.Sha384 => Sha384DigestUri,
        WellKnownOids.Sha512 => Sha512DigestUri,
        _ => null
    };


    /// <summary>Determines whether a URI names SHA-256.</summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="Sha256DigestUri"/>.</returns>
    public static bool IsSha256DigestUri(string? algorithmUri) =>
        string.Equals(algorithmUri, Sha256DigestUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names SHA-384.</summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="Sha384DigestUri"/>.</returns>
    public static bool IsSha384DigestUri(string? algorithmUri) =>
        string.Equals(algorithmUri, Sha384DigestUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names SHA-512.</summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="Sha512DigestUri"/>.</returns>
    public static bool IsSha512DigestUri(string? algorithmUri) =>
        string.Equals(algorithmUri, Sha512DigestUri, StringComparison.Ordinal);


    /// <summary>
    /// Determines whether a URI names a digest algorithm this library computes.
    /// </summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when <see cref="DigestAlgorithmFromUri"/> resolves it.</returns>
    public static bool IsSupportedDigestUri(string? algorithmUri) =>
        DigestAlgorithmFromUri(algorithmUri) is not null;


    /// <summary>
    /// Determines whether a URI names a digest algorithm this library knows by name and refuses to compute.
    /// </summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="Sha1DigestUri"/> or <see cref="Md5DigestUri"/>.</returns>
    /// <remarks>
    /// The distinction from "unrecognised" exists so a refusal can say which algorithm was asked for. MD5 is
    /// refused unconditionally and SHA-1 is refused for anything this wave creates; a caller reading a container
    /// produced against an older profile learns which of the two it met.
    /// </remarks>
    public static bool IsRefusedDigestUri(string? algorithmUri) =>
        string.Equals(algorithmUri, Sha1DigestUri, StringComparison.Ordinal)
        || string.Equals(algorithmUri, Md5DigestUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names Canonical XML 1.0, in either of its two forms.</summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="CanonicalXml10Uri"/> or <see cref="CanonicalXml10WithCommentsUri"/>.</returns>
    public static bool IsCanonicalXml10Uri(string? algorithmUri) =>
        string.Equals(algorithmUri, CanonicalXml10Uri, StringComparison.Ordinal)
        || string.Equals(algorithmUri, CanonicalXml10WithCommentsUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names Exclusive XML Canonicalization 1.0, in either of its two forms.</summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="ExclusiveCanonicalXml10Uri"/> or <see cref="ExclusiveCanonicalXml10WithCommentsUri"/>.</returns>
    public static bool IsExclusiveCanonicalXml10Uri(string? algorithmUri) =>
        string.Equals(algorithmUri, ExclusiveCanonicalXml10Uri, StringComparison.Ordinal)
        || string.Equals(algorithmUri, ExclusiveCanonicalXml10WithCommentsUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names Canonical XML 1.1, in either of its two forms.</summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="CanonicalXml11Uri"/> or <see cref="CanonicalXml11WithCommentsUri"/>.</returns>
    public static bool IsCanonicalXml11Uri(string? algorithmUri) =>
        string.Equals(algorithmUri, CanonicalXml11Uri, StringComparison.Ordinal)
        || string.Equals(algorithmUri, CanonicalXml11WithCommentsUri, StringComparison.Ordinal);


    /// <summary>
    /// Determines whether a URI names a canonicalization algorithm of the space RFC 3275 and RFC 4051 define.
    /// </summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is one of the six identifiers named here.</returns>
    /// <remarks>
    /// Recognition is not support: whether the canonicalization seam a caller supplied implements the algorithm
    /// is that seam's own statement. What this answers is whether a document names a canonicalization algorithm
    /// at all, which is what RFC 6283 clause 4.1.2's "Algorithm identifiers (URIs) MUST be used as defined in
    /// [RFC3275] and [RFC4051]" requires of a conformant producer.
    /// </remarks>
    public static bool IsRecognizedCanonicalizationUri(string? algorithmUri) =>
        IsCanonicalXml10Uri(algorithmUri)
        || IsExclusiveCanonicalXml10Uri(algorithmUri)
        || IsCanonicalXml11Uri(algorithmUri);


    /// <summary>
    /// Determines whether a recognised canonicalization URI names the comment-preserving form of its algorithm.
    /// </summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is one of the three <c>#WithComments</c> identifiers.</returns>
    /// <remarks>
    /// The distinction is load-bearing rather than cosmetic for an Evidence Record: a renewal hashes the
    /// canonical octets of an element the document may carry comments inside, and the two forms of one algorithm
    /// produce different octets for exactly that document. A seam that answered a <c>#WithComments</c> identifier
    /// with comment-stripped octets would compute a root nothing matches.
    /// </remarks>
    public static bool IsCanonicalizationWithComments(string? algorithmUri) =>
        string.Equals(algorithmUri, CanonicalXml10WithCommentsUri, StringComparison.Ordinal)
        || string.Equals(algorithmUri, ExclusiveCanonicalXml10WithCommentsUri, StringComparison.Ordinal)
        || string.Equals(algorithmUri, CanonicalXml11WithCommentsUri, StringComparison.Ordinal);
}
