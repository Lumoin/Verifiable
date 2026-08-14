using System;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The padding/scheme family a <c>ds:SignatureMethod</c> URI names, decoupled from the digest algorithm the
/// same URI also names: the
/// <c>ecdsa-shaNNN</c> identifiers name only the hash
/// (<see href="https://www.rfc-editor.org/rfc/rfc4051#section-2.3.6">IETF RFC 4051 clause 2.3.6</see>,
/// restated by
/// <see href="https://www.rfc-editor.org/rfc/rfc9231#section-2.3.6">IETF RFC 9231 clause 2.3.6</see>), and
/// this family carries no curve of its own for the same reason.
/// </summary>
public enum XmlSignatureAlgorithmFamily
{
    /// <summary>RSA PKCS#1 v1.5.</summary>
    RsaPkcs1,

    /// <summary>RSASSA-PSS (MGF1, salt length equal to the hash's own output length).</summary>
    RsaPss,

    /// <summary>ECDSA, over whichever NIST curve the signing key itself states.</summary>
    Ecdsa
}


/// <summary>
/// The family and digest a <c>ds:SignatureMethod</c> URI names. Never a curve: resolve the
/// dispatch <see cref="Tag"/> from the KEY's own tag with
/// <see cref="XmlSignatureWellKnown.SignatureAlgorithmFromKeyTag"/>, and check the two agree with
/// <see cref="XmlSignatureWellKnown.IsConsistentWithKey"/> before dispatching verification.
/// </summary>
/// <param name="Family">The padding/scheme family.</param>
/// <param name="Digest">The digest algorithm the URI names.</param>
public readonly record struct XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily Family, PkiDigestAlgorithm Digest);


/// <summary>
/// The XML Signature wire names this library recognises — the core namespace, the digest algorithm
/// identifiers a <c>ds:DigestMethod</c> element names an algorithm by, the canonicalization algorithm
/// identifiers a <c>CanonicalizationMethod</c> element names one by, the signature-method algorithm
/// identifiers a <c>ds:SignatureMethod</c> element names one by, and the transform identifiers a
/// <c>ds:Transform</c> element names one by — together with the mapping onto <see cref="PkiDigestAlgorithm"/>
/// and onto the house <see cref="CryptoAlgorithm"/>/<see cref="Tag"/> vocabulary, which is what the
/// registered digest and signature-verification seams dispatch on.
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
/// <strong>Signature-method recognition names a family and a digest, never a curve.</strong>
/// <see href="https://www.rfc-editor.org/rfc/rfc4051#section-2.3.6">IETF RFC 4051 clause 2.3.6</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc9231#section-2.3.6">IETF RFC 9231 clause 2.3.6</see> name the
/// <c>ecdsa-shaNNN</c> identifiers by the hash alone — the curve is a property of the signing key, not of the
/// URI — so <see cref="SignatureAlgorithmFromUri"/> resolves an <see cref="XmlSignatureAlgorithm"/> (family +
/// digest), never a curve-specific <see cref="Tag"/>. The dispatch <see cref="Tag"/>
/// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> verifies signatures with comes from
/// the KEY material's own <see cref="Tag"/>, resolved by <see cref="SignatureAlgorithmFromKeyTag"/> — exactly
/// the <c>JAdESSignatureFacts.VerifyCryptographyAsync</c> dispatch idiom
/// (<c>publicKey.Tag.Get&lt;CryptoAlgorithm&gt;()</c>) — and <see cref="IsConsistentWithKey"/> refuses a
/// URI/key pairing (wrong family, or the right family but a digest the URI's stated hash does not match)
/// before any dispatch is attempted.
/// </para>
/// <para>
/// <strong>Transform recognition (stage 2 growth).</strong> Transform-identifier recognition restates,
/// byte-identically, the same six-plus-transform set <c>Verifiable.Xml</c>'s <c>XmlSignatureIdentifiers</c>
/// states independently (a bijection test proves the restatement in both directions, the same discipline the
/// six canonicalization identifiers already follow) — this library still executes no transform and still
/// ships no XML canonicalizer; recognition here exists only so a caller who never references the leaf can
/// still classify a <c>Transform Algorithm</c> URI.
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
    /// refused unconditionally and SHA-1 is refused for anything this library creates; a caller reading a container
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
    /// Every canonicalization algorithm identifier <see cref="IsRecognizedCanonicalizationUri"/> accepts,
    /// gathered in one enumerable place — the half of the bijection proof this type carries: a test
    /// binds its own leaf-side pairing fixture against this list's exact content, so a canonicalization
    /// identifier added here without the matching leaf-side addition changes this list's content rather than
    /// passing unnoticed.
    /// </summary>
    public static IReadOnlyList<string> AllCanonicalizationUris { get; } =
    [
        CanonicalXml10Uri,
        CanonicalXml10WithCommentsUri,
        ExclusiveCanonicalXml10Uri,
        ExclusiveCanonicalXml10WithCommentsUri,
        CanonicalXml11Uri,
        CanonicalXml11WithCommentsUri
    ];


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


    /// <summary>
    /// RSA PKCS#1 v1.5 with SHA-256, <c>http://www.w3.org/2001/04/xmldsig-more#rsa-sha256</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc4051#section-2.3.2">IETF RFC 4051 clause 2.3.2</see>,
    /// restated unchanged by
    /// <see href="https://www.rfc-editor.org/rfc/rfc9231#section-2.3.2">IETF RFC 9231 clause 2.3.2</see>).
    /// </summary>
    public static string RsaSha256SignatureUri { get; } = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    /// <summary>
    /// RSA PKCS#1 v1.5 with SHA-384, <c>http://www.w3.org/2001/04/xmldsig-more#rsa-sha384</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc4051#section-2.3.3">IETF RFC 4051 clause 2.3.3</see>).
    /// </summary>
    public static string RsaSha384SignatureUri { get; } = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";

    /// <summary>
    /// RSA PKCS#1 v1.5 with SHA-512, <c>http://www.w3.org/2001/04/xmldsig-more#rsa-sha512</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc4051#section-2.3.4">IETF RFC 4051 clause 2.3.4</see>).
    /// </summary>
    public static string RsaSha512SignatureUri { get; } = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

    /// <summary>
    /// ECDSA with SHA-256, <c>http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256</c>. RFC 4051, the
    /// predecessor <see cref="RsaSha256SignatureUri"/> cites, defines only <c>ecdsa-sha1</c>; the
    /// SHA-256/384/512 forms were added by
    /// <see href="https://www.rfc-editor.org/rfc/rfc6931#section-2.3.6">IETF RFC 6931 clause 2.3.6</see> and
    /// restated unchanged by
    /// <see href="https://www.rfc-editor.org/rfc/rfc9231#section-2.3.6">IETF RFC 9231 clause 2.3.6</see>, the
    /// RFC that obsoletes it.
    /// </summary>
    public static string EcdsaSha256SignatureUri { get; } = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

    /// <summary>
    /// ECDSA with SHA-384, <c>http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6931#section-2.3.6">IETF RFC 6931 clause 2.3.6</see>,
    /// restated unchanged by RFC 9231 clause 2.3.6).
    /// </summary>
    public static string EcdsaSha384SignatureUri { get; } = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";

    /// <summary>
    /// ECDSA with SHA-512, <c>http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6931#section-2.3.6">IETF RFC 6931 clause 2.3.6</see>,
    /// restated unchanged by RFC 9231 clause 2.3.6).
    /// </summary>
    public static string EcdsaSha512SignatureUri { get; } = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";

    /// <summary>
    /// RSASSA-PSS with SHA-256, MGF1-SHA256 and a salt length equal to the hash's output length — the
    /// fixed-parameter identifier <c>http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6931#section-2.3.10">IETF RFC 6931 clause 2.3.10</see>,
    /// restated unchanged by RFC 9231 clause 2.3.10).
    /// </summary>
    /// <remarks>
    /// RFC 6931/9231 clause 2.3.9 also registers a single parameterized identifier,
    /// <c>http://www.w3.org/2007/05/xmldsig-more#rsa-pss</c>, whose digest/MGF/salt-length choice rides in an
    /// <c>RSAPSSParams</c> child of <c>SignatureMethod</c> rather than in the URI itself — adjudicated OUT of
    /// <see cref="SignatureAlgorithmFromUri"/> because resolving it needs that child's content, which this
    /// Pki-layer type does not read (the structural read lives in <c>Verifiable.Xml</c>). The three
    /// fixed-parameter identifiers this type states name the SAME algorithm the parameterized identifier's
    /// documented defaults produce when every parameter is omitted (clause 2.3.9: "If they do not [appear],
    /// the defaults make this equivalent to [...] sha256-rsa-MGF1"), so a caller who only ever sees the
    /// fixed-parameter form loses nothing meeting the RFC's own default reading.
    /// </remarks>
    public static string RsaPssSha256SignatureUri { get; } = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";

    /// <summary>
    /// RSASSA-PSS with SHA-384, MGF1-SHA384 and a salt length equal to the hash's output length,
    /// <c>http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6931#section-2.3.10">IETF RFC 6931 clause 2.3.10</see>,
    /// restated unchanged by RFC 9231 clause 2.3.10).
    /// </summary>
    public static string RsaPssSha384SignatureUri { get; } = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1";

    /// <summary>
    /// RSASSA-PSS with SHA-512, MGF1-SHA512 and a salt length equal to the hash's output length,
    /// <c>http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6931#section-2.3.10">IETF RFC 6931 clause 2.3.10</see>,
    /// restated unchanged by RFC 9231 clause 2.3.10).
    /// </summary>
    public static string RsaPssSha512SignatureUri { get; } = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";

    /// <summary>
    /// RSA PKCS#1 v1.5 with SHA-1, <c>http://www.w3.org/2000/09/xmldsig#rsa-sha1</c>
    /// (<see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-PKCS1">XML Signature clause
    /// 6.4.2</see>). Recognised so a document naming it is refused for the algorithm rather than for being
    /// unreadable; never resolved by <see cref="SignatureAlgorithmFromUri"/>.
    /// </summary>
    public static string RsaSha1SignatureUri { get; } = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    /// <summary>
    /// DSA with SHA-1, <c>http://www.w3.org/2000/09/xmldsig#dsa-sha1</c>
    /// (<see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-DSA">XML Signature clause
    /// 6.4.1</see>). Recognised for the same reason as <see cref="RsaSha1SignatureUri"/>; this library
    /// verifies no DSA signature of any hash, so nothing resolves it.
    /// </summary>
    public static string DsaSha1SignatureUri { get; } = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";

    /// <summary>
    /// HMAC with SHA-1, <c>http://www.w3.org/2000/09/xmldsig#hmac-sha1</c>
    /// (<see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-HMAC">XML Signature clause
    /// 6.3.1</see>). Recognised for the same reason as <see cref="RsaSha1SignatureUri"/>; MAC verification is
    /// out of this library's scope regardless of hash (the same stance applies to the structural
    /// <c>HMACOutputLength</c> field), so nothing resolves it.
    /// </summary>
    public static string HmacSha1SignatureUri { get; } = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";


    /// <summary>
    /// Resolves the family and digest a <c>ds:SignatureMethod</c> URI names — never a
    /// curve-specific <see cref="Tag"/>: RFC 4051/RFC 9231 clause 2.3.6 name only the hash in the
    /// <c>ecdsa-shaNNN</c> identifiers, and the curve is a property the signing key states, not the URI.
    /// </summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns>The resolved family and digest, or <see langword="null"/> when this library will not verify it.</returns>
    /// <remarks>
    /// Resolve the dispatch <see cref="Tag"/> from the KEY's own tag with
    /// <see cref="SignatureAlgorithmFromKeyTag"/>, and check the two agree with <see cref="IsConsistentWithKey"/>
    /// before dispatching verification through <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> —
    /// a P-384 key under this method's <see cref="EcdsaSha256SignatureUri"/> is a legal wire combination this
    /// method alone cannot rule out (the URI names only SHA-256, never the curve), so the URI's resolution and
    /// the key's resolution are deliberately two separate steps.
    /// </remarks>
    public static XmlSignatureAlgorithm? SignatureAlgorithmFromUri(string? algorithmUri) => algorithmUri switch
    {
        null => null,
        _ when IsRsaSha256SignatureUri(algorithmUri) => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPkcs1, PkiDigestAlgorithm.Sha256),
        _ when IsRsaSha384SignatureUri(algorithmUri) => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPkcs1, PkiDigestAlgorithm.Sha384),
        _ when IsRsaSha512SignatureUri(algorithmUri) => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPkcs1, PkiDigestAlgorithm.Sha512),
        _ when IsEcdsaSha256SignatureUri(algorithmUri) => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.Ecdsa, PkiDigestAlgorithm.Sha256),
        _ when IsEcdsaSha384SignatureUri(algorithmUri) => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.Ecdsa, PkiDigestAlgorithm.Sha384),
        _ when IsEcdsaSha512SignatureUri(algorithmUri) => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.Ecdsa, PkiDigestAlgorithm.Sha512),
        _ when IsRsaPssSha256SignatureUri(algorithmUri) => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPss, PkiDigestAlgorithm.Sha256),
        _ when IsRsaPssSha384SignatureUri(algorithmUri) => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPss, PkiDigestAlgorithm.Sha384),
        _ when IsRsaPssSha512SignatureUri(algorithmUri) => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPss, PkiDigestAlgorithm.Sha512),
        _ => null
    };


    /// <summary>
    /// Resolves the family and digest the house verification registry's own fixed pairing implies for a
    /// signing/verification <see cref="Tag"/> — <see cref="CryptoTags.P256Signature"/> pairs with SHA-256,
    /// <see cref="CryptoTags.P384Signature"/> with SHA-384 and <see cref="CryptoTags.P521Signature"/> with
    /// SHA-512 (a registry convention <c>Verifiable.Microsoft.MicrosoftCryptographicFunctions</c> fixes;
    /// nothing in RFC 4051/RFC 9231 requires it — the curve is genuinely a key property, this method just
    /// states which digest THIS library's registry always pairs with which curve), and an RSA digest is
    /// already part of the <see cref="CryptoAlgorithm"/> itself (<see cref="CryptoAlgorithm.RsaSha256"/> and
    /// its siblings), so it reads straight off the tag.
    /// </summary>
    /// <param name="keyTag">The signing or verification key's own <see cref="Tag"/>, or <see langword="null"/>.</param>
    /// <returns>The family and digest the tag implies, or <see langword="null"/> when the tag names no algorithm this method resolves.</returns>
    public static XmlSignatureAlgorithm? SignatureAlgorithmFromKeyTag(Tag? keyTag)
    {
        if(keyTag is null || !keyTag.TryGet<CryptoAlgorithm>(out CryptoAlgorithm algorithm))
        {
            return null;
        }

        return algorithm switch
        {
            var a when a == CryptoAlgorithm.P256 => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.Ecdsa, PkiDigestAlgorithm.Sha256),
            var a when a == CryptoAlgorithm.P384 => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.Ecdsa, PkiDigestAlgorithm.Sha384),
            var a when a == CryptoAlgorithm.P521 => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.Ecdsa, PkiDigestAlgorithm.Sha512),
            var a when a == CryptoAlgorithm.RsaSha256 => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPkcs1, PkiDigestAlgorithm.Sha256),
            var a when a == CryptoAlgorithm.RsaSha384 => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPkcs1, PkiDigestAlgorithm.Sha384),
            var a when a == CryptoAlgorithm.RsaSha512 => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPkcs1, PkiDigestAlgorithm.Sha512),
            var a when a == CryptoAlgorithm.RsaSha256Pss => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPss, PkiDigestAlgorithm.Sha256),
            var a when a == CryptoAlgorithm.RsaSha384Pss => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPss, PkiDigestAlgorithm.Sha384),
            var a when a == CryptoAlgorithm.RsaSha512Pss => new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPss, PkiDigestAlgorithm.Sha512),
            _ => null
        };
    }


    /// <summary>
    /// Determines whether a <c>ds:SignatureMethod</c> URI and the key about to verify it agree — a
    /// consistency predicate, checked BEFORE any verification dispatch. The URI resolves to a
    /// family and digest via <see cref="SignatureAlgorithmFromUri"/>, the key's own <see cref="Tag"/>
    /// resolves to a family and digest via <see cref="SignatureAlgorithmFromKeyTag"/>, and the two must name
    /// the SAME family and the SAME digest. A P-384 key under <see cref="EcdsaSha256SignatureUri"/> is the
    /// right family but the wrong digest (a legal wire combination the URI alone cannot rule out, since it
    /// names only the hash); an RSA key under any ECDSA URI is a family mismatch outright. Either refuses
    /// here.
    /// </summary>
    /// <param name="algorithmUri">The <c>SignatureMethod Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <param name="keyTag">The verification key's own <see cref="Tag"/>, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when both resolve and name the same family and digest.</returns>
    public static bool IsConsistentWithKey(string? algorithmUri, Tag? keyTag)
    {
        XmlSignatureAlgorithm? fromUri = SignatureAlgorithmFromUri(algorithmUri);
        XmlSignatureAlgorithm? fromKey = SignatureAlgorithmFromKeyTag(keyTag);

        return fromUri is not null && fromKey is not null && fromUri.Value == fromKey.Value;
    }


    /// <summary>Determines whether a URI names RSA PKCS#1 v1.5 with SHA-256.</summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="RsaSha256SignatureUri"/>.</returns>
    public static bool IsRsaSha256SignatureUri(string? algorithmUri) =>
        string.Equals(algorithmUri, RsaSha256SignatureUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names RSA PKCS#1 v1.5 with SHA-384.</summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="RsaSha384SignatureUri"/>.</returns>
    public static bool IsRsaSha384SignatureUri(string? algorithmUri) =>
        string.Equals(algorithmUri, RsaSha384SignatureUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names RSA PKCS#1 v1.5 with SHA-512.</summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="RsaSha512SignatureUri"/>.</returns>
    public static bool IsRsaSha512SignatureUri(string? algorithmUri) =>
        string.Equals(algorithmUri, RsaSha512SignatureUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names ECDSA with SHA-256.</summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="EcdsaSha256SignatureUri"/>.</returns>
    public static bool IsEcdsaSha256SignatureUri(string? algorithmUri) =>
        string.Equals(algorithmUri, EcdsaSha256SignatureUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names ECDSA with SHA-384.</summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="EcdsaSha384SignatureUri"/>.</returns>
    public static bool IsEcdsaSha384SignatureUri(string? algorithmUri) =>
        string.Equals(algorithmUri, EcdsaSha384SignatureUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names ECDSA with SHA-512.</summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="EcdsaSha512SignatureUri"/>.</returns>
    public static bool IsEcdsaSha512SignatureUri(string? algorithmUri) =>
        string.Equals(algorithmUri, EcdsaSha512SignatureUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names the fixed-parameter RSASSA-PSS form with SHA-256.</summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="RsaPssSha256SignatureUri"/>.</returns>
    public static bool IsRsaPssSha256SignatureUri(string? algorithmUri) =>
        string.Equals(algorithmUri, RsaPssSha256SignatureUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names the fixed-parameter RSASSA-PSS form with SHA-384.</summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="RsaPssSha384SignatureUri"/>.</returns>
    public static bool IsRsaPssSha384SignatureUri(string? algorithmUri) =>
        string.Equals(algorithmUri, RsaPssSha384SignatureUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names the fixed-parameter RSASSA-PSS form with SHA-512.</summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="RsaPssSha512SignatureUri"/>.</returns>
    public static bool IsRsaPssSha512SignatureUri(string? algorithmUri) =>
        string.Equals(algorithmUri, RsaPssSha512SignatureUri, StringComparison.Ordinal);


    /// <summary>
    /// Determines whether a URI names a signature-method algorithm this library verifies.
    /// </summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when <see cref="SignatureAlgorithmFromUri"/> resolves it.</returns>
    public static bool IsSupportedSignatureUri(string? algorithmUri) =>
        SignatureAlgorithmFromUri(algorithmUri) is not null;


    /// <summary>
    /// Determines whether a URI names a signature-method algorithm this library knows by name and refuses to
    /// verify.
    /// </summary>
    /// <param name="algorithmUri">The <c>Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns>
    /// <see langword="true"/> when the value is <see cref="RsaSha1SignatureUri"/>, <see cref="DsaSha1SignatureUri"/>
    /// or <see cref="HmacSha1SignatureUri"/>.
    /// </returns>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-AlgID">XML Signature clause
    /// 6.1</see> marks DSAwithSHA1 and HMAC-SHA1 "Required" and RSA-SHA1 "Recommended" — this library refuses
    /// all three regardless, a DEVIATION governed by
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clause 6.2.1's delegation to TS 119 312's algorithm-suitability practice
    /// (which does not list SHA-1 among the hash functions a XAdES signature may rely on), the same posture
    /// <see cref="IsRefusedDigestUri"/> already takes for <see cref="Sha1DigestUri"/>.
    /// </remarks>
    public static bool IsRefusedSignatureUri(string? algorithmUri) =>
        string.Equals(algorithmUri, RsaSha1SignatureUri, StringComparison.Ordinal)
        || string.Equals(algorithmUri, DsaSha1SignatureUri, StringComparison.Ordinal)
        || string.Equals(algorithmUri, HmacSha1SignatureUri, StringComparison.Ordinal);


    /// <summary>
    /// The enveloped-signature transform, <c>http://www.w3.org/2000/09/xmldsig#enveloped-signature</c>
    /// (<see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-EnvelopedSignature">XML
    /// Signature clause 6.6.4</see>). Byte-identical to <c>Verifiable.Xml</c>'s own
    /// <c>XmlSignatureIdentifiers.EnvelopedSignatureTransformUri</c> — a bijection test proves the
    /// restatement in both directions, a discipline that extends to every transform identifier below.
    /// </summary>
    public static string EnvelopedSignatureTransformUri { get; } = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    /// <summary>The base64 decoding transform, <c>http://www.w3.org/2000/09/xmldsig#base64</c> (XML Signature clause 6.6.2).</summary>
    public static string Base64TransformUri { get; } = "http://www.w3.org/2000/09/xmldsig#base64";

    /// <summary>The XPath filtering transform, <c>http://www.w3.org/TR/1999/REC-xpath-19991116</c> (XML Signature clause 6.6.3).</summary>
    public static string XPathTransformUri { get; } = "http://www.w3.org/TR/1999/REC-xpath-19991116";

    /// <summary>The XSLT transform, <c>http://www.w3.org/TR/1999/REC-xslt-19991116</c> (XML Signature clause 6.6.5).</summary>
    public static string XsltTransformUri { get; } = "http://www.w3.org/TR/1999/REC-xslt-19991116";

    /// <summary>
    /// The XML-Signature XPath Filter 2.0 transform, <c>http://www.w3.org/2002/06/xmldsig-filter2</c>
    /// (ETSI EN 319 132-1 V1.3.1 clause 6.3(g)).
    /// </summary>
    public static string XPathFilter2TransformUri { get; } = "http://www.w3.org/2002/06/xmldsig-filter2";

    /// <summary>
    /// The OOXML package Relationships transform, <c>http://schemas.openxmlformats.org/package/2006/RelationshipTransform</c>
    /// (ECMA-376; ETSI EN 319 132-1 V1.3.1 clause 6.3(g)).
    /// </summary>
    public static string RelationshipTransformUri { get; } = "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";


    /// <summary>Determines whether a URI names the enveloped-signature transform.</summary>
    /// <param name="algorithmUri">The <c>Transform Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="EnvelopedSignatureTransformUri"/>.</returns>
    public static bool IsEnvelopedSignatureTransformUri(string? algorithmUri) =>
        string.Equals(algorithmUri, EnvelopedSignatureTransformUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names the base64 transform.</summary>
    /// <param name="algorithmUri">The <c>Transform Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="Base64TransformUri"/>.</returns>
    public static bool IsBase64TransformUri(string? algorithmUri) =>
        string.Equals(algorithmUri, Base64TransformUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names the XPath filtering transform.</summary>
    /// <param name="algorithmUri">The <c>Transform Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="XPathTransformUri"/>.</returns>
    public static bool IsXPathTransformUri(string? algorithmUri) =>
        string.Equals(algorithmUri, XPathTransformUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names the XSLT transform.</summary>
    /// <param name="algorithmUri">The <c>Transform Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="XsltTransformUri"/>.</returns>
    public static bool IsXsltTransformUri(string? algorithmUri) =>
        string.Equals(algorithmUri, XsltTransformUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names the XPath Filter 2.0 transform.</summary>
    /// <param name="algorithmUri">The <c>Transform Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="XPathFilter2TransformUri"/>.</returns>
    public static bool IsXPathFilter2TransformUri(string? algorithmUri) =>
        string.Equals(algorithmUri, XPathFilter2TransformUri, StringComparison.Ordinal);


    /// <summary>Determines whether a URI names the OOXML Relationships transform.</summary>
    /// <param name="algorithmUri">The <c>Transform Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="RelationshipTransformUri"/>.</returns>
    public static bool IsRelationshipTransformUri(string? algorithmUri) =>
        string.Equals(algorithmUri, RelationshipTransformUri, StringComparison.Ordinal);


    /// <summary>
    /// Determines whether a URI names a transform identifier this library recognises — mirroring, byte-
    /// identically, the transform-URI set <c>Verifiable.Xml</c>'s <c>XmlSignatureIdentifiers</c> states
    /// independently. Recognition is not execution: this library still runs no transform.
    /// </summary>
    /// <param name="algorithmUri">The <c>Transform Algorithm</c> attribute value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is one of the six identifiers named here.</returns>
    public static bool IsRecognizedTransformUri(string? algorithmUri) =>
        IsEnvelopedSignatureTransformUri(algorithmUri)
        || IsBase64TransformUri(algorithmUri)
        || IsXPathTransformUri(algorithmUri)
        || IsXsltTransformUri(algorithmUri)
        || IsXPathFilter2TransformUri(algorithmUri)
        || IsRelationshipTransformUri(algorithmUri);


    /// <summary>
    /// Every transform identifier <see cref="IsRecognizedTransformUri"/> accepts, gathered in one enumerable
    /// place — the half of the bijection proof this type carries: a test binds its own leaf-side
    /// pairing fixture against this list's exact content, so a transform identifier added here without the
    /// matching leaf-side addition changes this list's content rather than passing unnoticed.
    /// </summary>
    public static IReadOnlyList<string> AllTransformUris { get; } =
    [
        EnvelopedSignatureTransformUri,
        Base64TransformUri,
        XPathTransformUri,
        XsltTransformUri,
        XPathFilter2TransformUri,
        RelationshipTransformUri
    ];
}
