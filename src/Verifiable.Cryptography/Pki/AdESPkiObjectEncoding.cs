using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>EncapsulatedPKIDataType</c> <c>Encoding</c> value set of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>, clause 5.1.3: the five ASN.1 encoding rules an encapsulated PKI object's
/// octets (<see cref="AdESPkiObject.Val"/>) may be encoded with. See <see cref="AdESPkiObjectEncodingUris"/>
/// for the URI identifier each value carries on the wire and the default that applies when the wire states
/// none.
/// </summary>
public enum AdESPkiObjectEncoding
{
    /// <summary>
    /// ASN.1 encoded per the Distinguished Encoding Rules (DER) — the encoding an
    /// <c>EncapsulatedPKIDataType</c>-typed element's content is in when the <c>Encoding</c> attribute is
    /// absent altogether (clause 5.1.3).
    /// </summary>
    Der,

    /// <summary>ASN.1 encoded per the Basic Encoding Rules (BER) (clause 5.1.3).</summary>
    Ber,

    /// <summary>ASN.1 encoded per the Canonical Encoding Rules (CER) (clause 5.1.3).</summary>
    Cer,

    /// <summary>ASN.1 encoded per the Packed Encoding Rules (PER) (clause 5.1.3).</summary>
    Per,

    /// <summary>ASN.1 encoded per the XML Encoding Rules (XER) (clause 5.1.3).</summary>
    Xer
}


/// <summary>
/// The clause 5.1.3 URI identifiers for each <see cref="AdESPkiObjectEncoding"/> value, and the mapping
/// between them and <see cref="AdESPkiObject.Encoding"/>'s wire string.
/// </summary>
/// <remarks>
/// <para>
/// These five URIs are restated here as this library's own literals, independent of
/// <c>Verifiable.Xml</c>'s <c>XAdESIdentifiers</c> (which states the same five for the leaf's own use) — a
/// bijection test pins the two restatements together, mirroring the
/// <see cref="XmlSignatureWellKnown.AllCanonicalizationUris"/>/<c>XmlSignatureIdentifiers</c> precedent.
/// <see cref="AdESPkiObject"/> itself carries
/// <see cref="AdESPkiObject.Encoding"/> as an exact-character-sequence <see cref="string"/>, never this enum
/// or <see cref="Uri"/>: the wire type is an open <c>tstr</c>/JSON string, so a value outside this
/// five-member set is a legal, if unrecognized, encoding identifier this library still carries verbatim — this
/// type only classifies a carried value that happens to name one of the five clause 5.1.3 defines.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
    Justification = "An encoding identifier is compared as written: clause 5.1.3 identifies the encoding by the URI string, and System.Uri normalises case, escaping and default ports, which would make two identifiers that name different encodings compare equal.")]
[SuppressMessage("Design", "CA1055:URI-like return values should not be strings",
    Justification = "The value is carried into AdESPkiObject.Encoding verbatim; a System.Uri round trip would re-serialise it, and this member's own exact-character-sequence contract would be violated.")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "These are registered encoding identifiers compared as strings, never dereferenced; nothing here fetches a URI.")]
public static class AdESPkiObjectEncodingUris
{
    /// <summary>
    /// The <c>EncapsulatedPKIDataType</c> <c>Encoding</c> value denoting DER, <c>http://uri.etsi.org/01903/v1.2.2#DER</c>
    /// (clause 5.1.3) — also the value <see cref="FromUri"/> resolves when the wire states no <c>Encoding</c>
    /// at all.
    /// </summary>
    public static string DerUri { get; } = "http://uri.etsi.org/01903/v1.2.2#DER";

    /// <summary>The <c>EncapsulatedPKIDataType</c> <c>Encoding</c> value denoting BER, <c>http://uri.etsi.org/01903/v1.2.2#BER</c> (clause 5.1.3).</summary>
    public static string BerUri { get; } = "http://uri.etsi.org/01903/v1.2.2#BER";

    /// <summary>The <c>EncapsulatedPKIDataType</c> <c>Encoding</c> value denoting CER, <c>http://uri.etsi.org/01903/v1.2.2#CER</c> (clause 5.1.3).</summary>
    public static string CerUri { get; } = "http://uri.etsi.org/01903/v1.2.2#CER";

    /// <summary>The <c>EncapsulatedPKIDataType</c> <c>Encoding</c> value denoting PER, <c>http://uri.etsi.org/01903/v1.2.2#PER</c> (clause 5.1.3).</summary>
    public static string PerUri { get; } = "http://uri.etsi.org/01903/v1.2.2#PER";

    /// <summary>The <c>EncapsulatedPKIDataType</c> <c>Encoding</c> value denoting XER, <c>http://uri.etsi.org/01903/v1.2.2#XER</c> (clause 5.1.3).</summary>
    public static string XerUri { get; } = "http://uri.etsi.org/01903/v1.2.2#XER";


    /// <summary>
    /// Resolves the <see cref="AdESPkiObjectEncoding"/> a <see cref="AdESPkiObject.Encoding"/> string names.
    /// </summary>
    /// <param name="encodingUri">
    /// The carried <c>Encoding</c> value, or <see langword="null"/> when the wire states none.
    /// </param>
    /// <returns>
    /// <see cref="AdESPkiObjectEncoding.Der"/> when <paramref name="encodingUri"/> is <see langword="null"/>
    /// (clause 5.1.3's absent-means-DER default) or names DER explicitly; the matching value for BER/CER/PER/
    /// XER; or <see langword="null"/> when <paramref name="encodingUri"/> is a non-null value naming none of
    /// the five (an open, unrecognized wire value — see the type remarks).
    /// </returns>
    public static AdESPkiObjectEncoding? FromUri(string? encodingUri) => encodingUri switch
    {
        null => AdESPkiObjectEncoding.Der,
        _ when string.Equals(encodingUri, DerUri, StringComparison.Ordinal) => AdESPkiObjectEncoding.Der,
        _ when string.Equals(encodingUri, BerUri, StringComparison.Ordinal) => AdESPkiObjectEncoding.Ber,
        _ when string.Equals(encodingUri, CerUri, StringComparison.Ordinal) => AdESPkiObjectEncoding.Cer,
        _ when string.Equals(encodingUri, PerUri, StringComparison.Ordinal) => AdESPkiObjectEncoding.Per,
        _ when string.Equals(encodingUri, XerUri, StringComparison.Ordinal) => AdESPkiObjectEncoding.Xer,
        _ => null
    };


    /// <summary>States the wire URI for a <see cref="AdESPkiObjectEncoding"/> value — the inverse of <see cref="FromUri"/>.</summary>
    /// <param name="encoding">The value to name.</param>
    /// <returns>The clause 5.1.3 URI identifier.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="encoding"/> is not one of the five declared values.</exception>
    public static string ToUri(AdESPkiObjectEncoding encoding) => encoding switch
    {
        AdESPkiObjectEncoding.Der => DerUri,
        AdESPkiObjectEncoding.Ber => BerUri,
        AdESPkiObjectEncoding.Cer => CerUri,
        AdESPkiObjectEncoding.Per => PerUri,
        AdESPkiObjectEncoding.Xer => XerUri,
        _ => throw new ArgumentOutOfRangeException(nameof(encoding), encoding,
            "Unknown AdESPkiObjectEncoding value (ETSI EN 319 132-1 V1.3.1, clause 5.1.3).")
    };


    /// <summary>
    /// Every clause 5.1.3 <c>Encoding</c> URI, gathered in one enumerable place — the half of the
    /// bijection proof this type carries: a test binds the leaf's own <c>XAdESIdentifiers</c> pairing fixture
    /// against this list's exact content, so an encoding identifier added here without the matching leaf-side
    /// addition changes this list's content rather than passing unnoticed.
    /// </summary>
    public static IReadOnlyList<string> All { get; } =
    [
        DerUri,
        BerUri,
        CerUri,
        PerUri,
        XerUri
    ];
}
