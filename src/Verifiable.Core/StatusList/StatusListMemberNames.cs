using System;

namespace Verifiable.Core.StatusList;

/// <summary>
/// Member names within the JOSE/COSE Status List object (<c>bits</c>/<c>lst</c>/<c>aggregation_uri</c>)
/// and the Status List reference object (<c>idx</c>/<c>uri</c>) embedded in a Referenced Token's
/// <c>status</c> claim.
/// </summary>
/// <remarks>
/// <para>
/// These are the §4.2 (JOSE Status List) and §6.2 (Referenced Token in JOSE) member names — distinct
/// from the JWT claim NAMES in <see cref="Verifiable.JCose.WellKnownJwtClaimNames"/>, which name the
/// top-level <c>status</c>/<c>status_list</c>/<c>ttl</c> claims themselves. The one home for each
/// member name here means <c>Verifiable.Json.StatusList.StatusListJsonConstants</c> and
/// <c>Verifiable.Cbor.StatusList.StatusListCborConstants</c> alias these constants rather than
/// carrying their own copy of the literal.
/// </para>
/// </remarks>
public static class StatusListMemberNames
{
    /// <summary>
    /// The UTF-8 source literal of <see cref="Bits"/>. Internal rather than public: <see cref="Bits"/>
    /// stays a compile-time <see langword="const"/> so the JSON/CBOR leaves' <c>switch</c> statements
    /// can use it as a case label, which rules out deriving it through
    /// <see cref="Verifiable.Cryptography.Text.Utf8Constants.ToInternedString(ReadOnlySpan{byte})"/> —
    /// so this span is not one of the interned-string-paired members the well-known-constant sweep
    /// polices.
    /// </summary>
    internal static ReadOnlySpan<byte> BitsUtf8 => "bits"u8;

    /// <summary>
    /// The <c>bits</c> member: "bits: REQUIRED. JSON Integer specifying the number of bits per
    /// Referenced Token in the compressed byte array (lst). The allowed values for bits are 1, 2, 4,
    /// and 8."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.2">Token Status List, Section 4.2</see>.
    /// </summary>
    public const string Bits = "bits";

    /// <summary>The UTF-8 source literal of <see cref="List"/>. Internal — see the remark on <see cref="BitsUtf8"/>.</summary>
    internal static ReadOnlySpan<byte> ListUtf8 => "lst"u8;

    /// <summary>
    /// The <c>lst</c> member: "lst: REQUIRED. JSON String that contains the status values for all the
    /// Referenced Tokens it conveys statuses for. The value MUST be the base64url-encoded compressed
    /// byte array as specified in Section 4.1."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.2">Token Status List, Section 4.2</see>.
    /// </summary>
    public const string List = "lst";

    /// <summary>The UTF-8 source literal of <see cref="AggregationUri"/>. Internal — see the remark on <see cref="BitsUtf8"/>.</summary>
    internal static ReadOnlySpan<byte> AggregationUriUtf8 => "aggregation_uri"u8;

    /// <summary>
    /// The <c>aggregation_uri</c> member: OPTIONAL, the URI of the Status List Aggregation this Status
    /// List participates in.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.2">Token Status List, Section 4.2</see>.
    /// </summary>
    public const string AggregationUri = "aggregation_uri";

    /// <summary>The UTF-8 source literal of <see cref="Index"/>. Internal — see the remark on <see cref="BitsUtf8"/>.</summary>
    internal static ReadOnlySpan<byte> IndexUtf8 => "idx"u8;

    /// <summary>
    /// The <c>idx</c> member: "REQUIRED. The idx (index) claim MUST specify a non-negative Integer
    /// that represents the index to check for status information in the Status List for the current
    /// Referenced Token."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token Status List, Section 6.2</see>.
    /// </summary>
    public const string Index = "idx";

    /// <summary>The UTF-8 source literal of <see cref="Uri"/>. Internal — see the remark on <see cref="BitsUtf8"/>.</summary>
    internal static ReadOnlySpan<byte> UriUtf8 => "uri"u8;

    /// <summary>
    /// The <c>uri</c> member: "REQUIRED. The uri (URI) claim MUST specify a String value that
    /// identifies the Status List Token containing the status information for the Referenced Token.
    /// The value of uri MUST be a URI conforming to [RFC3986]."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token Status List, Section 6.2</see>.
    /// </summary>
    public const string Uri = "uri";
}
