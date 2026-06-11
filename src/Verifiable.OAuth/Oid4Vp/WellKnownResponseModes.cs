using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Response mode constants for OID4VP Authorization Responses, as defined in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8">OID4VP 1.0 §8</see>.
/// </summary>
/// <remarks>
/// EWC RFC002 restricts the supported response modes for cross-device flows to
/// <c>direct_post</c>, <c>direct_post.jwt</c>, <c>dc_api</c>, and <c>dc_api.jwt</c>.
/// The <c>fragment</c> mode is defined for completeness but is NOT RECOMMENDED
/// by EWC RFC002 for cross-device flows.
/// </remarks>
[DebuggerDisplay("WellKnownResponseModes")]
public static class WellKnownResponseModes
{
    //Response mode values — OID4VP 1.0 §8.

    /// <summary>The UTF-8 source literal of <see cref="DirectPost"/>.</summary>
    public static ReadOnlySpan<byte> DirectPostUtf8 => "direct_post"u8;

    /// <summary>
    /// The <c>direct_post</c> response mode. The Wallet POSTs the Authorization
    /// Response parameters form-encoded directly to the <c>response_uri</c> endpoint.
    /// Per OID4VP 1.0 §8.2.
    /// </summary>
    public static readonly string DirectPost = Utf8Constants.ToInternedString(DirectPostUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DirectPostJwt"/>.</summary>
    public static ReadOnlySpan<byte> DirectPostJwtUtf8 => "direct_post.jwt"u8;

    /// <summary>
    /// The <c>direct_post.jwt</c> response mode. The Wallet POSTs a single
    /// <c>response</c> parameter containing a signed and/or encrypted JWT to
    /// the <c>response_uri</c> endpoint. Required by HAIP 1.0 for the
    /// cross-device encrypted response flow. Per OID4VP 1.0 §8.3.1.
    /// </summary>
    public static readonly string DirectPostJwt = Utf8Constants.ToInternedString(DirectPostJwtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DcApi"/>.</summary>
    public static ReadOnlySpan<byte> DcApiUtf8 => "dc_api"u8;

    /// <summary>
    /// The <c>dc_api</c> response mode. Used with the W3C Digital Credentials API.
    /// Per OID4VP 1.0 Appendix A.
    /// </summary>
    public static readonly string DcApi = Utf8Constants.ToInternedString(DcApiUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DcApiJwt"/>.</summary>
    public static ReadOnlySpan<byte> DcApiJwtUtf8 => "dc_api.jwt"u8;

    /// <summary>
    /// The <c>dc_api.jwt</c> response mode. Encrypted variant of <see cref="DcApi"/>.
    /// Per OID4VP 1.0 Appendix A.
    /// </summary>
    public static readonly string DcApiJwt = Utf8Constants.ToInternedString(DcApiJwtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Fragment"/>.</summary>
    public static ReadOnlySpan<byte> FragmentUtf8 => "fragment"u8;

    /// <summary>
    /// The <c>fragment</c> response mode. The default when no response mode is
    /// specified and the <c>redirect_uri</c> is used. NOT RECOMMENDED by EWC RFC002
    /// for cross-device flows. Per OAuth 2.0 Multiple Response Types.
    /// </summary>
    public static readonly string Fragment = Utf8Constants.ToInternedString(FragmentUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Query"/>.</summary>
    public static ReadOnlySpan<byte> QueryUtf8 => "query"u8;

    /// <summary>
    /// The <c>query</c> response mode per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>.
    /// The Wallet appends Authorization Response parameters to the
    /// <c>redirect_uri</c>'s query string. Same-device same-process use only —
    /// OID4VP cross-device deployments use <see cref="DirectPost"/> /
    /// <see cref="DirectPostJwt"/> instead because cross-device has no
    /// redirect URI to navigate the user-agent to.
    /// </summary>
    public static readonly string Query = Utf8Constants.ToInternedString(QueryUtf8);


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>direct_post</c>.</summary>
    public static bool IsDirectPost(string value) =>
        string.Equals(value, DirectPost, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>direct_post.jwt</c>.</summary>
    public static bool IsDirectPostJwt(string value) =>
        string.Equals(value, DirectPostJwt, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>dc_api</c>.</summary>
    public static bool IsDcApi(string value) =>
        string.Equals(value, DcApi, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>dc_api.jwt</c>.</summary>
    public static bool IsDcApiJwt(string value) =>
        string.Equals(value, DcApiJwt, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>fragment</c>.</summary>
    public static bool IsFragment(string value) =>
        string.Equals(value, Fragment, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>query</c>.</summary>
    public static bool IsQuery(string value) =>
        string.Equals(value, Query, StringComparison.Ordinal);

    /// <summary>
    /// Returns <see langword="true"/> when the response mode delivers the
    /// Authorization Response by navigating the user-agent back to the
    /// Verifier's <c>redirect_uri</c> — i.e. <see cref="Fragment"/> or
    /// <see cref="Query"/>. The Wallet returns a redirect URL rather than
    /// POSTing, so deployments wiring these modes must own user-agent
    /// navigation themselves.
    /// </summary>
    public static bool IsRedirectVariant(string value) =>
        IsFragment(value) || IsQuery(value);


    /// <summary>
    /// Returns <see langword="true"/> when the response mode requires a direct
    /// HTTP POST to the <c>response_uri</c> endpoint, i.e. <c>direct_post</c>
    /// or <c>direct_post.jwt</c>.
    /// </summary>
    public static bool IsDirectPostVariant(string value) =>
        IsDirectPost(value) || IsDirectPostJwt(value);

    /// <summary>
    /// Returns <see langword="true"/> when the response mode uses the W3C
    /// Digital Credentials API, i.e. <c>dc_api</c> or <c>dc_api.jwt</c>.
    /// </summary>
    public static bool IsDcApiVariant(string value) =>
        IsDcApi(value) || IsDcApiJwt(value);

    /// <summary>
    /// Returns <see langword="true"/> when the response mode requires encryption
    /// of the Authorization Response, i.e. <c>direct_post.jwt</c> or
    /// <c>dc_api.jwt</c>.
    /// </summary>
    public static bool RequiresEncryption(string value) =>
        IsDirectPostJwt(value) || IsDcApiJwt(value);


    /// <summary>
    /// Returns the canonical form of a well-known response mode value, or the
    /// original value when not recognized. Comparison is case-sensitive per
    /// OID4VP 1.0 §8.
    /// </summary>
    public static string GetCanonicalizedValue(string value) => value switch
    {
        _ when IsDirectPost(value) => DirectPost,
        _ when IsDirectPostJwt(value) => DirectPostJwt,
        _ when IsDcApi(value) => DcApi,
        _ when IsDcApiJwt(value) => DcApiJwt,
        _ when IsFragment(value) => Fragment,
        _ when IsQuery(value) => Query,
        _ => value
    };
}
