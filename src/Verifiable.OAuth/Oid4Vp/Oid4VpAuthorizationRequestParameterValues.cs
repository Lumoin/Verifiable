using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Well-known VALUES for OID4VP-specific authorization request parameters.
/// Distinct from <see cref="Oid4VpAuthorizationRequestParameterNames"/>
/// which holds the NAMES of those parameters; this class holds the
/// enumerated-set values for OID4VP name-constrained parameters
/// (currently only <c>response_type</c>).
/// </summary>
/// <remarks>
/// Most OID4VP parameter values are flow-specific (a DCQL query JSON,
/// a response URI, an inline client metadata object) and don't have
/// well-known canonical forms. Only the parameters whose values are
/// constrained to a small enumerated set have entries here.
/// </remarks>
public static class Oid4VpAuthorizationRequestParameterValues
{
    //response_type values — OID4VP 1.0 §5.1.

    /// <summary>The UTF-8 source literal of <see cref="ResponseTypeVpToken"/>.</summary>
    public static ReadOnlySpan<byte> ResponseTypeVpTokenUtf8 => "vp_token"u8;

    /// <summary>
    /// The <c>vp_token</c> value for the OAuth <c>response_type</c>
    /// parameter, which triggers the OID4VP flow per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1">OID4VP 1.0 §5.1</see>.
    /// </summary>
    public static readonly string ResponseTypeVpToken = Utf8Constants.ToInternedString(ResponseTypeVpTokenUtf8);


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <see cref="ResponseTypeVpToken"/>.
    /// </summary>
    public static bool IsResponseTypeVpToken(string value) =>
        string.Equals(value, ResponseTypeVpToken, StringComparison.Ordinal);


    //request_uri_method values — OID4VP 1.0 §5.10.

    /// <summary>The UTF-8 source literal of <see cref="RequestUriMethodGet"/>.</summary>
    public static ReadOnlySpan<byte> RequestUriMethodGetUtf8 => "get"u8;

    /// <summary>
    /// The <c>get</c> value for the <c>request_uri_method</c> parameter — the
    /// default: the Wallet GETs the <c>request_uri</c> endpoint.
    /// </summary>
    public static readonly string RequestUriMethodGet = Utf8Constants.ToInternedString(RequestUriMethodGetUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RequestUriMethodPost"/>.</summary>
    public static ReadOnlySpan<byte> RequestUriMethodPostUtf8 => "post"u8;

    /// <summary>
    /// The <c>post</c> value for the <c>request_uri_method</c> parameter — the
    /// Wallet POSTs to the <c>request_uri</c> endpoint, carrying
    /// <c>wallet_nonce</c> and (optionally) <c>wallet_metadata</c>.
    /// </summary>
    public static readonly string RequestUriMethodPost = Utf8Constants.ToInternedString(RequestUriMethodPostUtf8);


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <see cref="RequestUriMethodGet"/>.</summary>
    public static bool IsRequestUriMethodGet(string value) =>
        string.Equals(value, RequestUriMethodGet, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <see cref="RequestUriMethodPost"/>.</summary>
    public static bool IsRequestUriMethodPost(string value) =>
        string.Equals(value, RequestUriMethodPost, StringComparison.Ordinal);
}
