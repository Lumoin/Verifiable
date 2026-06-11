using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Authorization response mode values used in OID4VP authorization requests.
/// </summary>
/// <remarks>
/// All values are case-sensitive per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0</see>.
/// </remarks>
public static class ResponseModeValues
{
    /// <summary>The UTF-8 source literal of <see cref="DirectPostJwt"/>.</summary>
    public static ReadOnlySpan<byte> DirectPostJwtUtf8 => "direct_post.jwt"u8;

    /// <summary>
    /// The authorization response sender HTTP-POSTs the response as a JWE to
    /// <c>response_uri</c>. Mandated by HAIP 1.0 for redirect-based flows.
    /// </summary>
    public static readonly string DirectPostJwt = Utf8Constants.ToInternedString(DirectPostJwtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DirectPost"/>.</summary>
    public static ReadOnlySpan<byte> DirectPostUtf8 => "direct_post"u8;

    /// <summary>
    /// The authorization response sender HTTP-POSTs the response in plain form to
    /// <c>response_uri</c>. Used in pre-HAIP deployments.
    /// </summary>
    public static readonly string DirectPost = Utf8Constants.ToInternedString(DirectPostUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DcApiJwt"/>.</summary>
    public static ReadOnlySpan<byte> DcApiJwtUtf8 => "dc_api.jwt"u8;

    /// <summary>
    /// Response mode for the W3C Digital Credentials API with JWE encryption.
    /// Mandated by HAIP 1.0 for DC API flows.
    /// </summary>
    public static readonly string DcApiJwt = Utf8Constants.ToInternedString(DcApiJwtUtf8);
}
