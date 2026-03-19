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
    /// <summary>
    /// The authorization response sender HTTP-POSTs the response as a JWE to
    /// <c>response_uri</c>. Mandated by HAIP 1.0 for redirect-based flows.
    /// </summary>
    public const string DirectPostJwt = "direct_post.jwt";

    /// <summary>
    /// The authorization response sender HTTP-POSTs the response in plain form to
    /// <c>response_uri</c>. Used in pre-HAIP deployments.
    /// </summary>
    public const string DirectPost = "direct_post";

    /// <summary>
    /// Response mode for the W3C Digital Credentials API with JWE encryption.
    /// Mandated by HAIP 1.0 for DC API flows.
    /// </summary>
    public const string DcApiJwt = "dc_api.jwt";
}
