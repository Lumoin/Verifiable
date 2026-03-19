using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Authorization Response parameter name constants for OID4VP, as defined in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">OID4VP 1.0 §8.1</see>.
/// </summary>
[DebuggerDisplay("AuthorizationResponseParameters")]
public static class AuthorizationResponseParameters
{
    /// <summary>
    /// The <c>vp_token</c> response parameter.
    /// When DCQL is used, the value is a JSON-encoded object whose keys are the
    /// <c>id</c> values from the DCQL query's <c>credentials</c> array and whose
    /// values are the matching Verifiable Presentations.
    /// Per OID4VP 1.0 §8.1.
    /// </summary>
    public const string VpToken = "vp_token";

    /// <summary>
    /// The <c>state</c> response parameter.
    /// Returned unchanged from the Authorization Request for CSRF protection
    /// per RFC 6749 §4.1.2 and RFC 9700 §4.7. OPTIONAL.
    /// </summary>
    public const string State = "state";

    /// <summary>
    /// The <c>response</c> parameter used in <c>direct_post.jwt</c> mode.
    /// Contains the compact JWE serialization of the encrypted Authorization
    /// Response per OID4VP 1.0 §8.3.1.
    /// </summary>
    public const string Response = "response";

    /// <summary>
    /// The <c>redirect_uri</c> parameter in the Verifier's response to the Wallet
    /// after a successful Authorization Response POST per OID4VP 1.0 §8.2.
    /// OPTIONAL. When present the Wallet redirects the user to this URI.
    /// </summary>
    public const string RedirectUri = "redirect_uri";


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>vp_token</c>.</summary>
    public static bool IsVpToken(string value) =>
        string.Equals(value, VpToken, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>state</c>.</summary>
    public static bool IsState(string value) =>
        string.Equals(value, State, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>response</c>.</summary>
    public static bool IsResponse(string value) =>
        string.Equals(value, Response, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>redirect_uri</c>.</summary>
    public static bool IsRedirectUri(string value) =>
        string.Equals(value, RedirectUri, StringComparison.Ordinal);


    /// <summary>
    /// Returns the canonical form of a well-known response parameter name, or
    /// the original value when not recognized. Comparison is case-sensitive per
    /// OID4VP 1.0 §8.1.
    /// </summary>
    public static string GetCanonicalizedValue(string value) => value switch
    {
        _ when IsVpToken(value) => VpToken,
        _ when IsState(value) => State,
        _ when IsResponse(value) => Response,
        _ when IsRedirectUri(value) => RedirectUri,
        _ => value
    };
}
