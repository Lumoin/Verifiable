using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Authorization Request parameter names native to OID4VP, as defined in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5">OID4VP 1.0 §5</see>.
/// </summary>
/// <remarks>
/// <para>
/// Contains only parameters that do not exist in base OAuth 2.0. Parameters
/// inherited from OAuth 2.0 without semantic change — <c>response_type</c>,
/// <c>client_id</c>, <c>state</c>, <c>response_mode</c> — are defined in
/// <see cref="Verifiable.OAuth.OAuthRequestParameters"/>. JWT claim names used
/// in JAR payloads — <c>iss</c>, <c>aud</c>, <c>nonce</c>, <c>client_id</c> —
/// are defined in <see cref="Verifiable.JCose.WellKnownJwtClaims"/>.
/// </para>
/// <para>
/// Used when constructing or parsing a JAR JWT payload, or when encoding a
/// direct (non-JAR) authorization request as form or query parameters.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthorizationRequestParameters")]
public static class AuthorizationRequestParameters
{
    /// <summary>The fixed value for <c>response_type</c> in OID4VP.</summary>
    /// <remarks>See <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1">OID4VP 1.0 §5.1</see>.</remarks>
    public const string ResponseTypeVpToken = "vp_token";

    /// <summary>The <c>client_id_scheme</c> parameter identifying the client identifier scheme.</summary>
    /// <remarks>See <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10">OID4VP 1.0 §5.10</see>.</remarks>
    public const string ClientIdScheme = "client_id_scheme";

    /// <summary>The <c>response_uri</c> parameter — the endpoint to POST the response to.</summary>
    /// <remarks>See <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-7.2">OID4VP 1.0 §7.2</see>.</remarks>
    public const string ResponseUri = "response_uri";

    /// <summary>The <c>dcql_query</c> parameter carrying the DCQL query object.</summary>
    /// <remarks>See <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6">OID4VP 1.0 §6</see>.</remarks>
    public const string DcqlQuery = "dcql_query";

    /// <summary>The <c>client_metadata</c> parameter carrying inline verifier metadata.</summary>
    /// <remarks>See <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.11">OID4VP 1.0 §5.11</see>.</remarks>
    public const string ClientMetadata = "client_metadata";


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>vp_token</c>.</summary>
    public static bool IsResponseTypeVpToken(string value) =>
        string.Equals(value, ResponseTypeVpToken, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>client_id_scheme</c>.</summary>
    public static bool IsClientIdScheme(string value) =>
        string.Equals(value, ClientIdScheme, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>response_uri</c>.</summary>
    public static bool IsResponseUri(string value) =>
        string.Equals(value, ResponseUri, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>dcql_query</c>.</summary>
    public static bool IsDcqlQuery(string value) =>
        string.Equals(value, DcqlQuery, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>client_metadata</c>.</summary>
    public static bool IsClientMetadata(string value) =>
        string.Equals(value, ClientMetadata, StringComparison.Ordinal);


    /// <summary>
    /// Returns the canonical form of a well-known OID4VP-native Authorization
    /// Request parameter name, or the original value when not recognized.
    /// Comparison is case-sensitive per OID4VP 1.0 §5.
    /// </summary>
    public static string GetCanonicalizedValue(string value) => value switch
    {
        _ when IsResponseTypeVpToken(value) => ResponseTypeVpToken,
        _ when IsClientIdScheme(value) => ClientIdScheme,
        _ when IsResponseUri(value) => ResponseUri,
        _ when IsDcqlQuery(value) => DcqlQuery,
        _ when IsClientMetadata(value) => ClientMetadata,
        _ => value
    };
}
