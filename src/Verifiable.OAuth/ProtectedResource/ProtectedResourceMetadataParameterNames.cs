namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// The OAuth 2.0 Protected Resource Metadata parameter names (RFC 9728 §2,
/// IANA "OAuth Protected Resource Metadata" registry §8.1).
/// </summary>
public static class ProtectedResourceMetadataParameterNames
{
    /// <summary><c>resource</c> — REQUIRED; the protected resource's resource identifier (§1.2).</summary>
    public static readonly string Resource = "resource";

    /// <summary><c>authorization_servers</c> — OPTIONAL; RFC 8414 issuer identifiers usable with this resource.</summary>
    public static readonly string AuthorizationServers = "authorization_servers";

    /// <summary><c>jwks_uri</c> — OPTIONAL; the resource's JWK Set URL. MUST use the https scheme.</summary>
    public static readonly string JwksUri = "jwks_uri";

    /// <summary><c>scopes_supported</c> — RECOMMENDED; scope values used in authorization requests for this resource.</summary>
    public static readonly string ScopesSupported = "scopes_supported";

    /// <summary><c>bearer_methods_supported</c> — OPTIONAL; see <see cref="BearerMethodValues"/>.</summary>
    public static readonly string BearerMethodsSupported = "bearer_methods_supported";

    /// <summary><c>resource_signing_alg_values_supported</c> — OPTIONAL; JWS algs for signing resource responses. <c>none</c> MUST NOT be used.</summary>
    public static readonly string ResourceSigningAlgValuesSupported = "resource_signing_alg_values_supported";

    /// <summary><c>resource_name</c> — RECOMMENDED; the human-readable resource name. May be language-tagged (§2.1).</summary>
    public static readonly string ResourceName = "resource_name";

    /// <summary><c>resource_documentation</c> — OPTIONAL; developer documentation URL. May be language-tagged (§2.1).</summary>
    public static readonly string ResourceDocumentation = "resource_documentation";

    /// <summary><c>resource_policy_uri</c> — OPTIONAL; data-usage policy URL. May be language-tagged (§2.1).</summary>
    public static readonly string ResourcePolicyUri = "resource_policy_uri";

    /// <summary><c>resource_tos_uri</c> — OPTIONAL; terms-of-service URL. May be language-tagged (§2.1).</summary>
    public static readonly string ResourceTosUri = "resource_tos_uri";

    /// <summary><c>tls_client_certificate_bound_access_tokens</c> — OPTIONAL boolean (RFC 8705 support); defaults to false when omitted.</summary>
    public static readonly string TlsClientCertificateBoundAccessTokens = "tls_client_certificate_bound_access_tokens";

    /// <summary><c>authorization_details_types_supported</c> — OPTIONAL; RFC 9396 authorization details type values.</summary>
    public static readonly string AuthorizationDetailsTypesSupported = "authorization_details_types_supported";

    /// <summary><c>dpop_signing_alg_values_supported</c> — OPTIONAL; JWS algs for validating DPoP proof JWTs (RFC 9449).</summary>
    public static readonly string DpopSigningAlgValuesSupported = "dpop_signing_alg_values_supported";

    /// <summary><c>dpop_bound_access_tokens_required</c> — OPTIONAL boolean (RFC 9449); defaults to false when omitted.</summary>
    public static readonly string DpopBoundAccessTokensRequired = "dpop_bound_access_tokens_required";

    /// <summary>
    /// <c>signed_metadata</c> — OPTIONAL; a JWT asserting the metadata values
    /// as claims (§2.2). It SHOULD NOT appear as a claim inside that JWT, and
    /// it is RECOMMENDED to reject metadata in which this occurs.
    /// </summary>
    public static readonly string SignedMetadata = "signed_metadata";
}


/// <summary>
/// The defined <c>bearer_methods_supported</c> values (RFC 9728 §2): the RFC
/// 6750 bearer-token carriage methods.
/// </summary>
public static class BearerMethodValues
{
    /// <summary><c>header</c> — the Authorization request header field (RFC 6750 §2.1).</summary>
    public static readonly string Header = "header";

    /// <summary><c>body</c> — the form-encoded body parameter (RFC 6750 §2.2).</summary>
    public static readonly string Body = "body";

    /// <summary><c>query</c> — the URI query parameter (RFC 6750 §2.3).</summary>
    public static readonly string Query = "query";


    /// <summary>Whether <paramref name="value"/> is one of the three defined values.</summary>
    public static bool IsDefined(string value) => Equals(value, Header) || Equals(value, Body) || Equals(value, Query);


    /// <summary>Compares two values for equality (code-point equality per RFC 9728 §6).</summary>
    public static bool Equals(string valueA, string valueB) =>
        object.ReferenceEquals(valueA, valueB) || System.StringComparer.Ordinal.Equals(valueA, valueB);
}
