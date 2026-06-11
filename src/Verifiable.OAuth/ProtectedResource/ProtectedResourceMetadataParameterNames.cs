using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// The OAuth 2.0 Protected Resource Metadata parameter names (RFC 9728 §2,
/// IANA "OAuth Protected Resource Metadata" registry §8.1).
/// </summary>
public static class ProtectedResourceMetadataParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="Resource"/>.</summary>
    public static ReadOnlySpan<byte> ResourceUtf8 => "resource"u8;

    /// <summary><c>resource</c> — REQUIRED; the protected resource's resource identifier (§1.2).</summary>
    public static readonly string Resource = Utf8Constants.ToInternedString(ResourceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationServers"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationServersUtf8 => "authorization_servers"u8;

    /// <summary><c>authorization_servers</c> — OPTIONAL; RFC 8414 issuer identifiers usable with this resource.</summary>
    public static readonly string AuthorizationServers = Utf8Constants.ToInternedString(AuthorizationServersUtf8);

    /// <summary>The UTF-8 source literal of <see cref="JwksUri"/>.</summary>
    public static ReadOnlySpan<byte> JwksUriUtf8 => "jwks_uri"u8;

    /// <summary><c>jwks_uri</c> — OPTIONAL; the resource's JWK Set URL. MUST use the https scheme.</summary>
    public static readonly string JwksUri = Utf8Constants.ToInternedString(JwksUriUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ScopesSupported"/>.</summary>
    public static ReadOnlySpan<byte> ScopesSupportedUtf8 => "scopes_supported"u8;

    /// <summary><c>scopes_supported</c> — RECOMMENDED; scope values used in authorization requests for this resource.</summary>
    public static readonly string ScopesSupported = Utf8Constants.ToInternedString(ScopesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="BearerMethodsSupported"/>.</summary>
    public static ReadOnlySpan<byte> BearerMethodsSupportedUtf8 => "bearer_methods_supported"u8;

    /// <summary><c>bearer_methods_supported</c> — OPTIONAL; see <see cref="BearerMethodValues"/>.</summary>
    public static readonly string BearerMethodsSupported = Utf8Constants.ToInternedString(BearerMethodsSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ResourceSigningAlgValuesSupported"/>.</summary>
    public static ReadOnlySpan<byte> ResourceSigningAlgValuesSupportedUtf8 => "resource_signing_alg_values_supported"u8;

    /// <summary><c>resource_signing_alg_values_supported</c> — OPTIONAL; JWS algs for signing resource responses. <c>none</c> MUST NOT be used.</summary>
    public static readonly string ResourceSigningAlgValuesSupported = Utf8Constants.ToInternedString(ResourceSigningAlgValuesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ResourceName"/>.</summary>
    public static ReadOnlySpan<byte> ResourceNameUtf8 => "resource_name"u8;

    /// <summary><c>resource_name</c> — RECOMMENDED; the human-readable resource name. May be language-tagged (§2.1).</summary>
    public static readonly string ResourceName = Utf8Constants.ToInternedString(ResourceNameUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ResourceDocumentation"/>.</summary>
    public static ReadOnlySpan<byte> ResourceDocumentationUtf8 => "resource_documentation"u8;

    /// <summary><c>resource_documentation</c> — OPTIONAL; developer documentation URL. May be language-tagged (§2.1).</summary>
    public static readonly string ResourceDocumentation = Utf8Constants.ToInternedString(ResourceDocumentationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ResourcePolicyUri"/>.</summary>
    public static ReadOnlySpan<byte> ResourcePolicyUriUtf8 => "resource_policy_uri"u8;

    /// <summary><c>resource_policy_uri</c> — OPTIONAL; data-usage policy URL. May be language-tagged (§2.1).</summary>
    public static readonly string ResourcePolicyUri = Utf8Constants.ToInternedString(ResourcePolicyUriUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ResourceTosUri"/>.</summary>
    public static ReadOnlySpan<byte> ResourceTosUriUtf8 => "resource_tos_uri"u8;

    /// <summary><c>resource_tos_uri</c> — OPTIONAL; terms-of-service URL. May be language-tagged (§2.1).</summary>
    public static readonly string ResourceTosUri = Utf8Constants.ToInternedString(ResourceTosUriUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TlsClientCertificateBoundAccessTokens"/>.</summary>
    public static ReadOnlySpan<byte> TlsClientCertificateBoundAccessTokensUtf8 => "tls_client_certificate_bound_access_tokens"u8;

    /// <summary><c>tls_client_certificate_bound_access_tokens</c> — OPTIONAL boolean (RFC 8705 support); defaults to false when omitted.</summary>
    public static readonly string TlsClientCertificateBoundAccessTokens = Utf8Constants.ToInternedString(TlsClientCertificateBoundAccessTokensUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationDetailsTypesSupported"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationDetailsTypesSupportedUtf8 => "authorization_details_types_supported"u8;

    /// <summary><c>authorization_details_types_supported</c> — OPTIONAL; RFC 9396 authorization details type values.</summary>
    public static readonly string AuthorizationDetailsTypesSupported = Utf8Constants.ToInternedString(AuthorizationDetailsTypesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DpopSigningAlgValuesSupported"/>.</summary>
    public static ReadOnlySpan<byte> DpopSigningAlgValuesSupportedUtf8 => "dpop_signing_alg_values_supported"u8;

    /// <summary><c>dpop_signing_alg_values_supported</c> — OPTIONAL; JWS algs for validating DPoP proof JWTs (RFC 9449).</summary>
    public static readonly string DpopSigningAlgValuesSupported = Utf8Constants.ToInternedString(DpopSigningAlgValuesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DpopBoundAccessTokensRequired"/>.</summary>
    public static ReadOnlySpan<byte> DpopBoundAccessTokensRequiredUtf8 => "dpop_bound_access_tokens_required"u8;

    /// <summary><c>dpop_bound_access_tokens_required</c> — OPTIONAL boolean (RFC 9449); defaults to false when omitted.</summary>
    public static readonly string DpopBoundAccessTokensRequired = Utf8Constants.ToInternedString(DpopBoundAccessTokensRequiredUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SignedMetadata"/>.</summary>
    public static ReadOnlySpan<byte> SignedMetadataUtf8 => "signed_metadata"u8;

    /// <summary>
    /// <c>signed_metadata</c> — OPTIONAL; a JWT asserting the metadata values
    /// as claims (§2.2). It SHOULD NOT appear as a claim inside that JWT, and
    /// it is RECOMMENDED to reject metadata in which this occurs.
    /// </summary>
    public static readonly string SignedMetadata = Utf8Constants.ToInternedString(SignedMetadataUtf8);
}


/// <summary>
/// The defined <c>bearer_methods_supported</c> values (RFC 9728 §2): the RFC
/// 6750 bearer-token carriage methods.
/// </summary>
public static class BearerMethodValues
{
    /// <summary>The UTF-8 source literal of <see cref="Header"/>.</summary>
    public static ReadOnlySpan<byte> HeaderUtf8 => "header"u8;

    /// <summary><c>header</c> — the Authorization request header field (RFC 6750 §2.1).</summary>
    public static readonly string Header = Utf8Constants.ToInternedString(HeaderUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Body"/>.</summary>
    public static ReadOnlySpan<byte> BodyUtf8 => "body"u8;

    /// <summary><c>body</c> — the form-encoded body parameter (RFC 6750 §2.2).</summary>
    public static readonly string Body = Utf8Constants.ToInternedString(BodyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Query"/>.</summary>
    public static ReadOnlySpan<byte> QueryUtf8 => "query"u8;

    /// <summary><c>query</c> — the URI query parameter (RFC 6750 §2.3).</summary>
    public static readonly string Query = Utf8Constants.ToInternedString(QueryUtf8);


    /// <summary>Whether <paramref name="value"/> is one of the three defined values.</summary>
    public static bool IsDefined(string value) => Equals(value, Header) || Equals(value, Body) || Equals(value, Query);


    /// <summary>Compares two values for equality (code-point equality per RFC 9728 §6).</summary>
    public static bool Equals(string valueA, string valueB) =>
        object.ReferenceEquals(valueA, valueB) || System.StringComparer.Ordinal.Equals(valueA, valueB);
}
