using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth;

/// <summary>
/// Well-known parameter NAMES for the OpenID Federation metadata
/// document per OpenID Federation 1.0. These are JSON keys appearing in
/// federation entity statements and federation endpoint discovery
/// documents.
/// </summary>
/// <remarks>
/// These are the NAMES of federation metadata parameters (e.g.,
/// <c>"federation_fetch_endpoint"</c>, <c>"federation_list_endpoint"</c>),
/// not their VALUES. Most carry endpoint URLs; a few carry other shapes
/// (an algorithm array for <see cref="EndpointAuthSigningAlgValuesSupported"/>,
/// or the §5.2.1 JWK-set parameters that MUST NOT appear under
/// <c>federation_entity</c>).
/// </remarks>
public static class FederationMetadataParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="FetchEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> FetchEndpointUtf8 => "federation_fetch_endpoint"u8;

    /// <summary>
    /// URL of the federation fetch endpoint for retrieving subordinate statements.
    /// </summary>
    public static readonly string FetchEndpoint = Utf8Constants.ToInternedString(FetchEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ListEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> ListEndpointUtf8 => "federation_list_endpoint"u8;

    /// <summary>
    /// URL of the federation list endpoint for listing subordinate entities.
    /// </summary>
    public static readonly string ListEndpoint = Utf8Constants.ToInternedString(ListEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ResolveEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> ResolveEndpointUtf8 => "federation_resolve_endpoint"u8;

    /// <summary>
    /// URL of the federation resolve endpoint.
    /// </summary>
    public static readonly string ResolveEndpoint = Utf8Constants.ToInternedString(ResolveEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustMarkStatusEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> TrustMarkStatusEndpointUtf8 => "federation_trust_mark_status_endpoint"u8;

    /// <summary>
    /// URL of the federation trust mark status endpoint.
    /// </summary>
    public static readonly string TrustMarkStatusEndpoint = Utf8Constants.ToInternedString(TrustMarkStatusEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustMarkListEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> TrustMarkListEndpointUtf8 => "federation_trust_mark_list_endpoint"u8;

    /// <summary>
    /// URL of the federation Trust Marked Entities Listing endpoint per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-5.1.1">Federation §5.1.1</see>
    /// (endpoint defined in §8.5). The spec wire name is
    /// <c>federation_trust_mark_list_endpoint</c>.
    /// </summary>
    public static readonly string TrustMarkListEndpoint = Utf8Constants.ToInternedString(TrustMarkListEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustMarkEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> TrustMarkEndpointUtf8 => "federation_trust_mark_endpoint"u8;

    /// <summary>
    /// URL of the federation trust mark endpoint.
    /// </summary>
    public static readonly string TrustMarkEndpoint = Utf8Constants.ToInternedString(TrustMarkEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="HistoricalKeysEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> HistoricalKeysEndpointUtf8 => "federation_historical_keys_endpoint"u8;

    /// <summary>
    /// URL of the federation historical keys endpoint.
    /// </summary>
    public static readonly string HistoricalKeysEndpoint = Utf8Constants.ToInternedString(HistoricalKeysEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FetchEndpointAuthMethods"/>.</summary>
    public static ReadOnlySpan<byte> FetchEndpointAuthMethodsUtf8 => "federation_fetch_endpoint_auth_methods"u8;

    /// <summary>
    /// <c>federation_fetch_endpoint_auth_methods</c> — the client-authentication
    /// methods the §8.1 fetch endpoint supports, per Federation §8.8.1. Parallels
    /// <c>token_endpoint_auth_methods_supported</c>; the value <c>none</c> (the
    /// default if omitted) means client authentication is not required.
    /// </summary>
    public static readonly string FetchEndpointAuthMethods = Utf8Constants.ToInternedString(FetchEndpointAuthMethodsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ListEndpointAuthMethods"/>.</summary>
    public static ReadOnlySpan<byte> ListEndpointAuthMethodsUtf8 => "federation_list_endpoint_auth_methods"u8;

    /// <summary>
    /// <c>federation_list_endpoint_auth_methods</c> — client-authentication
    /// methods the §8.2 listing endpoint supports, per Federation §8.8.1.
    /// </summary>
    public static readonly string ListEndpointAuthMethods = Utf8Constants.ToInternedString(ListEndpointAuthMethodsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ResolveEndpointAuthMethods"/>.</summary>
    public static ReadOnlySpan<byte> ResolveEndpointAuthMethodsUtf8 => "federation_resolve_endpoint_auth_methods"u8;

    /// <summary>
    /// <c>federation_resolve_endpoint_auth_methods</c> — client-authentication
    /// methods the §8.3 resolve endpoint supports, per Federation §8.8.1.
    /// </summary>
    public static readonly string ResolveEndpointAuthMethods = Utf8Constants.ToInternedString(ResolveEndpointAuthMethodsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustMarkStatusEndpointAuthMethods"/>.</summary>
    public static ReadOnlySpan<byte> TrustMarkStatusEndpointAuthMethodsUtf8 => "federation_trust_mark_status_endpoint_auth_methods"u8;

    /// <summary>
    /// <c>federation_trust_mark_status_endpoint_auth_methods</c> — client-authentication
    /// methods the §8.4 trust mark status endpoint supports, per Federation §8.8.1.
    /// </summary>
    public static readonly string TrustMarkStatusEndpointAuthMethods = Utf8Constants.ToInternedString(TrustMarkStatusEndpointAuthMethodsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustMarkListEndpointAuthMethods"/>.</summary>
    public static ReadOnlySpan<byte> TrustMarkListEndpointAuthMethodsUtf8 => "federation_trust_mark_list_endpoint_auth_methods"u8;

    /// <summary>
    /// <c>federation_trust_mark_list_endpoint_auth_methods</c> — client-authentication
    /// methods the §8.5 trust marked entities listing endpoint supports, per Federation §8.8.1.
    /// </summary>
    public static readonly string TrustMarkListEndpointAuthMethods = Utf8Constants.ToInternedString(TrustMarkListEndpointAuthMethodsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustMarkEndpointAuthMethods"/>.</summary>
    public static ReadOnlySpan<byte> TrustMarkEndpointAuthMethodsUtf8 => "federation_trust_mark_endpoint_auth_methods"u8;

    /// <summary>
    /// <c>federation_trust_mark_endpoint_auth_methods</c> — client-authentication
    /// methods the §8.6 trust mark endpoint supports, per Federation §8.8.1.
    /// </summary>
    public static readonly string TrustMarkEndpointAuthMethods = Utf8Constants.ToInternedString(TrustMarkEndpointAuthMethodsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="HistoricalKeysEndpointAuthMethods"/>.</summary>
    public static ReadOnlySpan<byte> HistoricalKeysEndpointAuthMethodsUtf8 => "federation_historical_keys_endpoint_auth_methods"u8;

    /// <summary>
    /// <c>federation_historical_keys_endpoint_auth_methods</c> — client-authentication
    /// methods the §8.7 historical keys endpoint supports, per Federation §8.8.1.
    /// </summary>
    public static readonly string HistoricalKeysEndpointAuthMethods = Utf8Constants.ToInternedString(HistoricalKeysEndpointAuthMethodsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EndpointAuthSigningAlgValuesSupported"/>.</summary>
    public static ReadOnlySpan<byte> EndpointAuthSigningAlgValuesSupportedUtf8 => "endpoint_auth_signing_alg_values_supported"u8;

    /// <summary>
    /// <c>endpoint_auth_signing_alg_values_supported</c> — the JWS <c>alg</c>
    /// values an entity supports for the <c>private_key_jwt</c> JWT used when
    /// authenticating to its federation endpoints (§8.8), per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-5.1.1">Federation §5.1.1</see>.
    /// Unlike the sibling endpoint members this is an array of algorithm
    /// identifiers, not a URL; the value <c>none</c> MUST NOT appear in it.
    /// </summary>
    public static readonly string EndpointAuthSigningAlgValuesSupported = Utf8Constants.ToInternedString(EndpointAuthSigningAlgValuesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Jwks"/>.</summary>
    public static ReadOnlySpan<byte> JwksUtf8 => "jwks"u8;

    /// <summary>
    /// <c>jwks</c> — an inline JWK Set for an Entity Type's metadata, per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-5.2.1">Federation §5.2.1</see>.
    /// Distinct from the Entity Statement's top-level <c>jwks</c> (the
    /// Federation Entity Keys); this §5.2.1 JWK-set parameter MUST NOT appear
    /// under <c>federation_entity</c> metadata.
    /// </summary>
    public static readonly string Jwks = Utf8Constants.ToInternedString(JwksUtf8);

    /// <summary>The UTF-8 source literal of <see cref="JwksUri"/>.</summary>
    public static ReadOnlySpan<byte> JwksUriUtf8 => "jwks_uri"u8;

    /// <summary>
    /// <c>jwks_uri</c> — a URL referencing an Entity Type's JWK Set, per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-5.2.1">Federation §5.2.1</see>.
    /// This §5.2.1 JWK-set parameter MUST NOT appear under
    /// <c>federation_entity</c> metadata.
    /// </summary>
    public static readonly string JwksUri = Utf8Constants.ToInternedString(JwksUriUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SignedJwksUri"/>.</summary>
    public static ReadOnlySpan<byte> SignedJwksUriUtf8 => "signed_jwks_uri"u8;

    /// <summary>
    /// <c>signed_jwks_uri</c> — a URL referencing a signed JWT whose payload is
    /// an Entity Type's JWK Set, per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-5.2.1">Federation §5.2.1</see>.
    /// This §5.2.1 JWK-set parameter MUST NOT appear under
    /// <c>federation_entity</c> metadata.
    /// </summary>
    public static readonly string SignedJwksUri = Utf8Constants.ToInternedString(SignedJwksUriUtf8);
}
