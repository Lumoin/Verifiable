namespace Verifiable.OAuth;

/// <summary>
/// Well-known parameter NAMES for the OAuth 2.0 Authorization Server
/// metadata document per
/// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414 §3</see>.
/// These are JSON keys appearing in the document published at
/// <c>/.well-known/oauth-authorization-server</c> (or the OIDC Discovery
/// equivalent at <c>/.well-known/openid-configuration</c>).
/// </summary>
/// <remarks>
/// These are the NAMES of metadata parameters (<c>"issuer"</c>,
/// <c>"authorization_endpoint"</c>, <c>"token_endpoint"</c>), not their
/// VALUES. Values are deployment-specific URLs, capability lists, or
/// boolean flags. Sibling registries for adjacent specs live in
/// <see cref="OpenIdProviderMetadataParameterNames"/>,
/// <see cref="FederationMetadataParameterNames"/>,
/// <see cref="CredentialIssuerMetadataParameterNames"/>, and
/// <see cref="AuthZenMetadataParameterNames"/>.
/// </remarks>
public static class AuthorizationServerMetadataParameterNames
{
    /// <summary>
    /// URL of the authorization server's issuer identifier.
    /// </summary>
    public static readonly string Issuer = "issuer";

    /// <summary>
    /// URL of the authorization server's authorization endpoint.
    /// </summary>
    public static readonly string AuthorizationEndpoint = "authorization_endpoint";

    /// <summary>
    /// URL of the authorization server's token endpoint.
    /// </summary>
    public static readonly string TokenEndpoint = "token_endpoint";

    /// <summary>
    /// URL of the authorization server's JWK Set document.
    /// </summary>
    public static readonly string JwksUri = "jwks_uri";

    /// <summary>
    /// URL of the authorization server's dynamic client registration endpoint.
    /// </summary>
    public static readonly string RegistrationEndpoint = "registration_endpoint";

    /// <summary>
    /// JSON array of supported scope values.
    /// </summary>
    public static readonly string ScopesSupported = "scopes_supported";

    /// <summary>
    /// JSON array of supported response types.
    /// </summary>
    public static readonly string ResponseTypesSupported = "response_types_supported";

    /// <summary>
    /// JSON array of supported grant types.
    /// </summary>
    public static readonly string GrantTypesSupported = "grant_types_supported";

    /// <summary>
    /// URL of the authorization server's token revocation endpoint (RFC 7009).
    /// </summary>
    public static readonly string RevocationEndpoint = "revocation_endpoint";

    /// <summary>
    /// URL of the authorization server's token introspection endpoint (RFC 7662).
    /// </summary>
    public static readonly string IntrospectionEndpoint = "introspection_endpoint";

    /// <summary>
    /// URL of the authorization server's pushed authorization request endpoint (RFC 9126).
    /// </summary>
    public static readonly string PushedAuthorizationRequestEndpoint = "pushed_authorization_request_endpoint";

    /// <summary>
    /// Whether the authorization server requires Pushed Authorization Requests (RFC 9126 §5).
    /// FAPI 2.0 §5.2.2 mandates this be <see langword="true"/>.
    /// </summary>
    public static readonly string RequirePushedAuthorizationRequests = "require_pushed_authorization_requests";

    /// <summary>
    /// Whether the authorization server supports the <c>iss</c> authorization response
    /// parameter (RFC 9207).
    /// </summary>
    public static readonly string AuthorizationResponseIssParameterSupported = "authorization_response_iss_parameter_supported";

    /// <summary>
    /// The JWS algorithms the authorization server accepts on DPoP proofs (RFC 9449 §5.1).
    /// </summary>
    public static readonly string DpopSigningAlgValuesSupported = "dpop_signing_alg_values_supported";

    /// <summary>
    /// URL of the Status List Aggregation endpoint (draft-ietf-oauth-status-list).
    /// </summary>
    public static readonly string StatusListAggregationEndpoint = "status_list_aggregation_endpoint";

    /// <summary>
    /// JSON array of client authentication methods the token endpoint
    /// accepts. RFC 8414 §2. IANA registry: <c>"none"</c>,
    /// <c>"client_secret_basic"</c>, <c>"client_secret_post"</c>,
    /// <c>"client_secret_jwt"</c>, <c>"private_key_jwt"</c>,
    /// <c>"tls_client_auth"</c>, <c>"self_signed_tls_client_auth"</c>,
    /// <c>"attest_jwt_client_auth"</c>.
    /// </summary>
    public static readonly string TokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported";

    /// <summary>
    /// JSON array of PKCE code challenge methods the authorization server
    /// supports per RFC 7636 §6.2.1. Registered values: <c>"plain"</c> and
    /// <c>"S256"</c>.
    /// </summary>
    public static readonly string CodeChallengeMethodsSupported = "code_challenge_methods_supported";

    /// <summary>
    /// JSON array of resource identifiers for OAuth protected resources usable
    /// with this authorization server, per RFC 9728 §4. OPTIONAL — used only
    /// when the set of legitimate protected resources is enumerable; an
    /// application contributes it through the discovery-fields seam.
    /// </summary>
    public static readonly string ProtectedResources = "protected_resources";
}
