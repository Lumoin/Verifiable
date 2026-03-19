namespace Verifiable.OAuth;

/// <summary>
/// Core OAuth 2.0 Authorization Server metadata keys (RFC 8414).
/// </summary>
public static class AuthorizationServerMetadataKeys
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
    /// URL of the Status List Aggregation endpoint (draft-ietf-oauth-status-list).
    /// </summary>
    public static readonly string StatusListAggregationEndpoint = "status_list_aggregation_endpoint";
}


/// <summary>
/// OpenID Connect Discovery metadata keys (OpenID.Discovery).
/// </summary>
public static class OpenIdProviderMetadataKeys
{
    /// <summary>
    /// URL of the OpenID Provider's UserInfo endpoint.
    /// </summary>
    public static readonly string UserinfoEndpoint = "userinfo_endpoint";

    /// <summary>
    /// JSON array of supported ID Token signing algorithms.
    /// </summary>
    public static readonly string IdTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported";

    /// <summary>
    /// JSON array of supported subject identifier types.
    /// </summary>
    public static readonly string SubjectTypesSupported = "subject_types_supported";
}


/// <summary>
/// OpenID Federation metadata keys (OpenID Federation 1.0).
/// </summary>
public static class FederationMetadataKeys
{
    /// <summary>
    /// URL of the federation fetch endpoint for retrieving subordinate statements.
    /// </summary>
    public static readonly string FetchEndpoint = "federation_fetch_endpoint";

    /// <summary>
    /// URL of the federation list endpoint for listing subordinate entities.
    /// </summary>
    public static readonly string ListEndpoint = "federation_list_endpoint";

    /// <summary>
    /// URL of the federation resolve endpoint.
    /// </summary>
    public static readonly string ResolveEndpoint = "federation_resolve_endpoint";

    /// <summary>
    /// URL of the federation trust mark status endpoint.
    /// </summary>
    public static readonly string TrustMarkStatusEndpoint = "federation_trust_mark_status_endpoint";

    /// <summary>
    /// URL of the federation trust mark listing endpoint.
    /// </summary>
    public static readonly string TrustMarkListingEndpoint = "federation_trust_mark_listing_endpoint";

    /// <summary>
    /// URL of the federation trust mark endpoint.
    /// </summary>
    public static readonly string TrustMarkEndpoint = "federation_trust_mark_endpoint";

    /// <summary>
    /// URL of the federation historical keys endpoint.
    /// </summary>
    public static readonly string HistoricalKeysEndpoint = "federation_historical_keys_endpoint";
}


/// <summary>
/// OpenID for Verifiable Credential Issuance metadata keys (OID4VCI).
/// </summary>
public static class CredentialIssuerMetadataKeys
{
    /// <summary>
    /// URL of the credential issuer's credential endpoint.
    /// </summary>
    public static readonly string CredentialEndpoint = "credential_endpoint";

    /// <summary>
    /// URL of the credential issuer's batch credential endpoint.
    /// </summary>
    public static readonly string BatchCredentialEndpoint = "batch_credential_endpoint";

    /// <summary>
    /// URL of the credential issuer's deferred credential endpoint.
    /// </summary>
    public static readonly string DeferredCredentialEndpoint = "deferred_credential_endpoint";

    /// <summary>
    /// URL of the credential issuer's notification endpoint.
    /// </summary>
    public static readonly string NotificationEndpoint = "notification_endpoint";
}


/// <summary>
/// AuthZEN Authorization API metadata keys (Authorization API 1.0).
/// </summary>
public static class AuthZenMetadataKeys
{
    /// <summary>
    /// URL of the PDP's access evaluation endpoint.
    /// </summary>
    public static readonly string EvaluationEndpoint = "evaluation_endpoint";

    /// <summary>
    /// URL of the PDP's batch access evaluations endpoint.
    /// </summary>
    public static readonly string EvaluationsEndpoint = "evaluations_endpoint";

    /// <summary>
    /// URL of the PDP's subject search endpoint.
    /// </summary>
    public static readonly string SubjectSearchEndpoint = "subject_search_endpoint";

    /// <summary>
    /// URL of the PDP's resource search endpoint.
    /// </summary>
    public static readonly string ResourceSearchEndpoint = "resource_search_endpoint";

    /// <summary>
    /// URL of the PDP's action search endpoint.
    /// </summary>
    public static readonly string ActionSearchEndpoint = "action_search_endpoint";
}
