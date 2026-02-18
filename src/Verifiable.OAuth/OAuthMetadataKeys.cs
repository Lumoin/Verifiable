namespace Verifiable.OAuth;

/// <summary>
/// Core OAuth 2.0 Authorization Server metadata keys (RFC 8414).
/// </summary>
public static class AuthorizationServerMetadataKeys
{
    /// <summary>
    /// URL of the authorization server's issuer identifier.
    /// </summary>
    public const string Issuer = "issuer";

    /// <summary>
    /// URL of the authorization server's authorization endpoint.
    /// </summary>
    public const string AuthorizationEndpoint = "authorization_endpoint";

    /// <summary>
    /// URL of the authorization server's token endpoint.
    /// </summary>
    public const string TokenEndpoint = "token_endpoint";

    /// <summary>
    /// URL of the authorization server's JWK Set document.
    /// </summary>
    public const string JwksUri = "jwks_uri";

    /// <summary>
    /// URL of the authorization server's dynamic client registration endpoint.
    /// </summary>
    public const string RegistrationEndpoint = "registration_endpoint";

    /// <summary>
    /// JSON array of supported scope values.
    /// </summary>
    public const string ScopesSupported = "scopes_supported";

    /// <summary>
    /// JSON array of supported response types.
    /// </summary>
    public const string ResponseTypesSupported = "response_types_supported";

    /// <summary>
    /// JSON array of supported grant types.
    /// </summary>
    public const string GrantTypesSupported = "grant_types_supported";

    /// <summary>
    /// URL of the authorization server's token revocation endpoint (RFC 7009).
    /// </summary>
    public const string RevocationEndpoint = "revocation_endpoint";

    /// <summary>
    /// URL of the authorization server's token introspection endpoint (RFC 7662).
    /// </summary>
    public const string IntrospectionEndpoint = "introspection_endpoint";

    /// <summary>
    /// URL of the authorization server's pushed authorization request endpoint (RFC 9126).
    /// </summary>
    public const string PushedAuthorizationRequestEndpoint = "pushed_authorization_request_endpoint";

    /// <summary>
    /// URL of the Status List Aggregation endpoint (draft-ietf-oauth-status-list).
    /// </summary>
    public const string StatusListAggregationEndpoint = "status_list_aggregation_endpoint";
}


/// <summary>
/// OpenID Connect Discovery metadata keys (OpenID.Discovery).
/// </summary>
public static class OpenIdProviderMetadataKeys
{
    /// <summary>
    /// URL of the OpenID Provider's UserInfo endpoint.
    /// </summary>
    public const string UserinfoEndpoint = "userinfo_endpoint";

    /// <summary>
    /// JSON array of supported ID Token signing algorithms.
    /// </summary>
    public const string IdTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported";

    /// <summary>
    /// JSON array of supported subject identifier types.
    /// </summary>
    public const string SubjectTypesSupported = "subject_types_supported";
}


/// <summary>
/// OpenID Federation metadata keys (OpenID Federation 1.0).
/// </summary>
public static class FederationMetadataKeys
{
    /// <summary>
    /// URL of the federation fetch endpoint for retrieving subordinate statements.
    /// </summary>
    public const string FetchEndpoint = "federation_fetch_endpoint";

    /// <summary>
    /// URL of the federation list endpoint for listing subordinate entities.
    /// </summary>
    public const string ListEndpoint = "federation_list_endpoint";

    /// <summary>
    /// URL of the federation resolve endpoint.
    /// </summary>
    public const string ResolveEndpoint = "federation_resolve_endpoint";

    /// <summary>
    /// URL of the federation trust mark status endpoint.
    /// </summary>
    public const string TrustMarkStatusEndpoint = "federation_trust_mark_status_endpoint";

    /// <summary>
    /// URL of the federation trust mark listing endpoint.
    /// </summary>
    public const string TrustMarkListingEndpoint = "federation_trust_mark_listing_endpoint";

    /// <summary>
    /// URL of the federation trust mark endpoint.
    /// </summary>
    public const string TrustMarkEndpoint = "federation_trust_mark_endpoint";

    /// <summary>
    /// URL of the federation historical keys endpoint.
    /// </summary>
    public const string HistoricalKeysEndpoint = "federation_historical_keys_endpoint";
}


/// <summary>
/// OpenID for Verifiable Credential Issuance metadata keys (OID4VCI).
/// </summary>
public static class CredentialIssuerMetadataKeys
{
    /// <summary>
    /// URL of the credential issuer's credential endpoint.
    /// </summary>
    public const string CredentialEndpoint = "credential_endpoint";

    /// <summary>
    /// URL of the credential issuer's batch credential endpoint.
    /// </summary>
    public const string BatchCredentialEndpoint = "batch_credential_endpoint";

    /// <summary>
    /// URL of the credential issuer's deferred credential endpoint.
    /// </summary>
    public const string DeferredCredentialEndpoint = "deferred_credential_endpoint";

    /// <summary>
    /// URL of the credential issuer's notification endpoint.
    /// </summary>
    public const string NotificationEndpoint = "notification_endpoint";
}


/// <summary>
/// AuthZEN Authorization API metadata keys (Authorization API 1.0).
/// </summary>
public static class AuthZenMetadataKeys
{
    /// <summary>
    /// URL of the PDP's access evaluation endpoint.
    /// </summary>
    public const string EvaluationEndpoint = "evaluation_endpoint";

    /// <summary>
    /// URL of the PDP's batch access evaluations endpoint.
    /// </summary>
    public const string EvaluationsEndpoint = "evaluations_endpoint";

    /// <summary>
    /// URL of the PDP's subject search endpoint.
    /// </summary>
    public const string SubjectSearchEndpoint = "subject_search_endpoint";

    /// <summary>
    /// URL of the PDP's resource search endpoint.
    /// </summary>
    public const string ResourceSearchEndpoint = "resource_search_endpoint";

    /// <summary>
    /// URL of the PDP's action search endpoint.
    /// </summary>
    public const string ActionSearchEndpoint = "action_search_endpoint";
}