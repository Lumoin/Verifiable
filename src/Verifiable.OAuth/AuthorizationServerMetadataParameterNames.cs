using Verifiable.Cryptography.Text;


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
    /// <summary>The UTF-8 source literal of <see cref="Issuer"/>.</summary>
    public static ReadOnlySpan<byte> IssuerUtf8 => "issuer"u8;

    /// <summary>
    /// URL of the authorization server's issuer identifier.
    /// </summary>
    public static readonly string Issuer = Utf8Constants.ToInternedString(IssuerUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationEndpointUtf8 => "authorization_endpoint"u8;

    /// <summary>
    /// URL of the authorization server's authorization endpoint.
    /// </summary>
    public static readonly string AuthorizationEndpoint = Utf8Constants.ToInternedString(AuthorizationEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TokenEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> TokenEndpointUtf8 => "token_endpoint"u8;

    /// <summary>
    /// URL of the authorization server's token endpoint.
    /// </summary>
    public static readonly string TokenEndpoint = Utf8Constants.ToInternedString(TokenEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="JwksUri"/>.</summary>
    public static ReadOnlySpan<byte> JwksUriUtf8 => "jwks_uri"u8;

    /// <summary>
    /// URL of the authorization server's JWK Set document.
    /// </summary>
    public static readonly string JwksUri = Utf8Constants.ToInternedString(JwksUriUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RegistrationEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> RegistrationEndpointUtf8 => "registration_endpoint"u8;

    /// <summary>
    /// URL of the authorization server's dynamic client registration endpoint.
    /// </summary>
    public static readonly string RegistrationEndpoint = Utf8Constants.ToInternedString(RegistrationEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ScopesSupported"/>.</summary>
    public static ReadOnlySpan<byte> ScopesSupportedUtf8 => "scopes_supported"u8;

    /// <summary>
    /// JSON array of supported scope values.
    /// </summary>
    public static readonly string ScopesSupported = Utf8Constants.ToInternedString(ScopesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ResponseTypesSupported"/>.</summary>
    public static ReadOnlySpan<byte> ResponseTypesSupportedUtf8 => "response_types_supported"u8;

    /// <summary>
    /// JSON array of supported response types.
    /// </summary>
    public static readonly string ResponseTypesSupported = Utf8Constants.ToInternedString(ResponseTypesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="GrantTypesSupported"/>.</summary>
    public static ReadOnlySpan<byte> GrantTypesSupportedUtf8 => "grant_types_supported"u8;

    /// <summary>
    /// JSON array of supported grant types.
    /// </summary>
    public static readonly string GrantTypesSupported = Utf8Constants.ToInternedString(GrantTypesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ResponseModesSupported"/>.</summary>
    public static ReadOnlySpan<byte> ResponseModesSupportedUtf8 => "response_modes_supported"u8;

    /// <summary>
    /// JSON array of supported response modes, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-2">RFC 8414 §2</see>.
    /// JARM §4 adds the four JWT-secured values
    /// (<see cref="Jarm.JarmResponseModes"/>).
    /// </summary>
    public static readonly string ResponseModesSupported = Utf8Constants.ToInternedString(ResponseModesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationDetailsTypesSupported"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationDetailsTypesSupportedUtf8 => "authorization_details_types_supported"u8;

    /// <summary>
    /// JSON array of the RFC 9396 authorization details type values the server supports, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-10">RFC 9396 §10</see>.
    /// </summary>
    public static readonly string AuthorizationDetailsTypesSupported = Utf8Constants.ToInternedString(AuthorizationDetailsTypesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RevocationEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> RevocationEndpointUtf8 => "revocation_endpoint"u8;

    /// <summary>
    /// URL of the authorization server's token revocation endpoint (RFC 7009).
    /// </summary>
    public static readonly string RevocationEndpoint = Utf8Constants.ToInternedString(RevocationEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IntrospectionEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> IntrospectionEndpointUtf8 => "introspection_endpoint"u8;

    /// <summary>
    /// URL of the authorization server's token introspection endpoint (RFC 7662).
    /// </summary>
    public static readonly string IntrospectionEndpoint = Utf8Constants.ToInternedString(IntrospectionEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="GlobalTokenRevocationEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> GlobalTokenRevocationEndpointUtf8 => "global_token_revocation_endpoint"u8;

    /// <summary>
    /// URL of the authorization server's Global Token Revocation endpoint
    /// (draft-parecki-oauth-global-token-revocation).
    /// </summary>
    public static readonly string GlobalTokenRevocationEndpoint = Utf8Constants.ToInternedString(GlobalTokenRevocationEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EndSessionEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> EndSessionEndpointUtf8 => "end_session_endpoint"u8;

    /// <summary>
    /// URL of the OP's RP-Initiated Logout end-session endpoint
    /// (<see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html">OIDC RP-Initiated Logout 1.0</see>).
    /// </summary>
    public static readonly string EndSessionEndpoint = Utf8Constants.ToInternedString(EndSessionEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UiLocalesSupported"/>.</summary>
    public static ReadOnlySpan<byte> UiLocalesSupportedUtf8 => "ui_locales_supported"u8;

    /// <summary>
    /// Languages and scripts supported for the user interface, as a JSON array of
    /// BCP47 language tags (<see href="https://openid.net/specs/openid-connect-discovery-1_0.html">OIDC Discovery 1.0 §3</see>).
    /// The library renders no user interface, so this is application-contributed (the
    /// deployment's UI languages) via <see cref="Server.AuthorizationServerIntegration.ContributeDiscoveryFieldsAsync"/>;
    /// it advertises the languages an OP would honour for the RP-Initiated Logout
    /// <c>ui_locales</c> request parameter.
    /// </summary>
    public static readonly string UiLocalesSupported = Utf8Constants.ToInternedString(UiLocalesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AcrValuesSupported"/>.</summary>
    public static ReadOnlySpan<byte> AcrValuesSupportedUtf8 => "acr_values_supported"u8;

    /// <summary>
    /// Authentication Context Class References the authorization server supports, as a
    /// JSON array (<see href="https://www.rfc-editor.org/rfc/rfc8414#section-2">RFC 8414 §2</see>;
    /// <see href="https://openid.net/specs/openid-connect-discovery-1_0.html">OIDC Discovery 1.0 §3</see>).
    /// <see href="https://www.rfc-editor.org/rfc/rfc9470#section-7">RFC 9470 §7</see> (step-up
    /// authentication) has the AS advertise this so resource servers and clients know which
    /// <c>acr</c> values they may demand. The supported assurance levels are a property of how
    /// a deployment authenticates End-Users — knowledge the transport-agnostic library does not
    /// hold — so this is application-contributed (the deployment's authentication levels) via
    /// <see cref="Server.AuthorizationServerIntegration.ContributeDiscoveryFieldsAsync"/>,
    /// mirroring <see cref="UiLocalesSupported"/>.
    /// </summary>
    public static readonly string AcrValuesSupported = Utf8Constants.ToInternedString(AcrValuesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="BackchannelLogoutSupported"/>.</summary>
    public static ReadOnlySpan<byte> BackchannelLogoutSupportedUtf8 => "backchannel_logout_supported"u8;

    /// <summary>
    /// Whether the OP supports OIDC Back-Channel Logout, advertised as
    /// <c>backchannel_logout_supported</c> per
    /// <see href="https://openid.net/specs/openid-connect-backchannel-1_0.html#BCSupport">OIDC Back-Channel Logout 1.0 §4</see>.
    /// </summary>
    public static readonly string BackchannelLogoutSupported = Utf8Constants.ToInternedString(BackchannelLogoutSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="BackchannelLogoutSessionSupported"/>.</summary>
    public static ReadOnlySpan<byte> BackchannelLogoutSessionSupportedUtf8 => "backchannel_logout_session_supported"u8;

    /// <summary>
    /// Whether the OP includes a <c>sid</c> claim in its Logout Tokens (enabling
    /// per-session back-channel logout), advertised as
    /// <c>backchannel_logout_session_supported</c> per
    /// <see href="https://openid.net/specs/openid-connect-backchannel-1_0.html#BCSupport">OIDC Back-Channel Logout 1.0 §4</see>.
    /// </summary>
    public static readonly string BackchannelLogoutSessionSupported = Utf8Constants.ToInternedString(BackchannelLogoutSessionSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PushedAuthorizationRequestEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> PushedAuthorizationRequestEndpointUtf8 => "pushed_authorization_request_endpoint"u8;

    /// <summary>
    /// URL of the authorization server's pushed authorization request endpoint (RFC 9126).
    /// </summary>
    public static readonly string PushedAuthorizationRequestEndpoint = Utf8Constants.ToInternedString(PushedAuthorizationRequestEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RequirePushedAuthorizationRequests"/>.</summary>
    public static ReadOnlySpan<byte> RequirePushedAuthorizationRequestsUtf8 => "require_pushed_authorization_requests"u8;

    /// <summary>
    /// Whether the authorization server requires Pushed Authorization Requests (RFC 9126 §5).
    /// FAPI 2.0 §5.2.2 mandates this be <see langword="true"/>.
    /// </summary>
    public static readonly string RequirePushedAuthorizationRequests = Utf8Constants.ToInternedString(RequirePushedAuthorizationRequestsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationResponseIssParameterSupported"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationResponseIssParameterSupportedUtf8 => "authorization_response_iss_parameter_supported"u8;

    /// <summary>
    /// Whether the authorization server supports the <c>iss</c> authorization response
    /// parameter (RFC 9207).
    /// </summary>
    public static readonly string AuthorizationResponseIssParameterSupported = Utf8Constants.ToInternedString(AuthorizationResponseIssParameterSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DpopSigningAlgValuesSupported"/>.</summary>
    public static ReadOnlySpan<byte> DpopSigningAlgValuesSupportedUtf8 => "dpop_signing_alg_values_supported"u8;

    /// <summary>
    /// The JWS algorithms the authorization server accepts on DPoP proofs (RFC 9449 §5.1).
    /// </summary>
    public static readonly string DpopSigningAlgValuesSupported = Utf8Constants.ToInternedString(DpopSigningAlgValuesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StatusListAggregationEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> StatusListAggregationEndpointUtf8 => "status_list_aggregation_endpoint"u8;

    /// <summary>
    /// URL of the Status List Aggregation endpoint (draft-ietf-oauth-status-list).
    /// </summary>
    public static readonly string StatusListAggregationEndpoint = Utf8Constants.ToInternedString(StatusListAggregationEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TokenEndpointAuthMethodsSupported"/>.</summary>
    public static ReadOnlySpan<byte> TokenEndpointAuthMethodsSupportedUtf8 => "token_endpoint_auth_methods_supported"u8;

    /// <summary>
    /// JSON array of client authentication methods the token endpoint
    /// accepts. RFC 8414 §2. IANA registry: <c>"none"</c>,
    /// <c>"client_secret_basic"</c>, <c>"client_secret_post"</c>,
    /// <c>"client_secret_jwt"</c>, <c>"private_key_jwt"</c>,
    /// <c>"tls_client_auth"</c>, <c>"self_signed_tls_client_auth"</c>,
    /// <c>"attest_jwt_client_auth"</c>.
    /// </summary>
    public static readonly string TokenEndpointAuthMethodsSupported = Utf8Constants.ToInternedString(TokenEndpointAuthMethodsSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CodeChallengeMethodsSupported"/>.</summary>
    public static ReadOnlySpan<byte> CodeChallengeMethodsSupportedUtf8 => "code_challenge_methods_supported"u8;

    /// <summary>
    /// JSON array of PKCE code challenge methods the authorization server
    /// supports per RFC 7636 §6.2.1. Registered values: <c>"plain"</c> and
    /// <c>"S256"</c>.
    /// </summary>
    public static readonly string CodeChallengeMethodsSupported = Utf8Constants.ToInternedString(CodeChallengeMethodsSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ProtectedResources"/>.</summary>
    public static ReadOnlySpan<byte> ProtectedResourcesUtf8 => "protected_resources"u8;

    /// <summary>
    /// JSON array of resource identifiers for OAuth protected resources usable
    /// with this authorization server, per RFC 9728 §4. OPTIONAL — used only
    /// when the set of legitimate protected resources is enumerable; an
    /// application contributes it through the discovery-fields seam.
    /// </summary>
    public static readonly string ProtectedResources = Utf8Constants.ToInternedString(ProtectedResourcesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PreAuthorizedGrantAnonymousAccessSupported"/>.</summary>
    public static ReadOnlySpan<byte> PreAuthorizedGrantAnonymousAccessSupportedUtf8 => "pre-authorized_grant_anonymous_access_supported"u8;

    /// <summary>
    /// Whether the Credential Issuer accepts a Token Request with a Pre-Authorized Code but
    /// without a <c>client_id</c>, advertised as
    /// <c>pre-authorized_grant_anonymous_access_supported</c> per
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.3">OID4VCI 1.0 §12.3</see>:
    /// "A boolean indicating whether the Credential Issuer accepts a Token Request with a
    /// Pre-Authorized Code but without a <c>client_id</c>. The default is false." The anonymous
    /// access BEHAVIOR is enforced by the
    /// <see cref="Server.ValidatePreAuthorizedCodeDelegate"/> seam (a deployment that requires
    /// client authentication denies with
    /// <see cref="Oid4Vci.PreAuthorizedCodeDenialReason.ClientAuthenticationRequired"/>); this
    /// parameter is the matching ADVERTISEMENT.
    /// </summary>
    public static readonly string PreAuthorizedGrantAnonymousAccessSupported = Utf8Constants.ToInternedString(PreAuthorizedGrantAnonymousAccessSupportedUtf8);
}
