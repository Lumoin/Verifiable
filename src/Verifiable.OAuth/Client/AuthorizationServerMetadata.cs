using System.Diagnostics;

namespace Verifiable.OAuth.Client;

/// <summary>
/// The authorization server's metadata document as published at
/// <c>/.well-known/oauth-authorization-server</c> per
/// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414</see> or
/// <c>/.well-known/openid-configuration</c> per
/// <see href="https://openid.net/specs/openid-connect-discovery-1_0.html">OIDC Discovery 1.0</see>.
/// </summary>
/// <remarks>
/// <para>
/// Resolved per-call from the AS's <see cref="Issuer"/> via the
/// <see cref="ResolveAuthorizationServerMetadataDelegate"/> on
/// <see cref="OAuthClientInfrastructure"/>. The client does not persist this
/// shape — it is fetched, cached briefly per the application's caching
/// policy, and discarded.
/// </para>
/// <para>
/// Fields are optional except <see cref="Issuer"/>; whether a particular
/// endpoint is set depends on which protocols the AS supports.
/// Per-call resolvers populate the fields the responding metadata document
/// actually carries.
/// </para>
/// <para>
/// JWKS material itself is resolved separately via
/// <see cref="ResolveAuthorizationServerJwksDelegate"/> rather than embedded
/// here, because JWKS rotation and AS metadata rotation are independent
/// concerns with different caching characteristics.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthorizationServerMetadata Issuer={Issuer}")]
public sealed record AuthorizationServerMetadata
{
    /// <summary>
    /// The authorization server's issuer identifier per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-2">RFC 8414 §2</see>.
    /// </summary>
    public required Uri Issuer { get; init; }


    //Endpoint URIs — RFC 8414 §2 / OIDC Discovery §3.

    /// <summary>The authorization endpoint per RFC 6749 §3.1.</summary>
    public Uri? AuthorizationEndpoint { get; init; }

    /// <summary>The token endpoint per RFC 6749 §3.2.</summary>
    public Uri? TokenEndpoint { get; init; }

    /// <summary>The PAR endpoint per RFC 9126 §5.</summary>
    public Uri? PushedAuthorizationRequestEndpoint { get; init; }

    /// <summary>The revocation endpoint per RFC 7009.</summary>
    public Uri? RevocationEndpoint { get; init; }

    /// <summary>The introspection endpoint per RFC 7662.</summary>
    public Uri? IntrospectionEndpoint { get; init; }

    /// <summary>The AS's JWKS URI per RFC 8414 §2.</summary>
    public Uri? JwksUri { get; init; }

    /// <summary>The RFC 7591 dynamic registration endpoint.</summary>
    public Uri? RegistrationEndpoint { get; init; }

    /// <summary>The OIDC RP-Initiated Logout end-session endpoint.</summary>
    public Uri? EndSessionEndpoint { get; init; }

    /// <summary>The OIDC userinfo endpoint per OIDC Core §5.3.</summary>
    public Uri? UserInfoEndpoint { get; init; }

    /// <summary>The device authorization endpoint per RFC 8628 §3.1.</summary>
    public Uri? DeviceAuthorizationEndpoint { get; init; }


    //"Supported" capability lists — RFC 8414 §2 / OIDC Discovery §3.
    //Used by client-side preflight checks before invoking optional flows.

    /// <summary>
    /// The OAuth 2.0 response types the AS supports, advertised as
    /// <c>response_types_supported</c>.
    /// </summary>
    public IReadOnlyList<string> ResponseTypesSupported { get; init; } = [];

    /// <summary>
    /// The OAuth 2.0 grant types the AS supports, advertised as
    /// <c>grant_types_supported</c>.
    /// </summary>
    public IReadOnlyList<string> GrantTypesSupported { get; init; } = [];

    /// <summary>
    /// The client authentication methods supported at the token endpoint,
    /// advertised as <c>token_endpoint_auth_methods_supported</c>.
    /// </summary>
    public IReadOnlyList<string> TokenEndpointAuthMethodsSupported { get; init; } = [];

    /// <summary>
    /// The JWS algorithms supported for <c>client_secret_jwt</c> and
    /// <c>private_key_jwt</c> client assertions, advertised as
    /// <c>token_endpoint_auth_signing_alg_values_supported</c>.
    /// </summary>
    public IReadOnlyList<string> TokenEndpointAuthSigningAlgValuesSupported { get; init; } = [];

    /// <summary>
    /// The scope values the AS supports, advertised as
    /// <c>scopes_supported</c>.
    /// </summary>
    public IReadOnlyList<string> ScopesSupported { get; init; } = [];

    /// <summary>
    /// The PKCE code-challenge methods the AS supports, advertised as
    /// <c>code_challenge_methods_supported</c>.
    /// </summary>
    public IReadOnlyList<string> CodeChallengeMethodsSupported { get; init; } = [];

    /// <summary>
    /// The JWS signing algorithms supported for ID tokens, advertised as
    /// <c>id_token_signing_alg_values_supported</c>.
    /// </summary>
    public IReadOnlyList<string> IdTokenSigningAlgValuesSupported { get; init; } = [];

    /// <summary>
    /// The JWS signing algorithms supported for request objects, advertised
    /// as <c>request_object_signing_alg_values_supported</c>.
    /// </summary>
    public IReadOnlyList<string> RequestObjectSigningAlgValuesSupported { get; init; } = [];

    /// <summary>
    /// The DPoP JWS signing algorithms supported, advertised as
    /// <c>dpop_signing_alg_values_supported</c> per RFC 9449 §5.1.
    /// </summary>
    public IReadOnlyList<string> DpopSigningAlgValuesSupported { get; init; } = [];


    /// <summary>
    /// Whether the AS requires pushed authorization requests per
    /// RFC 9126 §5; advertised as <c>require_pushed_authorization_requests</c>.
    /// </summary>
    public bool RequirePushedAuthorizationRequests { get; init; }

    /// <summary>
    /// Whether the AS supports the <c>iss</c> authorization response parameter;
    /// advertised as <c>authorization_response_iss_parameter_supported</c> per RFC 9207.
    /// </summary>
    public bool AuthorizationResponseIssParameterSupported { get; init; }

    /// <summary>
    /// Whether the AS requires signed request objects; advertised as
    /// <c>require_signed_request_object</c> per RFC 9101 §10.6.
    /// </summary>
    public bool RequireSignedRequestObject { get; init; }
}
