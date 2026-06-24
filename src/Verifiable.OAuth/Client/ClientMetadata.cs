using System.Diagnostics;

namespace Verifiable.OAuth.Client;

/// <summary>
/// The client metadata wire-format record per
/// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-2">RFC 7591 §2</see>.
/// Used as the request body for dynamic client registration, the response
/// body the AS returns, the document body served at a CIMD client metadata
/// URL, and the <c>openid_relying_party</c> metadata block inside an OpenID
/// Federation 1.1 entity statement.
/// </summary>
/// <remarks>
/// <para>
/// Distinct from <see cref="ClientRegistration"/>: <see cref="ClientMetadata"/>
/// is the wire shape that crosses the network; <see cref="ClientRegistration"/>
/// is the runtime record the application persists locally and threads
/// through protocol calls. Dynamic registration produces a
/// <see cref="ClientMetadata"/> request body, the AS returns a metadata
/// response, and the application combines that response with its locally
/// held key material to construct a <see cref="ClientRegistration"/>.
/// </para>
/// <para>
/// Field names mirror RFC 7591 §2 names; the runtime types use the
/// library's typed identifiers
/// (<see cref="ClientAuthenticationMethod"/>, <see cref="GrantType"/>,
/// <see cref="ResponseType"/>) rather than raw strings. Wire serialization
/// at the <c>Verifiable.OAuth.Json</c> boundary is responsible for the
/// string ↔ typed-value mapping; <see cref="ClientMetadata"/> itself stays
/// strongly typed.
/// </para>
/// <para>
/// Fields not yet modelled here (the human-facing localised fields like
/// <c>logo_uri</c>, <c>tos_uri</c>, <c>policy_uri</c>, <c>contacts</c>,
/// <c>client_name#xx</c> locale variants) land when their flows arrive.
/// The fields below cover the protocol-significant set.
/// </para>
/// </remarks>
[DebuggerDisplay("ClientMetadata ClientName={ClientName}")]
public sealed record ClientMetadata
{
    /// <summary>
    /// Human-readable name for the client. RFC 7591 §2 <c>client_name</c>.
    /// </summary>
    public string? ClientName { get; init; }

    /// <summary>
    /// Web page describing the client. RFC 7591 §2 <c>client_uri</c>.
    /// </summary>
    public Uri? ClientUri { get; init; }

    /// <summary>
    /// Redirect URIs registered for this client. RFC 7591 §2 <c>redirect_uris</c>.
    /// </summary>
    public IReadOnlyList<Uri> RedirectUris { get; init; } = [];

    /// <summary>
    /// Grant types this client may use. RFC 7591 §2 <c>grant_types</c>.
    /// </summary>
    public IReadOnlyList<GrantType> GrantTypes { get; init; } = [];

    /// <summary>
    /// Response types this client may use. RFC 7591 §2 <c>response_types</c>.
    /// </summary>
    public IReadOnlyList<ResponseType> ResponseTypes { get; init; } = [];

    /// <summary>
    /// Client authentication method. RFC 7591 §2 <c>token_endpoint_auth_method</c>.
    /// </summary>
    public ClientAuthenticationMethod? TokenEndpointAuthMethod { get; init; }

    /// <summary>
    /// Signing algorithm for <c>client_secret_jwt</c> and
    /// <c>private_key_jwt</c> client assertions. RFC 7591 §2
    /// <c>token_endpoint_auth_signing_alg</c>.
    /// </summary>
    public string? TokenEndpointAuthSigningAlg { get; init; }

    /// <summary>
    /// Space-separated scope string. RFC 7591 §2 <c>scope</c>.
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>
    /// The RFC 9396 authorization details <c>type</c> values the client will use, the client
    /// registration metadata parameter <c>authorization_details_types</c> registered by
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-14.5">RFC 9396 §14.5</see> in the
    /// IANA OAuth Dynamic Client Registration Metadata registry
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9396#section-10">RFC 9396 §10</see>:
    /// "Clients MAY indicate the authorization details types they will use ..."). The AS stores
    /// this on <see cref="Server.ClientRecord.AllowedAuthorizationDetailsTypes"/> and refuses any
    /// authorization details object whose <c>type</c> is outside it. <see langword="null"/> when
    /// the client registered no such restriction.
    /// </summary>
    public IReadOnlyList<string>? AuthorizationDetailsTypes { get; init; }

    /// <summary>
    /// The authorization grant profiles this client implements — the client metadata parameter
    /// <c>authorization_grant_profiles_supported</c> per draft-ietf-oauth-identity-assertion-authz-grant
    /// §8 (a JSON array of profile identifier strings). A client that includes
    /// <c>urn:ietf:params:oauth:grant-profile:id-jag</c> MUST also include both
    /// <c>urn:ietf:params:oauth:grant-type:token-exchange</c> and
    /// <c>urn:ietf:params:oauth:grant-type:jwt-bearer</c> in <see cref="GrantTypes"/>, since the client
    /// uses Token Exchange to obtain the ID-JAG from the IdP Authorization Server and the JWT Bearer grant
    /// to redeem it at the Resource Authorization Server. <see langword="null"/> when the client declares
    /// no grant profiles. Mirrors the Resource Authorization Server's <c>authorization_grant_profiles_supported</c>
    /// AS-metadata parameter (§7.2).
    /// </summary>
    public IReadOnlyList<string>? AuthorizationGrantProfilesSupported { get; init; }

    /// <summary>
    /// URL of the client's JWKS document. RFC 7591 §2 <c>jwks_uri</c>.
    /// </summary>
    public Uri? JwksUri { get; init; }

    /// <summary>
    /// Inline JWKS as a JSON string. RFC 7591 §2 <c>jwks</c>. Mutually
    /// exclusive with <see cref="JwksUri"/>.
    /// </summary>
    /// <remarks>
    /// Kept as an opaque string because <c>System.Text.Json</c> is banned in
    /// this assembly. Parsing into a typed JWKS shape happens at the
    /// <c>Verifiable.OAuth.Json</c> boundary.
    /// </remarks>
    public string? Jwks { get; init; }


    //OIDC Dynamic Registration 1.0 fields (extends RFC 7591).

    /// <summary>
    /// Application type per OIDC Dynamic Registration 1.0 §2 —
    /// <c>web</c> or <c>native</c>.
    /// </summary>
    public string? ApplicationType { get; init; }

    /// <summary>
    /// Signing algorithm for ID tokens issued to this client.
    /// </summary>
    public string? IdTokenSignedResponseAlg { get; init; }

    /// <summary>
    /// Signing algorithm for request objects this client submits.
    /// </summary>
    public string? RequestObjectSigningAlg { get; init; }

    /// <summary>
    /// Encryption algorithm for request objects this client submits.
    /// </summary>
    public string? RequestObjectEncryptionAlg { get; init; }


    //OIDC RP-Initiated / Back-Channel / Front-Channel Logout fields.

    /// <summary>
    /// URIs allowed as <c>post_logout_redirect_uri</c> values in RP-Initiated
    /// Logout requests per OIDC RP-Initiated Logout §2.1.
    /// </summary>
    public IReadOnlyList<Uri> PostLogoutRedirectUris { get; init; } = [];

    /// <summary>
    /// Back-channel logout endpoint per OIDC Back-Channel Logout 1.0 §2.2.
    /// </summary>
    public Uri? BackchannelLogoutUri { get; init; }

    /// <summary>
    /// Whether back-channel logout tokens for this client must carry the
    /// <c>sid</c> claim.
    /// </summary>
    public bool BackchannelLogoutSessionRequired { get; init; }

    /// <summary>
    /// Front-channel logout URI per OIDC Front-Channel Logout 1.0 §2.2.
    /// </summary>
    public Uri? FrontchannelLogoutUri { get; init; }

    /// <summary>
    /// Whether front-channel logout calls for this client must carry
    /// <c>iss</c> and <c>sid</c> query parameters.
    /// </summary>
    public bool FrontchannelLogoutSessionRequired { get; init; }
}
