using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Client;

/// <summary>
/// A client's registration with one authorization server. The per-call unit
/// of state for every OAuth protocol method an
/// <see cref="OAuthClient"/> drives — every protocol-method invocation takes
/// a <see cref="ClientRegistration"/> as its first argument and reads the
/// client identifier, redirect URIs, signing key material, and lifecycle
/// metadata from it.
/// </summary>
/// <remarks>
/// <para>
/// A single application may carry many registrations: one per AS it talks
/// to, multiple registrations against one AS for separate purposes (first-party
/// flows, B2B agent flows, per-tenant), or a runtime mix of pre-registered,
/// dynamically-registered, CIMD-published, and federation-resolved
/// registrations. The application owns persistence; the library does not
/// supply a registration store.
/// </para>
/// <para>
/// <strong>Lifecycle models.</strong> A registration carries one of several
/// lifecycle shapes, distinguished by which optional fields are set:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <strong>Pre-registered.</strong> Out-of-band registration; only the
///     core fields are populated. No <see cref="AccessToken"/>, no
///     <see cref="ClientMetadataUri"/>, no <see cref="FederationEntityId"/>.
///   </description></item>
///   <item><description>
///     <strong>RFC 7591 dynamic registration.</strong>
///     <see cref="AccessToken"/> and <see cref="ManagementUri"/> are set,
///     produced by an <c>OAuthDynamicRegistrationClient.RegisterAsync</c>
///     call. <see cref="RegisteredAt"/> and
///     <see cref="RegistrationExpiresAt"/> record the lifecycle bounds.
///   </description></item>
///   <item><description>
///     <strong>CIMD per <see href="https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/">the
///     OAuth Client ID Metadata Document draft</see>.</strong>
///     <see cref="ClientId"/> is an absolute URL; <see cref="ClientMetadataUri"/>
///     equals <see cref="ClientId"/>'s string value. The application publishes
///     the metadata document at that URL; the authorization server fetches it
///     on first use.
///   </description></item>
///   <item><description>
///     <strong>OpenID Federation 1.1 per <see href="https://openid.net/specs/openid-federation-1_1-final.html">OpenID
///     Federation 1.1</see>.</strong> <see cref="FederationEntityId"/> is set
///     to the relying party's federation entity URL;
///     <see cref="AuthorityHints"/> lists the parent authorities. The AS
///     resolves the trust chain on first use and applies metadata policies
///     along the chain.
///   </description></item>
/// </list>
/// <para>
/// <strong>What is NOT on the registration.</strong> The authorization
/// server's endpoints, supported algorithms, supported response types, and
/// JWKS are AS-side metadata the client discovers separately via the
/// resolvers on <see cref="OAuthClientInfrastructure"/>. The registration
/// carries only the AS's <see cref="AuthorizationServerIssuer"/> identifier;
/// per-call resolution turns that into resolved endpoints and JWKS.
/// </para>
/// <para>
/// <strong>Profile.</strong> The <see cref="Profile"/> slot selects the
/// security profile this registration runs under
/// (<see cref="PolicyProfile.Fapi20"/>, <see cref="PolicyProfile.Haip10"/>,
/// <see cref="PolicyProfile.Rfc6749WithPkce"/>). Client-side dispatchers in
/// <see cref="ClientPolicyProfiles"/> resolve profile-bound delegates
/// (callback validator, PKCE method selection, JAR composition rules) from
/// the profile choice.
/// </para>
/// </remarks>
[DebuggerDisplay("ClientRegistration ClientId={ClientId} Issuer={AuthorizationServerIssuer}")]
public sealed record ClientRegistration
{
    /// <summary>
    /// The client identifier known to the authorization server. Opaque for
    /// pre-registered and RFC 7591 lifecycles; an absolute URL for CIMD; a
    /// federation entity URL for OpenID Federation; a DID URI for
    /// DID-based deployments.
    /// </summary>
    public required ClientId ClientId { get; init; }

    /// <summary>
    /// The authorization server's issuer identifier per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-2">RFC 8414 §2</see>.
    /// A URL using the <c>https</c> scheme with no query or fragment. Resolved
    /// per-call into the AS's endpoint metadata and JWKS via the resolver
    /// delegates on <see cref="OAuthClientInfrastructure"/>.
    /// </summary>
    public required Uri AuthorizationServerIssuer { get; init; }

    /// <summary>
    /// The redirect URIs this registration is allowed to use per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>.
    /// Per-call options pick one of these values, or default to the first
    /// entry when none is specified.
    /// </summary>
    public IReadOnlyList<Uri> RedirectUris { get; init; } = [];

    /// <summary>
    /// The space-separated scope string this registration is allowed to
    /// request per <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>.
    /// Per-call options may request a subset.
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>
    /// The grant types this registration is configured to use.
    /// </summary>
    public IReadOnlyList<GrantType> GrantTypes { get; init; } = [];

    /// <summary>
    /// The response types this registration is configured to use at the
    /// authorization endpoint.
    /// </summary>
    public IReadOnlyList<ResponseType> ResponseTypes { get; init; } = [];

    /// <summary>
    /// The token endpoint authentication method this registration uses.
    /// Determines how the client authenticates at token, revocation,
    /// introspection, and registration management endpoints.
    /// </summary>
    public required ClientAuthenticationMethod AuthenticationMethod { get; init; }

    /// <summary>
    /// The security profile this registration runs under. <see langword="null"/>
    /// means the library default (<see cref="PolicyProfile.Fapi20"/>) applies.
    /// Profile-bound resolvers on
    /// <see cref="OAuthClientInfrastructure"/> dispatch on this value.
    /// </summary>
    public PolicyProfile? Profile { get; init; }


    /// <summary>
    /// The signing key material this client uses for JAR composition,
    /// <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/> client
    /// assertions, and any other signing that protocol methods may need.
    /// </summary>
    /// <remarks>
    /// Non-owning reference — the application owns the key material's
    /// disposal. The library reads the key for the duration of a call and
    /// does not retain it across calls.
    /// </remarks>
    public PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>? SigningKeyMaterial { get; init; }

    /// <summary>
    /// The mutual-TLS or attestation key material used by methods like
    /// <see cref="ClientAuthenticationMethod.TlsClientAuth"/>,
    /// <see cref="ClientAuthenticationMethod.SelfSignedTlsClientAuth"/>,
    /// <see cref="ClientAuthenticationMethod.AttestJwtClientAuth"/>, and
    /// <see cref="ClientAuthenticationMethod.SpiffeJwt"/>. Held separately
    /// from <see cref="SigningKeyMaterial"/> because client authentication
    /// keys and request-signing keys are independent concerns that may
    /// rotate independently.
    /// </summary>
    /// <remarks>
    /// Non-owning reference; see the remarks on
    /// <see cref="SigningKeyMaterial"/>.
    /// </remarks>
    public PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>? AuthenticationKeyMaterial { get; init; }

    /// <summary>
    /// The URI at which this client's JWKS document is published, when
    /// the client uses external JWKS publication rather than embedding the
    /// JWKS in CIMD or federation metadata. <see langword="null"/> when
    /// the keys are embedded.
    /// </summary>
    public Uri? JwksUri { get; init; }


    //RFC 7591 / 7592 dynamic registration lifecycle bits.

    /// <summary>
    /// The instant the AS issued the registration response per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">RFC 7591 §3.2.1</see>.
    /// <see langword="null"/> for non-dynamic lifecycles.
    /// </summary>
    public DateTimeOffset? RegisteredAt { get; init; }

    /// <summary>
    /// The instant after which the registration expires per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">RFC 7591 §3.2.1</see>.
    /// <see langword="null"/> for non-dynamic lifecycles or when the AS
    /// does not expire registrations.
    /// </summary>
    public DateTimeOffset? RegistrationExpiresAt { get; init; }

    /// <summary>
    /// The RFC 7591 §3.2.1 <c>registration_access_token</c>. Bearer credential
    /// used to authenticate RFC 7592 read, update, and delete calls against
    /// <see cref="ManagementUri"/>. <see langword="null"/> for non-dynamic
    /// lifecycles.
    /// </summary>
    public RegistrationAccessToken? AccessToken { get; init; }

    /// <summary>
    /// The RFC 7591 §3.2.1 <c>registration_client_uri</c> — the management
    /// endpoint per <see href="https://www.rfc-editor.org/rfc/rfc7592">RFC 7592</see>
    /// for this specific registration. <see langword="null"/> when the AS
    /// does not support management or the lifecycle does not use it.
    /// </summary>
    public Uri? ManagementUri { get; init; }


    //CIMD lifecycle bits.

    /// <summary>
    /// The URI at which the client's metadata document is published per the
    /// <see href="https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/">CIMD draft</see>.
    /// For CIMD-lifecycle registrations this equals the string value of
    /// <see cref="ClientId"/>. <see langword="null"/> for non-CIMD
    /// lifecycles.
    /// </summary>
    /// <remarks>
    /// A short URL is RECOMMENDED, since the URI may be displayed to the end user in
    /// authorization or management interfaces, and a stable URL that does not change
    /// frequently is RECOMMENDED as well — authorization servers compare Client
    /// Identifier URLs by simple string comparison, so a changed URL is an entirely
    /// different client with no relationship to the previous one
    /// (draft-ietf-oauth-client-id-metadata-document-02 §3, §8.3). See
    /// <see cref="ClientIdentifierUrl"/> for the URL shape rules.
    /// </remarks>
    public Uri? ClientMetadataUri { get; init; }


    //OpenID Federation 1.1 lifecycle bits.

    /// <summary>
    /// The federation entity URL identifying this relying party in the
    /// trust chain per
    /// <see href="https://openid.net/specs/openid-federation-1_1-final.html">OpenID Federation 1.1 §1.2</see>.
    /// For federation-lifecycle registrations this typically equals the string
    /// value of <see cref="ClientId"/>. <see langword="null"/> for
    /// non-federation lifecycles.
    /// </summary>
    public Uri? FederationEntityId { get; init; }

    /// <summary>
    /// The parent authorities this entity hints at per
    /// <see href="https://openid.net/specs/openid-federation-1_1-final.html#section-3.1">OpenID Federation 1.1 §3.1</see>
    /// — the intermediate authorities or trust anchors above this leaf in
    /// the federation. Empty for non-federation lifecycles.
    /// </summary>
    public IReadOnlyList<Uri> AuthorityHints { get; init; } = [];


    //OIDC logout slots.

    /// <summary>
    /// The post-logout redirect URIs the AS may use after a successful
    /// RP-Initiated Logout per
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout">OIDC RP-Initiated Logout §2.1</see>.
    /// Empty when the registration does not support post-logout redirection.
    /// </summary>
    public IReadOnlyList<Uri> PostLogoutRedirectUris { get; init; } = [];

    /// <summary>
    /// The URI the AS POSTs the logout token to during OIDC Back-Channel
    /// Logout per
    /// <see href="https://openid.net/specs/openid-connect-backchannel-1_0.html">OIDC Back-Channel Logout 1.0</see>.
    /// <see langword="null"/> when the registration does not participate in
    /// back-channel logout.
    /// </summary>
    public Uri? BackchannelLogoutUri { get; init; }

    /// <summary>
    /// Whether back-channel logout tokens for this registration must carry
    /// the <c>sid</c> claim per
    /// <see href="https://openid.net/specs/openid-connect-backchannel-1_0.html#BCRegistration">OIDC Back-Channel Logout §2.2</see>.
    /// </summary>
    public bool BackchannelLogoutSessionRequired { get; init; }

    /// <summary>
    /// The URI the AS loads in an iframe during OIDC Front-Channel Logout
    /// per
    /// <see href="https://openid.net/specs/openid-connect-frontchannel-1_0.html">OIDC Front-Channel Logout 1.0</see>.
    /// <see langword="null"/> when the registration does not participate in
    /// front-channel logout.
    /// </summary>
    public Uri? FrontchannelLogoutUri { get; init; }

    /// <summary>
    /// Whether front-channel logout calls for this registration must carry
    /// <c>iss</c> and <c>sid</c> query parameters per
    /// <see href="https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout">OIDC Front-Channel Logout §3</see>.
    /// </summary>
    public bool FrontchannelLogoutSessionRequired { get; init; }
}
