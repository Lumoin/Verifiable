using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.AuthCode.Server.States;

/// <summary>
/// Records that a refresh token has been issued under an authorization
/// code or refresh-rotation flow. Persisted via
/// <see cref="SaveServerFlowStateDelegate"/>; the application's lambda
/// writes a secondary index keyed by the refresh-token string for
/// O(1) lookup on the next refresh exchange.
/// </summary>
/// <remarks>
/// <para>
/// Refresh tokens are opaque random strings (not JWTs), generated via
/// CSPRNG. The library stores the state under a fresh flow id; the
/// application's index translates the wire token back to the flow id
/// via <see cref="ResolveCorrelationKeyDelegate"/>.
/// </para>
/// <para>
/// On a successful refresh exchange, the AS invalidates this state
/// (the application's <see cref="DeleteServerFlowStateDelegate"/> removes
/// the index entry and the flow record) and creates a new
/// <see cref="ServerRefreshTokenIssuedState"/> for the rotated token.
/// Reuse of an invalidated refresh token returns <c>invalid_grant</c>
/// per RFC 6749 §5.2 and RFC 9700 §2.2.2.
/// </para>
/// </remarks>
[DebuggerDisplay("ServerRefreshTokenIssued ClientId={ClientId,nq} IssuedAt={IssuedAt} Bound={Confirmation is not null}")]
public sealed record ServerRefreshTokenIssuedState: FlowState
{
    /// <summary>The OAuth client identifier the refresh token was issued to.</summary>
    public required string ClientId { get; init; }

    /// <summary>The opaque refresh-token string. Wire form.</summary>
    public required string RefreshToken { get; init; }

    /// <summary>
    /// The wire <c>grant_type</c> that first minted this refresh-token chain, carried
    /// verbatim across rotation. Only <c>authorization_code</c> marks the chain as
    /// continuing a genuine End-User authentication event; every other origin
    /// (<c>client_credentials</c>, <c>token_exchange</c>, <c>jwt_bearer</c>,
    /// <c>pre_authorized_code</c>) is non-End-User and MUST NOT yield a default
    /// id_token on redemption. Values are the <see cref="WellKnownGrantTypes"/> constants.
    /// </summary>
    public required string OriginatingGrantType { get; init; }

    /// <summary>The UTC instant the refresh token was issued.</summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>
    /// The OP session identifier (<c>sid</c>) established at the original authentication,
    /// carried verbatim across rotation so a refreshed ID Token keeps the same <c>sid</c> claim,
    /// per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse">OIDC
    /// Core §12.2</see>, which requires the same rules to apply as at original authentication.
    /// <see langword="null"/> when no session was established.
    /// </summary>
    public string? SessionId { get; init; }

    /// <summary>
    /// The subject identifier the refresh token was issued for. Becomes
    /// the <c>sub</c> claim on the access token issued by the refresh
    /// exchange.
    /// </summary>
    public required string SubjectId { get; init; }

    /// <summary>
    /// The scope originally granted at authorization. Refreshed access
    /// tokens inherit this scope; per RFC 6749 §6, refresh requests
    /// MAY narrow scope but never widen it.
    /// </summary>
    public required string Scope { get; init; }

    /// <summary>
    /// The RFC 7800 confirmation method established at issuance, or
    /// <see langword="null"/> when the refresh token is Bearer (no
    /// sender constraint). On refresh exchange, when this is non-null,
    /// the AS validates the presented DPoP proof's thumbprint matches
    /// <see cref="ConfirmationMethod.JwkThumbprint"/> per RFC 9449 §5.
    /// </summary>
    public ConfirmationMethod? Confirmation { get; init; }

    /// <summary>
    /// The instant the End-User authenticated at the original authorization, carried
    /// forward across refresh rotations so the refreshed access token's <c>auth_time</c>
    /// claim stays fixed. Per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2.1">RFC 9068 §2.2.1</see>,
    /// the authentication-context claims remain the same across all access tokens that
    /// derive from a given authorization response, including those obtained by refreshing.
    /// <see langword="null"/> when no End-User authentication backs the token (e.g. a
    /// grant shape with no interactive login).
    /// </summary>
    public DateTimeOffset? AuthTime { get; init; }

    /// <summary>
    /// The Authentication Context Class Reference (<c>acr</c>) established at the original
    /// authorization, carried forward across refresh rotations so the refreshed access
    /// token's <c>acr</c> claim stays fixed per RFC 9068 §2.2.1. <see langword="null"/>
    /// when no authentication-context reference was established.
    /// </summary>
    public string? Acr { get; init; }

    /// <summary>
    /// The RFC 9396 <c>authorization_details</c> granted to the access token this refresh token
    /// was minted alongside, verbatim, or <see langword="null"/> when the grant carried none. The
    /// refresh exchange resolves the granted <c>credential_identifiers</c> against it — optionally
    /// narrowed by a refresh-request subset per RFC 9396 §6.1 — re-emits the §7 token-response
    /// echo and the §9.1 access-token claim, and carries the value across rotation so a second
    /// refresh still carries the details. Mirrors <c>ServerCodeIssuedState.AuthorizationDetails</c>
    /// so the granted details survive the authorization-code-to-refresh handover.
    /// </summary>
    public string? AuthorizationDetails { get; init; }
}
