using System.Diagnostics;

namespace Verifiable.OAuth.AuthCode.Server.States;

/// <summary>
/// The Authorization Server issued an authorization code and redirected the client.
/// The server is waiting for the token endpoint to be called.
/// </summary>
/// <remarks>
/// <para>
/// The authorization code is stored as a hash — the raw code was returned to the
/// client in the redirect and must never be stored verbatim. The token endpoint
/// hashes the received code and compares against <see cref="CodeHash"/>.
/// </para>
/// <para>
/// <see cref="SubjectId"/> identifies the authenticated subject so that the issued
/// token can be bound to the correct user without re-authenticating. The
/// <see cref="AuthTime"/> is carried forward for ID Token <c>auth_time</c> claims.
/// </para>
/// <para>
/// Transitions to <see cref="ServerTokenIssuedState"/> when
/// <see cref="ServerTokenExchangeSucceeded"/> arrives with a matching code hash.
/// </para>
/// </remarks>
[DebuggerDisplay("ServerCodeIssued FlowId={FlowId} SubjectId={SubjectId}")]
public sealed record ServerCodeIssuedState: OAuthFlowState
{
    /// <summary>
    /// SHA-256 hash of the authorization code returned to the client.
    /// The token endpoint hashes the received <c>code</c> and compares against
    /// this value. The raw code is never stored.
    /// </summary>
    public required string CodeHash { get; init; }

    /// <summary>
    /// The redirect URI the code was issued to. Validated again at the token
    /// endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 §4.1.3</see>.
    /// </summary>
    public required Uri RedirectUri { get; init; }

    /// <summary>
    /// The PKCE code challenge carried forward from <see cref="ParRequestReceivedState"/>
    /// so the token endpoint can verify <c>code_verifier</c> without reloading
    /// the PAR entry.
    /// </summary>
    public required string CodeChallenge { get; init; }

    /// <summary>
    /// The scope granted at the authorization endpoint.
    /// May be narrower than what was requested in the PAR body.
    /// </summary>
    public required string Scope { get; init; }

    /// <summary>
    /// The identifier of the authenticated subject, e.g. a user identifier from
    /// the application's identity store. Bound into the issued token as <c>sub</c>.
    /// </summary>
    public required string SubjectId { get; init; }

    /// <summary>
    /// The UTC instant at which the subject authenticated. Carried into the ID Token
    /// as <c>auth_time</c> per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>.
    /// </summary>
    public required DateTimeOffset AuthTime { get; init; }

    /// <summary>The client identifier, carried forward for token endpoint validation.</summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The <c>nonce</c> carried forward from the authorization request. Bound into
    /// the ID Token at the token endpoint per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OIDC Core §3.1.2.1</see>.
    /// </summary>
    public required string Nonce { get; init; }
}
