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

    /// <summary>
    /// The End-User's authentication session identifier (<c>sid</c>) established at
    /// authorize time, carried forward so the token endpoint can emit it as the ID
    /// Token's <c>sid</c> claim. <see langword="null"/> when no session-scoped
    /// identifier was stamped.
    /// </summary>
    public string? SessionId { get; init; }

    /// <summary>
    /// The Authentication Context Class Reference (<c>acr</c>) established at authorize
    /// time, carried forward so the token endpoint can emit it as the access token's
    /// <c>acr</c> claim per RFC 9068 §2.2.1 / RFC 9470 §5. <see langword="null"/> when no
    /// authentication-context reference was stamped.
    /// </summary>
    public string? Acr { get; init; }

    /// <summary>
    /// The opaque <c>state</c> value from the authorization request, carried forward so the
    /// success redirect echoes it back to the client per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>.
    /// <see langword="null"/> when the request carried no <c>state</c>.
    /// </summary>
    public string? State { get; init; }

    /// <summary>
    /// The RFC 9396 <c>authorization_details</c> the authorization request was authorized with,
    /// verbatim, or <see langword="null"/> when none was requested. The token endpoint resolves
    /// the granted <c>credential_identifiers</c> against it — optionally narrowed by a
    /// token-request subset per OID4VCI 1.0 §6.1.1 — and echoes the grant in the token
    /// response's <c>authorization_details</c> per §6.2.
    /// </summary>
    public string? AuthorizationDetails { get; init; }

    /// <summary>
    /// The <c>response_mode</c> the authorization request asked for, carried forward so the
    /// authorize response site knows whether to wrap the response in a JARM JWT
    /// (<see cref="Jarm.JarmResponseModes"/>) and which §2.3 encoding to apply.
    /// <see langword="null"/> when the request carried no <c>response_mode</c>.
    /// </summary>
    public string? ResponseMode { get; init; }
}
