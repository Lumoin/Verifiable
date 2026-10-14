using System.Diagnostics;
using Verifiable.OAuth.Server;

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
/// <see cref="AuthTime"/> the host stamped is carried forward for the <c>auth_time</c> claims;
/// an instant the host did not stamp is carried as unknown.
/// </para>
/// <para>
/// Transitions to <see cref="ServerTokenIssuedState"/> when
/// <see cref="ServerTokenExchangeSucceeded"/> arrives with a matching code hash.
/// </para>
/// </remarks>
[DebuggerDisplay("ServerCodeIssued FlowId={FlowId} SubjectId={SubjectId}")]
public sealed record ServerCodeIssuedState: FlowState
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
    /// The accepted S256 wire method from
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>, retained
    /// for code binding per <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.4">§4.4</see>:
    /// "it MUST associate the "code_challenge" and
    /// "code_challenge_method" values with the authorization code so it can be verified later."
    /// Token verification selects this bound method per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.5">§4.5</see>.
    /// The library accepts S256 only, consistent with
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-7.5.2">OAuth 2.1 §7.5.2</see>.
    /// </summary>
    public required string CodeChallengeMethod { get; init; }

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
    /// The UTC instant at which the subject authenticated, as the host stamped it on the
    /// authorize-time context, or <see langword="null"/> when the host stamped none. Carried into
    /// the ID Token as <c>auth_time</c> per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0 section 2</see>:
    /// "Time when the End-User authentication occurred."
    /// </summary>
    /// <remarks>
    /// <para>
    /// The authentication instant is a fact of the host's own authentication, so the library
    /// states none it was not given: an unknown instant is carried as unknown, never replaced by
    /// the instant the authorize leg ran. The member is <c>required</c> so the site that builds the
    /// state states the instant, <see langword="null"/> when it is unknown.
    /// </para>
    /// <para>
    /// What follows from an unknown instant, as <see cref="AcrAmrClaimContributor"/> writes the claim:
    /// the access tokens of the code redemption and of every refresh, and every refreshed ID Token,
    /// carry no <c>auth_time</c>; the ID Token of the code redemption carries one only when the
    /// application's resolver returns <see cref="Oidc.AuthenticationContext.AuthTime"/>, which the
    /// contributor reads before this instant. A request that asks for a maximum authentication age is
    /// refused before a code is issued
    /// (<see cref="AuthCodeEndpoints.EvaluateAuthenticationRequirementsAsync"/>). The same clause
    /// states when the claim may be left out: "When a max_age request is made or when auth_time is
    /// requested as an Essential Claim, then this Claim is REQUIRED; otherwise, its inclusion is
    /// OPTIONAL."
    /// </para>
    /// </remarks>
    public required DateTimeOffset? AuthTime { get; init; }

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

    /// <summary>
    /// The <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>
    /// <c>resource</c> indicator(s) the authorization request was granted with (space-delimited
    /// when multiple), shape-validated at PAR/authorize receipt, or <see langword="null"/> when
    /// none was requested. Per §2.1 the requested resource "is applicable to the full
    /// authorization grant" — this is that grant. The token endpoint resolves the effective
    /// access-token audience against it — optionally narrowed by a token-request subset per
    /// §2.2 — and carries the value verbatim onto <c>ServerRefreshTokenIssuedState</c> so the
    /// refresh token stays bound to the full original grant (§2.2).
    /// </summary>
    public string? Resource { get; init; }

    /// <summary>
    /// The DPoP binding of the authorization code: the JWK SHA-256 Thumbprint the authorization
    /// request named with <c>dpop_jkt</c>, or the thumbprint of the DPoP proof checked at the
    /// pushed request, or <see langword="null"/> when the code is bound to no DPoP public key.
    /// The token endpoint redeems a bound code only under a DPoP proof whose public key has this
    /// thumbprint, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10">RFC 9449 Section 10</see>:
    /// "When a token request is received, the authorization server computes the JWK Thumbprint
    /// of the proof-of-possession public key in the DPoP proof and verifies that it matches the
    /// dpop_jkt parameter value in the authorization request. If they do not match, it MUST
    /// reject the request." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10.1">Section 10.1</see>:
    /// "reject the subsequent token request unless a DPoP proof for the same key is provided."
    /// </summary>
    public ConfirmationMethod? Confirmation { get; init; }
}
