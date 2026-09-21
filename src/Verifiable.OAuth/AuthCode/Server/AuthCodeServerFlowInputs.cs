using System.Diagnostics;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.Server;

using Verifiable.OAuth.Server.Audit;
namespace Verifiable.OAuth.AuthCode.Server;

/// <summary>
/// Discriminated union base for inputs to the server-side Authorization Code flow PDA.
/// </summary>
public abstract record AuthCodeServerFlowInput: FlowInput;


/// <summary>
/// Carries a validated PAR request body. Transitions the PDA from its initial sentinel
/// state to <see cref="ParRequestReceivedState"/>.
/// </summary>
/// <remarks>
/// All effectful work — PKCE validation, redirect URI match, scope check — is performed
/// by the handler before constructing this input. The transition function is pure.
/// </remarks>
/// <param name="FlowId">The fresh identifier generated for this flow.</param>
/// <param name="RequestUri">The <c>request_uri</c> assigned to this PAR entry.</param>
/// <param name="CodeChallenge">The validated code challenge.</param>
/// <param name="CodeChallengeMethod">
/// The validated <c>code_challenge_method</c> — <c>S256</c> or, under a deployment that accepts it,
/// <c>plain</c> — per
/// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>. Carried
/// forward so the token endpoint verifies <c>code_verifier</c> against this PERSISTED method,
/// never against a method named on the token request itself.
/// </param>
/// <param name="RedirectUri">The validated redirect URI.</param>
/// <param name="Scope">The requested scope.</param>
/// <param name="ClientId">The client identifier from the request.</param>
/// <param name="Nonce">
/// The <c>nonce</c> from the request. Bound into the ID Token per
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OIDC Core §3.1.2.1</see>.
/// </param>
/// <param name="ExpectedIssuer">The server's issuer identifier.</param>
/// <param name="ReceivedAt">The UTC instant the PAR request arrived.</param>
/// <param name="ExpiresAt">The UTC instant the <c>request_uri</c> expires.</param>
/// <param name="ExpiresIn">
/// The <c>request_uri</c> lifetime in seconds returned to the client as the
/// <c>expires_in</c> field of the PAR response per
/// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>.
/// Carried explicitly so the wire value is what was promised at PAR time
/// rather than a recomputation at response-build time.
/// </param>
/// <param name="AcrValues">The requested Authentication Context Class Reference values, space-delimited. <see langword="null"/> when the request carried none.</param>
/// <param name="MaxAge">The requested maximum authentication age in seconds. <see langword="null"/> when the request carried none.</param>
/// <param name="Prompt">The requested <c>prompt</c> (space-delimited). <see langword="null"/> when the request carried none.</param>
/// <param name="State">The client's opaque <c>state</c> value, echoed back at the redirect. <see langword="null"/> when the request carried none.</param>
/// <param name="AuthorizationDetails">The RFC 9396 <c>authorization_details</c> the request carried, surfaced to the authorization-decision seam. <see langword="null"/> when absent.</param>
/// <param name="ResponseMode">The requested <c>response_mode</c>. <see langword="null"/> when the request carried none.</param>
/// <param name="IssuerState">
/// The OID4VCI 1.0 §5.1.3 <c>issuer_state</c> the Wallet echoed, carried verbatim and UNTRUSTED
/// to the authorization-decision seam. <see langword="null"/> when the request carried none.
/// </param>
/// <param name="Resource">
/// The RFC 8707 <c>resource</c> indicator(s) the request carried (space-delimited when multiple),
/// surfaced to the authorization-decision seam. <see langword="null"/> when absent.
/// </param>
[DebuggerDisplay("ServerParValidated FlowId={FlowId} RequestUri={RequestUri}")]
public sealed record ServerParValidated(
    string FlowId,
    Uri RequestUri,
    string CodeChallenge,
    string CodeChallengeMethod,
    Uri RedirectUri,
    string Scope,
    string ClientId,
    string Nonce,
    string ExpectedIssuer,
    DateTimeOffset ReceivedAt,
    DateTimeOffset ExpiresAt,
    int ExpiresIn,
    string? AcrValues = null,
    int? MaxAge = null,
    string? Prompt = null,
    string? State = null,
    string? AuthorizationDetails = null,
    string? ResponseMode = null,
    string? IssuerState = null,
    string? Resource = null): AuthCodeServerFlowInput;


/// <summary>
/// Carries the result of a completed authorization interaction. Transitions
/// <see cref="ParRequestReceivedState"/> to <see cref="ServerCodeIssuedState"/>.
/// </summary>
/// <remarks>
/// The authorization code is passed as a hash — the raw code was returned to the
/// client in the redirect. The handler hashes the generated code before constructing
/// this input so the raw code never enters the PDA.
/// </remarks>
/// <param name="CodeHash">SHA-256 hash of the authorization code returned to the client.</param>
/// <param name="SubjectId">The authenticated subject identifier.</param>
/// <param name="AuthTime">The UTC instant at which the subject authenticated.</param>
/// <param name="Scope">The scope granted at the authorization endpoint.</param>
/// <param name="CompletedAt">The UTC instant the authorization completed.</param>
/// <param name="ExpiresAt">
/// The UTC instant the issued authorization code expires, computed at the authorize site as
/// <c>CompletedAt + context.AuthorizationCodeLifetime</c> per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>: "A
/// maximum authorization code lifetime of 10 minutes is RECOMMENDED." Carried explicitly rather
/// than left for the transition to inherit <see cref="Verifiable.Server.FlowState.ExpiresAt"/> — the
/// <c>request_uri</c>'s own, typically shorter, lifetime — so the code's expiry is governed by the
/// authorization-code policy regardless of how much of the <c>request_uri</c> lifetime remained
/// when the authorize step ran.
/// </param>
/// <param name="SessionId">
/// The End-User's authentication session identifier (<c>sid</c>), carried into the
/// ID Token's <c>sid</c> claim. <see langword="null"/> when the deployment stamps no
/// session-scoped identifier.
/// </param>
/// <param name="Acr">
/// The Authentication Context Class Reference (<c>acr</c>) established for the
/// authentication, carried into the access token's <c>acr</c> claim per RFC 9068 §2.2.1
/// / RFC 9470 §5. <see langword="null"/> when no authentication-context reference was stamped.
/// </param>
[DebuggerDisplay("ServerAuthorizeCompleted SubjectId={SubjectId}")]
public sealed record ServerAuthorizeCompleted(
    string CodeHash,
    string SubjectId,
    DateTimeOffset AuthTime,
    string Scope,
    DateTimeOffset CompletedAt,
    DateTimeOffset ExpiresAt,
    string? SessionId = null,
    string? Acr = null): AuthCodeServerFlowInput;


/// <summary>
/// Carries the result of a successful token exchange. Transitions
/// <see cref="ServerCodeIssuedState"/> to <see cref="ServerTokenIssuedState"/>.
/// </summary>
/// <remarks>
/// <para>
/// The token bytes are not present — only the per-token-type audit metadata in
/// <paramref name="IssuedTokens"/>. The signed tokens were already returned to the
/// client in the HTTP response before this input is constructed.
/// </para>
/// <para>
/// A response that emits an access token and an ID token together produces an
/// <see cref="IssuedTokenAuditSet"/> with two entries — one keyed by
/// <see cref="WellKnownTokenTypes.AccessToken"/> and one by
/// <see cref="WellKnownTokenTypes.IdToken"/>.
/// </para>
/// </remarks>
/// <param name="IssuedTokens">The per-token-type audit metadata for tokens emitted in this response.</param>
/// <param name="IssuedAt">The UTC instant the response was assembled.</param>
/// <param name="ExpiresAt">
/// The UTC instant the resulting <see cref="ServerTokenIssuedState"/> should be treated as stale.
/// For a code-grant issuance this is the longest-lived token in <paramref name="IssuedTokens"/>.
/// For a refresh rotation it is at least the freshly-minted successor refresh token's own
/// expiry — never merely the access token's — so the retired record a later reuse of the
/// just-rotated-out token resolves to (<see cref="AuthCode.AuthCodeEndpoints.HandleRefreshTokenReuseAsync"/>)
/// outlives every token that presentation could be asked to revoke; an access-token-only expiry
/// would let <c>EndpointServer.HandleCoreAsync</c>'s expiry gate discard the retired record while
/// the successor it protects is still live.
/// </param>
[DebuggerDisplay("ServerTokenExchangeSucceeded ({IssuedTokens.Audits.Count} tokens)")]
public sealed record ServerTokenExchangeSucceeded(
    IssuedTokenAuditSet IssuedTokens,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt): AuthCodeServerFlowInput
{
    /// <summary>
    /// The RFC 7800 confirmation method established at the token endpoint,
    /// or <see langword="null"/> when no proof-of-possession binding ran
    /// (Bearer issuance). Populated with the DPoP <c>jkt</c> thumbprint when
    /// the request carried a validated DPoP proof; extensible to MTLS
    /// <c>x5t#S256</c> and other binding methods. Recorded onto
    /// <see cref="States.ServerTokenIssuedState.Confirmation"/> in the
    /// transition that consumes this input.
    /// </summary>
    public ConfirmationMethod? Confirmation { get; init; }

    /// <summary>
    /// The client identifier the redeemed code was bound to, carried forward from
    /// <see cref="States.ServerCodeIssuedState.ClientId"/> so a later replay of this same code
    /// can be re-verified exactly as a first presentation would.
    /// <see langword="null"/> when this input transitions a refresh-rotated flow instead of a
    /// code grant.
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// The redirect URI the redeemed code was bound to, carried forward from
    /// <see cref="States.ServerCodeIssuedState.RedirectUri"/> for the same replay-verification
    /// purpose as <see cref="ClientId"/>.
    /// </summary>
    public Uri? RedirectUri { get; init; }

    /// <summary>
    /// The PKCE code challenge the redeemed code was bound to, carried forward from
    /// <see cref="States.ServerCodeIssuedState.CodeChallenge"/> for the same replay-verification
    /// purpose as <see cref="ClientId"/>.
    /// </summary>
    public string? CodeChallenge { get; init; }

    /// <summary>
    /// The <c>code_challenge_method</c> the redeemed code was bound to, carried forward from
    /// <see cref="States.ServerCodeIssuedState.CodeChallengeMethod"/> for the same
    /// replay-verification purpose as <see cref="ClientId"/>.
    /// </summary>
    public string? CodeChallengeMethod { get; init; }

    /// <summary>
    /// The internal flow identifier of the freshly-rotated refresh token this response issued in
    /// place of the one just redeemed, or <see langword="null"/> when this input transitions a
    /// code-grant flow instead of a refresh rotation (or the deployment issues no refresh tokens).
    /// Recorded onto <see cref="States.ServerTokenIssuedState.SuccessorRefreshFlowId"/> — the
    /// family link a later reuse of the JUST-RETIRED refresh token walks to revoke the current
    /// successor per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2">RFC 9700 §4.14.2</see>.
    /// </summary>
    public string? SuccessorRefreshFlowId { get; init; }
}


/// <summary>
/// Carries a VALID replay of an already-redeemed authorization code, detected by
/// <see cref="AuthCodeEndpoints.HandleAuthorizationCodeReplayAsync"/> after revocation has run.
/// Transitions <see cref="ServerTokenIssuedState"/> back to itself with
/// <see cref="ServerTokenIssuedState.RevokedAt"/> set to <see cref="RevokedAt"/> and every other
/// field copied forward unchanged (a record <c>with</c> expression) — the PDA stays pure; the
/// revocation side effects (calling the optional revoke delegate, deleting the sibling refresh
/// record) have already happened in the endpoint before this input is constructed, exactly as
/// token minting's own side effects precede <see cref="ServerTokenExchangeSucceeded"/>.
/// </summary>
/// <param name="RevokedAt">The UTC instant the replay was detected and revocation ran.</param>
[DebuggerDisplay("ServerAuthorizationCodeReplayDetected RevokedAt={RevokedAt}")]
public sealed record ServerAuthorizationCodeReplayDetected(
    DateTimeOffset RevokedAt): AuthCodeServerFlowInput;


/// <summary>
/// Carries a valid reuse of a retired refresh token after family revocation has run.
/// The pure transition copies the retired state and sets only its revocation timestamp,
/// allowing the runner to persist a sequential once-only marker. This records the result of
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
/// draft-16 §4.3.1</see>: "it will revoke the active refresh token as well as the access
/// authorization grant associated with it."
/// </summary>
/// <param name="RevokedAt">The server UTC instant the valid reuse triggered revocation.</param>
[DebuggerDisplay("ServerRefreshTokenReuseDetected RevokedAt={RevokedAt}")]
public sealed record ServerRefreshTokenReuseDetected(
    DateTimeOffset RevokedAt): AuthCodeServerFlowInput;


/// <summary>
/// Signals a failure at any point in the server flow. Accepted from any
/// non-terminal state. Transitions to <see cref="ServerFlowFailedState"/>.
/// </summary>
/// <param name="ErrorCode">The OAuth 2.0 wire error code.</param>
/// <param name="Reason">Human-readable reason for server-side audit logging.</param>
/// <param name="FailedAt">The UTC instant the failure occurred.</param>
[DebuggerDisplay("ServerFail ErrorCode={ErrorCode}")]
public sealed record ServerFail(
    string ErrorCode,
    string Reason,
    DateTimeOffset FailedAt): AuthCodeServerFlowInput;


/// <summary>
/// Carries a validated and authorized direct authorization request — Authorization Code
/// flow with PKCE per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749">RFC 6749</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc7636">RFC 7636</see> without Pushed
/// Authorization Request. Transitions the PDA directly from its initial sentinel state
/// to <see cref="ServerCodeIssuedState"/> in a single step.
/// </summary>
/// <remarks>
/// <para>
/// In the PAR-backed flow the authorize step is a separate HTTP request — the user
/// authenticates and consents between the PAR call and the authorize call, so the flow
/// must persist intermediate state. In the direct authorization flow the authorization
/// request itself arrives with the subject already authenticated (carried in the context
/// bag), so validation, authentication confirmation, and code issuance all happen in the
/// same HTTP request. There is no intermediate state to persist.
/// </para>
/// <para>
/// All effectful work — PKCE validation, redirect URI match, scope check, subject
/// identity confirmation — is performed by the handler before constructing this input.
/// The transition function is pure.
/// </para>
/// </remarks>
/// <param name="FlowId">The fresh identifier generated for this flow.</param>
/// <param name="CodeHash">SHA-256 hash of the authorization code returned to the client.</param>
/// <param name="CodeChallenge">The validated code challenge.</param>
/// <param name="CodeChallengeMethod">
/// The validated <c>code_challenge_method</c> — <c>S256</c> or, under a deployment that accepts it,
/// <c>plain</c> — per
/// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>. Carried
/// forward so the token endpoint verifies <c>code_verifier</c> against this PERSISTED method,
/// never against a method named on the token request itself.
/// </param>
/// <param name="RedirectUri">The validated redirect URI.</param>
/// <param name="Scope">The requested scope.</param>
/// <param name="ClientId">The client identifier from the request.</param>
/// <param name="Nonce">
/// The <c>nonce</c> from the request. Bound into the ID Token per
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OIDC Core §3.1.2.1</see>.
/// </param>
/// <param name="SubjectId">The authenticated subject identifier.</param>
/// <param name="AuthTime">The UTC instant at which the subject authenticated.</param>
/// <param name="ExpectedIssuer">The server's issuer identifier.</param>
/// <param name="CompletedAt">The UTC instant the authorization completed.</param>
/// <param name="ExpiresAt">The UTC instant the authorization session expires.</param>
/// <param name="SessionId">
/// The End-User's authentication session identifier (<c>sid</c>), carried into the
/// ID Token's <c>sid</c> claim. <see langword="null"/> when the deployment stamps no
/// session-scoped identifier.
/// </param>
/// <param name="Acr">
/// The Authentication Context Class Reference (<c>acr</c>) established for the
/// authentication, carried into the access token's <c>acr</c> claim per RFC 9068 §2.2.1
/// / RFC 9470 §5. <see langword="null"/> when no authentication-context reference was stamped.
/// </param>
/// <param name="State">The client's opaque <c>state</c> value, echoed back at the redirect. <see langword="null"/> when the request carried none.</param>
/// <param name="AuthorizationDetails">The RFC 9396 <c>authorization_details</c> the request carried, surfaced to the authorization-decision seam. <see langword="null"/> when absent.</param>
/// <param name="ResponseMode">The requested <c>response_mode</c>. <see langword="null"/> when the request carried none.</param>
/// <param name="IssuerState">
/// The OID4VCI 1.0 §5.1.3 <c>issuer_state</c> the Wallet echoed, carried verbatim and UNTRUSTED
/// to the authorization-decision seam. <see langword="null"/> when the request carried none.
/// </param>
/// <param name="Resource">
/// The RFC 8707 <c>resource</c> indicator(s) the request carried (space-delimited when multiple),
/// surfaced to the authorization-decision seam. <see langword="null"/> when absent.
/// </param>
[DebuggerDisplay("ServerDirectAuthorizeCompleted FlowId={FlowId} ClientId={ClientId}")]
public sealed record ServerDirectAuthorizeCompleted(
    string FlowId,
    string CodeHash,
    string CodeChallenge,
    string CodeChallengeMethod,
    Uri RedirectUri,
    string Scope,
    string ClientId,
    string Nonce,
    string SubjectId,
    DateTimeOffset AuthTime,
    string ExpectedIssuer,
    DateTimeOffset CompletedAt,
    DateTimeOffset ExpiresAt,
    string? SessionId = null,
    string? Acr = null,
    string? State = null,
    string? AuthorizationDetails = null,
    string? ResponseMode = null,
    string? IssuerState = null,
    string? Resource = null): AuthCodeServerFlowInput;
