using System.Diagnostics;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.Server;

using Verifiable.OAuth.Server.Audit;
namespace Verifiable.OAuth.AuthCode.Server;

/// <summary>
/// Discriminated union base for inputs to the server-side Authorization Code flow PDA.
/// </summary>
[DebuggerDisplay("{GetType().Name,nq}")]
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
/// <param name="CodeChallenge">The validated S256 code challenge.</param>
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
/// The UTC instant the longest-lived token in <paramref name="IssuedTokens"/>
/// expires. Used to populate the inherited <c>ExpiresAt</c> on
/// <see cref="ServerTokenIssuedState"/> for stale-state cleanup.
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
}


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
/// <param name="CodeChallenge">The validated S256 code challenge.</param>
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
