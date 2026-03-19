using System.Diagnostics;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.AuthCode.Server;

/// <summary>
/// Discriminated union base for inputs to the server-side Authorization Code flow PDA.
/// </summary>
[DebuggerDisplay("{GetType().Name,nq}")]
public abstract record AuthCodeServerFlowInput: OAuthFlowInput;


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
    DateTimeOffset ExpiresAt): AuthCodeServerFlowInput;


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
[DebuggerDisplay("ServerAuthorizeCompleted SubjectId={SubjectId}")]
public sealed record ServerAuthorizeCompleted(
    string CodeHash,
    string SubjectId,
    DateTimeOffset AuthTime,
    string Scope,
    DateTimeOffset CompletedAt): AuthCodeServerFlowInput;


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
    DateTimeOffset ExpiresAt): AuthCodeServerFlowInput;


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
    DateTimeOffset ExpiresAt): AuthCodeServerFlowInput;
