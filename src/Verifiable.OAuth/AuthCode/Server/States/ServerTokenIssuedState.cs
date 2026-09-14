using System.Diagnostics;
using Verifiable.OAuth.Server;

using Verifiable.OAuth.Server.Audit;
namespace Verifiable.OAuth.AuthCode.Server.States;

/// <summary>
/// The Authorization Server issued one or more tokens. Terminal success state.
/// </summary>
/// <remarks>
/// <para>
/// Normal issuance halts here. Valid code replay and refresh reuse may re-enter this state
/// through their marker inputs, preserving the issuance audit and setting <see cref="RevokedAt"/>.
/// </para>
/// <para>
/// The token bytes themselves are never stored in the PDA state — only the
/// per-token audit metadata in <see cref="IssuedTokens"/>. The compact JWS
/// strings were returned to the client in the token endpoint response body and
/// exist only there. Each entry in the audit set captures the <c>jti</c> for
/// replay detection and the signing-key identifier for revocation by key.
/// </para>
/// <para>
/// A registration that emits both an access token and an ID token in one
/// response produces a state with two entries in <see cref="IssuedTokens"/> —
/// keyed by <see cref="WellKnownTokenTypes.AccessToken"/> and
/// <see cref="WellKnownTokenTypes.IdToken"/> — each with its own
/// <see cref="IssuedTokenAudit"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("ServerTokenIssued FlowId={FlowId} SubjectId={SubjectId}")]
public sealed record ServerTokenIssuedState: FlowState
{
    /// <summary>
    /// The set of audit records for tokens emitted in this response, keyed by
    /// the response field name each producing <see cref="TokenProducer"/>
    /// declared.
    /// </summary>
    public required IssuedTokenAuditSet IssuedTokens { get; init; }

    /// <summary>The subject the tokens were issued to.</summary>
    public required string SubjectId { get; init; }

    /// <summary>The scope granted in this response.</summary>
    public required string Scope { get; init; }

    /// <summary>
    /// The UTC instant the response was assembled. Identical for every token in
    /// <see cref="IssuedTokens"/> — each token's per-token <c>IssuedAt</c> mirrors
    /// this value, repeated on the audit record so audit consumers don't need
    /// to dereference back to the parent state.
    /// </summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>
    /// The RFC 7800 confirmation method established at issuance time, or
    /// <see langword="null"/> when the token was issued without sender
    /// constraint (Bearer). Carries the DPoP <c>jkt</c> thumbprint when DPoP
    /// enforcement bound the token; extensible to MTLS <c>x5t#S256</c> and
    /// other binding methods. Mirrors the <c>cnf</c> claim embedded in the
    /// issued access token JWT.
    /// </summary>
    public ConfirmationMethod? Confirmation { get; init; }

    /// <summary>
    /// The client identifier this response was issued to, non-<see langword="null"/> exactly
    /// when this state was reached via a code-grant token exchange (the sibling refresh-rotation
    /// transition into this same record type leaves it <see langword="null"/>, since a
    /// <c>code</c> correlation key can never resolve to a refresh-rotated flow — see
    /// <see cref="AuthCode.AuthCodeServerFlowTransitions"/>). A replayed presentation of the code
    /// that produced this state re-verifies <c>client_id</c> against this value exactly as a
    /// first presentation would.
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// The redirect URI the code was issued to, carried forward from
    /// <see cref="ServerCodeIssuedState.RedirectUri"/> so a replayed presentation can re-run the
    /// same conditional <c>redirect_uri</c> check per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 §4.1.3</see>.
    /// <see langword="null"/> exactly when <see cref="ClientId"/> is — see that member's remarks.
    /// </summary>
    public Uri? RedirectUri { get; init; }

    /// <summary>
    /// The PKCE code challenge carried forward from <see cref="ServerCodeIssuedState.CodeChallenge"/>
    /// so a replayed presentation of the code re-runs PKCE verification identically to a first
    /// presentation. <see langword="null"/> exactly when <see cref="ClientId"/> is.
    /// </summary>
    public string? CodeChallenge { get; init; }

    /// <summary>
    /// The <c>code_challenge_method</c> carried forward from
    /// <see cref="ServerCodeIssuedState.CodeChallengeMethod"/> so PKCE re-verification on replay
    /// dispatches on the same persisted method a first presentation would have used.
    /// <see langword="null"/> exactly when <see cref="ClientId"/> is.
    /// </summary>
    public string? CodeChallengeMethod { get; init; }

    /// <summary>
    /// The internal flow identifier of the sibling <see cref="ServerRefreshTokenIssuedState"/>
    /// this response also issued, or <see langword="null"/> when refresh-token issuance was not
    /// configured for this response (<c>oauth.SaveFlowStateAsync</c> was null at issuance) or
    /// this state was reached via refresh-token rotation rather than a code grant. A VALID replay
    /// of the code that produced this state revokes the refresh token by walking
    /// <see cref="AuthCode.AuthCodeEndpoints.RevokeRefreshTokenChainAsync"/> starting at this
    /// identifier — the record here may itself already be retired by one or more rotations since
    /// the code was redeemed, so the walk follows <see cref="SuccessorRefreshFlowId"/> links to the
    /// family's still-live token and deletes THAT record, revoking every intermediate hop's
    /// audited access tokens along the way, implementing
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>'s
    /// "SHOULD revoke (when possible)". The raw refresh secret is not carried onto this state.
    /// </summary>
    public string? RefreshFlowId { get; init; }

    /// <summary>
    /// The server UTC instant a valid code replay or refresh reuse triggered token revocation.
    /// Null until a <see cref="ServerAuthorizationCodeReplayDetected"/> or
    /// <see cref="ServerRefreshTokenReuseDetected"/> input sets it through a pure record-copy
    /// transition. Sequential repeats skip revocation once it is set; concurrent presentations
    /// may repeat idempotent audit revocations. This records
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>'s
    /// "MUST deny" / "SHOULD revoke (when possible)" and
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>'s refresh-family revocation.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; init; }

    /// <summary>
    /// The internal flow identifier of the refresh token that replaced the one redeemed to reach
    /// this state, or <see langword="null"/> when this state was reached via a code-grant token
    /// exchange rather than refresh rotation (or the deployment issues no refresh tokens). The
    /// family link a reuse of the JUST-RETIRED refresh token walks: a later presentation of the
    /// SAME refresh token that produced this state resolves back to it, and
    /// <see cref="AuthCode.AuthCodeEndpoints.HandleRefreshTokenReuseAsync"/> starts
    /// <see cref="AuthCode.AuthCodeEndpoints.RevokeRefreshTokenChainAsync"/> at this identifier —
    /// following further <see cref="SuccessorRefreshFlowId"/> links, when this record has itself
    /// since rotated again, until the family's still-live token is reached and deleted — per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2">RFC 9700 §4.14.2</see>,
    /// which describes reuse of a rotated-out refresh token as a signal of possible token theft.
    /// </summary>
    public string? SuccessorRefreshFlowId { get; init; }

    /// <summary>
    /// The flow holding the audit of the access token minted alongside the refresh token
    /// whose rotation produced this retired record. Copied from
    /// <see cref="ServerRefreshTokenIssuedState.PredecessorFlowId"/> so a valid reuse revokes
    /// that paired token under
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>: "it will revoke the active refresh token as well as the access
    /// authorization grant associated with it." Null for a code-grant issuance or an imported
    /// refresh state without this link.
    /// </summary>
    public string? PredecessorFlowId { get; init; }
}
