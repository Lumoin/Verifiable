using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.AuthCode.Server.States;

/// <summary>
/// The Authorization Server issued one or more tokens. Terminal success state.
/// </summary>
/// <remarks>
/// <para>
/// No further transitions are defined from this state. The PDA halts here and
/// <c>PushdownAutomaton.IsAccepted</c> returns <see langword="true"/>.
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
public sealed record ServerTokenIssuedState: OAuthFlowState
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
}
