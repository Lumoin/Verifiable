namespace Verifiable.OAuth.Dpop;

/// <summary>
/// Validates a DPoP proof against an inbound request and the receiver's
/// expectations. Used by the AS at the token endpoint and by the
/// application playing the RS role at resource endpoints.
/// </summary>
/// <remarks>
/// <para>
/// Validation is pure: structural parse + signature verify + claim shape
/// checks. <c>jti</c> replay defense is intentionally <em>not</em> the
/// validator's responsibility — replay tracking is a stateful policy
/// decision the AS-side handler owns and persists through whatever
/// storage abstraction the deployment provides. The validator returns
/// the parsed claims (including <c>jti</c> and <c>iat</c>) on success;
/// the caller decides whether to admit the proof against its replay
/// store.
/// </para>
/// </remarks>
public delegate ValueTask<DpopValidationResult> ValidateDpopProofDelegate(
    DpopProofValidationRequest request,
    CancellationToken cancellationToken);
