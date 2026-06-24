using System.Diagnostics;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// The proof-of-possession outcome of the
/// draft-ietf-oauth-identity-assertion-authz-grant §9.8.1.2 decision matrix, combining whether the
/// redeemed ID-JAG is key-bound (carries a <c>cnf.jkt</c>) with whether the client presented a valid
/// DPoP proof and whether the Resource Server requires sender-constrained tokens.
/// </summary>
public enum IdJagDpopDecisionKind
{
    /// <summary>§9.8.1.2.4 — no key binding and no proof: an unconstrained Bearer token is issued.</summary>
    BearerToken,

    /// <summary>
    /// §9.8.1.2.1 / §9.8.1.2.3 — a sender-constrained (DPoP-bound) token is issued, bound to
    /// <see cref="IdJagDpopDecision.BoundKeyThumbprint"/>.
    /// </summary>
    SenderConstrainedToken,

    /// <summary>§9.8.1.2.2 — the grant is key-bound but no DPoP proof was presented: reject with <c>invalid_grant</c>.</summary>
    RejectProofRequired,

    /// <summary>§9.8.1.2.1 step 4 — the DPoP proof key does not match the grant's <c>cnf.jkt</c>: reject with <c>invalid_grant</c>.</summary>
    RejectKeyMismatch,

    /// <summary>
    /// §9.8.1.2.4 — the grant is not key-bound and no proof was presented, but the Resource Server
    /// requires sender-constrained tokens: reject with <c>invalid_grant</c>.
    /// </summary>
    RejectSenderConstrainedRequired
}


/// <summary>
/// Evaluates the draft-ietf-oauth-identity-assertion-authz-grant §9.8.1.2 proof-of-possession matrix
/// for redeeming an ID-JAG at a Resource Authorization Server: given the grant's bound key thumbprint
/// (the <c>cnf.jkt</c> claim, if any), the thumbprint of a validated DPoP proof (if one was
/// presented), and the Resource Server's sender-constraint requirement, it returns whether to issue a
/// Bearer or DPoP-bound token or to reject the request.
/// </summary>
/// <remarks>
/// The DPoP proof's cryptographic validation (signature, <c>htm</c>/<c>htu</c>, replay) and the
/// thumbprint computation are the caller's concern — typically
/// <see cref="AuthCode.Server.DpopTokenEndpointValidation"/> over the request's <c>DPoP</c> header,
/// which yields a <see cref="Server.ConfirmationMethod"/>. This helper is the pure branch decision,
/// so the four §9.8.1.2 cases are each unit-testable. The grant's bound key thumbprint reaches it via
/// <see cref="IdJagAssertionValidationResult.ConfirmationKeyThumbprint"/> →
/// <see cref="JwtBearer.JwtBearerGrant.RequiredKeyThumbprint"/>.
/// </remarks>
[DebuggerDisplay("IdJagDpopDecision {Kind}")]
public sealed record IdJagDpopDecision
{
    /// <summary>The matrix outcome.</summary>
    public required IdJagDpopDecisionKind Kind { get; init; }

    /// <summary>
    /// The JWK SHA-256 thumbprint the issued access token is bound to, for
    /// <see cref="IdJagDpopDecisionKind.SenderConstrainedToken"/>; otherwise <see langword="null"/>.
    /// </summary>
    public string? BoundKeyThumbprint { get; init; }

    /// <summary>Whether the outcome is a rejection (one of the <c>Reject*</c> kinds).</summary>
    public bool IsRejected => Kind
        is IdJagDpopDecisionKind.RejectProofRequired
        or IdJagDpopDecisionKind.RejectKeyMismatch
        or IdJagDpopDecisionKind.RejectSenderConstrainedRequired;


    /// <summary>
    /// Applies the §9.8.1.2 matrix.
    /// </summary>
    /// <param name="grantKeyThumbprint">
    /// The grant's bound key thumbprint — the <c>cnf.jkt</c> claim of the ID-JAG — or
    /// <see langword="null"/> when the grant carries no <c>cnf</c> claim.
    /// </param>
    /// <param name="presentedKeyThumbprint">
    /// The JWK SHA-256 thumbprint of a successfully validated DPoP proof presented on the redeem
    /// request, or <see langword="null"/> when no DPoP proof was presented.
    /// </param>
    /// <param name="resourceServerRequiresSenderConstrained">
    /// Whether the Resource Server configuration requires sender-constrained tokens (§9.8.1.2.4).
    /// </param>
    /// <returns>The decision.</returns>
    public static IdJagDpopDecision Evaluate(
        string? grantKeyThumbprint,
        string? presentedKeyThumbprint,
        bool resourceServerRequiresSenderConstrained)
    {
        if(grantKeyThumbprint is not null)
        {
            //§9.8.1.2.2: a key-bound grant MUST be redeemed with a DPoP proof.
            if(presentedKeyThumbprint is null)
            {
                return new IdJagDpopDecision { Kind = IdJagDpopDecisionKind.RejectProofRequired };
            }

            //§9.8.1.2.1 step 4: the thumbprints MUST match exactly.
            if(!string.Equals(grantKeyThumbprint, presentedKeyThumbprint, StringComparison.Ordinal))
            {
                return new IdJagDpopDecision { Kind = IdJagDpopDecisionKind.RejectKeyMismatch };
            }

            //§9.8.1.2.1 step 5: bind the issued token to the same key.
            return new IdJagDpopDecision
            {
                Kind = IdJagDpopDecisionKind.SenderConstrainedToken,
                BoundKeyThumbprint = presentedKeyThumbprint
            };
        }

        //§9.8.1.2.3: no cnf but a valid DPoP proof — issue a sender-constrained token bound to it.
        if(presentedKeyThumbprint is not null)
        {
            return new IdJagDpopDecision
            {
                Kind = IdJagDpopDecisionKind.SenderConstrainedToken,
                BoundKeyThumbprint = presentedKeyThumbprint
            };
        }

        //§9.8.1.2.4: no cnf and no proof — Bearer, unless the Resource Server requires constraint.
        return resourceServerRequiresSenderConstrained
            ? new IdJagDpopDecision { Kind = IdJagDpopDecisionKind.RejectSenderConstrainedRequired }
            : new IdJagDpopDecision { Kind = IdJagDpopDecisionKind.BearerToken };
    }
}
