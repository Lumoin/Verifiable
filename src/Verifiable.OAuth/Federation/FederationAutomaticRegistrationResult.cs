using System.Diagnostics;
using Verifiable.OAuth.Trust;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Outcome of <see cref="FederationAutomaticRegistration.ResolveAsync"/> — the
/// OpenID Federation 1.0 §12.1 automatic-registration assessment of a Relying
/// Party whose <c>client_id</c> is its Entity Identifier. Either carries the
/// RP's effective (policy-applied) metadata and the validated chain (the RP is
/// admitted for the request), or a structured <see cref="RejectionReason"/>.
/// </summary>
/// <remarks>
/// <para>
/// Same fail-closed, sealed-record-with-nullable-fields shape as the other
/// Federation result types (<see cref="TrustChainValidationOutcome"/>,
/// <see cref="MetadataPolicyApplyResult"/>): <see cref="IsRegistered"/> is
/// derived purely from the absence of a rejection reason, so a result can
/// never be both registered and rejected.
/// </para>
/// <para>
/// The application projects <see cref="EffectiveMetadata"/> onto a per-request
/// <see cref="Server.ClientRecord"/> (redirect URIs, scopes, jwks, …); the
/// library does not assemble the record itself because the remaining fields
/// (tenant, capability set, token lifetimes) are deployment choices. The
/// <see cref="Assessment"/> and <see cref="ValidUntil"/> carry the
/// party-trust decision so the application can bound the ephemeral
/// registration's lifetime to the chain's earliest expiry and record the
/// decision for audit.
/// </para>
/// </remarks>
[DebuggerDisplay("FederationAutomaticRegistrationResult Registered={IsRegistered} Subject={Subject.Value,nq}")]
public sealed record FederationAutomaticRegistrationResult
{
    /// <summary>
    /// The Relying Party's Entity Identifier — the <c>client_id</c> the
    /// automatic registration was assessed for. Always set, on both success
    /// and rejection.
    /// </summary>
    public required EntityIdentifier Subject { get; init; }

    /// <summary>
    /// The RP's effective metadata for the requested entity type after
    /// §6.1.4 policy application, when registered; otherwise
    /// <see langword="null"/>.
    /// </summary>
    public IReadOnlyDictionary<string, object>? EffectiveMetadata { get; init; }

    /// <summary>
    /// The validated trust chain (leaf → anchor), when registered; otherwise
    /// <see langword="null"/>.
    /// </summary>
    public TrustChain? Chain { get; init; }

    /// <summary>
    /// The instant past which the registration MUST be re-assessed — the
    /// party-trust engine's earliest expiry bound (typically the chain's
    /// soonest <c>exp</c>). <see langword="null"/> when unbounded.
    /// </summary>
    public DateTimeOffset? ValidUntil { get; init; }

    /// <summary>
    /// The party-trust assessment that admitted (or would have admitted) the
    /// RP, for audit / observability. <see langword="null"/> on rejections
    /// that never reached the trust engine.
    /// </summary>
    public PartyTrustAssessment? Assessment { get; init; }

    /// <summary>
    /// The reason automatic registration was refused; <see langword="null"/>
    /// when the RP is registered.
    /// </summary>
    public string? RejectionReason { get; init; }

    /// <summary>
    /// <see langword="true"/> when the RP was admitted for the request.
    /// </summary>
    public bool IsRegistered => RejectionReason is null;


    /// <summary>
    /// Builds a success result admitting the RP with its resolved effective
    /// metadata, validated chain, and trust decision.
    /// </summary>
    public static FederationAutomaticRegistrationResult Registered(
        EntityIdentifier subject,
        IReadOnlyDictionary<string, object> effectiveMetadata,
        TrustChain chain,
        DateTimeOffset? validUntil,
        PartyTrustAssessment assessment)
    {
        ArgumentNullException.ThrowIfNull(effectiveMetadata);
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(assessment);

        return new FederationAutomaticRegistrationResult
        {
            Subject = subject,
            EffectiveMetadata = effectiveMetadata,
            Chain = chain,
            ValidUntil = validUntil,
            Assessment = assessment
        };
    }


    /// <summary>
    /// Builds a rejection result with the given reason. The optional
    /// <paramref name="assessment"/> is carried when the rejection came from
    /// the trust engine (so the audit trail keeps the verdicts).
    /// </summary>
    public static FederationAutomaticRegistrationResult Rejected(
        EntityIdentifier subject,
        string reason,
        PartyTrustAssessment? assessment = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        return new FederationAutomaticRegistrationResult
        {
            Subject = subject,
            RejectionReason = reason,
            Assessment = assessment
        };
    }
}
