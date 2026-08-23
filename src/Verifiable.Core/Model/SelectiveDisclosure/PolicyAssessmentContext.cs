using System;
using System.Collections.Generic;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Context provided to a <see cref="PolicyAssessorDelegate{TCredential}"/> for making
/// disclosure decisions.
/// </summary>
/// <remarks>
/// <para>
/// This context represents the state at a specific point in the policy pipeline
/// (Layer 4 of the DCQL Disclosure Architecture). It carries the lattice computation
/// result from Layer 3 and enables the assessor to make informed decisions about
/// narrowing or rejecting the proposed disclosure.
/// </para>
/// <para>
/// <strong>Assessor contract:</strong> Assessors may narrow <see cref="ProposedPaths"/>
/// (remove paths) or widen it within <see cref="SetDisclosureLattice{TClaim}.Top"/>, and must
/// keep <see cref="SetDisclosureLattice{TClaim}.Bottom"/>. A returned set that leaves those
/// bounds does not take effect: the computation clamps it back with
/// <see cref="SetDisclosureLattice{TClaim}.Clamp"/> and records the attempt, so an assessor
/// gains nothing by returning one. Assessors can query the lattice to check bounds, compute
/// alternative disclosure sets, or verify that removing a path would not violate mandatory
/// requirements.
/// </para>
/// <para>
/// <strong>Contextual inputs:</strong> In addition to the credential and lattice, assessors
/// may use the <see cref="Format"/> to apply format-aware policies, the
/// <see cref="QueryRequirementId"/> to correlate with external policy stores, and the
/// <see cref="SatisfiesRequirements"/> flag to decide whether further narrowing is acceptable.
/// Advanced deployments may extend this context (via wrapper patterns) with additional
/// signals such as verifier trust level, declared purpose, time of day, geolocation, or
/// device attestation status.
/// </para>
/// </remarks>
/// <typeparam name="TCredential">The application-specific credential type.</typeparam>
public sealed class PolicyAssessmentContext<TCredential>
{
    /// <summary>
    /// The credential being considered for disclosure.
    /// </summary>
    public required TCredential Credential { get; init; }

    /// <summary>
    /// The query requirement this disclosure satisfies.
    /// </summary>
    public required string QueryRequirementId { get; init; }

    /// <summary>
    /// The paths proposed for disclosure by the lattice computation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The assessor may narrow this set (remove paths) or expand it (add paths within
    /// the lattice top), and must not remove mandatory paths (lattice bottom). The returned
    /// set is a proposal: the computation clamps it into <see cref="Lattice"/> before adopting
    /// it, so paths outside the bounds are dropped and mandatory or ancestor paths are restored.
    /// </para>
    /// </remarks>
    public required IReadOnlySet<CredentialPath> ProposedPaths { get; init; }

    /// <summary>
    /// The lattice for this credential, enabling the assessor to query bounds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Assessors can use the lattice to check whether removing a path would
    /// violate mandatory requirements (<see cref="SetDisclosureLattice{TClaim}.Bottom"/>),
    /// whether alternative paths exist in the selectable set, or to compute
    /// minimum and maximum disclosure bounds for constraint solving.
    /// </para>
    /// <para>
    /// SAT solver assessors use the lattice bounds as constraints in the
    /// satisfiability problem. AI assessors may use the lattice to compute
    /// the privacy cost of each additional path disclosure.
    /// </para>
    /// </remarks>
    public required SetDisclosureLattice<CredentialPath> Lattice { get; init; }

    /// <summary>
    /// Whether the proposed paths satisfy all verifier requirements.
    /// </summary>
    public required bool SatisfiesRequirements { get; init; }

    /// <summary>
    /// Paths that are in conflict (verifier requires but user excluded).
    /// </summary>
    public IReadOnlySet<CredentialPath>? ConflictingPaths { get; init; }

    /// <summary>
    /// The credential format, for format-aware policy decisions.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Assessors may use this to apply format-specific policies (e.g., different
    /// rules for SD-JWT versus mso_mdoc credentials) or to determine whether
    /// ZKP escalation is possible for the credential's format.
    /// </para>
    /// </remarks>
    public string? Format { get; init; }

    /// <summary>
    /// Contextual signals from the requesting party, the attestation, and the environment.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Keyed by well-known types. Assessors retrieve signals by type, enabling
    /// compile-time safety for common signal types while remaining extensible for
    /// application-specific signals. The computation merges requesting party signals
    /// with per-credential attestation metadata, with attestation metadata taking
    /// precedence when both contain the same type key.
    /// </para>
    /// </remarks>
    public IReadOnlyDictionary<Type, object>? Signals { get; init; }
}
