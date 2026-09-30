using System.Diagnostics;

namespace Verifiable.Core.Relations;

/// <summary>
/// The record of one comparison: what was compared, under which <see cref="ComparisonRelation"/>, with
/// which <see cref="ComparisonOutcome"/>, by whose rule (<see cref="ComparisonBasis"/>) and what was decided
/// (<see cref="ComparisonDecision"/>).
/// </summary>
/// <remarks>
/// <para>
/// A refusal is never silent. The answer that leaves the library reads the same for a
/// <see cref="ComparisonDecision.Deny"/> and a <see cref="ComparisonDecision.IndeterminateDeny"/>; this record
/// is where the two stay apart, together with the values and the rule that produced them, so the audit trail
/// keeps the attempt and not only its result. The remarks of
/// <see cref="Verifiable.Core.Model.SelectiveDisclosure.DisclosureComputation{TCredential}"/> set the same
/// discipline for a disclosure proposal the pipeline clamps.
/// </para>
/// <para>
/// The candidate and the reference are the current value and the predecessor of the
/// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-prover-verifier-spec.txt">PIC Prover and Verifier (pic-prover-verifier-02) Section 4.2</see>
/// comparisons. Either can be a personal identifier, so the debugger display shows the relation, the
/// outcome, the basis and the decision only.
/// </para>
/// </remarks>
/// <typeparam name="TCandidate">The type of the value presented at this step.</typeparam>
/// <typeparam name="TReference">The type of the value the candidate is judged against.</typeparam>
[DebuggerDisplay("Comparison(Relation={Relation}, Outcome={Outcome}, Basis={Basis}, Decision={Decision})")]
public sealed class ComparisonRecord<TCandidate, TReference>
{
    /// <summary>The relation the comparison asked to hold, read "candidate RELATION reference".</summary>
    public required ComparisonRelation Relation { get; init; }

    /// <summary>Whether the relation held, failed, or could not be decided.</summary>
    public required ComparisonOutcome Outcome { get; init; }

    /// <summary>Whose rule decided <see cref="Outcome"/>.</summary>
    public required ComparisonBasis Basis { get; init; }

    /// <summary>What <see cref="Outcome"/> led to.</summary>
    public required ComparisonDecision Decision { get; init; }

    /// <summary>The value presented at this step: the current value of the PIC comparisons.</summary>
    public required TCandidate Candidate { get; init; }

    /// <summary>The value the candidate was judged against: the predecessor of the PIC comparisons.</summary>
    public required TReference Reference { get; init; }

    /// <summary>A human-readable reason for the decision, when the deciding rule gave one.</summary>
    public string? Reason { get; init; }
}
