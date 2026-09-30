namespace Verifiable.Core.Relations;

/// <summary>
/// The answer to whether a <see cref="ComparisonRelation"/> holds between a candidate and a reference:
/// it holds, it fails, or nothing could decide.
/// </summary>
/// <remarks>
/// <para>
/// A relation that neither the value's own rule nor the application's comparison defines answers
/// <see cref="Indeterminate"/>, and <see cref="Indeterminate"/> is never read as <see cref="Holds"/>.
/// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-prover-verifier-spec.txt">PIC Prover and Verifier (pic-prover-verifier-02) Section 4.2</see>
/// states the same discipline for its profiles: "a Verifier MUST reject a PCA whose profile is unknown or
/// does not define a deterministic comparison."
/// </para>
/// <para>
/// What an outcome leads to, a permit or a refusal, is a separate decision; the record of a comparison keeps
/// the outcome and the decision side by side. Which decision an <see cref="Indeterminate"/> outcome leads to
/// belongs to the profile that compares: a profile may permit an undecided comparison of a value its
/// specification makes optional, the record keeping that nothing decided it.
/// </para>
/// </remarks>
public enum ComparisonOutcome
{
    /// <summary>The relation holds between the candidate and the reference.</summary>
    Holds,

    /// <summary>The relation was decided and does not hold between the candidate and the reference.</summary>
    Fails,

    /// <summary>
    /// Nothing could decide the relation: neither the value's own rule nor the application's comparison
    /// defines it for these values. Never read as <see cref="Holds"/>.
    /// </summary>
    Indeterminate
}
