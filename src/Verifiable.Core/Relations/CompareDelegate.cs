namespace Verifiable.Core.Relations;

/// <summary>
/// The application's comparison: decides whether <paramref name="relation"/> holds between
/// <paramref name="candidate"/> and <paramref name="reference"/> where the value's own rule cannot decide it.
/// </summary>
/// <remarks>
/// <para>
/// The library applies a value's own deterministic comparison itself and records it as
/// <see cref="ComparisonBasis.ProfileRule"/>. What that rule cannot decide, for instance whether two
/// identifiers from different namespaces name the same party, is the application's knowledge; the library
/// asks this delegate and records its answer as <see cref="ComparisonBasis.ApplicationRule"/>.
/// </para>
/// <para>
/// The comparison is asynchronous because an application's mapping may need a lookup the application
/// performs itself. The library keeps no cache of the answers and retries nothing: a failure inside the
/// delegate is the application's to handle.
/// </para>
/// <para>
/// The comparison is deterministic by the application's obligation: the same candidate, reference and
/// relation give the same outcome. An audit record is only as good as the rule it names, and
/// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-prover-verifier-spec.txt">PIC Prover and Verifier (pic-prover-verifier-02) Section 4.2</see>
/// asks every profile that introduces an authority representation to define "its syntax, its equivalence
/// relation, its attenuation order" and "a deterministic comparison sufficient for non-expansion
/// validation." The same discipline holds for the comparison an application supplies.
/// </para>
/// <para>
/// A relation the application does not define answers <see cref="ComparisonOutcome.Indeterminate"/>, never
/// <see cref="ComparisonOutcome.Holds"/>.
/// </para>
/// </remarks>
/// <typeparam name="TCandidate">The type of the value presented at this step.</typeparam>
/// <typeparam name="TReference">The type of the value the candidate is judged against.</typeparam>
/// <param name="candidate">The value presented at this step.</param>
/// <param name="reference">The value the candidate is judged against.</param>
/// <param name="relation">The relation asked to hold, read "candidate RELATION reference".</param>
/// <param name="cancellationToken">The token that cancels the comparison.</param>
/// <returns>Whether the relation holds, fails, or cannot be decided by the application.</returns>
public delegate ValueTask<ComparisonOutcome> CompareDelegate<in TCandidate, in TReference>(TCandidate candidate, TReference reference, ComparisonRelation relation, CancellationToken cancellationToken);
