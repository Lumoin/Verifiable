namespace Verifiable.Core.SelectiveDisclosure.Strategy;

/// <summary>
/// How a requirement is satisfied: by disclosing the underlying value or by
/// generating a zero-knowledge proof of a predicate over it.
/// </summary>
/// <remarks>
/// <para>
/// This distinction is fundamental to entropy accounting. A direct disclosure
/// releases the attribute value, contributing its full entropy weight to the
/// strategy's total. A predicate proof satisfies the verifier's requirement
/// without revealing the value, contributing zero or near-zero entropy.
/// </para>
/// <para>
/// Example: a verifier requires proof of age. Direct disclosure reveals
/// <c>/birthdate = 1990-03-15</c> (high entropy — narrows population significantly).
/// Predicate proof demonstrates <c>/birthdate &lt; 2008-03-03</c> (low entropy —
/// only confirms membership in a large age cohort).
/// </para>
/// </remarks>
public enum SatisfactionMode
{
    /// <summary>
    /// The attribute value is disclosed directly to the verifier.
    /// Full entropy weight applies.
    /// </summary>
    Disclosure,

    /// <summary>
    /// A zero-knowledge predicate proof is generated.
    /// Entropy weight is zero or near-zero depending on predicate selectivity.
    /// </summary>
    PredicateProof
}
