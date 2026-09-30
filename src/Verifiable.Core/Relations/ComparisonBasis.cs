namespace Verifiable.Core.Relations;

/// <summary>
/// Whose rule decided a comparison's <see cref="ComparisonOutcome"/>: the value's own deterministic
/// comparison, the application's comparison, or nothing.
/// </summary>
/// <remarks>
/// An audit reader asks not only whether a relation held but on whose authority: a comparison the library
/// decided from the value's own rule, and one the application decided from its own mapping, carry the same
/// outcome and different accountability. The basis keeps that apart. <see cref="None"/> pairs with
/// <see cref="ComparisonOutcome.Indeterminate"/>: when nothing could decide, nothing is named as the
/// decider.
/// </remarks>
public enum ComparisonBasis
{
    /// <summary>The value's own deterministic comparison, which the library applies, decided the outcome.</summary>
    ProfileRule,

    /// <summary>The application's comparison, supplied as a delegate, decided the outcome.</summary>
    ApplicationRule,

    /// <summary>
    /// Nothing could decide: neither the value's own rule nor the application's comparison defines the
    /// relation for these values. The outcome is <see cref="ComparisonOutcome.Indeterminate"/>.
    /// </summary>
    None
}
