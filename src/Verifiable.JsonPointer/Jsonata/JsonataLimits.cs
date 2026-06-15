namespace Verifiable.JsonPointer.Jsonata;

/// <summary>
/// The named bounds the minimal in-repo JSONata evaluator enforces so a pathological template or
/// input cannot hang, stack-overflow, or over-allocate while producing a credential. Each bound is
/// an explicit named constant tripped to a typed <see cref="JsonataEvaluationLimitException"/>. The
/// values are generous for the VCALM credential-template shapes (a handful of nested objects, paths
/// a few segments deep) yet small enough to keep evaluation bounded and deterministic. The full
/// JSONata engine from <c>Lumoin.Veritas</c> that supersedes this evaluator carries its own bounds.
/// </summary>
public static class JsonataLimits
{
    /// <summary>
    /// The maximum number of characters a template source may contain before parsing is refused
    /// (<see cref="JsonataLimit.ExpressionLength"/>). A VCALM credential template is a few hundred
    /// to a few thousand characters; the ceiling stops an over-sized blob from being parsed at all.
    /// </summary>
    public const int MaxExpressionLength = 64 * 1024;

    /// <summary>
    /// The maximum object / array nesting depth the parser accepts before refusing
    /// (<see cref="JsonataLimit.ParseDepth"/>). The Appendix-D credential templates nest a handful
    /// of objects deep; this caps the parser's recursion so a deeply-nested source cannot overflow
    /// the stack during parsing.
    /// </summary>
    public const int MaxParseDepth = 64;

    /// <summary>
    /// The maximum recursive-descent depth the evaluator reaches before refusing
    /// (<see cref="JsonataLimit.EvaluationDepth"/>). Enforced on every recursive step — path
    /// navigation, object construction, array construction — so a pathological AST cannot overflow
    /// the stack during evaluation.
    /// </summary>
    public const int MaxEvaluationDepth = 128;

    /// <summary>
    /// The maximum number of evaluation steps (one per evaluated node) before the evaluator refuses
    /// (<see cref="JsonataLimit.EvaluationSteps"/>). A broad but shallow template — many sibling
    /// members — is bounded by this even when it never reaches the depth limit.
    /// </summary>
    public const int MaxEvaluationSteps = 100_000;
}
