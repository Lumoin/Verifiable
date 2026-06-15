namespace Verifiable.JsonPointer.Jsonata;

/// <summary>
/// Raised when a template uses a JSONata construct the minimal in-repo evaluator does not implement
/// (predicates, arithmetic, comparison / boolean operators, conditionals, the <c>$</c>-function
/// library, wildcards, higher-order functions, regex, lambdas, the transform operator). Erroring is
/// deliberate: the evaluator output becomes an issued credential, so an unsupported construct is a
/// hard stop rather than a silent mis-evaluation. A deployment wires the full JSONata engine from
/// <c>Lumoin.Veritas</c> to supersede this minimal evaluator and handle these constructs.
/// </summary>
public sealed class JsonataUnsupportedFeatureException: Exception
{
    /// <summary>
    /// Creates the exception with a message naming the unsupported construct.
    /// </summary>
    /// <param name="message">The message describing the unsupported construct.</param>
    public JsonataUnsupportedFeatureException(string message): base(message)
    {
    }


    /// <summary>
    /// Creates the exception with a message and an inner cause.
    /// </summary>
    /// <param name="message">The message describing the unsupported construct.</param>
    /// <param name="innerException">The underlying cause.</param>
    public JsonataUnsupportedFeatureException(string message, Exception innerException): base(message, innerException)
    {
    }


    /// <summary>
    /// Creates the exception with the default minimal-scope message.
    /// </summary>
    public JsonataUnsupportedFeatureException(): base(
        "This JSONata construct is not supported by the minimal in-repo evaluator; wire the full engine.")
    {
    }
}


/// <summary>
/// Raised when a template's source text or the evaluation of a template against an input exceeds one
/// of the evaluator's bounds (parse nesting depth, expression length, evaluation depth, or evaluation
/// step count). The bounds keep a pathological template or input from hanging, overflowing the stack,
/// or over-allocating while producing a credential. The bound that tripped is named in the message
/// and carried in <see cref="Limit"/>.
/// </summary>
public sealed class JsonataEvaluationLimitException: Exception
{
    /// <summary>
    /// The named limit that was exceeded.
    /// </summary>
    public JsonataLimit Limit { get; }


    /// <summary>
    /// Creates the exception for a specific exceeded limit.
    /// </summary>
    /// <param name="limit">The named limit that was exceeded.</param>
    /// <param name="message">The message describing how the bound was exceeded.</param>
    public JsonataEvaluationLimitException(JsonataLimit limit, string message): base(message)
    {
        Limit = limit;
    }


    /// <summary>
    /// Creates the exception with a message.
    /// </summary>
    /// <param name="message">The message describing how the bound was exceeded.</param>
    public JsonataEvaluationLimitException(string message): base(message)
    {
    }


    /// <summary>
    /// Creates the exception with a message and an inner cause.
    /// </summary>
    /// <param name="message">The message describing how the bound was exceeded.</param>
    /// <param name="innerException">The underlying cause.</param>
    public JsonataEvaluationLimitException(string message, Exception innerException): base(message, innerException)
    {
    }


    /// <summary>
    /// Creates the exception with the default message.
    /// </summary>
    public JsonataEvaluationLimitException(): base("A JSONata evaluation bound was exceeded.")
    {
    }
}


/// <summary>
/// The named bounds the minimal in-repo JSONata evaluator enforces, carried by
/// <see cref="JsonataEvaluationLimitException"/> so a caller can tell which bound a pathological
/// template or input tripped.
/// </summary>
public enum JsonataLimit
{
    /// <summary>The template source text exceeds <see cref="JsonataLimits.MaxExpressionLength"/> characters.</summary>
    ExpressionLength = 0,

    /// <summary>The parser's bracket / brace nesting exceeds <see cref="JsonataLimits.MaxParseDepth"/>.</summary>
    ParseDepth,

    /// <summary>The evaluator's recursive descent exceeds <see cref="JsonataLimits.MaxEvaluationDepth"/>.</summary>
    EvaluationDepth,

    /// <summary>The evaluator's step count exceeds <see cref="JsonataLimits.MaxEvaluationSteps"/>.</summary>
    EvaluationSteps
}


/// <summary>
/// Raised when a template's source text is not a well-formed expression the minimal in-repo
/// evaluator can parse (an unterminated string, a missing brace / bracket / colon, a stray token,
/// or trailing text after the expression). Distinct from
/// <see cref="JsonataUnsupportedFeatureException"/>: that signals a construct the evaluator
/// recognizes but does not implement, this signals text that is not valid JSONata at all.
/// </summary>
public sealed class JsonataParseException: Exception
{
    /// <summary>
    /// The zero-based character position in the template source where the parse failed.
    /// </summary>
    public int Position { get; }


    /// <summary>
    /// Creates the exception at a source position.
    /// </summary>
    /// <param name="message">The message describing the malformed text.</param>
    /// <param name="position">The zero-based character position where the parse failed.</param>
    public JsonataParseException(string message, int position): base(message)
    {
        Position = position;
    }


    /// <summary>
    /// Creates the exception with a message.
    /// </summary>
    /// <param name="message">The message describing the malformed text.</param>
    public JsonataParseException(string message): base(message)
    {
    }


    /// <summary>
    /// Creates the exception with a message and an inner cause.
    /// </summary>
    /// <param name="message">The message describing the malformed text.</param>
    /// <param name="innerException">The underlying cause.</param>
    public JsonataParseException(string message, Exception innerException): base(message, innerException)
    {
    }


    /// <summary>
    /// Creates the exception with the default message.
    /// </summary>
    public JsonataParseException(): base("The JSONata template source is malformed.")
    {
    }
}
