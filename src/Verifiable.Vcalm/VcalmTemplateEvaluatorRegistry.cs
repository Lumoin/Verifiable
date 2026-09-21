using System.Text;
using Verifiable.Foundation;

namespace Verifiable.Vcalm;

/// <summary>
/// The W3C VCALM 1.0 §3.6.1 credential-template evaluation seam: a registry that selects a
/// <see cref="VcalmTemplateEvaluator"/> by the template's
/// <see cref="VcalmCredentialTemplate.TemplateType"/> and evaluates the template against the exchange
/// variables. This is the integration point a §3.6 workflow surface (V-5c) consumes to turn an issue
/// request's template + variables into a credential body; V-5c itself is out of scope here — this is
/// the seam plus the one evaluator that needs no engine.
/// </summary>
/// <remarks>
/// <para>
/// <c>Verifiable.Vcalm</c> ships NO <c>jsonata</c> evaluator: JSONata evaluation requires a real
/// engine, and this library takes no reference to one (not to <c>the application.Jsonata</c>, not to
/// any in-repo substitute). A deployment registers the engine of its choice for
/// <see cref="JsonataTemplateType"/> through <see cref="Register"/>; a template whose type has no
/// registered evaluator is refused (fail-closed) by <see cref="Evaluate"/> rather than evaluated by a
/// substitute mechanism — VCALM 1.0 §3.6.1's <c>credentialTemplates[].type</c> selects the mechanism
/// the workflow author actually asked for.
/// </para>
/// <para>
/// <see cref="LiteralTemplateType"/> (<c>literal</c>) IS wired by default: a template that carries no
/// variable references — a constant credential body. Its source bytes ARE the rendered result, so it
/// needs no evaluation engine at all.
/// </para>
/// <para>
/// The seam carries raw UTF-8 JSON bytes, not <c>System.Text.Json</c> — the <c>Verifiable.Vcalm</c>
/// serialization firewall keeps STJ out of the library; the application adapts its JSON to bytes at
/// the boundary. <see cref="Limits"/> bounds what crosses the seam; an evaluation engine's own
/// internal evaluation limits (expression depth, loop iteration counts, and so on) are the wirer's
/// concern, configured on the engine itself.
/// </para>
/// </remarks>
public sealed class VcalmTemplateEvaluatorRegistry: WiringComponent
{
    /// <summary>
    /// The §3.6.1 template type whose body is JSONata: <c>jsonata</c>. The only template type VCALM
    /// Appendix D uses. No evaluator is registered for it by default — a deployment supplies one.
    /// </summary>
    public const string JsonataTemplateType = "jsonata";

    /// <summary>
    /// The template type whose body is a constant (variable-free) credential body: <c>literal</c>.
    /// </summary>
    public const string LiteralTemplateType = "literal";


    /// <summary>The application operations keyed by their declared mechanism type.</summary>
    private Dictionary<string, VcalmTemplateEvaluator> Evaluators { get; set; }


    /// <summary>
    /// The size bounds this registry enforces around every registered evaluator's inputs and output.
    /// Settable so a deployment can size them for its own workflows; defaults to
    /// <see cref="VcalmTemplateLimits"/>'s sensible defaults.
    /// </summary>
    public VcalmTemplateLimits Limits
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    } = new();


    /// <summary>
    /// Creates a registry with the one evaluator that needs no engine wired: <c>literal</c>, for a
    /// constant body. No <c>jsonata</c> evaluator is registered — a deployment supplies one through
    /// <see cref="Register"/>.
    /// </summary>
    public VcalmTemplateEvaluatorRegistry()
    {
        Evaluators = new Dictionary<string, VcalmTemplateEvaluator>(StringComparer.Ordinal)
        {
            [LiteralTemplateType] = EvaluateLiteral
        };
    }


    /// <summary>
    /// Registers (or supersedes) the evaluator for a template type. A deployment calls this with a
    /// real JSONata engine (for example <c>the application.Jsonata</c>) for
    /// <see cref="JsonataTemplateType"/> to make <c>jsonata</c> templates evaluable.
    /// </summary>
    /// <param name="templateType">The §3.6.1 template type the evaluator handles.</param>
    /// <param name="evaluator">The evaluator to register for the type.</param>
    public void Register(string templateType, VcalmTemplateEvaluator evaluator)
    {
        lock(MutationLock)
        {
            EnsureMutable();
            ArgumentException.ThrowIfNullOrEmpty(templateType);
            ArgumentNullException.ThrowIfNull(evaluator);

            Evaluators[templateType] = evaluator;

        }
    }


    /// <summary>
    /// Whether an evaluator is registered for a template type.
    /// </summary>
    /// <param name="templateType">The §3.6.1 template type.</param>
    /// <returns><see langword="true"/> when an evaluator is registered for the type.</returns>
    public bool IsRegistered(string templateType)
    {
        ArgumentNullException.ThrowIfNull(templateType);

        return Evaluators.ContainsKey(templateType);
    }


    /// <summary>
    /// Evaluates a §3.6.1 credential template against the exchange variables, selecting the evaluator
    /// by the template's <see cref="VcalmCredentialTemplate.TemplateType"/> and enforcing
    /// <see cref="Limits"/> around it: the template source and the variables are checked BEFORE the
    /// evaluator runs, the rendered result AFTER (an oversized result is disposed, not returned).
    /// </summary>
    /// <param name="template">The credential template to evaluate.</param>
    /// <param name="variablesJson">The exchange variables the template maps into a credential body, as UTF-8 JSON.</param>
    /// <param name="pool">The pool the rendered result is allocated from; the caller owns and disposes it.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A successful result carrying the rendered credential (or <see langword="null"/> for the
    /// JSONata <c>undefined</c> outcome), or a failure result — VCALM 1.0 §3.6.1: an unregistered
    /// template type, an over-limit template / variables / result, or the registered evaluator itself
    /// throwing — that the caller reports through its own refusal path rather than a thrown exception.
    /// A cancellation request is propagated as <see cref="OperationCanceledException"/>, never turned
    /// into a failure result.
    /// </returns>
    /// <exception cref="ArgumentNullException">When <paramref name="template"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public VcalmTemplateEvaluationResult Evaluate(
        VcalmCredentialTemplate template,
        ReadOnlyMemory<byte> variablesJson,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(template);
        ArgumentNullException.ThrowIfNull(pool);

        if(!Evaluators.TryGetValue(template.TemplateType, out VcalmTemplateEvaluator? evaluator))
        {
            //VCALM 1.0 §3.6.1: credentialTemplates[].type selects the evaluation mechanism a workflow
            //step's issueRequest relies on. An unregistered type is a mechanism this instance cannot
            //honour, so the step fails closed rather than being evaluated by a substitute. The
            //client-supplied type is not repeated back: the caller's own request already names it.
            return VcalmTemplateEvaluationResult.Failure(
                "No credential-template evaluator is registered for the requested template type.");
        }

        int templateByteCount = Encoding.UTF8.GetByteCount(template.Template);
        if(templateByteCount > Limits.MaxTemplateBytes)
        {
            return VcalmTemplateEvaluationResult.Failure(
                $"The credential template is {templateByteCount} bytes, exceeding the maximum of {Limits.MaxTemplateBytes} bytes.");
        }

        if(variablesJson.Length > Limits.MaxVariablesBytes)
        {
            return VcalmTemplateEvaluationResult.Failure(
                $"The template evaluation variables are {variablesJson.Length} bytes, exceeding the maximum of {Limits.MaxVariablesBytes} bytes.");
        }

        PooledMemory? rendered;
        try
        {
            rendered = evaluator(template, variablesJson, pool, cancellationToken);
        }
        catch(Exception exception) when(exception is not OperationCanceledException)
        {
            //Fail-closed per this seam's own contract (see the summary above): a registered evaluator
            //(a real engine, not a substitute) throwing on malformed or over-limit input reaches the
            //caller as a refusal through the §3.6 problem-details path, never as an unhandled
            //exception escaping the library.
            return VcalmTemplateEvaluationResult.Failure(
                $"The registered evaluator for template type '{template.TemplateType}' failed: {exception.Message}");
        }

        if(rendered is not null && rendered.Length > Limits.MaxResultBytes)
        {
            int renderedLength = rendered.Length;
            rendered.Dispose();

            return VcalmTemplateEvaluationResult.Failure(
                $"The rendered credential template is {renderedLength} bytes, exceeding the maximum of {Limits.MaxResultBytes} bytes.");
        }

        return VcalmTemplateEvaluationResult.Success(rendered);
    }


    /// <summary>
    /// The built-in <c>literal</c> pass-through: the template's own UTF-8 encoded source IS the
    /// rendered credential body, copied into a pooled buffer. It reads no variables — a template
    /// that references one is a workflow-authoring error the evaluation cannot detect at this layer.
    /// </summary>
    /// <param name="template">The credential template whose source is the rendered result.</param>
    /// <param name="variablesJson">Unused: the literal evaluator reads no variables.</param>
    /// <param name="pool">The pool the rendered result is allocated from.</param>
    /// <param name="cancellationToken">Unused: the literal evaluator does no asynchronous or long-running work.</param>
    /// <returns>The template's own source, copied into a pooled UTF-8 buffer.</returns>
    private static PooledMemory EvaluateLiteral(
        VcalmCredentialTemplate template,
        ReadOnlyMemory<byte> variablesJson,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        byte[] utf8 = Encoding.UTF8.GetBytes(template.Template);

        return PooledMemory.FromBytes(utf8, pool, BufferTags.Json);
    }


    /// <summary>Copies mechanism membership into an independent alteration candidate.</summary>
    protected override WiringComponent CloneCore()
    {
        VcalmTemplateEvaluatorRegistry copy = (VcalmTemplateEvaluatorRegistry)base.CloneCore();
        copy.Evaluators = new(Evaluators, StringComparer.Ordinal);

        return copy;
    }
}


/// <summary>
/// The outcome of a <see cref="VcalmTemplateEvaluatorRegistry.Evaluate"/> call: either the rendered
/// credential body (possibly <see langword="null"/> for the JSONata <c>undefined</c> outcome) or a
/// failure detail the caller reports through its own VCALM refusal path.
/// </summary>
public sealed record VcalmTemplateEvaluationResult
{
    /// <summary>Whether the evaluation succeeded (a registered evaluator ran within the configured bounds).</summary>
    public required bool IsSuccess { get; init; }


    /// <summary>
    /// The rendered credential body on success, owned by the caller, who must dispose it. Also
    /// <see langword="null"/> on success when the evaluation itself produced no result (JSONata
    /// <c>undefined</c>), and always <see langword="null"/> on failure.
    /// </summary>
    public PooledMemory? Rendered { get; init; }


    /// <summary>The failure detail, populated only when <see cref="IsSuccess"/> is <see langword="false"/>.</summary>
    public string? FailureDetail { get; init; }


    /// <summary>Creates a successful result, carrying the rendered body or <see langword="null"/> for "no result".</summary>
    public static VcalmTemplateEvaluationResult Success(PooledMemory? rendered) =>
        new() { IsSuccess = true, Rendered = rendered };


    /// <summary>Creates a failed result carrying the refusal detail.</summary>
    public static VcalmTemplateEvaluationResult Failure(string detail) =>
        new() { IsSuccess = false, FailureDetail = detail };


}
