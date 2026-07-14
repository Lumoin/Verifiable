using System.Collections.Generic;
using Verifiable.JsonPointer.Jsonata;

namespace Verifiable.Vcalm;

/// <summary>
/// The W3C VCALM 1.0 §3.6.1 credential-template evaluation seam: a registry that selects a
/// <see cref="VcalmTemplateEvaluator"/> by the template's
/// <see cref="VcalmCredentialTemplate.TemplateType"/> and evaluates the template against the exchange
/// variables. This is the integration point a §3.6 workflow surface (V-5c) consumes to turn an issue
/// request's template + variables into a credential body; V-5c itself is out of scope here — this is
/// the seam plus the wiring so a <c>jsonata</c> template can be evaluated.
/// </summary>
/// <remarks>
/// <para>
/// Two evaluators are wired by default:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see cref="JsonataTemplateType"/> (<c>jsonata</c>), backed by the minimal in-repo JSONata engine
/// in <c>Verifiable.JsonPointer</c> — just enough to make the §3.6 credential-template feature
/// function (field / path navigation into the variables, object / array construction of the
/// credential, string concatenation, literals). A deployment registers the full JSONata engine from
/// <c>Lumoin.Veritas</c> for <c>jsonata</c> through <see cref="Register"/> to supersede the minimal
/// one as the production evaluator.
/// </description></item>
/// <item><description>
/// <see cref="LiteralTemplateType"/> (<c>literal</c>), a pass-through for a template that carries no
/// variable references — a constant credential body. It evaluates the body against an empty context,
/// so a template that does reference a variable navigates it to nothing rather than substituting.
/// </description></item>
/// </list>
/// <para>
/// The seam passes the neutral <see cref="JsonataValue"/> model, not <c>System.Text.Json</c> — the
/// <c>Verifiable.Vcalm</c> serialization firewall keeps STJ out of the library; the application
/// adapts its JSON to the model at the boundary.
/// </para>
/// </remarks>
public sealed class VcalmTemplateEvaluatorRegistry
{
    /// <summary>
    /// The §3.6.1 template type whose body is JSONata: <c>jsonata</c>. The only template type VCALM
    /// Appendix D uses.
    /// </summary>
    public const string JsonataTemplateType = "jsonata";

    /// <summary>
    /// The template type whose body is a constant (variable-free) credential body: <c>literal</c>.
    /// </summary>
    public const string LiteralTemplateType = "literal";


    private Dictionary<string, VcalmTemplateEvaluator> Evaluators { get; }


    /// <summary>
    /// Creates a registry with the two built-in evaluators wired: <c>jsonata</c> backed by the
    /// minimal in-repo engine, and <c>literal</c> for a constant body.
    /// </summary>
    public VcalmTemplateEvaluatorRegistry()
    {
        Evaluators = new Dictionary<string, VcalmTemplateEvaluator>(StringComparer.Ordinal)
        {
            [JsonataTemplateType] = EvaluateJsonata,
            [LiteralTemplateType] = EvaluateLiteral
        };
    }


    /// <summary>
    /// Registers (or supersedes) the evaluator for a template type. A deployment calls this with the
    /// full JSONata engine from <c>Lumoin.Veritas</c> for <see cref="JsonataTemplateType"/> to replace
    /// the minimal in-repo evaluator as the production one.
    /// </summary>
    /// <param name="templateType">The §3.6.1 template type the evaluator handles.</param>
    /// <param name="evaluator">The evaluator to register for the type.</param>
    public void Register(string templateType, VcalmTemplateEvaluator evaluator)
    {
        ArgumentException.ThrowIfNullOrEmpty(templateType);
        ArgumentNullException.ThrowIfNull(evaluator);

        Evaluators[templateType] = evaluator;
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
    /// by the template's <see cref="VcalmCredentialTemplate.TemplateType"/>.
    /// </summary>
    /// <param name="template">The credential template to evaluate.</param>
    /// <param name="variables">The exchange variables the template maps into a credential body.</param>
    /// <returns>The produced credential body.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="template"/> is <c>null</c>.</exception>
    /// <exception cref="KeyNotFoundException">When no evaluator is registered for the template type.</exception>
    public JsonataValue Evaluate(VcalmCredentialTemplate template, JsonataValue variables)
    {
        ArgumentNullException.ThrowIfNull(template);

        if(!Evaluators.TryGetValue(template.TemplateType, out VcalmTemplateEvaluator? evaluator))
        {
            throw new KeyNotFoundException(
                $"No VCALM credential-template evaluator is registered for the template type '{template.TemplateType}'.");
        }

        return evaluator(template, variables);
    }


    //The built-in jsonata evaluator: the minimal in-repo engine, superseded in production by the
    //full Lumoin.Veritas engine a deployment registers for the jsonata type.
    private static JsonataValue EvaluateJsonata(VcalmCredentialTemplate template, JsonataValue variables)
    {
        return JsonataEvaluator.Evaluate(template.Template, variables);
    }


    //The built-in literal pass-through: a constant credential body evaluated against an empty
    //context, so any variable reference navigates to nothing.
    private static JsonataValue EvaluateLiteral(VcalmCredentialTemplate template, JsonataValue variables)
    {
        return JsonataEvaluator.Evaluate(template.Template, JsonataValue.Null);
    }
}
