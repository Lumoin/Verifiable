using Verifiable.JsonPointer.Jsonata;

namespace Verifiable.Vcalm;

/// <summary>
/// Evaluates a W3C VCALM 1.0 §3.6.1 credential template against the exchange variables, producing
/// the credential body. The template's <see cref="VcalmCredentialTemplate.TemplateType"/> selects the
/// evaluator; the <paramref name="variables"/> are the gathered exchange claims / values the template
/// maps into the credential.
/// </summary>
/// <remarks>
/// This is the integration point a §3.6 workflow surface (V-5c) consumes to turn an issue request's
/// template + variables into a credential body. The default <c>jsonata</c> evaluator is backed by the
/// minimal in-repo JSONata engine in <c>Verifiable.JsonPointer</c>; a deployment registers the full
/// JSONata engine from <c>Lumoin.Veritas</c> to supersede it. The seam passes the neutral
/// <see cref="JsonataValue"/> model, not <c>System.Text.Json</c> — the <c>Verifiable.Vcalm</c>
/// serialization firewall keeps STJ out of the library.
/// </remarks>
/// <param name="template">The §3.6.1 credential template to evaluate.</param>
/// <param name="variables">The exchange variables the template maps into a credential body.</param>
/// <returns>The produced credential body.</returns>
public delegate JsonataValue VcalmTemplateEvaluator(VcalmCredentialTemplate template, JsonataValue variables);
