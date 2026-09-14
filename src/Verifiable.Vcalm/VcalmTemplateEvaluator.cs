using Verifiable.Foundation;

namespace Verifiable.Vcalm;

/// <summary>
/// Evaluates a W3C VCALM 1.0 §3.6.1 credential template against the exchange variables, producing
/// the credential body as UTF-8 JSON. The template's <see cref="VcalmCredentialTemplate.TemplateType"/>
/// selects the evaluator through <see cref="VcalmTemplateEvaluatorRegistry"/>; <paramref name="variablesJson"/>
/// is the gathered exchange claims / values the template maps into a credential, itself UTF-8 JSON.
/// </summary>
/// <remarks>
/// This is the integration point a §3.6 workflow surface (V-5c) consumes to turn an issue request's
/// template + variables into a credential body. <c>Verifiable.Vcalm</c> ships no <c>jsonata</c>
/// evaluator of its own — the seam carries raw bytes precisely so the application can wire a real
/// JSONata engine (for example <c>Lumoin.Veritas.Jsonata</c>) without <c>Verifiable.Vcalm</c> taking a
/// reference to it or to <c>System.Text.Json</c> (the serialization firewall). The one built-in
/// evaluator, <c>literal</c>, needs no engine at all — see
/// <see cref="VcalmTemplateEvaluatorRegistry.LiteralTemplateType"/>.
/// </remarks>
/// <param name="template">The §3.6.1 credential template to evaluate.</param>
/// <param name="variablesJson">The exchange variables the template maps into a credential body, as UTF-8 JSON.</param>
/// <param name="pool">The pool the rendered result is allocated from; the caller of the evaluator owns and disposes the returned buffer.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The rendered credential body as an owned, pooled UTF-8 JSON buffer, or <see langword="null"/> when
/// the evaluation produces no result (the JSONata <c>undefined</c> outcome).
/// </returns>
public delegate PooledMemory? VcalmTemplateEvaluator(
    VcalmCredentialTemplate template,
    ReadOnlyMemory<byte> variablesJson,
    BaseMemoryPool pool,
    CancellationToken cancellationToken);
