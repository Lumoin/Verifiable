namespace Verifiable.Vcalm;

/// <summary>
/// Size bounds the W3C VCALM 1.0 §3.6.1 credential-template evaluation seam enforces around a
/// deployment's registered <see cref="VcalmTemplateEvaluator"/>: the template source, the exchange
/// variables fed to it, and the rendered credential body it returns.
/// </summary>
/// <remarks>
/// <para>
/// These bounds belong to <see cref="VcalmTemplateEvaluatorRegistry"/>, not to the registered
/// evaluator: <see cref="VcalmTemplateEvaluatorRegistry.Evaluate"/> refuses BEFORE invoking the
/// evaluator when the template or the variables exceed their bound, and AFTER when the rendered
/// result exceeds its bound (disposing the oversized result rather than returning it). An
/// evaluation engine's OWN internal evaluation limits — expression depth, loop iteration counts, and
/// so on (for example the <c>Lumoin.Veritas.Jsonata</c> engine's <c>JsonataLimits</c>) — are the
/// wirer's concern; this type bounds only what crosses the seam.
/// </para>
/// <para>
/// Instantiated once and set on <see cref="VcalmIntegration.VcalmTemplateEvaluators"/> at the
/// integration/options level where the registry is configured; the defaults are sized for a small
/// admin-authored §3.6.1 credential template, not an arbitrarily large document.
/// </para>
/// </remarks>
public sealed record VcalmTemplateLimits
{
    /// <summary>
    /// The maximum size, in UTF-8 bytes, of a §3.6.1 credential template's <c>template</c> source.
    /// Defaults to 64 KiB.
    /// </summary>
    public int MaxTemplateBytes { get; init; } = 64 * 1024;

    /// <summary>
    /// The maximum size, in UTF-8 bytes, of the exchange variables fed to a template evaluation.
    /// Defaults to 256 KiB.
    /// </summary>
    public int MaxVariablesBytes { get; init; } = 256 * 1024;

    /// <summary>
    /// The maximum size, in UTF-8 bytes, of a rendered credential body a template evaluation
    /// produces. Defaults to 1 MiB.
    /// </summary>
    public int MaxResultBytes { get; init; } = 1024 * 1024;
}
