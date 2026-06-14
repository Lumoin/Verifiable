using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// A W3C VCALM 1.0 §3.6.1 credential template: the <c>type</c> that selects how the template body is
/// evaluated and the verbatim <c>template</c> body itself, optionally identified by <c>id</c>. A
/// workflow's <c>credentialTemplates</c> array carries one of these per entry; an issue request
/// names one by id or index and supplies the exchange <c>variables</c> the template maps into a
/// credential body.
/// </summary>
/// <remarks>
/// <para>
/// This is the neutral shape the template-evaluation seam consumes — the <see cref="VcalmTemplateEvaluator"/>
/// reads <see cref="TemplateType"/> to select an evaluator and feeds it <see cref="Template"/> with the
/// exchange variables. <c>Verifiable.Vcalm</c> stays free of <c>System.Text.Json</c>: the template
/// body is the verbatim source string and the variables / result are the neutral
/// <see cref="Verifiable.JsonPointer.Jsonata.JsonataValue"/> model, not an STJ document.
/// </para>
/// <para>
/// VCALM's only registered template type is <c>jsonata</c> (Appendix D). The minimal in-repo
/// evaluator handles the §3.6 credential-template subset; a deployment registers the full JSONata
/// engine from <c>Lumoin.Veritas</c> to supersede it.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmCredentialTemplate Id={Id} Type={TemplateType}")]
public sealed record VcalmCredentialTemplate
{
    /// <summary>
    /// The §3.6.1 template <c>type</c> that selects the evaluator (e.g. <c>jsonata</c>). Compared
    /// ordinally and case-sensitively against the registered evaluator keys.
    /// </summary>
    public required string TemplateType { get; init; }

    /// <summary>
    /// The §3.6.1 verbatim template <c>template</c> body — the source the selected evaluator
    /// interprets against the exchange variables.
    /// </summary>
    public required string Template { get; init; }

    /// <summary>
    /// The OPTIONAL §3.6.1 template <c>id</c>, by which an issue request's
    /// <c>credentialTemplateId</c> selects this template. <see langword="null"/> when the workflow
    /// identifies the template only by its array index (<c>credentialTemplateIndex</c>).
    /// </summary>
    public string? Id { get; init; }
}
