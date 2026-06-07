using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// The verdict an <see cref="AssessVpDisclosureDelegate"/> returns, derived from
/// the Core disclosure engine's <c>DisclosureStrategyGraph</c>.
/// </summary>
[DebuggerDisplay("Assessment(Satisfied={Satisfied}, OverDisclosed={OverDisclosed})")]
public sealed record Oid4VpDisclosureAssessment
{
    /// <summary>
    /// Whether the disclosed claims satisfy the credential query's requirements —
    /// <c>graph.Satisfied</c>. Surfaced onto
    /// <see cref="Verifiable.OAuth.Validation.ValidationContext.DcqlSatisfied"/>.
    /// </summary>
    public required bool Satisfied { get; init; }

    /// <summary>
    /// Whether the presentation disclosed claims beyond what the query asked — the
    /// disclosed paths that the engine did not select for disclosure. Surfaced onto
    /// <see cref="Verifiable.OAuth.Validation.ValidationContext.DcqlOverDisclosed"/>.
    /// </summary>
    public required bool OverDisclosed { get; init; }
}
