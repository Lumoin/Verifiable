using System.Diagnostics;

namespace Verifiable.OAuth.AuthZen;

/// <summary>
/// The <c>options</c> object of an OpenID AuthZEN Authorization API 1.0 Access
/// Evaluations API request — currently the batch evaluation
/// <see cref="Semantic"/>. Modelled as its own record so the options surface
/// can grow without reshaping <see cref="AccessEvaluationsRequest"/>.
/// </summary>
[DebuggerDisplay("AccessEvaluationsOptions Semantic={Semantic}")]
public sealed record AccessEvaluationsOptions
{
    /// <summary>
    /// How the PDP processes the <c>evaluations</c> array. Defaults to
    /// <see cref="AuthZenEvaluationsSemantic.ExecuteAll"/> per the spec.
    /// </summary>
    public AuthZenEvaluationsSemantic Semantic { get; init; } = AuthZenEvaluationsSemantic.ExecuteAll;
}
