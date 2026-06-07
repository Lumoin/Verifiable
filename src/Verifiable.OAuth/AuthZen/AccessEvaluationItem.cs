using System.Diagnostics;

namespace Verifiable.OAuth.AuthZen;

/// <summary>
/// One entry of the <c>evaluations</c> array of an OpenID AuthZEN
/// Authorization API 1.0 Access Evaluations API request. Each field is
/// optional: a field left <see langword="null"/> inherits the request-level
/// default (<see cref="AccessEvaluationsRequest.Subject"/> and siblings); a
/// field set here overrides the default for this item.
/// </summary>
/// <remarks>
/// Whole-entity override per the spec — a present <see cref="Subject"/>
/// replaces the default Subject entirely (not a field-level merge). The
/// library resolves each item against the request defaults before handing the
/// resulting <see cref="AccessEvaluationRequest"/> to the PDP seam.
/// </remarks>
[DebuggerDisplay("AccessEvaluationItem")]
public sealed record AccessEvaluationItem
{
    /// <summary>The Subject for this item, or <see langword="null"/> to inherit the default.</summary>
    public AuthZenSubject? Subject { get; init; }

    /// <summary>The Action for this item, or <see langword="null"/> to inherit the default.</summary>
    public AuthZenAction? Action { get; init; }

    /// <summary>The Resource for this item, or <see langword="null"/> to inherit the default.</summary>
    public AuthZenResource? Resource { get; init; }

    /// <summary>The Context for this item, or <see langword="null"/> to inherit the default.</summary>
    public IReadOnlyDictionary<string, object>? Context { get; init; }
}
