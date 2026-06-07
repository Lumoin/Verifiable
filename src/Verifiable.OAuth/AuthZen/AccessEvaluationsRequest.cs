using System.Diagnostics;

namespace Verifiable.OAuth.AuthZen;

/// <summary>
/// An OpenID AuthZEN Authorization API 1.0 Access Evaluations API (batch)
/// request — a set of decisions posed in one round-trip. The request-level
/// <see cref="Subject"/>, <see cref="Action"/>, <see cref="Resource"/>, and
/// <see cref="Context"/> supply defaults; each entry of
/// <see cref="Evaluations"/> may override them. <see cref="Options"/> selects
/// the batch evaluation semantic.
/// </summary>
/// <remarks>
/// <para>
/// The library parses the inbound JSON body into this neutral shape via the
/// application-supplied
/// <see cref="Server.ParseAccessEvaluationsRequestDelegate"/> (the
/// <c>Verifiable.OAuth</c> serialization firewall keeps STJ out of the
/// library), then resolves each <see cref="AccessEvaluationItem"/> against the
/// defaults into a full <see cref="AccessEvaluationRequest"/> and evaluates it
/// through the shared PDP seam <see cref="Server.EvaluateAccessDelegate"/>,
/// honouring <see cref="Options"/> for short-circuit.
/// </para>
/// <para>
/// When <see cref="Evaluations"/> is empty the request behaves as a single
/// Access Evaluation over the request-level defaults.
/// </para>
/// </remarks>
[DebuggerDisplay("AccessEvaluationsRequest Count={Evaluations.Count}")]
public sealed record AccessEvaluationsRequest
{
    /// <summary>The default Subject for entries that omit one. Optional.</summary>
    public AuthZenSubject? Subject { get; init; }

    /// <summary>The default Action for entries that omit one. Optional.</summary>
    public AuthZenAction? Action { get; init; }

    /// <summary>The default Resource for entries that omit one. Optional.</summary>
    public AuthZenResource? Resource { get; init; }

    /// <summary>The default Context for entries that omit one. Optional.</summary>
    public IReadOnlyDictionary<string, object>? Context { get; init; }

    /// <summary>
    /// The per-item requests. Empty (the default) means evaluate the
    /// request-level defaults as a single Access Evaluation.
    /// </summary>
    public IReadOnlyList<AccessEvaluationItem> Evaluations { get; init; } = [];

    /// <summary>
    /// The batch options, or <see langword="null"/> to apply the spec default
    /// (<see cref="AuthZenEvaluationsSemantic.ExecuteAll"/>).
    /// </summary>
    public AccessEvaluationsOptions? Options { get; init; }
}
