using System.Diagnostics;

namespace Verifiable.OAuth.AuthZen;

/// <summary>
/// The Action entity of an OpenID AuthZEN Authorization API 1.0 Access
/// Evaluation — the operation the subject seeks to perform on the resource
/// (e.g. <c>can_read</c>, <c>can_delete</c>).
/// </summary>
/// <remarks>
/// Neutral information-model POCO. <see cref="Properties"/> is the free-form
/// attribute bag the Policy Decision Point's policy may read; the library
/// never interprets it.
/// </remarks>
[DebuggerDisplay("AuthZenAction {Name,nq}")]
public sealed record AuthZenAction
{
    /// <summary>The action's name (e.g. <c>can_read</c>). Required.</summary>
    public required string Name { get; init; }

    /// <summary>Free-form action attributes the PDP policy may consult. Optional.</summary>
    public IReadOnlyDictionary<string, object>? Properties { get; init; }
}
