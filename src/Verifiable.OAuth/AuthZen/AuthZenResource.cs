using System.Diagnostics;

namespace Verifiable.OAuth.AuthZen;

/// <summary>
/// The Resource entity of an OpenID AuthZEN Authorization API 1.0 Access
/// Evaluation — the protected object access is being evaluated against (an
/// account, document, API, …).
/// </summary>
/// <remarks>
/// Neutral information-model POCO. <see cref="Properties"/> is the free-form
/// attribute bag the Policy Decision Point's policy may read (owner, labels,
/// sensitivity, …); the library never interprets it.
/// </remarks>
[DebuggerDisplay("AuthZenResource {Type,nq}:{Id,nq}")]
public sealed record AuthZenResource
{
    /// <summary>The resource's type (e.g. <c>account</c>, <c>document</c>). Required.</summary>
    public required string Type { get; init; }

    /// <summary>The resource's identifier within its <see cref="Type"/>. Required.</summary>
    public required string Id { get; init; }

    /// <summary>Free-form resource attributes the PDP policy may consult. Optional.</summary>
    public IReadOnlyDictionary<string, object>? Properties { get; init; }
}
