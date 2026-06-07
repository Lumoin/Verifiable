using System.Diagnostics;

namespace Verifiable.OAuth.AuthZen;

/// <summary>
/// The Subject entity of an OpenID AuthZEN Authorization API 1.0 Access
/// Evaluation — the principal whose access is being evaluated (a user,
/// service, device, …).
/// </summary>
/// <remarks>
/// Neutral information-model POCO. <see cref="Properties"/> is the free-form
/// attribute bag the Policy Decision Point's policy may read (roles,
/// department, assurance level, …); the library never interprets it.
/// </remarks>
[DebuggerDisplay("AuthZenSubject {Type,nq}:{Id,nq}")]
public sealed record AuthZenSubject
{
    /// <summary>The subject's type (e.g. <c>user</c>, <c>service</c>). Required.</summary>
    public required string Type { get; init; }

    /// <summary>The subject's identifier within its <see cref="Type"/>. Required.</summary>
    public required string Id { get; init; }

    /// <summary>Free-form subject attributes the PDP policy may consult. Optional.</summary>
    public IReadOnlyDictionary<string, object>? Properties { get; init; }
}
