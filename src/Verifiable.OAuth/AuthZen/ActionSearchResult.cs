using System.Diagnostics;

namespace Verifiable.OAuth.AuthZen;

/// <summary>
/// The result of an OpenID AuthZEN Authorization API 1.0 Action Search — the
/// Actions the subject may perform on the resource, plus the response
/// <see cref="Page"/> and an optional <see cref="Context"/>. Produced by the
/// <see cref="Server.SearchActionsDelegate"/> seam and serialised by the
/// library to <c>{ "page": { … }, "results": [ … ] }</c>.
/// </summary>
[DebuggerDisplay("ActionSearchResult Count={Results.Count}")]
public sealed record ActionSearchResult
{
    /// <summary>The matching Action entities, in the order to return them.</summary>
    public IReadOnlyList<AuthZenAction> Results { get; init; } = [];

    /// <summary>The response pagination object. Defaults to <see cref="AccessSearchPage.End"/>.</summary>
    public AccessSearchPage Page { get; init; } = AccessSearchPage.End;

    /// <summary>Optional response context conveyed alongside the results.</summary>
    public IReadOnlyDictionary<string, object>? Context { get; init; }
}
