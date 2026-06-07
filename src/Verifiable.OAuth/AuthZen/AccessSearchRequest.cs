using System.Diagnostics;

namespace Verifiable.OAuth.AuthZen;

/// <summary>
/// An OpenID AuthZEN Authorization API 1.0 Search API request — the question
/// "enumerate the entities of the searched dimension that satisfy this query"
/// (§7). One neutral shape serves all three search endpoints; which fields
/// carry query criteria and which entity is being enumerated depends on the
/// endpoint:
/// <list type="bullet">
///   <item><description>
///   Subject Search: <see cref="Subject"/> carries the searched <c>type</c>
///   (its <c>id</c> is ignored); <see cref="Action"/> and <see cref="Resource"/>
///   are the criteria. Results are Subjects.
///   </description></item>
///   <item><description>
///   Resource Search: <see cref="Resource"/> carries the searched <c>type</c>
///   (its <c>id</c> is ignored); <see cref="Subject"/> and <see cref="Action"/>
///   are the criteria. Results are Resources.
///   </description></item>
///   <item><description>
///   Action Search: <see cref="Action"/> is omitted; <see cref="Subject"/> and
///   <see cref="Resource"/> are the criteria. Results are the permitted Actions.
///   </description></item>
/// </list>
/// </summary>
/// <remarks>
/// The library parses the inbound JSON into this shape via the
/// application-supplied <see cref="Server.ParseAccessSearchRequestDelegate"/>
/// and hands it to the endpoint's search seam; the seam owns enumeration and
/// paging.
/// </remarks>
[DebuggerDisplay("AccessSearchRequest")]
public sealed record AccessSearchRequest
{
    /// <summary>The Subject — searched dimension (Subject Search) or criterion (otherwise). Optional per endpoint.</summary>
    public AuthZenSubject? Subject { get; init; }

    /// <summary>The Action — criterion, or absent for Action Search. Optional per endpoint.</summary>
    public AuthZenAction? Action { get; init; }

    /// <summary>The Resource — searched dimension (Resource Search) or criterion (otherwise). Optional per endpoint.</summary>
    public AuthZenResource? Resource { get; init; }

    /// <summary>Free-form request context the search policy may consult. Optional.</summary>
    public IReadOnlyDictionary<string, object>? Context { get; init; }

    /// <summary>The pagination cursor, or <see langword="null"/> for the first page with the seam's default size.</summary>
    public AccessSearchPageRequest? Page { get; init; }
}
