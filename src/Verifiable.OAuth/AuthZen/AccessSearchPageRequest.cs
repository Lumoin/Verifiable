using System.Diagnostics;

namespace Verifiable.OAuth.AuthZen;

/// <summary>
/// The request-side <c>page</c> object of an OpenID AuthZEN Authorization API
/// 1.0 Search API request — the pagination cursor a Policy Enforcement Point
/// sends to continue or bound a search.
/// </summary>
/// <remarks>
/// The library carries these values opaquely to the search seam; it neither
/// generates nor interprets the <see cref="Token"/>. The seam owns paging.
/// </remarks>
[DebuggerDisplay("AccessSearchPageRequest Token={Token} Limit={Limit}")]
public sealed record AccessSearchPageRequest
{
    /// <summary>
    /// An opaque continuation token from the <c>next_token</c> of a prior
    /// response, or <see langword="null"/> for the first page.
    /// </summary>
    public string? Token { get; init; }

    /// <summary>
    /// The maximum number of results to return (a non-negative integer), or
    /// <see langword="null"/> for the seam's default.
    /// </summary>
    public int? Limit { get; init; }

    /// <summary>Additional implementation-specific request paging attributes. Optional.</summary>
    public IReadOnlyDictionary<string, object>? Properties { get; init; }
}
