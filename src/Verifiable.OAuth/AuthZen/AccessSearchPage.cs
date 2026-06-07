using System.Diagnostics;

namespace Verifiable.OAuth.AuthZen;

/// <summary>
/// The response-side <c>page</c> object of an OpenID AuthZEN Authorization API
/// 1.0 Search API response. <see cref="NextToken"/> is REQUIRED on the wire;
/// an empty string signals the end of results.
/// </summary>
/// <remarks>
/// A search seam that does not paginate can return results with the default
/// <see cref="End"/> page — the library then emits <c>"next_token": ""</c>,
/// the conformant end-of-results signal.
/// </remarks>
[DebuggerDisplay("AccessSearchPage NextToken={NextToken} Count={Count} Total={Total}")]
public sealed record AccessSearchPage
{
    /// <summary>
    /// The continuation token for the next page; an empty string (the default)
    /// signals the end of results. Always emitted.
    /// </summary>
    public string NextToken { get; init; } = "";

    /// <summary>The number of results included in this response. Optional.</summary>
    public long? Count { get; init; }

    /// <summary>The total number of results matching the query criteria. Optional.</summary>
    public long? Total { get; init; }

    /// <summary>
    /// Additional implementation-specific pagination response attributes (§7).
    /// Emitted as members of the <c>page</c> object when present; omitted when
    /// <see langword="null"/> or empty.
    /// </summary>
    public IReadOnlyDictionary<string, object>? Properties { get; init; }


    /// <summary>The end-of-results page — <c>next_token</c> empty, no counts.</summary>
    public static AccessSearchPage End { get; } = new();
}
