using System.Diagnostics;

namespace Verifiable.OAuth.Server.Routing;

/// <summary>
/// Path-equality helper for matcher acceptance tests. Normalises request
/// paths against target URI paths by stripping query strings, fragments,
/// and trailing slashes before exact comparison.
/// </summary>
/// <remarks>
/// <para>
/// Matchers compose with this helper to compare an inbound request's path
/// against the absolute path of their endpoint's resolved URI:
/// <code>
/// if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
///     return ValueTask.FromResult&lt;MatchPayload?&gt;(null);
/// </code>
/// </para>
/// <para>
/// The helper is endpoint-shape-independent: it doesn't know about
/// path-segment tenancy or any other URL convention. Whatever path the
/// application's <c>ResolveEndpointUriAsync</c> produced, the matcher
/// compares the request path against that URI's <c>AbsolutePath</c>.
/// </para>
/// </remarks>
[DebuggerDisplay("PathEquals")]
public static class PathEquals
{
    /// <summary>
    /// Whether <paramref name="requestPath"/> equals
    /// <paramref name="targetPath"/> after stripping query string,
    /// fragment, and any single trailing slash on the request path.
    /// <paramref name="targetPath"/> is assumed normalised (it comes from
    /// the application's resolved URI's <c>AbsolutePath</c>).
    /// </summary>
    public static bool Equals(string requestPath, string targetPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetPath);

        ReadOnlySpan<char> pathSpan = requestPath.AsSpan();

        //Strip query string and fragment.
        int queryStart = pathSpan.IndexOf('?');
        if(queryStart >= 0) { pathSpan = pathSpan[..queryStart]; }

        int fragmentStart = pathSpan.IndexOf('#');
        if(fragmentStart >= 0) { pathSpan = pathSpan[..fragmentStart]; }

        //Strip a single trailing slash, but not the root slash itself.
        if(pathSpan.Length > 1 && pathSpan[^1] == '/')
        {
            pathSpan = pathSpan[..^1];
        }

        return pathSpan.SequenceEqual(targetPath.AsSpan());
    }
}
