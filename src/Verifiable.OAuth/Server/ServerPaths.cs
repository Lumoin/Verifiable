using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Path-comparison helpers for matcher acceptance tests. Concentrates the
/// path-parsing logic that matchers need into one library-owned location.
/// </summary>
/// <remarks>
/// <para>
/// Phase 4's design discipline puts path parsing in the matchers (not in
/// a chain-level filter, not in the skin), but it puts the *implementation*
/// of path parsing in one place. Matchers compose with the helpers on
/// this class rather than open-coding <c>EndsWith</c> or substring checks.
/// </para>
/// <para>
/// The helpers handle:
/// </para>
/// <list type="bullet">
/// <item><description>Query-string and fragment stripping (a path with
/// <c>?</c> or <c>#</c> still matches its base form).</description></item>
/// <item><description>Trailing-slash normalization
/// (<c>/par/</c> matches <c>/par</c>).</description></item>
/// <item><description>Segment-placeholder substitution (the path templates
/// in <see cref="ServerEndpointPaths"/> carry <c>{segment}</c>; the helper
/// substitutes from the registration's tenant identifier).</description></item>
/// <item><description>Exact comparison after normalization, not
/// suffix-match — so a path like <c>/foo/par</c> does not match the PAR
/// template of a tenant whose segment is something else.</description></item>
/// </list>
/// <para>
/// As new endpoint families bring new path patterns
/// (sub-resource paths under a registration, alternative tenant placement,
/// etc.) the helpers grow. The discipline is: matchers describe what they
/// accept; helpers describe how paths are structured.
/// </para>
/// </remarks>
[DebuggerDisplay("ServerPaths")]
public static class ServerPaths
{
    private const string SegmentPlaceholder = "{segment}";


    /// <summary>
    /// Whether <paramref name="requestPath"/> matches the per-registration
    /// endpoint <paramref name="pathTemplate"/> after substituting
    /// <paramref name="segment"/> for the <c>{segment}</c> placeholder.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The path templates in <see cref="ServerEndpointPaths"/> carry the
    /// literal <c>{segment}</c> placeholder; the helper performs the
    /// substitution at comparison time so that callers do not have to
    /// pre-compute substituted paths per registration.
    /// </para>
    /// <para>
    /// Matchers typically pass <c>context.Registration!.TenantId.Value</c>
    /// for the segment — the dispatcher has already loaded the registration
    /// before the chain walks, so the segment is available. Tenant resolution
    /// strategies that do not place tenant identity in the URL path (subdomain,
    /// header, mTLS) still pass <c>TenantId.Value</c>; the path templates for
    /// those deployments would not include <c>{segment}</c> and the
    /// substitution is a no-op.
    /// </para>
    /// </remarks>
    /// <param name="requestPath">
    /// The raw path from the inbound request, as supplied by the skin via
    /// <see cref="IncomingRequest.Path"/>. May include a query string or
    /// fragment; both are stripped before comparison.
    /// </param>
    /// <param name="pathTemplate">
    /// One of the path-template constants on <see cref="ServerEndpointPaths"/>,
    /// e.g. <see cref="ServerEndpointPaths.Par"/>. Carries the literal
    /// <c>{segment}</c> placeholder for per-registration endpoints.
    /// </param>
    /// <param name="segment">
    /// The segment to substitute for <c>{segment}</c>. Typically the
    /// registration's <see cref="TenantId"/> string value.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when the request path equals the substituted
    /// template after normalization; <see langword="false"/> otherwise.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Thrown when any argument is <see langword="null"/>, empty, or
    /// whitespace.
    /// </exception>
    public static bool IsEndpoint(string requestPath, string pathTemplate, string segment)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(pathTemplate);
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);

        string concretePath = pathTemplate.Replace(
            SegmentPlaceholder, segment, StringComparison.Ordinal);

        return PathEquals(requestPath, concretePath);
    }


    /// <summary>
    /// Whether <paramref name="requestPath"/> matches a global endpoint
    /// <paramref name="pathTemplate"/> that has no segment placeholder.
    /// </summary>
    /// <remarks>
    /// Used by matchers for endpoints that are not per-registration —
    /// global client registration (<c>/connect/register</c>), eventually
    /// server-global discovery and JWKS in Phase 6.
    /// </remarks>
    /// <param name="requestPath">The raw path from the inbound request.</param>
    /// <param name="pathTemplate">
    /// A global path template from <see cref="ServerEndpointPaths"/>, e.g.
    /// <see cref="ServerEndpointPaths.GlobalRegistration"/>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when the request path equals the template
    /// after normalization; <see langword="false"/> otherwise.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Thrown when any argument is <see langword="null"/>, empty, or
    /// whitespace.
    /// </exception>
    public static bool IsGlobalEndpoint(string requestPath, string pathTemplate)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(pathTemplate);

        return PathEquals(requestPath, pathTemplate);
    }


    /// <summary>
    /// Strips query string and fragment from <paramref name="path"/>, then
    /// strips trailing slash, then compares for exact equality with
    /// <paramref name="other"/> (which is assumed already-normalized — it
    /// comes from a library-defined template).
    /// </summary>
    private static bool PathEquals(string path, string other)
    {
        ReadOnlySpan<char> pathSpan = path.AsSpan();

        //Strip query string and fragment.
        int queryStart = pathSpan.IndexOf('?');
        if(queryStart >= 0)
        {
            pathSpan = pathSpan[..queryStart];
        }

        int fragmentStart = pathSpan.IndexOf('#');
        if(fragmentStart >= 0)
        {
            pathSpan = pathSpan[..fragmentStart];
        }

        //Strip a single trailing slash, but not the root slash itself.
        if(pathSpan.Length > 1 && pathSpan[^1] == '/')
        {
            pathSpan = pathSpan[..^1];
        }

        return pathSpan.SequenceEqual(other.AsSpan());
    }
}
