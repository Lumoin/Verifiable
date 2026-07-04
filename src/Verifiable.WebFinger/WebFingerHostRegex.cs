using System.Text.RegularExpressions;

namespace Verifiable.WebFinger;

/// <summary>
/// Source-generated regular expression validating that a WebFinger query host is a bare authority.
/// </summary>
public static partial class WebFingerHostRegex
{
    /// <summary>
    /// Matches a bare host authority — a reg-name or bracketed IPv6 literal, with an optional <c>:port</c> —
    /// and nothing else, per the <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2">RFC 3986
    /// §3.2.2</see> host grammar.
    /// </summary>
    /// <remarks>
    /// The allowlisted character set excludes <c>@</c>, <c>/</c>, <c>#</c>, <c>?</c>, whitespace, and control
    /// characters, so a matching host cannot re-anchor a URI authority (userinfo confusion via a <c>@</c>) or
    /// truncate the fixed <c>/.well-known/webfinger</c> path when spliced into the authority position. The
    /// bracketed branch keeps an IPv6 literal delimited so its inner colons cannot leak into a port.
    /// </remarks>
    /// <returns>A compiled regex matching a bare host authority.</returns>
    [GeneratedRegex(@"^(\[[0-9A-Fa-f:.]+\]|[a-zA-Z0-9._~%-]+)(:[0-9]+)?$")]
    public static partial Regex BareHost();
}
