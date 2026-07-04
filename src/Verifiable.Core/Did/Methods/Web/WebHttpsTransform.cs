using System;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Text;

namespace Verifiable.Core.Did.Methods.Web;

/// <summary>
/// How a did:web-family transform maps a validated path segment into the HTTPS URL path. This differs by method
/// specification: did:web uses the segment as-is, did:webplus percent-decodes it, and did:webvh percent-decodes,
/// validates, then re-encodes it to a canonical RFC3986 percent-encoding.
/// </summary>
public enum WebHttpsSegmentMapping
{
    /// <summary>The segment is used verbatim — the did:web method-specific id is already in URL path form ("used as-is").</summary>
    Preserve,

    /// <summary>The segment is percent-decoded (did:webplus DID-to-URL Mapping: "percent-decode").</summary>
    Decode,

    /// <summary>The segment is percent-decoded then re-encoded to a canonical RFC3986 percent-encoding, uppercase hex (did:webvh DID-to-HTTPS Transformation).</summary>
    DecodeThenReencode
}


/// <summary>
/// The per-method policy the shared did:web-family transform (<see cref="WebHttpsTransform.MapToUrl"/>) is
/// parameterized by, capturing where the three method specifications legitimately differ: how many leading
/// method-specific-id segments precede the host (did:webvh's SCID), whether the host is IDNA-encoded, whether a
/// <c>localhost</c> host selects <c>http</c>, whether a <c>/.well-known</c> segment is inserted when the identifier
/// declares no path, the minimum number of path segments the identifier MUST carry, how each path segment is
/// mapped, and the document file name appended last.
/// </summary>
public sealed record WebHttpsTransformPolicy
{
    /// <summary>The number of leading colon-delimited segments before the host (did:webvh drops its SCID; the others drop none).</summary>
    public int LeadingSegmentsToDrop { get; init; }

    /// <summary>Whether the host is IDNA/Punycode-encoded per IDNA2008 (did:webvh).</summary>
    public bool IdnaEncodeHost { get; init; }

    /// <summary>Whether a <c>localhost</c> host selects the <c>http</c> scheme instead of <c>https</c> (did:webplus, to ease local testing).</summary>
    public bool LocalhostUsesHttp { get; init; }

    /// <summary>Whether a <c>/.well-known</c> segment is inserted when the identifier declares no path (did:web, did:webvh).</summary>
    public bool WellKnownWhenNoPath { get; init; }

    /// <summary>The minimum number of path segments the identifier MUST carry after the host (did:webplus requires the trailing root-self-hash).</summary>
    public int MinimumPathSegments { get; init; }

    /// <summary>How each path segment is mapped into the URL path.</summary>
    public required WebHttpsSegmentMapping SegmentMapping { get; init; }

    /// <summary>The document file name appended last (for example <c>did.json</c>, <c>did.jsonl</c> or <c>did-documents.jsonl</c>).</summary>
    public required string DocumentFileName { get; init; }
}


/// <summary>
/// The shared did:web-family DID-to-HTTPS transformation: the one algorithm that maps a colon-delimited
/// method-specific identifier onto its document URL, so did:web, did:webvh and did:webplus do not each re-derive
/// the split, host handling, security guards and URL assembly. The security-relevant rules — IP-literal host
/// rejection and path-traversal rejection — are defined and tested once here; the per-specification differences
/// are supplied through a <see cref="WebHttpsTransformPolicy"/>.
/// </summary>
public static class WebHttpsTransform
{
    /// <summary>The RFC 8615 well-known path segment inserted when a did:web-family identifier declares no path.</summary>
    private const string WellKnownSegment = ".well-known";

    /// <summary>The host name that selects the <c>http</c> scheme under a policy that allows it (did:webplus local testing).</summary>
    private const string LocalHostName = "localhost";

    /// <summary>IDNA/Punycode mapping for internationalized hosts (RFC3491 normalization is applied by <see cref="IdnMapping.GetAscii(string)"/>).</summary>
    private static IdnMapping DomainIdnMapping { get; } = new();


    /// <summary>
    /// Maps a did:web-family method-specific identifier to the URL its DID document is fetched from, per
    /// <paramref name="policy"/>. The common algorithm — colon-split, host extraction (a <c>%3A</c>-encoded port is
    /// preserved, an IP-literal host is rejected), path-segment validation (a <c>%2F</c>, dot-segment, empty or
    /// whitespace-bounded segment is rejected) and URL assembly — is shared; the policy captures the
    /// per-specification differences.
    /// </summary>
    /// <param name="methodSpecificId">The identifier with its <c>did:&lt;method&gt;:</c> prefix already removed.</param>
    /// <param name="identifier">The full DID identifier, used only in rejection messages.</param>
    /// <param name="policy">The per-method transform policy.</param>
    /// <returns>The document URL.</returns>
    /// <exception cref="ArgumentException">Thrown when the identifier has no host, an IP-literal host, fewer than the required path segments, or an unsafe path segment.</exception>
    [SuppressMessage("Design", "CA1055:URI-like return values should not be strings", Justification = "DID document URLs contain method-specific syntax that System.Uri does not handle correctly; the DID method surface uses string URLs consistently.")]
    public static string MapToUrl(string methodSpecificId, string identifier, WebHttpsTransformPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(methodSpecificId);
        ArgumentNullException.ThrowIfNull(identifier);
        ArgumentNullException.ThrowIfNull(policy);

        //Colons in the method-specific id are path separators; a %3A is a literal colon (a port) that stays within
        //its segment. The host is the first segment after any leading segments the method carries (did:webvh's SCID).
        string[] segments = methodSpecificId.Split(':');
        if(segments.Length <= policy.LeadingSegmentsToDrop || segments[policy.LeadingSegmentsToDrop].Length == 0)
        {
            throw new ArgumentException(
                $"The DID identifier '{identifier}' does not contain a host segment.", nameof(identifier));
        }

        int pathSegmentCount = segments.Length - policy.LeadingSegmentsToDrop - 1;
        if(pathSegmentCount < policy.MinimumPathSegments)
        {
            throw new ArgumentException(
                $"The DID identifier '{identifier}' is missing a required trailing segment.", nameof(identifier));
        }

        //The host segment carries an optional %3A-encoded port. Split it off so the host name alone is IP-checked,
        //IDNA-encoded and used to choose the scheme, while the numeric port is preserved verbatim.
        string hostSegment = segments[policy.LeadingSegmentsToDrop];
        int portIndex = hostSegment.IndexOf("%3A", StringComparison.OrdinalIgnoreCase);
        string hostName = portIndex >= 0 ? hostSegment[..portIndex] : hostSegment;
        string? port = portIndex >= 0 ? hostSegment[(portIndex + 3)..] : null;

        if(IsIpAddressHost(hostName))
        {
            throw new ArgumentException(
                $"The DID identifier '{identifier}' host '{hostName}' must be a domain name, not an IP address.", nameof(identifier));
        }

        string scheme = policy.LocalhostUsesHttp && string.Equals(hostName, LocalHostName, StringComparison.OrdinalIgnoreCase)
            ? "http"
            : "https";

        string mappedHostName = policy.IdnaEncodeHost ? DomainIdnMapping.GetAscii(hostName) : hostName;
        var location = new StringBuilder(port is null ? mappedHostName : $"{mappedHostName}:{port}");

        for(int i = policy.LeadingSegmentsToDrop + 1; i < segments.Length; i++)
        {
            string segment = segments[i];
            if(ContainsEncodedSlash(segment) || IsUnsafePathSegment(segment))
            {
                throw new ArgumentException(
                    $"The DID identifier '{identifier}' has an invalid path segment '{segment}'.", nameof(identifier));
            }

            location.Append('/');
            location.Append(MapSegment(segment, policy.SegmentMapping));
        }

        if(pathSegmentCount == 0 && policy.WellKnownWhenNoPath)
        {
            location.Append('/');
            location.Append(WellKnownSegment);
        }

        location.Append('/');
        location.Append(policy.DocumentFileName);

        return $"{scheme}://{location}";

        //Maps a validated path segment per the method's specified encoding (see WebHttpsSegmentMapping): the
        //did:webvh decode-then-encode canonicalizes an already-percent-encoded segment (it is idempotent) rather
        //than double-encoding it.
        static string MapSegment(string segment, WebHttpsSegmentMapping mapping) => mapping switch
        {
            WebHttpsSegmentMapping.Preserve => segment,
            WebHttpsSegmentMapping.Decode => Uri.UnescapeDataString(segment),
            WebHttpsSegmentMapping.DecodeThenReencode => Uri.EscapeDataString(Uri.UnescapeDataString(segment)),
            _ => throw new ArgumentOutOfRangeException(nameof(mapping), mapping, "Unknown did:web-family path-segment mapping.")
        };
    }


    /// <summary>
    /// Determines whether a host string is an IP-address literal (IPv4 dotted-quad or a bracketed/raw IPv6
    /// literal) rather than a domain name. The value is percent-decoded for the check so a literal smuggled in
    /// encoded form (for example a bracketed IPv6 with percent-encoded brackets) is still caught. A did:web-family
    /// host MUST be a domain name, so the caller rejects an IP-literal host at the method layer rather than relying
    /// on a downstream SSRF policy that only blocks private/loopback ranges.
    /// </summary>
    /// <param name="host">The host (already stripped of any port) to test.</param>
    /// <returns><see langword="true"/> when the host is an IP-address literal.</returns>
    private static bool IsIpAddressHost(string host)
    {
        string candidate = Uri.UnescapeDataString(host);

        if(candidate.StartsWith('['))
        {
            //A bracketed IPv6 literal: the address is between the brackets, anything after ']' is a port.
            int close = candidate.IndexOf(']', StringComparison.Ordinal);
            candidate = close > 0 ? candidate[1..close] : candidate.Trim('[', ']');
        }
        else
        {
            //An unbracketed host with a single ':' is host:port (IPv4 or domain); two or more colons is a raw
            //IPv6 literal. Strip a single trailing port; leave a multi-colon IPv6 candidate intact.
            int firstColon = candidate.IndexOf(':', StringComparison.Ordinal);
            if(firstColon >= 0)
            {
                int lastColon = candidate.LastIndexOf(':');
                if(firstColon == lastColon)
                {
                    candidate = candidate[..firstColon];
                }
            }
        }

        return IPAddress.TryParse(candidate, out _);
    }


    /// <summary>
    /// Whether a path segment carries a percent-encoded path separator (<c>%2F</c>, the encoded <c>/</c>). A
    /// segment that encodes its own separator would forge an extra path segment after decode, so a caller rejects
    /// it rather than silently splitting it (the URL-confusion mitigation the did:web-family transformation requires).
    /// </summary>
    /// <param name="segment">A single method-specific-identifier path segment (still percent-encoded).</param>
    /// <returns><see langword="true"/> when the segment contains an encoded path separator.</returns>
    private static bool ContainsEncodedSlash(string segment)
    {
        return segment.Contains("%2F", StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// Whether a path segment, after percent-decoding, is unsafe to map into the DID's location: an empty segment,
    /// a dot-segment (<c>.</c> or <c>..</c>) that RFC3986 §3.3 dot-segment removal would use to re-target the path,
    /// a segment carrying a raw <c>/</c>, <c>\</c> or NUL, or one bounded by whitespace. Such a segment does not
    /// name a single path component and so MUST fail the transformation — this closes a traversal where a literal
    /// or encoded <c>..</c> segment would escape the DID's designated location.
    /// </summary>
    /// <param name="segment">A single method-specific-identifier path segment (still percent-encoded).</param>
    /// <returns><see langword="true"/> when the decoded segment is not a single, safe path component.</returns>
    private static bool IsUnsafePathSegment(string segment)
    {
        string decoded = Uri.UnescapeDataString(segment);
        if(decoded.Length == 0 || decoded.Equals(".", StringComparison.Ordinal) || decoded.Equals("..", StringComparison.Ordinal))
        {
            return true;
        }

        if(decoded.Contains('/', StringComparison.Ordinal)
            || decoded.Contains('\\', StringComparison.Ordinal)
            || decoded.Contains('\0', StringComparison.Ordinal))
        {
            return true;
        }

        return char.IsWhiteSpace(decoded[0]) || char.IsWhiteSpace(decoded[^1]);
    }
}
