namespace Verifiable.OAuth;

/// <summary>
/// The outcome of validating a candidate Client Identifier URL against
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-3">
/// draft-ietf-oauth-client-id-metadata-document-02 Section 3</see>. <see cref="IsValid"/> aggregates only
/// the MUST/MUST NOT-tier rules (CIMD-001, CIMD-002, CIMD-004, CIMD-005, CIMD-007, plus the structural
/// "is this even an absolute https URL" precondition); <see cref="HasQueryComponent"/> (CIMD-006) and
/// <see cref="IsRootPath"/> (CIMD-011) are SHOULD/NOT RECOMMENDED-tier advisories that never affect it.
/// </summary>
public sealed record ClientIdentifierUrlValidationResult
{
    /// <summary>
    /// Whether the candidate satisfies every MUST/MUST NOT-tier rule in Section 3: it has the
    /// <c>scheme://authority/path</c> shape, the scheme is <c>https</c>, there is no userinfo
    /// component, the path component is non-empty, no path segment is <c>.</c> or <c>..</c>, and there
    /// is no fragment component. <see cref="HasQueryComponent"/> and <see cref="IsRootPath"/> do not
    /// affect this value.
    /// </summary>
    public bool IsValid { get; init; }

    /// <summary>
    /// The candidate does not have the <c>scheme://authority/path</c> absolute-URL shape a Client
    /// Identifier URL requires — for example a relative reference, an empty string, or a scheme that
    /// uses the opaque (non-authority) form. When this is <see langword="true"/> every other flag on
    /// this result stays at its default (structurally there is no authority or path to inspect).
    /// </summary>
    public bool NotAnAbsoluteUrl { get; init; }

    /// <summary>
    /// Section 3: "MUST use the https URL scheme" (CIMD-001). The scheme comparison is
    /// case-insensitive per <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.1">RFC 3986
    /// §3.1</see> — this is independent of the ordinal whole-URL comparison
    /// <see cref="ClientIdentifierUrl.IsMatch(string, string)"/> performs.
    /// </summary>
    public bool NotHttpsScheme { get; init; }

    /// <summary>
    /// Section 3: "MUST NOT contain a userinfo component defined by [RFC3986]" (CIMD-002).
    /// </summary>
    public bool HasUserinfo { get; init; }

    /// <summary>
    /// Section 3: "MUST contain a path component" (CIMD-004) — the candidate has no path at all, e.g.
    /// <c>https://example.com</c>. A path of exactly <c>/</c> satisfies this rule (see
    /// <see cref="IsRootPath"/> for its separate advisory).
    /// </summary>
    public bool MissingPathComponent { get; init; }

    /// <summary>
    /// Section 3: "MUST NOT contain single-dot or double-dot path components" (CIMD-005) — a path
    /// segment equal to exactly <c>.</c> or <c>..</c>, anywhere in the path.
    /// </summary>
    public bool HasDotSegments { get; init; }

    /// <summary>
    /// Section 3: "MUST NOT contain a fragment component" (CIMD-007).
    /// </summary>
    public bool HasFragment { get; init; }

    /// <summary>
    /// Section 3: "SHOULD NOT contain a query component" (CIMD-006). Advisory — does not affect
    /// <see cref="IsValid"/>.
    /// </summary>
    public bool HasQueryComponent { get; init; }

    /// <summary>
    /// Section 3: "Using a path of / ... is NOT RECOMMENDED, since the Client ID Metadata Document
    /// would then be served at the root of the domain" (CIMD-011). Advisory — does not affect
    /// <see cref="IsValid"/>.
    /// </summary>
    public bool IsRootPath { get; init; }
}


/// <summary>
/// Validates a candidate Client Identifier URL against
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-3">
/// draft-ietf-oauth-client-id-metadata-document-02 Section 3</see>, and compares two Client Identifier
/// URLs (or a URL against a document's <c>client_id</c> value) the way Section 3 (CIMD-008) and Section 4
/// (CIMD-016) both require: simple string comparison per
/// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.1">RFC 3986 §6.2.1</see>.
/// </summary>
/// <remarks>
/// <see cref="ClientIdentifierUrl.Validate(string)"/> operates on the raw candidate string, never on a parsed <see cref="Uri"/>:
/// <see cref="Uri"/> normalization erases exactly the distinctions Section 3 depends on. Constructing a
/// <see cref="Uri"/> from <c>https://example.com</c> invents a <c>/</c> path, masking the CIMD-004
/// missing-path defect, and <see cref="Uri.Equals(object?)"/> treats <c>https://example.com:443/client</c>
/// as equal to <c>https://example.com/client</c>, masking the CIMD-008 default-port non-equivalence the
/// spec calls out by name. A short URL and a URL that stays stable for the client's lifetime (Section 3,
/// RECOMMENDED — CIMD-009/CIMD-010; a changing URL "will appear to the authorization server to be an
/// entirely different Client Identifier URL", Section 8.3) are qualitative deployment guidance with no
/// machine-checkable shape: they are not represented as a flag on
/// <see cref="ClientIdentifierUrlValidationResult"/>, and the same guidance governs
/// <see cref="Verifiable.OAuth.Client.ClientRegistration.ClientMetadataUri"/>.
/// </remarks>
public static class ClientIdentifierUrl
{
    private const string SingleDotSegment = ".";
    private const string DoubleDotSegment = "..";
    private const string AuthorityMarker = "://";

    /// <summary>
    /// Validates <paramref name="candidate"/> against every Section 3 rule and returns the full defect
    /// taxonomy — this never throws for a malformed candidate, since classifying malformed input is the
    /// method's purpose.
    /// </summary>
    /// <param name="candidate">The raw, unparsed candidate Client Identifier URL string.</param>
    public static ClientIdentifierUrlValidationResult Validate(string candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        ReadOnlySpan<char> value = candidate.AsSpan();

        int fragmentDelimiter = value.IndexOf('#');
        bool hasFragment = fragmentDelimiter >= 0;
        ReadOnlySpan<char> withoutFragment = hasFragment ? value[..fragmentDelimiter] : value;

        int queryDelimiter = withoutFragment.IndexOf('?');
        bool hasQuery = queryDelimiter >= 0;
        ReadOnlySpan<char> withoutQuery = hasQuery ? withoutFragment[..queryDelimiter] : withoutFragment;

        int authorityMarker = withoutQuery.IndexOf(AuthorityMarker, StringComparison.Ordinal);
        if(authorityMarker <= 0)
        {
            return new ClientIdentifierUrlValidationResult
            {
                IsValid = false,
                NotAnAbsoluteUrl = true
            };
        }

        ReadOnlySpan<char> scheme = withoutQuery[..authorityMarker];
        ReadOnlySpan<char> authorityAndPath = withoutQuery[(authorityMarker + AuthorityMarker.Length)..];

        bool isNotHttpsScheme = !scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

        int pathDelimiter = authorityAndPath.IndexOf('/');
        bool isMissingPath = pathDelimiter < 0;
        ReadOnlySpan<char> authority = isMissingPath ? authorityAndPath : authorityAndPath[..pathDelimiter];
        ReadOnlySpan<char> path = isMissingPath ? ReadOnlySpan<char>.Empty : authorityAndPath[pathDelimiter..];

        bool hasUserinfo = authority.IndexOf('@') >= 0;
        bool isRootPath = !isMissingPath && path.Equals("/", StringComparison.Ordinal);
        bool hasDotSegments = HasDotSegments(path);

        bool isValid = !isNotHttpsScheme
            && !hasUserinfo
            && !isMissingPath
            && !hasDotSegments
            && !hasFragment;

        return new ClientIdentifierUrlValidationResult
        {
            IsValid = isValid,
            NotHttpsScheme = isNotHttpsScheme,
            HasUserinfo = hasUserinfo,
            MissingPathComponent = isMissingPath,
            HasDotSegments = hasDotSegments,
            HasFragment = hasFragment,
            HasQueryComponent = hasQuery,
            IsRootPath = isRootPath
        };
    }


    /// <summary>
    /// Whether <paramref name="first"/> and <paramref name="second"/> are the identical Client
    /// Identifier URL, per the "simple string comparison" Section 3 (CIMD-008) requires for two Client
    /// Identifier URLs and Section 4 (CIMD-016) requires for a document's <c>client_id</c> value against
    /// the URL used to fetch it: ordinal, code-point-by-code-point equality with no scheme
    /// case-folding, no percent-encoding case-folding, and no default-port elision. The spec's own
    /// example: <c>https://example.com/client</c> and <c>https://example.com:443/client</c> are NOT
    /// equivalent even though 443 is the default port for the https scheme.
    /// </summary>
    /// <param name="first">The first candidate Client Identifier URL string.</param>
    /// <param name="second">The second candidate Client Identifier URL string.</param>
    public static bool IsMatch(string first, string second)
    {
        ArgumentNullException.ThrowIfNull(first);
        ArgumentNullException.ThrowIfNull(second);

        return string.Equals(first, second, StringComparison.Ordinal);
    }


    /// <summary>
    /// Whether <paramref name="path"/> — a leading-slash path component, or empty — contains a path
    /// segment equal to exactly <c>.</c> or <c>..</c> (CIMD-005). A segment such as <c>a..b</c> or
    /// <c>..b</c> is not a dot segment: the whole segment, delimited by <c>/</c>, must equal one of the
    /// two literal forms.
    /// </summary>
    private static bool HasDotSegments(ReadOnlySpan<char> path)
    {
        while(path.Length > 0)
        {
            ReadOnlySpan<char> remainder = path[1..];
            int nextSlash = remainder.IndexOf('/');
            ReadOnlySpan<char> segment = nextSlash < 0 ? remainder : remainder[..nextSlash];

            if(segment.Equals(SingleDotSegment, StringComparison.Ordinal) || segment.Equals(DoubleDotSegment, StringComparison.Ordinal))
            {
                return true;
            }

            path = nextSlash < 0 ? ReadOnlySpan<char>.Empty : remainder[nextSlash..];
        }

        return false;
    }
}
