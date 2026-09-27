using Verifiable.Cryptography.Text;

namespace Verifiable.Core.Transport;

/// <summary>
/// Problem type URI names with UTF-8 twins, recognition predicates, and
/// <see cref="GetCanonicalizedValue"/> for sharing their interned strings.
/// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3.1.1">RFC 9457 §3.1.1</see>:
/// "Consumers MUST use the "type" URI (after resolution, if necessary) as the
/// problem type's primary identifier."
/// </summary>
/// <remarks>
/// <para>
/// <see cref="AboutBlank"/> is registered by RFC 9457. The three rate-limit registrations
/// are proposed by draft-ietf-httpapi-ratelimit-headers-11 until that draft is published
/// as an RFC. Their recommended HTTP status codes describe usage; this catalog emits no response.
/// </para>
/// <para>
/// RFC 6749 error codes are not problem types, and MCP 2026-07-28 defines no RFC 9457
/// problem types, so neither contributes entries here. The catalog uses
/// <see cref="StringComparison.Ordinal"/> without URI normalization as its local
/// comparison policy, preserving each defining URI's spelling.
/// </para>
/// </remarks>
public static class WellKnownProblemTypes
{
    /// <summary>
    /// The UTF-8 source of <see cref="AboutBlank"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-4.2.1">RFC 9457 §4.2.1</see>:
    /// "Type URI: about:blank".
    /// </summary>
    public static ReadOnlySpan<byte> AboutBlankUtf8 => "about:blank"u8;

    /// <summary>
    /// The interned default problem type derived from <see cref="AboutBlankUtf8"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3.1.1">RFC 9457 §3.1.1</see>:
    /// "When this member is not present, its value is assumed to be "about:blank"."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-4.2.1">§4.2.1</see>:
    /// "the problem has no additional semantics beyond that of the HTTP status code".
    /// </summary>
    public static string AboutBlank { get; } = Utf8Constants.ToInternedString(AboutBlankUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="QuotaExceeded"/>.
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-5.1">RateLimit draft-11 §5.1</see>:
    /// "This section defines the "https://iana.org/assignments/http-problem-types#quota-exceeded" problem type."
    /// The registration is proposed until the draft is published as an RFC.
    /// </summary>
    public static ReadOnlySpan<byte> QuotaExceededUtf8 => "https://iana.org/assignments/http-problem-types#quota-exceeded"u8;

    /// <summary>
    /// The interned quota-exceeded type derived from <see cref="QuotaExceededUtf8"/>;
    /// its registration is proposed until draft-ietf-httpapi-ratelimit-headers-11 is published as an RFC.
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-10.2.1">Draft §10.2.1</see>:
    /// "Recommended HTTP status code: 429".
    /// </summary>
    public static string QuotaExceeded { get; } = Utf8Constants.ToInternedString(QuotaExceededUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="TemporaryReducedCapacity"/>.
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-5.2">RateLimit draft-11 §5.2</see>:
    /// "This section defines the "https://iana.org/assignments/http-problem-types#temporary-reduced-capacity" problem type."
    /// The registration is proposed until the draft is published as an RFC.
    /// </summary>
    public static ReadOnlySpan<byte> TemporaryReducedCapacityUtf8 => "https://iana.org/assignments/http-problem-types#temporary-reduced-capacity"u8;

    /// <summary>
    /// The interned reduced-capacity type derived from <see cref="TemporaryReducedCapacityUtf8"/>;
    /// its registration is proposed until draft-ietf-httpapi-ratelimit-headers-11 is published as an RFC.
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-10.2.2">Draft §10.2.2</see>:
    /// "Recommended HTTP status code: 503".
    /// </summary>
    public static string TemporaryReducedCapacity { get; } = Utf8Constants.ToInternedString(TemporaryReducedCapacityUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="AbnormalUsageDetected"/>.
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-5.3">RateLimit draft-11 §5.3</see>:
    /// "This section defines the "https://iana.org/assignments/http-problem-types#abnormal-usage-detected" problem type."
    /// The registration is proposed until the draft is published as an RFC.
    /// </summary>
    public static ReadOnlySpan<byte> AbnormalUsageDetectedUtf8 => "https://iana.org/assignments/http-problem-types#abnormal-usage-detected"u8;

    /// <summary>
    /// The interned abnormal-usage type derived from <see cref="AbnormalUsageDetectedUtf8"/>;
    /// its registration is proposed until draft-ietf-httpapi-ratelimit-headers-11 is published as an RFC.
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-10.2.3">Draft §10.2.3</see>:
    /// "Recommended HTTP status code: 429".
    /// </summary>
    public static string AbnormalUsageDetected { get; } = Utf8Constants.ToInternedString(AbnormalUsageDetectedUtf8);


    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="AboutBlank"/> under <see cref="Equals"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-4.2.1">RFC 9457 §4.2.1</see>:
    /// "Type URI: about:blank".
    /// </summary>
    public static bool IsAboutBlank(string value) => Equals(value, AboutBlank);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="QuotaExceeded"/> under <see cref="Equals"/>.
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-5.1">RateLimit draft-11 §5.1</see>:
    /// "This section defines the "https://iana.org/assignments/http-problem-types#quota-exceeded" problem type."
    /// This is a proposed registration in an Internet-Draft.
    /// </summary>
    public static bool IsQuotaExceeded(string value) => Equals(value, QuotaExceeded);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="TemporaryReducedCapacity"/> under <see cref="Equals"/>.
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-5.2">RateLimit draft-11 §5.2</see>:
    /// "This section defines the "https://iana.org/assignments/http-problem-types#temporary-reduced-capacity" problem type."
    /// This is a proposed registration in an Internet-Draft.
    /// </summary>
    public static bool IsTemporaryReducedCapacity(string value) => Equals(value, TemporaryReducedCapacity);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="AbnormalUsageDetected"/> under <see cref="Equals"/>.
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-5.3">RateLimit draft-11 §5.3</see>:
    /// "This section defines the "https://iana.org/assignments/http-problem-types#abnormal-usage-detected" problem type."
    /// This is a proposed registration in an Internet-Draft.
    /// </summary>
    public static bool IsAbnormalUsageDetected(string value) => Equals(value, AbnormalUsageDetected);


    /// <summary>
    /// Returns the interned instance for an ordinally matching problem type, or the input unchanged.
    /// This is the catalog's local storage policy for the identifier in
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3.1.1">RFC 9457 §3.1.1</see>:
    /// "Consumers MUST use the "type" URI (after resolution, if necessary) as the problem type's primary identifier."
    /// </summary>
    public static string GetCanonicalizedValue(string value) => value switch
    {
        var v when IsAboutBlank(v) => AboutBlank,
        var v when IsQuotaExceeded(v) => QuotaExceeded,
        var v when IsTemporaryReducedCapacity(v) => TemporaryReducedCapacity,
        var v when IsAbnormalUsageDetected(v) => AbnormalUsageDetected,
        _ => value
    };


    /// <summary>
    /// Compares problem type spellings using the catalog's local <see cref="StringComparison.Ordinal"/> policy.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3.1.1">RFC 9457 §3.1.1</see>:
    /// "Consumers MUST use the "type" URI (after resolution, if necessary) as the problem type's primary identifier."
    /// URI resolution and normalization remain the caller's responsibility.
    /// </summary>
    public static bool Equals(string valueA, string valueB) =>
        string.Equals(valueA, valueB, StringComparison.Ordinal);
}
