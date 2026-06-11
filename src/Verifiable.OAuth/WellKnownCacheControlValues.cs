using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth;

/// <summary>
/// Well-known values for the HTTP <c>Cache-Control</c> response header.
/// </summary>
/// <remarks>
/// <para>
/// Only the directives the library currently emits are listed.
/// <see href="https://www.rfc-editor.org/rfc/rfc7234#section-5.2">RFC 7234 §5.2</see>
/// defines the full directive set; additional values appear here when a
/// call site actually emits them.
/// </para>
/// </remarks>
public static class WellKnownCacheControlValues
{
    /// <summary>The UTF-8 source literal of <see cref="NoStore"/>.</summary>
    public static ReadOnlySpan<byte> NoStoreUtf8 => "no-store"u8;

    /// <summary>
    /// The <c>no-store</c> directive per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7234#section-5.2.2.3">RFC 7234 §5.2.2.3</see>.
    /// Forbids any cache from storing the response. Required per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1#section-3.2.3">OAuth 2.1 §3.2.3</see>
    /// on responses carrying tokens, credentials, or other sensitive information.
    /// </summary>
    public static readonly string NoStore = Utf8Constants.ToInternedString(NoStoreUtf8);
}
