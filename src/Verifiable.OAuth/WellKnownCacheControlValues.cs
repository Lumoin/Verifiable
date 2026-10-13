using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth;

/// <summary>
/// Well-known values for the HTTP <c>Cache-Control</c> response header.
/// </summary>
/// <remarks>
/// <para>
/// Only the directives the library emits, or reads in a response its shared caches hold, are listed.
/// <see href="https://www.rfc-editor.org/rfc/rfc7234#section-5.2">RFC 7234 §5.2</see>
/// defines the full directive set; additional values appear here when a
/// call site actually emits or reads them.
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
    public static string NoStore { get; } = Utf8Constants.ToInternedString(NoStoreUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Private"/>.</summary>
    public static ReadOnlySpan<byte> PrivateUtf8 => "private"u8;

    /// <summary>
    /// The <c>private</c> response directive per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2.2.7">RFC 9111 §5.2.2.7</see>:
    /// "The unqualified private response directive indicates that a shared cache MUST NOT store the
    /// response (i.e., the response is intended for a single user)." The library's shared caches
    /// (<see cref="Verifiable.Core.Outbound.HttpCacheFreshness"/>) hold no response carrying it unqualified.
    /// </summary>
    public static string Private { get; } = Utf8Constants.ToInternedString(PrivateUtf8);
}
