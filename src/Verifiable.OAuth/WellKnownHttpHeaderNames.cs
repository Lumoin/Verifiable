using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth;

/// <summary>
/// HTTP header name constants used by the OAuth surface, plus per-header
/// <c>IsXxx</c> predicates and a central <see cref="Equals"/> method
/// anchoring the comparison rule.
/// </summary>
/// <remarks>
/// <para>
/// HTTP header names are <strong>case-insensitive on the wire</strong> per
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110 §5.1</see>.
/// The canonical spellings here use the conventions established by their
/// defining specifications (<c>Authorization</c> per RFC 9110 §11.6.2,
/// <c>DPoP</c> and <c>DPoP-Nonce</c> per RFC 9449 §4 and §8). Comparisons
/// here use <see cref="StringComparison.OrdinalIgnoreCase"/> per the spec
/// rule, centralised in <see cref="Equals"/>.
/// </para>
/// <para>
/// Only headers the library currently composes or reads are listed. Other
/// HTTP headers (<c>Content-Type</c>, <c>Accept</c>, <c>WWW-Authenticate</c>,
/// <c>Retry-After</c>, …) are not added speculatively — they appear here
/// when a call site actually needs them.
/// </para>
/// </remarks>
[DebuggerDisplay("WellKnownHttpHeaderNames")]
public static class WellKnownHttpHeaderNames
{
    /// <summary>The UTF-8 source literal of <see cref="Authorization"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationUtf8 => "Authorization"u8;

    /// <summary>
    /// The <c>Authorization</c> request header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.2">RFC 9110 §11.6.2</see>.
    /// Carries the credentials the client uses to authenticate to the server.
    /// </summary>
    public static readonly string Authorization = Utf8Constants.ToInternedString(AuthorizationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Accept"/>.</summary>
    public static ReadOnlySpan<byte> AcceptUtf8 => "Accept"u8;

    /// <summary>
    /// The <c>Accept</c> request header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-12.5.1">RFC 9110 §12.5.1</see>
    /// — the response media types the caller can process. A resource server requests
    /// an RFC 9701 signed introspection response by setting it to
    /// <c>application/token-introspection+jwt</c>.
    /// </summary>
    public static readonly string Accept = Utf8Constants.ToInternedString(AcceptUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AcceptLanguage"/>.</summary>
    public static ReadOnlySpan<byte> AcceptLanguageUtf8 => "Accept-Language"u8;

    /// <summary>
    /// The <c>Accept-Language</c> request header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-12.5.4">RFC 9110 §12.5.4</see>
    /// — the natural languages the caller prefers in the response. OID4VCI 1.0 §12.2.2: "The
    /// Wallet is RECOMMENDED to send an Accept-Language header in the HTTP GET request to
    /// indicate the language(s) preferred for display." Its values use the language tags defined
    /// in RFC 3066.
    /// </summary>
    public static readonly string AcceptLanguage = Utf8Constants.ToInternedString(AcceptLanguageUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ContentLanguage"/>.</summary>
    public static ReadOnlySpan<byte> ContentLanguageUtf8 => "Content-Language"u8;

    /// <summary>
    /// The <c>Content-Language</c> response header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.5">RFC 9110 §8.5</see>.
    /// OID4VCI 1.0 §12.2.2: a Credential Issuer that filters the metadata's internationalized
    /// display data to the requested language(s) MUST "indicate returned languages using the
    /// HTTP Content-Language Header". Its values use the language tags defined in RFC 3066.
    /// </summary>
    public static readonly string ContentLanguage = Utf8Constants.ToInternedString(ContentLanguageUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DPoP"/>.</summary>
    public static ReadOnlySpan<byte> DPoPUtf8 => "DPoP"u8;

    /// <summary>
    /// The <c>DPoP</c> request header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4">RFC 9449 §4</see>.
    /// Carries the proof JWS bound to the request the client is making.
    /// </summary>
    public static readonly string DPoP = Utf8Constants.ToInternedString(DPoPUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DPoPNonce"/>.</summary>
    public static ReadOnlySpan<byte> DPoPNonceUtf8 => "DPoP-Nonce"u8;

    /// <summary>
    /// The <c>DPoP-Nonce</c> response header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see>
    /// (AS) and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">§9</see> (RS).
    /// Carries a server-issued nonce the client must echo in the next proof's
    /// <c>nonce</c> claim.
    /// </summary>
    public static readonly string DPoPNonce = Utf8Constants.ToInternedString(DPoPNonceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CacheControl"/>.</summary>
    public static ReadOnlySpan<byte> CacheControlUtf8 => "Cache-Control"u8;

    /// <summary>
    /// The <c>Cache-Control</c> response header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7234#section-5.2">RFC 7234 §5.2</see>.
    /// Used with <see cref="WellKnownCacheControlValues.NoStore"/> on
    /// token-bearing responses per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1#section-3.2.3">OAuth 2.1 §3.2.3</see>.
    /// </summary>
    public static readonly string CacheControl = Utf8Constants.ToInternedString(CacheControlUtf8);

    /// <summary>The UTF-8 source literal of <see cref="WwwAuthenticate"/>.</summary>
    public static ReadOnlySpan<byte> WwwAuthenticateUtf8 => "WWW-Authenticate"u8;

    /// <summary>
    /// The <c>WWW-Authenticate</c> response header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 §11.6.1</see>.
    /// Carries the authentication challenge on <c>401</c> responses; RFC 9728 §5.1
    /// adds the <c>resource_metadata</c> challenge parameter pointing at the
    /// protected resource's metadata document.
    /// </summary>
    public static readonly string WwwAuthenticate = Utf8Constants.ToInternedString(WwwAuthenticateUtf8);


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Authorization</c> header.
    /// </summary>
    public static bool IsAuthorization(string name) => Equals(name, Authorization);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>DPoP</c> header.
    /// </summary>
    public static bool IsDPoP(string name) => Equals(name, DPoP);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>DPoP-Nonce</c> header.
    /// </summary>
    public static bool IsDPoPNonce(string name) => Equals(name, DPoPNonce);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Cache-Control</c> header.
    /// </summary>
    public static bool IsCacheControl(string name) => Equals(name, CacheControl);


    /// <summary>
    /// Returns the canonical instance for <paramref name="name"/> when it
    /// matches one of the well-known headers, otherwise the input unchanged.
    /// </summary>
    public static string GetCanonicalizedValue(string name) => name switch
    {
        var n when IsAuthorization(n) => Authorization,
        var n when IsDPoP(n) => DPoP,
        var n when IsDPoPNonce(n) => DPoPNonce,
        var n when IsCacheControl(n) => CacheControl,
        _ => name
    };


    /// <summary>
    /// Compares two HTTP header names per the library's comparison rule
    /// (ordinal, case-insensitive — header names are case-insensitive per
    /// RFC 9110 §5.1).
    /// </summary>
    public static bool Equals(string nameA, string nameB) =>
        string.Equals(nameA, nameB, StringComparison.OrdinalIgnoreCase);
}
