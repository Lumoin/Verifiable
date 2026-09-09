using Verifiable.Cryptography.Text;

namespace Verifiable.Core.Transport;

/// <summary>
/// HTTP header name constants, plus per-header <c>IsXxx</c> predicates and a
/// central <see cref="Equals"/> method anchoring the comparison rule.
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
/// Every entry the library reads or composes anywhere — request, response,
/// and cache-freshness headers alike — is named here: <see cref="Authorization"/>,
/// <see cref="Accept"/>, <see cref="AcceptLanguage"/>, <see cref="ContentLanguage"/>,
/// <see cref="ContentType"/>, <see cref="DPoP"/>, <see cref="DPoPNonce"/>,
/// <see cref="CacheControl"/>, <see cref="WwwAuthenticate"/>, <see cref="Location"/>,
/// <see cref="Date"/>, <see cref="Age"/>, and <see cref="Expires"/>. Each carries its
/// own <c>IsXxx</c> predicate and a row in <see cref="GetCanonicalizedValue"/>. This
/// type lives in <c>Verifiable.Core.Transport</c> beside <see cref="HttpHeaderSet"/> —
/// a transport vocabulary the OAuth, Server, DIDComm, VCALM, and did:webvh surfaces
/// all read, not an OAuth-only one.
/// </para>
/// </remarks>
public static class WellKnownHttpHeaderNames
{
    /// <summary>The UTF-8 source literal of <see cref="Authorization"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationUtf8 => "Authorization"u8;

    /// <summary>
    /// The <c>Authorization</c> request header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.2">RFC 9110 §11.6.2</see>.
    /// Carries the credentials the client uses to authenticate to the server.
    /// </summary>
    public static string Authorization { get; } = Utf8Constants.ToInternedString(AuthorizationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Accept"/>.</summary>
    public static ReadOnlySpan<byte> AcceptUtf8 => "Accept"u8;

    /// <summary>
    /// The <c>Accept</c> request header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-12.5.1">RFC 9110 §12.5.1</see>
    /// — the response media types the caller can process. A resource server requests
    /// an RFC 9701 signed introspection response by setting it to
    /// <c>application/token-introspection+jwt</c>.
    /// </summary>
    public static string Accept { get; } = Utf8Constants.ToInternedString(AcceptUtf8);

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
    public static string AcceptLanguage { get; } = Utf8Constants.ToInternedString(AcceptLanguageUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ContentLanguage"/>.</summary>
    public static ReadOnlySpan<byte> ContentLanguageUtf8 => "Content-Language"u8;

    /// <summary>
    /// The <c>Content-Language</c> response header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.5">RFC 9110 §8.5</see>.
    /// OID4VCI 1.0 §12.2.2: a Credential Issuer that filters the metadata's internationalized
    /// display data to the requested language(s) MUST "indicate returned languages using the
    /// HTTP Content-Language Header". Its values use the language tags defined in RFC 3066.
    /// </summary>
    public static string ContentLanguage { get; } = Utf8Constants.ToInternedString(ContentLanguageUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ContentType"/>.</summary>
    public static ReadOnlySpan<byte> ContentTypeUtf8 => "Content-Type"u8;

    /// <summary>
    /// The <c>Content-Type</c> header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3">RFC 9110 §8.3</see>:
    /// "The 'Content-Type' header field indicates the media type of the associated
    /// representation … A sender that generates a message containing content SHOULD
    /// generate a Content-Type header field in that message unless the intended media
    /// type of the enclosed representation is unknown to the sender."
    /// </summary>
    public static string ContentType { get; } = Utf8Constants.ToInternedString(ContentTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DPoP"/>.</summary>
    public static ReadOnlySpan<byte> DPoPUtf8 => "DPoP"u8;

    /// <summary>
    /// The <c>DPoP</c> request header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4">RFC 9449 §4</see>.
    /// Carries the proof JWS bound to the request the client is making.
    /// </summary>
    public static string DPoP { get; } = Utf8Constants.ToInternedString(DPoPUtf8);

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
    public static string DPoPNonce { get; } = Utf8Constants.ToInternedString(DPoPNonceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CacheControl"/>.</summary>
    public static ReadOnlySpan<byte> CacheControlUtf8 => "Cache-Control"u8;

    /// <summary>
    /// The <c>Cache-Control</c> header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111 §5.2</see>.
    /// Used with the <c>no-store</c> directive on token-bearing responses per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1#section-3.2.3">OAuth 2.1 §3.2.3</see>,
    /// and read for its <c>max-age</c>/<c>s-maxage</c>/<c>no-store</c>/<c>no-cache</c>
    /// directives by <see cref="Verifiable.Core.OutboundFetch.HttpCacheFreshness"/>.
    /// </summary>
    public static string CacheControl { get; } = Utf8Constants.ToInternedString(CacheControlUtf8);

    /// <summary>The UTF-8 source literal of <see cref="WwwAuthenticate"/>.</summary>
    public static ReadOnlySpan<byte> WwwAuthenticateUtf8 => "WWW-Authenticate"u8;

    /// <summary>
    /// The <c>WWW-Authenticate</c> response header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 §11.6.1</see>.
    /// Carries the authentication challenge on <c>401</c> responses; RFC 9728 §5.1
    /// adds the <c>resource_metadata</c> challenge parameter pointing at the
    /// protected resource's metadata document.
    /// </summary>
    public static string WwwAuthenticate { get; } = Utf8Constants.ToInternedString(WwwAuthenticateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Location"/>.</summary>
    public static ReadOnlySpan<byte> LocationUtf8 => "Location"u8;

    /// <summary>
    /// The <c>Location</c> header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-10.2.2">RFC 9110 §10.2.2</see>:
    /// "used in some responses to refer to a specific resource in relation to the response.
    /// … For 201 (Created) responses, the Location value refers to the primary resource
    /// created by the request. For 3xx (Redirection) responses, the Location value refers
    /// to the preferred target resource for automatically redirecting the request." Read by
    /// <see cref="Verifiable.Core.OutboundFetch.OutboundFetch"/>'s redirect loop on every hop.
    /// </summary>
    public static string Location { get; } = Utf8Constants.ToInternedString(LocationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Date"/>.</summary>
    public static ReadOnlySpan<byte> DateUtf8 => "Date"u8;

    /// <summary>
    /// The <c>Date</c> header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-6.6.1">RFC 9110 §6.6.1</see>:
    /// "represents the date and time at which the message was originated". Read by
    /// <see cref="Verifiable.Core.OutboundFetch.HttpCacheFreshness"/> as the reference instant
    /// for the <see cref="Expires"/> fallback (RFC 9111 §4.2.1).
    /// </summary>
    public static string Date { get; } = Utf8Constants.ToInternedString(DateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Age"/>.</summary>
    public static ReadOnlySpan<byte> AgeUtf8 => "Age"u8;

    /// <summary>
    /// The <c>Age</c> response header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.1">RFC 9111 §5.1</see>:
    /// "The 'Age' response header field conveys the sender's estimate of the time since the
    /// response was generated or successfully validated at the origin server." Read by
    /// <see cref="Verifiable.Core.OutboundFetch.HttpCacheFreshness"/> to reduce a computed
    /// freshness lifetime by the time already elapsed.
    /// </summary>
    public static string Age { get; } = Utf8Constants.ToInternedString(AgeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Expires"/>.</summary>
    public static ReadOnlySpan<byte> ExpiresUtf8 => "Expires"u8;

    /// <summary>
    /// The <c>Expires</c> response header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.3">RFC 9111 §5.3</see>:
    /// "The 'Expires' response header field gives the date/time after which the response is
    /// considered stale." Read by <see cref="Verifiable.Core.OutboundFetch.HttpCacheFreshness"/>
    /// as the fallback freshness signal (against <see cref="Date"/>) when no
    /// <see cref="CacheControl"/> <c>max-age</c>/<c>s-maxage</c> directive is present.
    /// </summary>
    public static string Expires { get; } = Utf8Constants.ToInternedString(ExpiresUtf8);


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Authorization</c> header.
    /// </summary>
    public static bool IsAuthorization(string name) => Equals(name, Authorization);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Accept</c> header.
    /// </summary>
    public static bool IsAccept(string name) => Equals(name, Accept);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Accept-Language</c> header.
    /// </summary>
    public static bool IsAcceptLanguage(string name) => Equals(name, AcceptLanguage);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Content-Language</c> header.
    /// </summary>
    public static bool IsContentLanguage(string name) => Equals(name, ContentLanguage);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Content-Type</c> header.
    /// </summary>
    public static bool IsContentType(string name) => Equals(name, ContentType);

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
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>WWW-Authenticate</c> header.
    /// </summary>
    public static bool IsWwwAuthenticate(string name) => Equals(name, WwwAuthenticate);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Location</c> header.
    /// </summary>
    public static bool IsLocation(string name) => Equals(name, Location);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Date</c> header.
    /// </summary>
    public static bool IsDate(string name) => Equals(name, Date);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Age</c> header.
    /// </summary>
    public static bool IsAge(string name) => Equals(name, Age);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Expires</c> header.
    /// </summary>
    public static bool IsExpires(string name) => Equals(name, Expires);


    /// <summary>
    /// Returns the canonical instance for <paramref name="name"/> when it
    /// matches one of the well-known headers, otherwise the input unchanged.
    /// </summary>
    public static string GetCanonicalizedValue(string name) => name switch
    {
        var n when IsAuthorization(n) => Authorization,
        var n when IsAccept(n) => Accept,
        var n when IsAcceptLanguage(n) => AcceptLanguage,
        var n when IsContentLanguage(n) => ContentLanguage,
        var n when IsContentType(n) => ContentType,
        var n when IsDPoP(n) => DPoP,
        var n when IsDPoPNonce(n) => DPoPNonce,
        var n when IsCacheControl(n) => CacheControl,
        var n when IsWwwAuthenticate(n) => WwwAuthenticate,
        var n when IsLocation(n) => Location,
        var n when IsDate(n) => Date,
        var n when IsAge(n) => Age,
        var n when IsExpires(n) => Expires,
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
