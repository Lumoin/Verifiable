using Verifiable.Cryptography.Text;
using Verifiable.JCose;


namespace Verifiable.OAuth;

/// <summary>
/// Media types and type identifiers for Token Status List specification.
/// </summary>
/// <remarks>
/// <para>
/// These values are used in HTTP <c>Accept</c> and <c>Content-Type</c> headers
/// when fetching or serving Status List Tokens, and in the <c>typ</c> header
/// parameter of JWT Status List Tokens.
/// </para>
/// </remarks>
public static class StatusListMediaTypes
{
    /// <summary>The UTF-8 source literal of <see cref="StatusListJwt"/>.</summary>
    public static ReadOnlySpan<byte> StatusListJwtUtf8 => WellKnownMediaTypes.Jwt.StatusListJwtUtf8;

    /// <summary>
    /// The JWT <c>typ</c> header value for Status List Tokens: <c>statuslist+jwt</c>. An alias of
    /// <see cref="WellKnownMediaTypes.Jwt.StatusListJwt"/> — the one home of the literal (every other
    /// <c>typ</c> short form the OAuth layer composes reads from that table) — kept here so callers
    /// already using this class's HTTP media-type members find the wire's <c>typ</c> value beside them.
    /// </summary>
    public static string StatusListJwt { get; } = WellKnownMediaTypes.Jwt.StatusListJwt;

    /// <summary>The UTF-8 source literal of <see cref="StatusListJwtContentType"/>.</summary>
    public static ReadOnlySpan<byte> StatusListJwtContentTypeUtf8 => "application/statuslist+jwt"u8;

    /// <summary>
    /// The HTTP content type for JWT-format Status List Tokens: "In the successful response, the
    /// Status Provider MUST use the following content-type: … application/statuslist+jwt … In the case
    /// of 'application/statuslist+jwt', the response MUST be of type JWT and follow the rules of
    /// Section 5.1."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.1">Token Status List, Section 8.1</see>
    /// and <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Section 8.2</see>.
    /// </summary>
    public static string StatusListJwtContentType { get; } = Utf8Constants.ToInternedString(StatusListJwtContentTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StatusListCwt"/>.</summary>
    public static ReadOnlySpan<byte> StatusListCwtUtf8 => "application/statuslist+cwt"u8;

    /// <summary>
    /// The CWT content type identifier for Status List Tokens — the media type "application/
    /// statuslist+cwt" this specification's §8.1/§8.2 registers beside <see cref="StatusListJwtContentType"/>.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.1">Token Status List, Section 8.1</see>
    /// and <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Section 8.2</see>.
    /// </summary>
    public static string StatusListCwt { get; } = Utf8Constants.ToInternedString(StatusListCwtUtf8);
}
