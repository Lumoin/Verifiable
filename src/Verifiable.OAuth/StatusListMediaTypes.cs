using Verifiable.Cryptography.Text;


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
    public static ReadOnlySpan<byte> StatusListJwtUtf8 => "statuslist+jwt"u8;

    /// <summary>
    /// The JWT <c>typ</c> header value for Status List Tokens: <c>statuslist+jwt</c>.
    /// </summary>
    public static readonly string StatusListJwt = Utf8Constants.ToInternedString(StatusListJwtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StatusListJwtContentType"/>.</summary>
    public static ReadOnlySpan<byte> StatusListJwtContentTypeUtf8 => "application/statuslist+jwt"u8;

    /// <summary>
    /// The HTTP content type for JWT-format Status List Tokens.
    /// </summary>
    public static readonly string StatusListJwtContentType = Utf8Constants.ToInternedString(StatusListJwtContentTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StatusListCwt"/>.</summary>
    public static ReadOnlySpan<byte> StatusListCwtUtf8 => "application/statuslist+cwt"u8;

    /// <summary>
    /// The CWT content type identifier for Status List Tokens.
    /// </summary>
    public static readonly string StatusListCwt = Utf8Constants.ToInternedString(StatusListCwtUtf8);
}
