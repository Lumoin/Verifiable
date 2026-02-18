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
    /// <summary>
    /// The JWT <c>typ</c> header value for Status List Tokens: <c>statuslist+jwt</c>.
    /// </summary>
    public const string StatusListJwt = "statuslist+jwt";

    /// <summary>
    /// The HTTP content type for JWT-format Status List Tokens.
    /// </summary>
    public const string StatusListJwtContentType = "application/statuslist+jwt";

    /// <summary>
    /// The CWT content type identifier for Status List Tokens.
    /// </summary>
    public const string StatusListCwt = "application/statuslist+cwt";
}