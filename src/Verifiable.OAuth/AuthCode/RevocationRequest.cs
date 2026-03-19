using System.Diagnostics;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The token hint type passed to the revocation endpoint.
/// </summary>
public enum TokenTypeHint
{
    /// <summary>
    /// The token being revoked is an access token.
    /// </summary>
    AccessToken,

    /// <summary>
    /// The token being revoked is a refresh token.
    /// </summary>
    RefreshToken
}


/// <summary>
/// The parameters that compose the body of a token revocation request.
/// </summary>
/// <remarks>
/// Posted as <c>application/x-www-form-urlencoded</c> to the revocation endpoint per
/// <see href="https://www.rfc-editor.org/rfc/rfc7009#section-2.1">RFC 7009 §2.1</see>.
/// Revocation is used during logout or when a session is invalidated. The authorization
/// server may revoke associated tokens when a refresh token is revoked.
/// </remarks>
[DebuggerDisplay("RevocationRequest ClientId={ClientId} Hint={Hint}")]
public sealed record RevocationRequest
{
    /// <summary>The client identifier registered with the authorization server.</summary>
    public required string ClientId { get; init; }

    /// <summary>The token to revoke.</summary>
    public required string Token { get; init; }

    /// <summary>
    /// A hint about the type of the token being revoked. Helps the authorization
    /// server locate the token more efficiently. <see langword="null"/> when no hint
    /// is provided.
    /// </summary>
    public TokenTypeHint? Hint { get; init; }
}