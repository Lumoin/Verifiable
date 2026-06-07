using System.Diagnostics;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The parameters that compose the body of an authorization code token exchange request.
/// </summary>
/// <remarks>
/// Posted as <c>application/x-www-form-urlencoded</c> to the token endpoint per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 §4.1.3</see>.
/// The <see cref="CodeVerifier"/> proves possession of the PKCE secret established
/// during the authorization request, preventing code injection per
/// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.5">RFC 9700 §4.5</see>.
/// </remarks>
[DebuggerDisplay("TokenRequest ClientId={ClientId}")]
public sealed record TokenRequest
{
    /// <summary>The client identifier registered with the authorization server.</summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The authorization code received in the redirect callback. Single-use.
    /// </summary>
    public required string Code { get; init; }

    /// <summary>
    /// The redirect URI used in the original authorization request.
    /// Must exactly match the value sent during PAR.
    /// </summary>
    public required Uri RedirectUri { get; init; }

    /// <summary>
    /// The Base64url-encoded PKCE code verifier whose SHA-256 hash was sent
    /// as the challenge during the authorization request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.5">RFC 7636 §4.5</see>.
    /// </summary>
    public required string CodeVerifier { get; init; }

    /// <summary>The grant type. Always <c>authorization_code</c> for this request.</summary>
    public string GrantType { get; init; } = "authorization_code";
}