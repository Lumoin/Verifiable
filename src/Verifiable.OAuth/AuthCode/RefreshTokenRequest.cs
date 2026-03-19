using System.Diagnostics;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The parameters that compose the body of a token refresh request.
/// </summary>
/// <remarks>
/// Posted as <c>application/x-www-form-urlencoded</c> to the token endpoint per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see>.
/// The refresh flow is independent of the authorization code PDA — the caller
/// initiates it when the access token has expired or is near expiry.
/// </remarks>
[DebuggerDisplay("RefreshTokenRequest ClientId={ClientId}")]
public sealed record RefreshTokenRequest
{
    /// <summary>The client identifier registered with the authorization server.</summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The refresh token issued during the original token exchange.
    /// Must be kept confidential.
    /// </summary>
    public required string RefreshToken { get; init; }

    /// <summary>
    /// The scopes to request in the refreshed token. When <see langword="null"/>,
    /// the authorization server issues the same scopes as the original grant.
    /// Must not exceed the originally granted scopes.
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>The grant type. Always <c>refresh_token</c> for this request.</summary>
    public string GrantType { get; init; } = "refresh_token";
}