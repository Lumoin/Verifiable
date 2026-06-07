using System;
using System.Diagnostics;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The response body returned by the token endpoint after a successful token refresh.
/// </summary>
/// <remarks>
/// Defined in
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see>.
/// The authorization server may issue a new refresh token alongside the new access token.
/// When a new refresh token is issued, the previous one is invalidated and the caller
/// must replace it in storage.
/// </remarks>
[DebuggerDisplay("RefreshTokenResponse TokenType={TokenType} ExpiresIn={ExpiresIn}")]
public sealed record RefreshTokenResponse
{
    /// <summary>The new access token. Replaces the previous access token.</summary>
    public required string AccessToken { get; init; }

    /// <summary>The token type. Typically <c>Bearer</c> or <c>DPoP</c>.</summary>
    public required string TokenType { get; init; }

    /// <summary>The new access token lifetime in seconds, if provided.</summary>
    public int? ExpiresIn { get; init; }

    /// <summary>
    /// A new refresh token, if the authorization server performs refresh token rotation.
    /// When present, the caller must replace the previous refresh token in storage with
    /// this value. <see langword="null"/> when the existing refresh token remains valid.
    /// </summary>
    public string? RefreshToken { get; init; }

    /// <summary>The granted scopes, if narrowed from the original grant.</summary>
    public string? Scope { get; init; }

    /// <summary>The UTC instant at which this response was received.</summary>
    public required DateTimeOffset ReceivedAt { get; init; }
}