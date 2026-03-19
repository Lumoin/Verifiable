using System.Diagnostics;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Carries a successful token endpoint response. Transitions from
/// <see cref="AuthorizationCodeReceived"/> to <see cref="TokenReceived"/>.
/// </summary>
/// <param name="AccessToken">The opaque access token.</param>
/// <param name="TokenType">The token type (e.g., <c>Bearer</c> or <c>DPoP</c>).</param>
/// <param name="ExpiresIn">The access token lifetime in seconds, if provided.</param>
/// <param name="RefreshToken">The refresh token, if issued.</param>
/// <param name="Scope">The granted scopes, if different from those requested.</param>
/// <param name="ReceivedAt">The UTC instant the token response was received.</param>
[DebuggerDisplay("TokenExchangeSucceeded")]
public sealed record TokenExchangeSucceeded(
    string AccessToken,
    string TokenType,
    int? ExpiresIn,
    string? RefreshToken,
    string? Scope,
    DateTimeOffset ReceivedAt): OAuthFlowInput;
