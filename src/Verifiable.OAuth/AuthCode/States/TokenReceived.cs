using System;
using System.Diagnostics;
using Verifiable.OAuth;

namespace Verifiable.OAuth.AuthCode.States;

/// <summary>
/// Tokens have been received from the token endpoint. Terminal success state.
/// </summary>
/// <remarks>
/// No further transitions are defined from this state. The PDA halts when it enters here
/// and <c>PushdownAutomaton.IsAccepted</c> returns <see langword="true"/>.
/// </remarks>
[DebuggerDisplay("TokenReceived FlowId={FlowId}")]
public sealed record TokenReceived: OAuthFlowState
{
    /// <summary>The opaque access token. Must be treated as a secret.</summary>
    public required string AccessToken { get; init; }

    /// <summary>
    /// The token type. Typically <c>Bearer</c> or <c>DPoP</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449">RFC 9449</see>.
    /// </summary>
    public required string TokenType { get; init; }

    /// <summary>The access token lifetime in seconds, if provided by the server.</summary>
    public int? ExpiresIn { get; init; }

    /// <summary>The refresh token, if issued.</summary>
    public string? RefreshToken { get; init; }

    /// <summary>The scopes granted, if different from those requested.</summary>
    public string? Scope { get; init; }

    /// <summary>The UTC instant at which the token response was received.</summary>
    public required DateTimeOffset ReceivedAt { get; init; }
}
