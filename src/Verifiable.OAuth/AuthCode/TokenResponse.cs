using System.Diagnostics;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The response body returned by the token endpoint after a successful exchange.
/// </summary>
/// <remarks>
/// Defined in
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
/// Maps directly to <see cref="Verifiable.OAuth.AuthCode.States.TokenReceivedState"/> via
/// <c>AuthCodeFlow</c>. The caller is responsible for parsing the JSON response body
/// and constructing this record before passing it to the flow.
/// </remarks>
[DebuggerDisplay("TokenResponse TokenType={TokenType} ExpiresIn={ExpiresIn}")]
public sealed record TokenResponse
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

    /// <summary>
    /// The refresh token, if issued. Present only when the authorization server
    /// grants offline access.
    /// </summary>
    public string? RefreshToken { get; init; }

    /// <summary>
    /// The granted scopes, if different from those requested. <see langword="null"/>
    /// when the granted scopes equal the requested scopes.
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>
    /// The ID Token, if issued. Present in an OpenID Connect token response per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse">OpenID Connect Core 1.0 §3.1.3.3</see>;
    /// <see langword="null"/> for plain OAuth 2.0 responses that carry no ID Token.
    /// </summary>
    public string? IdToken { get; init; }

    /// <summary>
    /// The <c>issued_token_type</c> of a token exchange's answer, the type of the token issued
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.1">RFC 8693 §2.2.1</see>: "REQUIRED. An identifier, as
    /// described in Section 3, for the representation of the issued security token."); <see langword="null"/> for an answer
    /// of any other grant, which names none.
    /// </summary>
    public string? IssuedTokenType { get; init; }
}
