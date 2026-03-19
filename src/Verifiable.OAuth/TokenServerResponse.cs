using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth;

/// <summary>
/// The success response body from a token endpoint per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// A server populates and serializes this type as the HTTP 200 response body when it
/// issues tokens. The client parses the wire bytes using
/// <see cref="OAuthResponseParsers.ParseTokenResponse"/>.
/// </para>
/// <para>
/// Serialization is handled in <c>Verifiable.Json</c>.
/// </para>
/// </remarks>
[DebuggerDisplay("TokenServerResponse TokenType={TokenType} ExpiresIn={ExpiresIn}")]
public sealed class TokenServerResponse: IEquatable<TokenServerResponse>
{
    /// <summary>The access token issued by the authorization server.</summary>
    public string AccessToken { get; init; } = string.Empty;

    /// <summary>The token type, e.g. <c>Bearer</c> per RFC 6749 §5.1.</summary>
    public string TokenType { get; init; } = string.Empty;

    /// <summary>The lifetime in seconds of the access token.</summary>
    public int ExpiresIn { get; init; }

    /// <summary>
    /// The refresh token, if issued.
    /// <see langword="null"/> when the server does not issue refresh tokens.
    /// </summary>
    public string? RefreshToken { get; init; }

    /// <summary>
    /// The scope of the access token. May differ from the requested scope if the server
    /// granted a subset per RFC 6749 §5.1.
    /// </summary>
    public string? Scope { get; init; }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(TokenServerResponse? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return AccessToken == other.AccessToken
            && TokenType == other.TokenType
            && ExpiresIn == other.ExpiresIn
            && RefreshToken == other.RefreshToken
            && Scope == other.Scope;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is TokenServerResponse other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() =>
        HashCode.Combine(AccessToken, TokenType, ExpiresIn, RefreshToken, Scope);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(TokenServerResponse? left, TokenServerResponse? right) =>
        left is null ? right is null : left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(TokenServerResponse? left, TokenServerResponse? right) =>
        !(left == right);
}
