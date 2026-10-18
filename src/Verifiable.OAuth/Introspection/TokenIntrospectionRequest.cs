using System.Diagnostics;
using System.Text;

namespace Verifiable.OAuth.Introspection;

/// <summary>
/// The parameters a protected resource sends to the authorization server's introspection endpoint
/// (<see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.1">RFC 7662 Section 2.1</see>): the token whose
/// state the resource asks about and, when the resource knows it, a hint naming the token's type. The operation
/// that sends them is <see cref="TokenIntrospectionClient.IntrospectAsync"/>.
/// </summary>
/// <remarks>
/// The token is a credential: neither <see cref="DebuggerDisplayAttribute"/> nor <see cref="ToString"/> shows it.
/// </remarks>
[DebuggerDisplay("TokenIntrospectionRequest TokenTypeHint={TokenTypeHint}")]
public sealed record TokenIntrospectionRequest
{
    /// <summary>
    /// The token sent as the <c>token</c> parameter.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.1">RFC 7662 Section 2.1</see>: "token REQUIRED. The
    /// string value of the token." An empty value is the caller's error and is refused by
    /// <see cref="TokenIntrospectionClient.IntrospectAsync"/> with an <see cref="ArgumentException"/> before anything
    /// is sent.
    /// </summary>
    public required string Token { get; init; }

    /// <summary>
    /// The hint sent verbatim as the <c>token_type_hint</c> parameter, or <see langword="null"/> to send none.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.1">RFC 7662 Section 2.1</see>: "token_type_hint
    /// OPTIONAL. A hint about the type of the token submitted for introspection. The protected resource MAY pass this
    /// parameter to help the authorization server optimize the token lookup." and "Values for this field are defined in
    /// the "OAuth Token Type Hints" registry defined in OAuth Token Revocation [RFC7009]." The registry's values are
    /// <c>access_token</c> and <c>refresh_token</c>; no value is refused, since the authorization server "MUST extend
    /// its search across all of its supported token types" when the hint does not locate the token.
    /// </summary>
    public string? TokenTypeHint { get; init; }


    /// <summary>
    /// The record's text: its type name and <see cref="TokenTypeHint"/> alone, so the token, a credential, never
    /// reaches a log line through the record's text.
    /// </summary>
    /// <returns>The text <c>TokenIntrospectionRequest { TokenTypeHint = &lt;hint&gt; }</c>.</returns>
    public override string ToString()
    {
        StringBuilder text = new();
        _ = text.Append("TokenIntrospectionRequest { TokenTypeHint = ").Append(TokenTypeHint).Append(" }");

        return text.ToString();
    }
}
