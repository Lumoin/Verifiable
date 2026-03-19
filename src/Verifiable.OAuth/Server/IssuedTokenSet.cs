using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The set of tokens issued by a token endpoint in a single response, keyed by their
/// response field name. Replaces ad-hoc <see cref="System.Collections.Generic.Dictionary{TKey, TValue}"/>
/// usage at endpoint composition sites with a typed handle that carries semantic meaning.
/// </summary>
/// <remarks>
/// <para>
/// Each entry maps a token-type response field name (e.g.,
/// <see cref="WellKnownTokenTypes.AccessToken"/>) to the compact JWS serialization of
/// the issued token. The well-known accessors (<see cref="IssuedTokenSetExtensions"/>)
/// surface specific tokens by name; applications add their own typed accessors via
/// extension blocks following the same pattern.
/// </para>
/// <para>
/// Token strings are transient — they appear in the HTTP response body once and are
/// not persisted into <see cref="ServerTokenIssuedState"/> or any other durable
/// flow state. Only the audit metadata (<c>jti</c>, signing key id, issued/expires
/// timestamps) is persisted; the token bytes themselves exist only in this set during
/// response composition.
/// </para>
/// <para>
/// Construct via <see cref="IssuedTokenSetBuilder"/> when assembling tokens incrementally,
/// or pass a pre-built dictionary to the constructor when the full set is known up front.
/// </para>
/// </remarks>
[DebuggerDisplay("IssuedTokenSet({Tokens.Count} tokens)")]
public sealed record IssuedTokenSet
{
    /// <summary>
    /// The issued tokens keyed by their response field name.
    /// </summary>
    public required IReadOnlyDictionary<string, string> Tokens { get; init; }


    /// <summary>
    /// Returns the compact JWS for the given token type, or <see langword="null"/>
    /// when no token of that type was issued.
    /// </summary>
    /// <param name="tokenType">The token type name; typically a member of <see cref="WellKnownTokenTypes"/>.</param>
    /// <returns>The compact JWS, or <see langword="null"/>.</returns>
    public string? Get(string tokenType)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenType);
        return Tokens.TryGetValue(tokenType, out string? value) ? value : null;
    }


    /// <summary>
    /// Whether this set contains a token of the given type.
    /// </summary>
    /// <param name="tokenType">The token type name; typically a member of <see cref="WellKnownTokenTypes"/>.</param>
    public bool Contains(string tokenType)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenType);
        return Tokens.ContainsKey(tokenType);
    }


    /// <summary>
    /// An empty <see cref="IssuedTokenSet"/> singleton used when no tokens were issued.
    /// </summary>
    public static IssuedTokenSet Empty { get; } = new()
    {
        Tokens = new Dictionary<string, string>(0)
    };
}
