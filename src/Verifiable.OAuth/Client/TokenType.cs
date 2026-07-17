using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Identifies an OAuth 2.0 Token Exchange security token type per
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-3">RFC 8693 §3</see>. Carried as the
/// <c>subject_token_type</c>, <c>actor_token_type</c>, <c>requested_token_type</c>, and
/// <c>issued_token_type</c> wire values.
/// </summary>
/// <remarks>
/// <para>
/// Follows the dynamic-value-type pattern shared with <see cref="GrantType"/>: a readonly struct
/// whose canonical values are static readonly properties, with equality determined by
/// <see cref="Code"/>. The wire-format string is looked up via the companion
/// <see cref="TokenTypeNames"/> class.
/// </para>
/// <para>
/// Codes 0–999 are reserved for library-defined values. Applications adding custom token types use
/// <see cref="Create"/> at code 1000 and above.
/// </para>
/// </remarks>
[DebuggerDisplay("{TokenTypeNames.GetName(this),nq}")]
public readonly struct TokenType: IEquatable<TokenType>
{
    /// <summary>Gets the numeric code identifying this token type.</summary>
    public int Code { get; }

    private TokenType(int code)
    {
        Code = code;
    }


    /// <summary>
    /// Access token. Wire value: <c>urn:ietf:params:oauth:token-type:access_token</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-3">RFC 8693 §3</see>).
    /// </summary>
    public static TokenType AccessToken { get; } = new(0);

    /// <summary>
    /// Refresh token. Wire value: <c>urn:ietf:params:oauth:token-type:refresh_token</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-3">RFC 8693 §3</see>).
    /// </summary>
    public static TokenType RefreshToken { get; } = new(1);

    /// <summary>
    /// OpenID Connect ID Token. Wire value: <c>urn:ietf:params:oauth:token-type:id_token</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-3">RFC 8693 §3</see>).
    /// </summary>
    public static TokenType IdToken { get; } = new(2);

    /// <summary>
    /// SAML 1.1 assertion. Wire value: <c>urn:ietf:params:oauth:token-type:saml1</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-3">RFC 8693 §3</see>).
    /// </summary>
    public static TokenType Saml1 { get; } = new(3);

    /// <summary>
    /// SAML 2.0 assertion. Wire value: <c>urn:ietf:params:oauth:token-type:saml2</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-3">RFC 8693 §3</see>).
    /// </summary>
    public static TokenType Saml2 { get; } = new(4);

    /// <summary>
    /// JSON Web Token. Wire value: <c>urn:ietf:params:oauth:token-type:jwt</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-3">RFC 8693 §3</see>).
    /// </summary>
    public static TokenType Jwt { get; } = new(5);

    /// <summary>
    /// Identity Assertion JWT Authorization Grant (ID-JAG). Wire value:
    /// <c>urn:ietf:params:oauth:token-type:id-jag</c>, used as the
    /// <c>requested_token_type</c> when minting and the <c>issued_token_type</c>
    /// echoed back (draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §4.3, §10.2).
    /// </summary>
    public static TokenType IdJag { get; } = new(6);


    /// <summary>
    /// Thread-safe registry of every library-defined token type plus any application-defined ones
    /// added through <see cref="Create"/>, keyed by <see cref="Code"/>. Backing store for the
    /// <see cref="TokenTypes"/> getter; a <see cref="ConcurrentDictionary{TKey, TValue}"/> is used
    /// rather than a plain list so that concurrent <see cref="Create"/> calls resolve atomically via
    /// <see cref="ConcurrentDictionary{TKey, TValue}.TryAdd"/> instead of racing on a separate
    /// contains-check followed by an add.
    /// </summary>
    private static ConcurrentDictionary<int, TokenType> registeredTokenTypesByCode { get; } = new()
    {
        [AccessToken.Code] = AccessToken,
        [RefreshToken.Code] = RefreshToken,
        [IdToken.Code] = IdToken,
        [Saml1.Code] = Saml1,
        [Saml2.Code] = Saml2,
        [Jwt.Code] = Jwt,
        [IdJag.Code] = IdJag
    };

    /// <summary>
    /// Gets all registered token type values including any custom ones. The enumeration order is
    /// whatever <see cref="ConcurrentDictionary{TKey, TValue}.Values"/> yields for
    /// <see cref="registeredTokenTypesByCode"/> — UNSPECIFIED, and MUST NOT be relied upon by callers
    /// (it is not insertion order, code order, or otherwise stable across framework versions).
    /// </summary>
    public static IReadOnlyList<TokenType> TokenTypes => [.. registeredTokenTypesByCode.Values];


    /// <summary>
    /// Creates a new <see cref="TokenType"/> for an application-defined token type.
    /// </summary>
    /// <param name="code">
    /// The numeric code identifying the token type. Use values <strong>1000 and above</strong> to
    /// avoid collisions with future library additions.
    /// </param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="code"/> is already registered.</exception>
    public static TokenType Create(int code)
    {
        TokenType newTokenType = new(code);
        if(!registeredTokenTypesByCode.TryAdd(code, newTokenType))
        {
            throw new ArgumentException(
                $"A token type with code {code} is already registered.", nameof(code));
        }

        return newTokenType;
    }


    /// <inheritdoc/>
    public override string ToString() => TokenTypeNames.GetName(this);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(TokenType other) => Code == other.Code;


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is TokenType other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(TokenType left, TokenType right) => left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(TokenType left, TokenType right) => !left.Equals(right);
}