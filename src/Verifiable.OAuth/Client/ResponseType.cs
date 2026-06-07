using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Identifies an OAuth 2.0 / OpenID Connect / OID4VP response type. Carried
/// on a client-side <see cref="ClientRegistration.ResponseTypes"/> list and
/// emitted as the <c>response_type</c> wire field on authorization requests.
/// </summary>
/// <remarks>
/// <para>
/// Follows the dynamic-enum pattern shared with <see cref="GrantType"/>.
/// Each canonical value represents an exact <c>response_type</c> wire-format
/// string; the order of tokens in the multi-token combinations
/// (<c>code id_token</c>, <c>id_token token</c>, and so on) follows the
/// OIDC Core 1.0 §3 ordering.
/// </para>
/// <para>
/// Codes 0–999 are reserved for library-defined values. Applications adding
/// custom response types use <see cref="Create"/> at code 1000 and above.
/// </para>
/// </remarks>
[DebuggerDisplay("{ResponseTypeNames.GetName(this),nq}")]
public readonly struct ResponseType: IEquatable<ResponseType>
{
    /// <summary>Gets the numeric code identifying this response type.</summary>
    public int Code { get; }

    private ResponseType(int code)
    {
        Code = code;
    }


    /// <summary>
    /// Authorization Code response per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1">RFC 6749 §4.1</see>.
    /// Wire value: <c>code</c>. Named <c>AuthorizationCode</c> rather than
    /// <c>Code</c> to avoid colliding with the inherited <see cref="Code"/>
    /// discriminator property and to mirror
    /// <see cref="GrantType.AuthorizationCode"/>.
    /// </summary>
    public static ResponseType AuthorizationCode { get; } = new(0);

    /// <summary>
    /// Implicit-flow access token response per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.2">RFC 6749 §4.2</see>.
    /// Wire value: <c>token</c>.
    /// </summary>
    /// <remarks>
    /// Deprecated by OAuth 2.1 and disallowed by FAPI 2.0. Present here for
    /// completeness when interoperating with legacy authorization servers.
    /// </remarks>
    public static ResponseType Token { get; } = new(1);

    /// <summary>
    /// OpenID Connect ID Token response per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth">OIDC Core §3.2</see>.
    /// Wire value: <c>id_token</c>.
    /// </summary>
    public static ResponseType IdToken { get; } = new(2);

    /// <summary>
    /// OIDC hybrid <c>code id_token</c> per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth">OIDC Core §3.3</see>.
    /// Wire value: <c>code id_token</c>.
    /// </summary>
    public static ResponseType CodeIdToken { get; } = new(3);

    /// <summary>
    /// OIDC hybrid <c>code token</c> per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth">OIDC Core §3.3</see>.
    /// Wire value: <c>code token</c>.
    /// </summary>
    public static ResponseType CodeToken { get; } = new(4);

    /// <summary>
    /// OIDC hybrid <c>id_token token</c> per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth">OIDC Core §3.3</see>.
    /// Wire value: <c>id_token token</c>.
    /// </summary>
    public static ResponseType IdTokenToken { get; } = new(5);

    /// <summary>
    /// OIDC hybrid <c>code id_token token</c> per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth">OIDC Core §3.3</see>.
    /// Wire value: <c>code id_token token</c>.
    /// </summary>
    public static ResponseType CodeIdTokenToken { get; } = new(6);

    /// <summary>
    /// OIDC <c>none</c> response type per
    /// <see href="https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none">Multiple Response Type Encoding §4</see>.
    /// Wire value: <c>none</c>.
    /// </summary>
    public static ResponseType None { get; } = new(7);

    /// <summary>
    /// OID4VP <c>vp_token</c> response per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0</see>.
    /// Wire value: <c>vp_token</c>.
    /// </summary>
    public static ResponseType VpToken { get; } = new(8);

    /// <summary>
    /// OID4VP hybrid <c>code vp_token</c>.
    /// Wire value: <c>code vp_token</c>.
    /// </summary>
    public static ResponseType CodeVpToken { get; } = new(9);


    private static readonly List<ResponseType> responseTypes =
    [
        AuthorizationCode, Token, IdToken,
        CodeIdToken, CodeToken, IdTokenToken, CodeIdTokenToken,
        None,
        VpToken, CodeVpToken
    ];

    /// <summary>Gets all registered response type values including any custom ones.</summary>
    public static IReadOnlyList<ResponseType> ResponseTypes => responseTypes.AsReadOnly();


    /// <summary>
    /// Creates a new <see cref="ResponseType"/> for an application-defined response type.
    /// </summary>
    /// <param name="code">
    /// The numeric code identifying the response type. Use values
    /// <strong>1000 and above</strong> to avoid collisions with future
    /// library additions.
    /// </param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="code"/> is already registered.</exception>
    public static ResponseType Create(int code)
    {
        for(int i = 0; i < responseTypes.Count; ++i)
        {
            if(responseTypes[i].Code == code)
            {
                throw new ArgumentException(
                    $"A response type with code {code} is already registered.", nameof(code));
            }
        }

        ResponseType newResponseType = new(code);
        responseTypes.Add(newResponseType);
        return newResponseType;
    }


    /// <inheritdoc/>
    public override string ToString() => ResponseTypeNames.GetName(this);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(ResponseType other) => Code == other.Code;


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is ResponseType other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(ResponseType left, ResponseType right) => left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(ResponseType left, ResponseType right) => !left.Equals(right);
}
