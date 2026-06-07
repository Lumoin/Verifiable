using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Identifies an OAuth 2.0 grant type. Carried on a client-side
/// <see cref="ClientRegistration.GrantTypes"/> list and emitted as the
/// <c>grant_type</c> wire field on token requests.
/// </summary>
/// <remarks>
/// <para>
/// Follows the dynamic-value-type pattern shared with other extensible
/// identifiers in the library: a readonly struct whose canonical values
/// are static readonly properties, with equality determined by
/// <see cref="Code"/>. The wire-format string is looked up via the
/// companion <see cref="GrantTypeNames"/> class.
/// </para>
/// <para>
/// Codes 0–999 are reserved for library-defined values. Applications adding
/// custom grant types use <see cref="Create"/> at code 1000 and above.
/// </para>
/// </remarks>
[DebuggerDisplay("{GrantTypeNames.GetName(this),nq}")]
public readonly struct GrantType: IEquatable<GrantType>
{
    /// <summary>Gets the numeric code identifying this grant type.</summary>
    public int Code { get; }

    private GrantType(int code)
    {
        Code = code;
    }


    /// <summary>
    /// Authorization Code grant per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1">RFC 6749 §4.1</see>.
    /// Wire value: <c>authorization_code</c>.
    /// </summary>
    public static GrantType AuthorizationCode { get; } = new(0);

    /// <summary>
    /// Refresh Token grant per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see>.
    /// Wire value: <c>refresh_token</c>.
    /// </summary>
    public static GrantType RefreshToken { get; } = new(1);

    /// <summary>
    /// Client Credentials grant per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.4">RFC 6749 §4.4</see>.
    /// Wire value: <c>client_credentials</c>.
    /// </summary>
    public static GrantType ClientCredentials { get; } = new(2);

    /// <summary>
    /// Resource Owner Password Credentials grant per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.3">RFC 6749 §4.3</see>.
    /// Wire value: <c>password</c>.
    /// </summary>
    /// <remarks>
    /// Deprecated by OAuth 2.1 and disallowed by FAPI 2.0. Present here for
    /// completeness when interoperating with legacy authorization servers.
    /// </remarks>
    public static GrantType Password { get; } = new(3);

    /// <summary>
    /// Device Authorization Grant per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8628">RFC 8628</see>.
    /// Wire value: <c>urn:ietf:params:oauth:grant-type:device_code</c>.
    /// </summary>
    public static GrantType DeviceCode { get; } = new(4);

    /// <summary>
    /// Token Exchange per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693">RFC 8693</see>.
    /// Wire value: <c>urn:ietf:params:oauth:grant-type:token-exchange</c>.
    /// </summary>
    public static GrantType TokenExchange { get; } = new(5);

    /// <summary>
    /// JWT Bearer Token grant per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.1">RFC 7523 §2.1</see>.
    /// Wire value: <c>urn:ietf:params:oauth:grant-type:jwt-bearer</c>.
    /// </summary>
    public static GrantType JwtBearer { get; } = new(6);

    /// <summary>
    /// SAML 2.0 Bearer Assertion grant per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7522#section-2.1">RFC 7522 §2.1</see>.
    /// Wire value: <c>urn:ietf:params:oauth:grant-type:saml2-bearer</c>.
    /// </summary>
    public static GrantType Saml2Bearer { get; } = new(7);

    /// <summary>
    /// CIBA grant per
    /// <see href="https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html">CIBA Core 1.0</see>.
    /// Wire value: <c>urn:openid:params:grant-type:ciba</c>.
    /// </summary>
    public static GrantType Ciba { get; } = new(8);

    /// <summary>
    /// Pre-Authorized Code grant per
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI</see>.
    /// Wire value: <c>urn:ietf:params:oauth:grant-type:pre-authorized_code</c>.
    /// </summary>
    public static GrantType PreAuthorizedCode { get; } = new(9);


    private static readonly List<GrantType> grantTypes =
    [
        AuthorizationCode,
        RefreshToken,
        ClientCredentials,
        Password,
        DeviceCode,
        TokenExchange,
        JwtBearer,
        Saml2Bearer,
        Ciba,
        PreAuthorizedCode
    ];

    /// <summary>Gets all registered grant type values including any custom ones.</summary>
    public static IReadOnlyList<GrantType> GrantTypes => grantTypes.AsReadOnly();


    /// <summary>
    /// Creates a new <see cref="GrantType"/> for an application-defined grant type.
    /// </summary>
    /// <param name="code">
    /// The numeric code identifying the grant type. Use values <strong>1000 and
    /// above</strong> to avoid collisions with future library additions.
    /// </param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="code"/> is already registered.</exception>
    public static GrantType Create(int code)
    {
        for(int i = 0; i < grantTypes.Count; ++i)
        {
            if(grantTypes[i].Code == code)
            {
                throw new ArgumentException(
                    $"A grant type with code {code} is already registered.", nameof(code));
            }
        }

        GrantType newGrantType = new(code);
        grantTypes.Add(newGrantType);
        return newGrantType;
    }


    /// <inheritdoc/>
    public override string ToString() => GrantTypeNames.GetName(this);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(GrantType other) => Code == other.Code;


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is GrantType other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(GrantType left, GrantType right) => left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(GrantType left, GrantType right) => !left.Equals(right);
}
