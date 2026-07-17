using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Identifies the client authentication method used when calling token,
/// revocation, introspection, or registration-management endpoints. Carried
/// on a client-side <see cref="ClientRegistration.AuthenticationMethod"/>
/// slot and emitted as the <c>token_endpoint_auth_method</c> metadata field.
/// </summary>
/// <remarks>
/// <para>
/// Follows the dynamic-enum pattern shared with <see cref="GrantType"/>.
/// Wire-format strings are owned by the companion
/// <see cref="ClientAuthenticationMethodNames"/> class.
/// </para>
/// <para>
/// The canonical values cover the methods defined in OAuth 2.0, OpenID
/// Connect Core 1.0 §9, RFC 7523, RFC 8705 (mTLS), the OAuth attestation-based
/// client authentication draft, and the OAuth SPIFFE client authentication
/// draft. Codes 0–999 are reserved for library-defined values.
/// </para>
/// </remarks>
[DebuggerDisplay("{ClientAuthenticationMethodNames.GetName(this),nq}")]
public readonly struct ClientAuthenticationMethod: IEquatable<ClientAuthenticationMethod>
{
    /// <summary>Gets the numeric code identifying this authentication method.</summary>
    public int Code { get; }

    private ClientAuthenticationMethod(int code)
    {
        Code = code;
    }


    /// <summary>
    /// Public client per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication">OIDC Core §9</see>.
    /// Wire value: <c>none</c>.
    /// </summary>
    /// <remarks>
    /// FAPI 2.0 disallows public clients on confidential surfaces. Native and
    /// browser-based applications that cannot keep a secret use this method
    /// in combination with PKCE.
    /// </remarks>
    public static ClientAuthenticationMethod None { get; } = new(0);

    /// <summary>
    /// HTTP Basic-style client secret per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1">RFC 6749 §2.3.1</see>.
    /// Wire value: <c>client_secret_basic</c>.
    /// </summary>
    public static ClientAuthenticationMethod ClientSecretBasic { get; } = new(1);

    /// <summary>
    /// Form-body client secret per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1">RFC 6749 §2.3.1</see>.
    /// Wire value: <c>client_secret_post</c>.
    /// </summary>
    public static ClientAuthenticationMethod ClientSecretPost { get; } = new(2);

    /// <summary>
    /// Symmetric JWT-based authentication per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523">RFC 7523</see> with
    /// HMAC algorithms over the client secret. Wire value:
    /// <c>client_secret_jwt</c>.
    /// </summary>
    public static ClientAuthenticationMethod ClientSecretJwt { get; } = new(3);

    /// <summary>
    /// Asymmetric JWT-based authentication per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523">RFC 7523</see> with
    /// the client's private signing key. Wire value: <c>private_key_jwt</c>.
    /// </summary>
    /// <remarks>
    /// FAPI 2.0 permits this method alongside <see cref="TlsClientAuth"/> as
    /// the two acceptable confidential-client authentication methods.
    /// </remarks>
    public static ClientAuthenticationMethod PrivateKeyJwt { get; } = new(4);

    /// <summary>
    /// PKI-bound mutual TLS per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8705#section-2.1">RFC 8705 §2.1</see>.
    /// Wire value: <c>tls_client_auth</c>.
    /// </summary>
    public static ClientAuthenticationMethod TlsClientAuth { get; } = new(5);

    /// <summary>
    /// Self-signed mutual TLS per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8705#section-2.2">RFC 8705 §2.2</see>.
    /// Wire value: <c>self_signed_tls_client_auth</c>.
    /// </summary>
    public static ClientAuthenticationMethod SelfSignedTlsClientAuth { get; } = new(6);

    /// <summary>
    /// Attestation-based client authentication per
    /// <see href="https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/">draft-ietf-oauth-attestation-based-client-auth</see>.
    /// Wire value: <c>attest_jwt_client_auth</c>.
    /// </summary>
    public static ClientAuthenticationMethod AttestJwtClientAuth { get; } = new(7);

    /// <summary>
    /// SPIFFE client authentication using a SPIFFE JWT-SVID as the
    /// <c>client_assertion</c> per
    /// <see href="https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/">draft-ietf-oauth-spiffe-client-auth</see>.
    /// Wire value: <c>spiffe_jwt</c>.
    /// </summary>
    /// <remarks>
    /// Composes naturally with OpenID Federation 1.1 — the SPIFFE bundle
    /// endpoint that publishes the verification keys is advertised through
    /// the federation entity statement's client metadata.
    /// </remarks>
    public static ClientAuthenticationMethod SpiffeJwt { get; } = new(8);


    private static List<ClientAuthenticationMethod> methods { get; } =
    [
        None,
        ClientSecretBasic,
        ClientSecretPost,
        ClientSecretJwt,
        PrivateKeyJwt,
        TlsClientAuth,
        SelfSignedTlsClientAuth,
        AttestJwtClientAuth,
        SpiffeJwt
    ];

    /// <summary>Gets all registered authentication method values including any custom ones.</summary>
    public static IReadOnlyList<ClientAuthenticationMethod> Methods => methods.AsReadOnly();


    /// <summary>
    /// Creates a new <see cref="ClientAuthenticationMethod"/> for an
    /// application-defined method.
    /// </summary>
    /// <param name="code">
    /// The numeric code identifying the method. Use values <strong>1000 and
    /// above</strong> to avoid collisions with future library additions.
    /// </param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="code"/> is already registered.</exception>
    public static ClientAuthenticationMethod Create(int code)
    {
        for(int i = 0; i < methods.Count; ++i)
        {
            if(methods[i].Code == code)
            {
                throw new ArgumentException(
                    $"A client authentication method with code {code} is already registered.", nameof(code));
            }
        }

        ClientAuthenticationMethod newMethod = new(code);
        methods.Add(newMethod);
        return newMethod;
    }


    /// <inheritdoc/>
    public override string ToString() => ClientAuthenticationMethodNames.GetName(this);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(ClientAuthenticationMethod other) => Code == other.Code;


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is ClientAuthenticationMethod other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(ClientAuthenticationMethod left, ClientAuthenticationMethod right) =>
        left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(ClientAuthenticationMethod left, ClientAuthenticationMethod right) =>
        !left.Equals(right);
}