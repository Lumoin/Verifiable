using System.Diagnostics;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The discovered OAuth 2.0 / OpenID Connect authorization server endpoint URLs.
/// </summary>
/// <remarks>
/// <para>
/// Populated by fetching and parsing the authorization server metadata document at
/// <c>{issuer}/.well-known/openid-configuration</c> or
/// <c>{issuer}/.well-known/oauth-authorization-server</c> per
/// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414</see> and
/// <see href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery 1.0</see>.
/// </para>
/// <para>
/// Construct using object initializer syntax and supply to
/// <see cref="AuthCodeFlowOptions.Create"/> after fetching and validating the
/// well-known metadata document. The same instance is safe to share across
/// concurrent requests for the lifetime of the authorization server configuration.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthorizationServerEndpoints Issuer={Issuer}")]
public sealed class AuthorizationServerEndpoints
{
    /// <summary>
    /// The issuer identifier of the authorization server.
    /// Validated against the <c>iss</c> claim in tokens and the metadata document
    /// per <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>.
    /// </summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// The Pushed Authorization Request endpoint URI per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126</see>.
    /// </summary>
    public required Uri PushedAuthorizationRequestEndpoint { get; init; }

    /// <summary>
    /// The authorization endpoint URI per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see>.
    /// </summary>
    public required Uri AuthorizationEndpoint { get; init; }

    /// <summary>
    /// The token endpoint URI per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 §3.2</see>.
    /// </summary>
    public required Uri TokenEndpoint { get; init; }

    /// <summary>
    /// The token revocation endpoint URI per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009">RFC 7009</see>.
    /// <see langword="null"/> when the authorization server does not advertise revocation.
    /// </summary>
    public Uri? RevocationEndpoint { get; init; }

    /// <summary>
    /// The JSON Web Key Set endpoint URI per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517</see>.
    /// Used to fetch the authorization server's public keys for token verification.
    /// <see langword="null"/> when the authorization server does not advertise a JWKS endpoint.
    /// </summary>
    public Uri? JwksUri { get; init; }

    /// <summary>
    /// The token introspection endpoint URI per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662">RFC 7662</see>.
    /// <see langword="null"/> when the authorization server does not advertise introspection.
    /// </summary>
    public Uri? IntrospectionEndpoint { get; init; }
}
