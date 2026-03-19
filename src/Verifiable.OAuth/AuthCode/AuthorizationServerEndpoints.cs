using System;
using System.Diagnostics;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The endpoint URIs resolved from an authorization server's metadata document.
/// </summary>
/// <remarks>
/// <para>
/// Constructed by the caller after fetching and parsing the well-known metadata document
/// via <see cref="Verifiable.OAuth.WellKnownPaths"/>. The library does not perform
/// discovery itself — HTTP and JSON parsing are the caller's responsibility.
/// </para>
/// <para>
/// All URI properties are required. Optional endpoints that the authorization server may
/// or may not advertise are represented as nullable.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthorizationServerEndpoints Issuer={Issuer}")]
public sealed record AuthorizationServerEndpoints
{
    /// <summary>
    /// The authorization server's issuer identifier. Used as the base for
    /// well-known URL computation and for mix-up attack defense per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>.
    /// </summary>
    /// <remarks>
    /// The issuer identifier is compared with exact string equality per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-3.3">RFC 8414 §3.3</see>.
    /// Do not normalise or trim this value — the comparison must be byte-for-byte identical
    /// to the value in the authorization server's metadata document.
    /// </remarks>
    public required string Issuer { get; init; }

    /// <summary>
    /// The pushed authorization request endpoint URI per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.1">RFC 9126 §2.1</see>.
    /// </summary>
    public required Uri PushedAuthorizationRequestEndpoint { get; init; }

    /// <summary>
    /// The authorization endpoint URI. Used as the redirect target after PAR succeeds.
    /// </summary>
    public required Uri AuthorizationEndpoint { get; init; }

    /// <summary>
    /// The token endpoint URI for authorization code exchange and token refresh.
    /// </summary>
    public required Uri TokenEndpoint { get; init; }

    /// <summary>
    /// The token revocation endpoint URI per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009">RFC 7009</see>.
    /// <see langword="null"/> if the authorization server does not advertise one.
    /// </summary>
    public Uri? RevocationEndpoint { get; init; }

    /// <summary>
    /// The JWK Set document URI for verifying tokens issued by this server.
    /// <see langword="null"/> if the authorization server does not advertise one.
    /// </summary>
    public Uri? JwksUri { get; init; }
}