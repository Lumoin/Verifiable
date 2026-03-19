using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Identifies a capability that an Authorization Server can offer to a registered client.
/// </summary>
/// <remarks>
/// <para>
/// Follows the same extensible "dynamic enum" pattern as
/// <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/>. Predefined values cover
/// all standard OAuth 2.0, OpenID Connect, and related protocol capabilities. Custom
/// capabilities can be added at application startup using <see cref="Create"/>.
/// </para>
/// <para>
/// Values are compared by their numeric code, not by reference, so instances are safe
/// to use as dictionary keys and in sets.
/// </para>
/// <para>
/// Use code values above 1000 for application-defined capabilities to avoid collisions
/// with future library additions.
/// </para>
/// </remarks>
[DebuggerDisplay("{ServerCapabilityNames.GetName(this),nq}")]
public readonly struct ServerCapabilityName: IEquatable<ServerCapabilityName>
{
    /// <summary>Gets the numeric code for this capability.</summary>
    public int Code { get; }

    private ServerCapabilityName(int code)
    {
        Code = code;
    }


    //OAuth 2.0 core grant types — codes 0–9.

    /// <summary>
    /// Authorization Code grant per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1">RFC 6749 §4.1</see>.
    /// </summary>
    public static ServerCapabilityName AuthorizationCode { get; } = new(0);

    /// <summary>
    /// Client Credentials grant per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.4">RFC 6749 §4.4</see>.
    /// </summary>
    public static ServerCapabilityName ClientCredentials { get; } = new(1);

    /// <summary>
    /// Refresh Token grant per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see>.
    /// </summary>
    public static ServerCapabilityName RefreshToken { get; } = new(2);

    /// <summary>
    /// Token Exchange per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693">RFC 8693</see>.
    /// Used for agent delegation and impersonation flows.
    /// </summary>
    public static ServerCapabilityName TokenExchange { get; } = new(3);


    //OAuth 2.0 extensions — codes 10–29.

    /// <summary>
    /// Pushed Authorization Requests per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126</see>.
    /// </summary>
    public static ServerCapabilityName PushedAuthorization { get; } = new(10);

    /// <summary>
    /// JWT-Secured Authorization Requests per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see>.
    /// </summary>
    public static ServerCapabilityName JwtSecuredAuthorizationRequest { get; } = new(11);

    /// <summary>
    /// Token Revocation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009">RFC 7009</see>.
    /// </summary>
    public static ServerCapabilityName TokenRevocation { get; } = new(12);

    /// <summary>
    /// Token Introspection per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662">RFC 7662</see>.
    /// </summary>
    public static ServerCapabilityName TokenIntrospection { get; } = new(13);

    /// <summary>
    /// Device Authorization Grant per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8628">RFC 8628</see>.
    /// </summary>
    public static ServerCapabilityName DeviceAuthorization { get; } = new(14);

    /// <summary>
    /// Dynamic Client Registration per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591">RFC 7591</see> and
    /// management per <see href="https://www.rfc-editor.org/rfc/rfc7592">RFC 7592</see>.
    /// </summary>
    public static ServerCapabilityName DynamicClientRegistration { get; } = new(15);

    /// <summary>
    /// JWKS endpoint — serves the JSON Web Key Set for this registration per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5">RFC 7517 §5</see>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Independent of token-issuance capabilities. Any registration that needs to
    /// publish its public signing key — including OID4VP Verifiers, OpenID Federation
    /// participants, and agent clients — can enable this capability without also
    /// enabling <see cref="AuthorizationCode"/> or <see cref="ClientCredentials"/>.
    /// </para>
    /// <para>
    /// The <see cref="AuthorizationServerOptions.BuildJwksDocumentAsync"/> delegate
    /// decides which keys to include based on the <see cref="ClientRegistration"/> and
    /// the per-request context bag. The delegate can return different key sets for
    /// different callers — for example, hiding keys that are in a rotation grace period
    /// for external callers while returning them for internal monitoring.
    /// </para>
    /// </remarks>
    public static ServerCapabilityName JwksEndpoint { get; } = new(16);

    /// <summary>
    /// Discovery endpoint — serves the per-registration OpenID Connect Discovery
    /// document at <c>/connect/{segment}/.well-known/openid-configuration</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Independent of token-issuance capabilities. Any registration that needs to
    /// advertise its endpoints via a discovery document can enable this capability.
    /// The discovery document lists only the endpoints that are active for this
    /// registration based on its <see cref="ClientRegistration.AllowedCapabilities"/>
    /// and the per-request <see cref="AuthorizationServerOptions.IsCapabilityAllowedAsync"/>
    /// delegate result.
    /// </para>
    /// </remarks>
    public static ServerCapabilityName DiscoveryEndpoint { get; } = new(17);

    /// <summary>
    /// Direct Authorization Code flow with PKCE per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749">RFC 6749</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636">RFC 7636</see> — the
    /// authorization endpoint accepts parameters directly without a prior Pushed
    /// Authorization Request.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Registrations that require PAR for all flows must not include this capability.
    /// Registrations that support both PAR and direct authorization include both
    /// <see cref="PushedAuthorization"/> and this capability.
    /// </para>
    /// </remarks>
    public static ServerCapabilityName DirectAuthorization { get; } = new(18);


    //OpenID Connect — codes 30–39.

    /// <summary>
    /// OpenID Connect authentication layer per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html">OIDC Core 1.0</see>.
    /// Enables ID Token issuance alongside access tokens.
    /// </summary>
    public static ServerCapabilityName OpenIdConnect { get; } = new(30);

    /// <summary>
    /// OpenID Connect UserInfo endpoint per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OIDC Core §5.3</see>.
    /// </summary>
    public static ServerCapabilityName UserInfo { get; } = new(31);

    /// <summary>
    /// OpenID Connect Session Management per
    /// <see href="https://openid.net/specs/openid-connect-session-1_0.html">OIDC Session 1.0</see>.
    /// </summary>
    public static ServerCapabilityName SessionManagement { get; } = new(32);


    //Federation and trust — codes 40–49.

    /// <summary>
    /// OpenID Federation 1.0 per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html">OpenID Federation 1.0</see>.
    /// Enables cross-tenant and cross-organization trust chain walking.
    /// </summary>
    public static ServerCapabilityName OpenIdFederation { get; } = new(40);


    //Verifiable Credentials — codes 50–59.

    /// <summary>
    /// OID4VP — OpenID for Verifiable Presentations per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0</see>.
    /// </summary>
    public static ServerCapabilityName VerifiablePresentation { get; } = new(50);

    /// <summary>
    /// OID4VCI — OpenID for Verifiable Credential Issuance per
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI 1.0</see>.
    /// </summary>
    public static ServerCapabilityName VerifiableCredentialIssuance { get; } = new(51);


    //Authorization API — codes 60–69.

    /// <summary>
    /// AuthZEN Authorization API 1.0 per
    /// <see href="https://openid.net/specs/authorization-api-1_0.html">Authorization API 1.0</see>.
    /// Enables this server to act as a Policy Decision Point.
    /// </summary>
    public static ServerCapabilityName AuthorizationApi { get; } = new(60);


    private static readonly List<ServerCapabilityName> knownCapabilities =
    [
        AuthorizationCode, ClientCredentials, RefreshToken, TokenExchange,
        PushedAuthorization, JwtSecuredAuthorizationRequest, TokenRevocation,
        TokenIntrospection, DeviceAuthorization, DynamicClientRegistration,
        JwksEndpoint, DiscoveryEndpoint, DirectAuthorization,
        OpenIdConnect, UserInfo, SessionManagement,
        OpenIdFederation,
        VerifiablePresentation, VerifiableCredentialIssuance,
        AuthorizationApi
    ];


    /// <summary>Gets all registered capability values including any custom ones.</summary>
    public static IReadOnlyList<ServerCapabilityName> KnownCapabilities =>
        knownCapabilities.AsReadOnly();


    /// <summary>
    /// Creates a new capability value for application-defined capabilities.
    /// </summary>
    /// <param name="code">
    /// The unique numeric code. Use values above 1000 to avoid collisions with
    /// future library additions.
    /// </param>
    /// <returns>The newly created capability.</returns>
    /// <exception cref="ArgumentException">Thrown when the code already exists.</exception>
    /// <remarks>
    /// Not thread-safe. Call only during application startup before concurrent access begins.
    /// </remarks>
    public static ServerCapabilityName Create(int code)
    {
        for(int i = 0; i < knownCapabilities.Count; ++i)
        {
            if(knownCapabilities[i].Code == code)
            {
                throw new ArgumentException(
                    $"A capability with code {code} already exists.", nameof(code));
            }
        }

        var capability = new ServerCapabilityName(code);
        knownCapabilities.Add(capability);
        return capability;
    }


    /// <inheritdoc/>
    public override string ToString() => ServerCapabilityNames.GetName(this);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(ServerCapabilityName other) => Code == other.Code;


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is ServerCapabilityName other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(ServerCapabilityName left, ServerCapabilityName right) =>
        left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(ServerCapabilityName left, ServerCapabilityName right) =>
        !left.Equals(right);
}


/// <summary>
/// Provides human-readable names for <see cref="ServerCapabilityName"/> values.
/// </summary>
public static class ServerCapabilityNames
{
    /// <summary>Gets the name for the specified capability.</summary>
    public static string GetName(ServerCapabilityName capability) =>
        GetName(capability.Code);

    /// <summary>Gets the name for the specified capability code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == ServerCapabilityName.AuthorizationCode.Code =>
            nameof(ServerCapabilityName.AuthorizationCode),
        var c when c == ServerCapabilityName.ClientCredentials.Code =>
            nameof(ServerCapabilityName.ClientCredentials),
        var c when c == ServerCapabilityName.RefreshToken.Code =>
            nameof(ServerCapabilityName.RefreshToken),
        var c when c == ServerCapabilityName.TokenExchange.Code =>
            nameof(ServerCapabilityName.TokenExchange),
        var c when c == ServerCapabilityName.PushedAuthorization.Code =>
            nameof(ServerCapabilityName.PushedAuthorization),
        var c when c == ServerCapabilityName.JwtSecuredAuthorizationRequest.Code =>
            nameof(ServerCapabilityName.JwtSecuredAuthorizationRequest),
        var c when c == ServerCapabilityName.TokenRevocation.Code =>
            nameof(ServerCapabilityName.TokenRevocation),
        var c when c == ServerCapabilityName.TokenIntrospection.Code =>
            nameof(ServerCapabilityName.TokenIntrospection),
        var c when c == ServerCapabilityName.DeviceAuthorization.Code =>
            nameof(ServerCapabilityName.DeviceAuthorization),
        var c when c == ServerCapabilityName.DynamicClientRegistration.Code =>
            nameof(ServerCapabilityName.DynamicClientRegistration),
        var c when c == ServerCapabilityName.JwksEndpoint.Code =>
            nameof(ServerCapabilityName.JwksEndpoint),
        var c when c == ServerCapabilityName.DiscoveryEndpoint.Code =>
            nameof(ServerCapabilityName.DiscoveryEndpoint),
        var c when c == ServerCapabilityName.DirectAuthorization.Code =>
            nameof(ServerCapabilityName.DirectAuthorization),
        var c when c == ServerCapabilityName.OpenIdConnect.Code =>
            nameof(ServerCapabilityName.OpenIdConnect),
        var c when c == ServerCapabilityName.UserInfo.Code =>
            nameof(ServerCapabilityName.UserInfo),
        var c when c == ServerCapabilityName.SessionManagement.Code =>
            nameof(ServerCapabilityName.SessionManagement),
        var c when c == ServerCapabilityName.OpenIdFederation.Code =>
            nameof(ServerCapabilityName.OpenIdFederation),
        var c when c == ServerCapabilityName.VerifiablePresentation.Code =>
            nameof(ServerCapabilityName.VerifiablePresentation),
        var c when c == ServerCapabilityName.VerifiableCredentialIssuance.Code =>
            nameof(ServerCapabilityName.VerifiableCredentialIssuance),
        var c when c == ServerCapabilityName.AuthorizationApi.Code =>
            nameof(ServerCapabilityName.AuthorizationApi),
        _ => $"Custom({code})"
    };
}
