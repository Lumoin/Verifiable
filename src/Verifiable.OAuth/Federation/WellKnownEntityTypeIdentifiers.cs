using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Library-shipped <see cref="EntityTypeIdentifier"/> instances for every
/// Entity Type defined in OpenID Federation 1.0 and Federation Wallet 1.0.
/// </summary>
/// <remarks>
/// <para>
/// Six standard identifiers per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-5.1">Federation §5.1</see>:
/// <see cref="FederationEntity"/>, <see cref="OpenIdRelyingParty"/>,
/// <see cref="OpenIdProvider"/>, <see cref="OAuthAuthorizationServer"/>,
/// <see cref="OAuthClient"/>, <see cref="OAuthResource"/>. Three additional
/// identifiers per
/// <see href="https://openid.net/specs/openid-federation-wallet-1_0.html#section-6">Federation Wallet 1.0 §6</see>:
/// <see cref="OpenIdWalletProvider"/>, <see cref="OpenIdCredentialIssuer"/>,
/// <see cref="OpenIdCredentialVerifier"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("WellKnownEntityTypeIdentifiers")]
public static class WellKnownEntityTypeIdentifiers
{
    //OpenID Federation 1.0 §5.1.

    /// <summary>
    /// <c>federation_entity</c> — every Federation entity has this type;
    /// the metadata under this key carries Federation-specific endpoints
    /// (<c>federation_fetch_endpoint</c>, etc.).
    /// </summary>
    public static readonly EntityTypeIdentifier FederationEntity = new("federation_entity");

    /// <summary>
    /// <c>openid_relying_party</c> — OpenID Connect Relying Party.
    /// </summary>
    public static readonly EntityTypeIdentifier OpenIdRelyingParty = new("openid_relying_party");

    /// <summary>
    /// <c>openid_provider</c> — OpenID Connect Provider.
    /// </summary>
    public static readonly EntityTypeIdentifier OpenIdProvider = new("openid_provider");

    /// <summary>
    /// <c>oauth_authorization_server</c> — OAuth 2.0 Authorization Server.
    /// </summary>
    public static readonly EntityTypeIdentifier OAuthAuthorizationServer = new("oauth_authorization_server");

    /// <summary>
    /// <c>oauth_client</c> — OAuth 2.0 Client.
    /// </summary>
    public static readonly EntityTypeIdentifier OAuthClient = new("oauth_client");

    /// <summary>
    /// <c>oauth_resource</c> — OAuth 2.0 Protected Resource.
    /// </summary>
    public static readonly EntityTypeIdentifier OAuthResource = new("oauth_resource");


    //OpenID Federation Wallet 1.0 §6.

    /// <summary>
    /// <c>openid_wallet_provider</c> — entity that provisions and attests
    /// to wallet instances per Wallet 1.0 §6.1.
    /// </summary>
    public static readonly EntityTypeIdentifier OpenIdWalletProvider = new("openid_wallet_provider");

    /// <summary>
    /// <c>openid_credential_issuer</c> — OID4VCI Credential Issuer per
    /// Wallet 1.0 §6.2.
    /// </summary>
    public static readonly EntityTypeIdentifier OpenIdCredentialIssuer = new("openid_credential_issuer");

    /// <summary>
    /// <c>openid_credential_verifier</c> — OID4VP Verifier per
    /// Wallet 1.0 §6.3. Distinct from <see cref="OpenIdRelyingParty"/>;
    /// Verifiers operate on Verifiable Presentations rather than ID Tokens.
    /// </summary>
    public static readonly EntityTypeIdentifier OpenIdCredentialVerifier = new("openid_credential_verifier");
}
