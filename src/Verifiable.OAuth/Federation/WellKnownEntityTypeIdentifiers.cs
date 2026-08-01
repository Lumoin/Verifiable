using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Library-shipped <see cref="EntityTypeIdentifier"/> instances for every
/// Entity Type defined in OpenID Federation 1.0 and Federation Wallet 1.0.
/// </summary>
/// <remarks>
/// <para>
/// The protocol-independent <see cref="FederationEntity"/> identifier is defined by
/// <see href="https://openid.net/specs/openid-federation-1_1-final.html#section-5.1.1">OpenID Federation 1.1 §5.1.1</see>.
/// The five protocol-specific identifiers — <see cref="OpenIdRelyingParty"/>, <see cref="OpenIdProvider"/>,
/// <see cref="OAuthAuthorizationServer"/>, <see cref="OAuthClient"/>, <see cref="OAuthResource"/> — moved to
/// <see href="https://openid.net/specs/openid-federation-connect-1_1-final.html#section-5.1.1">OpenID Federation Connect 1.1 §5.1.1–§5.1.5</see>
/// in the 1.1 split (they were Federation 1.0 §5.1.2–§5.1.6). Federation 1.1 §5.1 licenses the rest:
/// "Additional Entity Type Identifiers MAY be defined to support use cases for other protocols."
/// </para>
/// <para>
/// Three such additional identifiers per
/// <see href="https://openid.net/specs/openid-federation-wallet-1_0.html#section-6">Federation Wallet 1.0 §6</see>:
/// <see cref="OpenIdWalletProvider"/>, <see cref="OpenIdCredentialIssuer"/>,
/// <see cref="OpenIdCredentialVerifier"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("WellKnownEntityTypeIdentifiers")]
public static class WellKnownEntityTypeIdentifiers
{
    //federation_entity: OpenID Federation 1.1 §5.1.1; the OIDC/OAuth types: Connect-1.1 §5.1.1–§5.1.5.

    /// <summary>
    /// <c>federation_entity</c> — every Federation entity has this type;
    /// the metadata under this key carries Federation-specific endpoints
    /// (<c>federation_fetch_endpoint</c>, etc.).
    /// </summary>
    public static EntityTypeIdentifier FederationEntity { get; } = new("federation_entity");

    /// <summary>
    /// <c>openid_relying_party</c> — OpenID Connect Relying Party.
    /// </summary>
    public static EntityTypeIdentifier OpenIdRelyingParty { get; } = new("openid_relying_party");

    /// <summary>
    /// <c>openid_provider</c> — OpenID Connect Provider.
    /// </summary>
    public static EntityTypeIdentifier OpenIdProvider { get; } = new("openid_provider");

    /// <summary>
    /// <c>oauth_authorization_server</c> — OAuth 2.0 Authorization Server.
    /// </summary>
    public static EntityTypeIdentifier OAuthAuthorizationServer { get; } = new("oauth_authorization_server");

    /// <summary>
    /// <c>oauth_client</c> — OAuth 2.0 Client.
    /// </summary>
    public static EntityTypeIdentifier OAuthClient { get; } = new("oauth_client");

    /// <summary>
    /// <c>oauth_resource</c> — OAuth 2.0 Protected Resource.
    /// </summary>
    public static EntityTypeIdentifier OAuthResource { get; } = new("oauth_resource");


    //OpenID Federation Wallet 1.0 §6.

    /// <summary>
    /// <c>openid_wallet_provider</c> — entity that provisions and attests
    /// to wallet instances per Wallet 1.0 §6.1.
    /// </summary>
    public static EntityTypeIdentifier OpenIdWalletProvider { get; } = new("openid_wallet_provider");

    /// <summary>
    /// <c>openid_credential_issuer</c> — OID4VCI Credential Issuer per
    /// Wallet 1.0 §6.2.
    /// </summary>
    public static EntityTypeIdentifier OpenIdCredentialIssuer { get; } = new("openid_credential_issuer");

    /// <summary>
    /// <c>openid_credential_verifier</c> — OID4VP Verifier per
    /// Wallet 1.0 §6.3. Distinct from <see cref="OpenIdRelyingParty"/>;
    /// Verifiers operate on Verifiable Presentations rather than ID Tokens.
    /// </summary>
    public static EntityTypeIdentifier OpenIdCredentialVerifier { get; } = new("openid_credential_verifier");
}
