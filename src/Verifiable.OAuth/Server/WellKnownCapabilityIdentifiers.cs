using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Library-shipped <see cref="CapabilityIdentifier"/> instances for every
/// protocol the library implements. URN scheme:
/// <c>urn:verifiable:capability:&lt;namespace&gt;:&lt;name&gt;</c> where
/// <c>&lt;namespace&gt;</c> groups related capabilities.
/// </summary>
/// <remarks>
/// <para>
/// One static property per identifier. Property names carry the namespace
/// prefix (<c>OAuth*</c>, <c>Oidc*</c>, <c>Federation*</c>, <c>Vc*</c>,
/// <c>AuthZen*</c>) so capability references at the call site disambiguate
/// without requiring a fully-qualified URN. The URN itself is the canonical
/// identity used in equality, hashing, and Discovery emission.
/// </para>
/// <para>
/// Downstream tracks add their own well-known classes (e.g.
/// <c>WellKnownFederationCapabilityIdentifiers</c> for Federation 1.0's
/// sub-capabilities) rather than extending this class. The closed set on
/// this class is "what the library shipped at this point in time"; track-
/// specific additions live near their consuming code.
/// </para>
/// </remarks>
[DebuggerDisplay("WellKnownCapabilityIdentifiers")]
public static class WellKnownCapabilityIdentifiers
{
    //OAuth 2.0 core grant types.

    /// <summary>
    /// Authorization Code grant per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1">RFC 6749 §4.1</see>.
    /// </summary>
    public static CapabilityIdentifier OAuthAuthorizationCode { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oauth:authorization_code");

    /// <summary>
    /// Client Credentials grant per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.4">RFC 6749 §4.4</see>.
    /// </summary>
    public static CapabilityIdentifier OAuthClientCredentials { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oauth:client_credentials");

    /// <summary>
    /// Refresh Token grant per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see>.
    /// </summary>
    public static CapabilityIdentifier OAuthRefreshToken { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oauth:refresh_token");

    /// <summary>
    /// Token Exchange per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693">RFC 8693</see>.
    /// </summary>
    public static CapabilityIdentifier OAuthTokenExchange { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oauth:token_exchange");


    //OAuth 2.0 extensions.

    /// <summary>
    /// Pushed Authorization Requests per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126</see>.
    /// </summary>
    public static CapabilityIdentifier OAuthPushedAuthorization { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oauth:par");

    /// <summary>
    /// JWT-Secured Authorization Requests per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see>.
    /// </summary>
    public static CapabilityIdentifier OAuthJwtSecuredAuthorizationRequest { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oauth:jar");

    /// <summary>
    /// Token Revocation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009">RFC 7009</see>.
    /// </summary>
    public static CapabilityIdentifier OAuthTokenRevocation { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oauth:revocation");

    /// <summary>
    /// Token Introspection per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662">RFC 7662</see>.
    /// </summary>
    public static CapabilityIdentifier OAuthTokenIntrospection { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oauth:introspection");

    /// <summary>
    /// OID4VCI 1.0 §7 Nonce Endpoint — issues the <c>c_nonce</c> challenge used in the
    /// proof of possession of key material in a Credential Request.
    /// </summary>
    public static CapabilityIdentifier Oid4VciNonceEndpoint { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oid4vci:nonce");

    /// <summary>
    /// OID4VCI 1.0 §6 Pre-Authorized Code grant — exchanges a
    /// <c>pre-authorized_code</c> (and optional <c>tx_code</c>) for an access token at
    /// the token endpoint, the grant the Credential Issuer hands the Wallet in a
    /// Credential Offer.
    /// </summary>
    public static CapabilityIdentifier Oid4VciPreAuthorizedCodeGrant { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oid4vci:pre_authorized_code");

    /// <summary>
    /// OID4VCI 1.0 §8 Credential Endpoint — issues one or more Credentials of the same
    /// Credential Configuration on presentation of a valid access token and holder
    /// proof(s) of possession.
    /// </summary>
    public static CapabilityIdentifier Oid4VciCredentialEndpoint { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oid4vci:credential");

    /// <summary>
    /// OID4VCI 1.0 §12.2 Credential Issuer Metadata — serves the
    /// <c>/.well-known/openid-credential-issuer</c> document describing the issuer's
    /// <c>credential_endpoint</c> and <c>credential_configurations_supported</c>.
    /// </summary>
    public static CapabilityIdentifier Oid4VciCredentialIssuerMetadata { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oid4vci:credential_issuer_metadata");

    /// <summary>
    /// OID4VCI 1.0 §9 Deferred Credential Endpoint — delivers Credentials whose issuance the
    /// Credential Endpoint deferred with a <c>transaction_id</c>, on presentation of a valid
    /// access token.
    /// </summary>
    public static CapabilityIdentifier Oid4VciDeferredCredentialEndpoint { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oid4vci:deferred_credential");

    /// <summary>
    /// OID4VCI 1.0 §11 Notification Endpoint — receives the Wallet's issuance-outcome events
    /// per <c>notification_id</c>, on presentation of a valid access token.
    /// </summary>
    public static CapabilityIdentifier Oid4VciNotificationEndpoint { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oid4vci:notification");

    /// <summary>
    /// OID4VCI 1.0 §4.1.3 Credential Offer Endpoint — serves a stored Credential Offer object
    /// by its id, the resource the <c>credential_offer_uri</c> in a by-reference deep link
    /// points the Wallet at. Unprotected and unsigned (§4.1.3).
    /// </summary>
    public static CapabilityIdentifier Oid4VciCredentialOfferEndpoint { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oid4vci:credential_offer");

    /// <summary>
    /// Global Token Revocation per
    /// <see href="https://datatracker.ietf.org/doc/draft-parecki-oauth-global-token-revocation/">draft-parecki-oauth-global-token-revocation</see>
    /// — an authenticated command that revokes all of a subject's tokens by
    /// RFC 9493 Subject Identifier, regardless of the authentication protocol or
    /// whether the user is present.
    /// </summary>
    public static CapabilityIdentifier OAuthGlobalTokenRevocation { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oauth:global_token_revocation");

    /// <summary>
    /// OpenID Connect RP-Initiated Logout 1.0 — the <c>end_session_endpoint</c> an RP
    /// redirects the User Agent to in order to terminate the End-User's session, per
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html">OIDC RP-Initiated Logout 1.0</see>.
    /// </summary>
    public static CapabilityIdentifier OidcRpInitiatedLogout { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oidc:rp_initiated_logout");

    /// <summary>
    /// OpenID Connect Back-Channel Logout 1.0 — the OP delivers a signed <c>logout_token</c>
    /// to each registered RP's <c>backchannel_logout_uri</c> when a session ends, per
    /// <see href="https://openid.net/specs/openid-connect-backchannel-1_0.html">OIDC Back-Channel Logout 1.0</see>.
    /// </summary>
    public static CapabilityIdentifier OidcBackChannelLogout { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oidc:back_channel_logout");

    /// <summary>
    /// Device Authorization Grant per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8628">RFC 8628</see>.
    /// </summary>
    public static CapabilityIdentifier OAuthDeviceAuthorization { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oauth:device_authorization");

    /// <summary>
    /// Dynamic Client Registration per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591">RFC 7591</see>.
    /// </summary>
    public static CapabilityIdentifier OAuthDynamicClientRegistration { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oauth:dynamic_client_registration");

    /// <summary>
    /// JWKS endpoint per OIDC Discovery / RFC 7517.
    /// </summary>
    public static CapabilityIdentifier OAuthJwksEndpoint { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oauth:jwks");

    /// <summary>
    /// OAuth Authorization Server Metadata Discovery per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414</see>.
    /// </summary>
    public static CapabilityIdentifier OAuthDiscoveryEndpoint { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oauth:discovery");

    /// <summary>
    /// Direct Authorization (non-PAR Authorization request) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>.
    /// </summary>
    public static CapabilityIdentifier OAuthDirectAuthorization { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oauth:direct_authorization");


    //OpenID Connect.

    /// <summary>
    /// OpenID Connect Core 1.0 per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html">OIDC Core 1.0</see>.
    /// </summary>
    public static CapabilityIdentifier OidcOpenIdConnect { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oidc:openid_connect");

    /// <summary>
    /// UserInfo endpoint per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OIDC Core §5.3</see>.
    /// </summary>
    public static CapabilityIdentifier OidcUserInfo { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oidc:userinfo");

    /// <summary>
    /// Session Management 1.0 per
    /// <see href="https://openid.net/specs/openid-connect-session-1_0.html">OIDC Session Management 1.0</see>.
    /// </summary>
    public static CapabilityIdentifier OidcSessionManagement { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oidc:session_management");


    //OpenID Federation. Phase B introduces sub-capabilities under this
    //namespace; this entry is the umbrella role.

    /// <summary>
    /// OpenID Federation 1.0 per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html">OpenID Federation 1.0</see>.
    /// </summary>
    public static CapabilityIdentifier FederationBase { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:federation:base");


    //Verifiable Credentials.

    /// <summary>
    /// OID4VP — OpenID for Verifiable Presentations 1.0.
    /// </summary>
    public static CapabilityIdentifier VcVerifiablePresentation { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:vc:verifiable_presentation");

    /// <summary>
    /// SIOPv2 — the Self-Issued OpenID Provider v2 Relying Party flow. Enables the
    /// request-preparation and Self-Issued ID Token response endpoints by which this
    /// Authorization Server, acting as the RP, requests and verifies a Self-Issued ID Token.
    /// </summary>
    public static CapabilityIdentifier SiopSelfIssuedOp { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:siop:self_issued_op");

    /// <summary>
    /// OID4VCI — OpenID for Verifiable Credential Issuance.
    /// </summary>
    public static CapabilityIdentifier VcVerifiableCredentialIssuance { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:vc:verifiable_credential_issuance");


    //AuthZEN — authorization API surface.

    /// <summary>
    /// AuthZEN authorization API.
    /// </summary>
    public static CapabilityIdentifier AuthZenAuthorizationApi { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:authzen:base");


    //Shared Signals — SSF/CAEP/RISC event-stream surface.

    /// <summary>
    /// OpenID Shared Signals Framework 1.0 Transmitter: serves the
    /// <c>/.well-known/ssf-configuration</c> Transmitter Configuration Metadata
    /// document (and, as the transmitter surface grows, the Stream Management
    /// API endpoints).
    /// </summary>
    public static CapabilityIdentifier SsfTransmitter { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:ssf:transmitter");

    /// <summary>
    /// OAuth 2.0 Protected Resource Metadata (RFC 9728): serves the
    /// <c>/.well-known/oauth-protected-resource</c> metadata document for a
    /// protected resource co-located with the server.
    /// </summary>
    public static CapabilityIdentifier OAuthProtectedResourceMetadata { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:oauth:protected_resource_metadata");
}
