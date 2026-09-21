using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Stable endpoint role identifiers used as the lookup key by
/// <see cref="Verifiable.Server.ServerIntegration.ResolveEndpointUriAsync"/>
/// and as the <see cref="ServerEndpoint.Name"/> value. The library's
/// builders construct endpoints with these names; the application's
/// <c>ResolveEndpointUriAsync</c> wiring switches on these to produce the
/// per-deployment URLs.
/// </summary>
/// <remarks>
/// <para>
/// Endpoint role is finer-grained than capability: the
/// <see cref="WellKnownCapabilityIdentifiers.OAuthAuthorizationCode"/> capability exposes
/// both <see cref="AuthCodeAuthorize"/> and <see cref="AuthCodeToken"/>,
/// which have distinct URLs. The role identifier is one-to-one with the
/// URL the application has to provide.
/// </para>
/// </remarks>
public static class WellKnownEndpointNames
{
    //AuthCode family
    /// <summary>The UTF-8 source literal of <see cref="AuthCodePar"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeParUtf8 => "AuthCode.Par"u8;

    /// <summary>The endpoint role for the pushed authorization request endpoint (<see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126</see>).</summary>
    public static string AuthCodePar { get; } = Utf8Constants.ToInternedString(AuthCodeParUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeJarPar"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeJarParUtf8 => "AuthCode.JarPar"u8;

    /// <summary>
    /// The endpoint role for a pushed authorization request whose body carries a signed
    /// Request Object, combining <see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126</see>
    /// (PAR) with <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see> (JAR).
    /// </summary>
    public static string AuthCodeJarPar { get; } = Utf8Constants.ToInternedString(AuthCodeJarParUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeAuthorize"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeAuthorizeUtf8 => "AuthCode.Authorize"u8;

    /// <summary>The endpoint role for the authorization endpoint (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see>).</summary>
    public static string AuthCodeAuthorize { get; } = Utf8Constants.ToInternedString(AuthCodeAuthorizeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeDirectAuthorize"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeDirectAuthorizeUtf8 => "AuthCode.DirectAuthorize"u8;

    /// <summary>
    /// The endpoint role for the authorization endpoint invoked directly, without a prior
    /// pushed authorization request (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see>).
    /// </summary>
    public static string AuthCodeDirectAuthorize { get; } = Utf8Constants.ToInternedString(AuthCodeDirectAuthorizeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeAuthorizeJarByValue"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeAuthorizeJarByValueUtf8 => "AuthCode.AuthorizeJarByValue"u8;

    /// <summary>
    /// The endpoint role for the authorization endpoint invoked with a by-value Request
    /// Object in the <c>request</c> parameter (<see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see>).
    /// </summary>
    public static string AuthCodeAuthorizeJarByValue { get; } = Utf8Constants.ToInternedString(AuthCodeAuthorizeJarByValueUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeRequestObjectConflict"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeRequestObjectConflictUtf8 => "AuthCode.RequestObjectConflict"u8;

    /// <summary>
    /// The endpoint role that rejects an authorization request carrying both <c>request</c>
    /// and <c>request_uri</c> (<see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 §5</see>).
    /// </summary>
    public static string AuthCodeRequestObjectConflict { get; } = Utf8Constants.ToInternedString(AuthCodeRequestObjectConflictUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeToken"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeTokenUtf8 => "AuthCode.Token"u8;

    /// <summary>The endpoint role for the token endpoint (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 §3.2</see>).</summary>
    public static string AuthCodeToken { get; } = Utf8Constants.ToInternedString(AuthCodeTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeRefreshToken"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeRefreshTokenUtf8 => "AuthCode.RefreshToken"u8;

    /// <summary>The endpoint role for the refresh-token grant on the token endpoint (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see>).</summary>
    public static string AuthCodeRefreshToken { get; } = Utf8Constants.ToInternedString(AuthCodeRefreshTokenUtf8);
    //The client_credentials grant (RFC 6749 §4.4) shares the token endpoint URL;
    //the grant_type field disambiguates, as it does for the refresh grant.
    /// <summary>The UTF-8 source literal of <see cref="ClientCredentialsToken"/>.</summary>
    public static ReadOnlySpan<byte> ClientCredentialsTokenUtf8 => "ClientCredentials.Token"u8;

    /// <summary>The endpoint role for the client credentials grant on the token endpoint (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.4">RFC 6749 §4.4</see>).</summary>
    public static string ClientCredentialsToken { get; } = Utf8Constants.ToInternedString(ClientCredentialsTokenUtf8);

    //The token-exchange grant (RFC 8693) shares the token endpoint URL; the grant_type
    //field disambiguates, as it does for the refresh and client_credentials grants.
    /// <summary>The UTF-8 source literal of <see cref="TokenExchangeToken"/>.</summary>
    public static ReadOnlySpan<byte> TokenExchangeTokenUtf8 => "TokenExchange.Token"u8;

    /// <summary>The endpoint role for the token-exchange grant on the token endpoint (<see href="https://www.rfc-editor.org/rfc/rfc8693">RFC 8693</see>).</summary>
    public static string TokenExchangeToken { get; } = Utf8Constants.ToInternedString(TokenExchangeTokenUtf8);

    //The JWT Bearer authorization grant (RFC 7523 §2.1/§3.1) shares the token endpoint URL;
    //the grant_type field disambiguates, as it does for the refresh, client_credentials, and
    //token-exchange grants.
    /// <summary>The UTF-8 source literal of <see cref="JwtBearerToken"/>.</summary>
    public static ReadOnlySpan<byte> JwtBearerTokenUtf8 => "JwtBearer.Token"u8;

    /// <summary>The endpoint role for the JWT Bearer authorization grant on the token endpoint (<see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.1">RFC 7523 §2.1</see>).</summary>
    public static string JwtBearerToken { get; } = Utf8Constants.ToInternedString(JwtBearerTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeRevoke"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeRevokeUtf8 => "AuthCode.Revoke"u8;

    /// <summary>The endpoint role for the token revocation endpoint (<see href="https://www.rfc-editor.org/rfc/rfc7009">RFC 7009</see>).</summary>
    public static string AuthCodeRevoke { get; } = Utf8Constants.ToInternedString(AuthCodeRevokeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeIntrospect"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeIntrospectUtf8 => "AuthCode.Introspect"u8;

    /// <summary>The endpoint role for the token introspection endpoint (<see href="https://www.rfc-editor.org/rfc/rfc7662">RFC 7662</see>).</summary>
    public static string AuthCodeIntrospect { get; } = Utf8Constants.ToInternedString(AuthCodeIntrospectUtf8);

    //Global Token Revocation (draft-parecki-oauth-global-token-revocation): an
    //authenticated JSON command that revokes all of a subject's tokens by
    //RFC 9493 Subject Identifier.
    /// <summary>The UTF-8 source literal of <see cref="GlobalTokenRevocation"/>.</summary>
    public static ReadOnlySpan<byte> GlobalTokenRevocationUtf8 => "GlobalTokenRevocation"u8;

    /// <summary>
    /// The endpoint role for the subject-scoped global token revocation command
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-parecki-oauth-global-token-revocation">draft-parecki-oauth-global-token-revocation</see>).
    /// </summary>
    public static string GlobalTokenRevocation { get; } = Utf8Constants.ToInternedString(GlobalTokenRevocationUtf8);

    //OID4VP family
    /// <summary>The UTF-8 source literal of <see cref="Oid4VpPar"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VpParUtf8 => "Oid4Vp.Par"u8;

    /// <summary>
    /// The endpoint role for the pushed authorization request endpoint of an OpenID4VP
    /// presentation request (<see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID4VP 1.0</see>).
    /// </summary>
    public static string Oid4VpPar { get; } = Utf8Constants.ToInternedString(Oid4VpParUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Oid4VpJarRequest"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VpJarRequestUtf8 => "Oid4Vp.JarRequest"u8;

    /// <summary>
    /// The endpoint role the Wallet dereferences by HTTP GET to fetch a signed OpenID4VP
    /// Request Object by reference (<see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID4VP 1.0</see>).
    /// </summary>
    public static string Oid4VpJarRequest { get; } = Utf8Constants.ToInternedString(Oid4VpJarRequestUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Oid4VpDirectPost"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VpDirectPostUtf8 => "Oid4Vp.DirectPost"u8;

    /// <summary>
    /// The endpoint role that receives the Wallet's <c>direct_post</c> Authorization Response
    /// (<see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID4VP 1.0</see>).
    /// </summary>
    public static string Oid4VpDirectPost { get; } = Utf8Constants.ToInternedString(Oid4VpDirectPostUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SiopRequestObject"/>.</summary>
    public static ReadOnlySpan<byte> SiopRequestObjectUtf8 => "Siop.RequestObject"u8;

    /// <summary>The SIOPv2 RP-internal request-preparation endpoint (the PAR-equivalent that starts the flow).</summary>
    public static string SiopRequestObject { get; } = Utf8Constants.ToInternedString(SiopRequestObjectUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SiopRequestObjectByReference"/>.</summary>
    public static ReadOnlySpan<byte> SiopRequestObjectByReferenceUtf8 => "Siop.RequestObjectByReference"u8;

    /// <summary>
    /// The SIOPv2 §9 signed Request Object endpoint served at the <c>request_uri</c>. The Wallet
    /// dereferences this URL with HTTP GET to fetch the signed Request Object (the SIOP parallel of
    /// the OID4VP JAR-fetch endpoint <see cref="Oid4VpJarRequest"/>).
    /// </summary>
    public static string SiopRequestObjectByReference { get; } = Utf8Constants.ToInternedString(SiopRequestObjectByReferenceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SiopResponse"/>.</summary>
    public static ReadOnlySpan<byte> SiopResponseUtf8 => "Siop.Response"u8;

    /// <summary>The SIOPv2 §10.2 Authorization Response endpoint that receives the Wallet's <c>id_token</c> POST.</summary>
    public static string SiopResponse { get; } = Utf8Constants.ToInternedString(SiopResponseUtf8);

    //Metadata family
    /// <summary>The UTF-8 source literal of <see cref="MetadataJwks"/>.</summary>
    public static ReadOnlySpan<byte> MetadataJwksUtf8 => "Metadata.Jwks"u8;

    /// <summary>The endpoint role for the JWK Set endpoint published as <c>jwks_uri</c> (<see href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517</see>).</summary>
    public static string MetadataJwks { get; } = Utf8Constants.ToInternedString(MetadataJwksUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MetadataDiscovery"/>.</summary>
    public static ReadOnlySpan<byte> MetadataDiscoveryUtf8 => "Metadata.Discovery"u8;

    /// <summary>
    /// The endpoint role for the OpenID Connect discovery document published at
    /// <c>/.well-known/openid-configuration</c> (<see href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">OpenID Connect Discovery 1.0 §4</see>).
    /// </summary>
    public static string MetadataDiscovery { get; } = Utf8Constants.ToInternedString(MetadataDiscoveryUtf8);

    //OAuth 2.0 Authorization Server Metadata (RFC 8414 §3): the same discovery
    //document published at the default well-known location formed by INSERTING
    // /.well-known/oauth-authorization-server between the host component and the
    //path component of the issuer identifier (the path-bearing rule, distinct
    //from the appended openid-configuration mount). RFC 8414 §3.1 permits the
    //same metadata at multiple well-known locations, so this role is a second
    //mount of the body MetadataDiscovery serves.
    /// <summary>The UTF-8 source literal of <see cref="MetadataOAuthAuthorizationServer"/>.</summary>
    public static ReadOnlySpan<byte> MetadataOAuthAuthorizationServerUtf8 => "Metadata.OAuthAuthorizationServer"u8;

    /// <summary>
    /// The endpoint role for the second mount of the discovery document at
    /// <c>/.well-known/oauth-authorization-server</c> (<see href="https://www.rfc-editor.org/rfc/rfc8414#section-3">RFC 8414 §3</see>).
    /// </summary>
    public static string MetadataOAuthAuthorizationServer { get; } = Utf8Constants.ToInternedString(MetadataOAuthAuthorizationServerUtf8);

    //Federation family
    /// <summary>The UTF-8 source literal of <see cref="FederationEntityConfiguration"/>.</summary>
    public static ReadOnlySpan<byte> FederationEntityConfigurationUtf8 => "Federation.EntityConfiguration"u8;

    /// <summary>
    /// The endpoint role for the Entity Configuration a federation participant serves about
    /// itself (<see href="https://openid.net/specs/openid-federation-1_0.html#section-8">OpenID Federation 1.0 §8</see>).
    /// </summary>
    public static string FederationEntityConfiguration { get; } = Utf8Constants.ToInternedString(FederationEntityConfigurationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FederationFetch"/>.</summary>
    public static ReadOnlySpan<byte> FederationFetchUtf8 => "Federation.Fetch"u8;

    /// <summary>
    /// The endpoint role for a Federation Entity's Fetch Endpoint, which returns a Subordinate
    /// Statement about an immediate subordinate (<see href="https://openid.net/specs/openid-federation-1_0.html#section-8.1">OpenID Federation 1.0 §8.1</see>).
    /// </summary>
    public static string FederationFetch { get; } = Utf8Constants.ToInternedString(FederationFetchUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FederationList"/>.</summary>
    public static ReadOnlySpan<byte> FederationListUtf8 => "Federation.List"u8;

    /// <summary>
    /// The endpoint role for a Federation Entity's Subordinate Listing Endpoint, which
    /// enumerates immediate subordinates (<see href="https://openid.net/specs/openid-federation-1_0.html#section-8.2">OpenID Federation 1.0 §8.2</see>).
    /// </summary>
    public static string FederationList { get; } = Utf8Constants.ToInternedString(FederationListUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FederationResolve"/>.</summary>
    public static ReadOnlySpan<byte> FederationResolveUtf8 => "Federation.Resolve"u8;

    /// <summary>
    /// The endpoint role for the Resolve Endpoint, which resolves the metadata and trust
    /// chain for an entity (<see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3">OpenID Federation 1.0 §8.3</see>).
    /// </summary>
    public static string FederationResolve { get; } = Utf8Constants.ToInternedString(FederationResolveUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FederationRegistration"/>.</summary>
    public static ReadOnlySpan<byte> FederationRegistrationUtf8 => "Federation.Registration"u8;

    /// <summary>
    /// The endpoint role for the Federation Registration Endpoint used by explicit client
    /// registration (<see href="https://openid.net/specs/openid-federation-1_0.html#section-9">OpenID Federation 1.0 §9</see>).
    /// </summary>
    public static string FederationRegistration { get; } = Utf8Constants.ToInternedString(FederationRegistrationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FederationHistoricalKeys"/>.</summary>
    public static ReadOnlySpan<byte> FederationHistoricalKeysUtf8 => "Federation.HistoricalKeys"u8;

    /// <summary>
    /// The endpoint role for the Historical Keys Endpoint, which publishes an entity's expired
    /// signing keys (<see href="https://openid.net/specs/openid-federation-1_0.html#section-8.4">OpenID Federation 1.0 §8.4</see>).
    /// </summary>
    public static string FederationHistoricalKeys { get; } = Utf8Constants.ToInternedString(FederationHistoricalKeysUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FederationTrustMark"/>.</summary>
    public static ReadOnlySpan<byte> FederationTrustMarkUtf8 => "Federation.TrustMark"u8;

    /// <summary>
    /// The endpoint role for the Trust Mark Endpoint, which issues a Trust Mark to a subject
    /// (<see href="https://openid.net/specs/openid-federation-1_0.html#section-8.5">OpenID Federation 1.0 §8.5</see>).
    /// </summary>
    public static string FederationTrustMark { get; } = Utf8Constants.ToInternedString(FederationTrustMarkUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FederationTrustMarkList"/>.</summary>
    public static ReadOnlySpan<byte> FederationTrustMarkListUtf8 => "Federation.TrustMarkList"u8;

    /// <summary>
    /// The endpoint role for the Trust Mark List Endpoint, which lists subjects holding a
    /// given Trust Mark (<see href="https://openid.net/specs/openid-federation-1_0.html#section-8.6">OpenID Federation 1.0 §8.6</see>).
    /// </summary>
    public static string FederationTrustMarkList { get; } = Utf8Constants.ToInternedString(FederationTrustMarkListUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FederationTrustMarkStatus"/>.</summary>
    public static ReadOnlySpan<byte> FederationTrustMarkStatusUtf8 => "Federation.TrustMarkStatus"u8;

    /// <summary>
    /// The endpoint role for the Trust Mark Status Endpoint, which reports whether a Trust
    /// Mark is currently valid (<see href="https://openid.net/specs/openid-federation-1_0.html#section-8.7">OpenID Federation 1.0 §8.7</see>).
    /// </summary>
    public static string FederationTrustMarkStatus { get; } = Utf8Constants.ToInternedString(FederationTrustMarkStatusUtf8);

    //Registration family
    /// <summary>The UTF-8 source literal of <see cref="RegistrationRegister"/>.</summary>
    public static ReadOnlySpan<byte> RegistrationRegisterUtf8 => "Registration.Register"u8;

    /// <summary>The endpoint role for the dynamic client registration endpoint (<see href="https://www.rfc-editor.org/rfc/rfc7591">RFC 7591</see>).</summary>
    public static string RegistrationRegister { get; } = Utf8Constants.ToInternedString(RegistrationRegisterUtf8);

    //OIDC family
    /// <summary>The UTF-8 source literal of <see cref="UserInfo"/>.</summary>
    public static ReadOnlySpan<byte> UserInfoUtf8 => "Oidc.UserInfo"u8;

    /// <summary>The endpoint role for the UserInfo Endpoint (<see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OpenID Connect Core 1.0 §5.3</see>).</summary>
    public static string UserInfo { get; } = Utf8Constants.ToInternedString(UserInfoUtf8);
    //OIDC RP-Initiated Logout 1.0 end-session endpoint.
    /// <summary>The UTF-8 source literal of <see cref="EndSession"/>.</summary>
    public static ReadOnlySpan<byte> EndSessionUtf8 => "Oidc.EndSession"u8;

    /// <summary>
    /// The endpoint role for the RP-Initiated Logout end-session endpoint
    /// (<see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout">OpenID Connect RP-Initiated Logout 1.0 §2</see>).
    /// </summary>
    public static string EndSession { get; } = Utf8Constants.ToInternedString(EndSessionUtf8);

    //AuthZEN family
    /// <summary>The UTF-8 source literal of <see cref="AuthZenAccessEvaluation"/>.</summary>
    public static ReadOnlySpan<byte> AuthZenAccessEvaluationUtf8 => "AuthZen.AccessEvaluation"u8;

    /// <summary>The endpoint role for the Access Evaluation API (<see href="https://openid.net/specs/authorization-api-1_0.html">AuthZEN Authorization API 1.0</see>).</summary>
    public static string AuthZenAccessEvaluation { get; } = Utf8Constants.ToInternedString(AuthZenAccessEvaluationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthZenAccessEvaluations"/>.</summary>
    public static ReadOnlySpan<byte> AuthZenAccessEvaluationsUtf8 => "AuthZen.AccessEvaluations"u8;

    /// <summary>The endpoint role for the batch Access Evaluations API (<see href="https://openid.net/specs/authorization-api-1_0.html">AuthZEN Authorization API 1.0 §6</see>).</summary>
    public static string AuthZenAccessEvaluations { get; } = Utf8Constants.ToInternedString(AuthZenAccessEvaluationsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthZenSearchSubject"/>.</summary>
    public static ReadOnlySpan<byte> AuthZenSearchSubjectUtf8 => "AuthZen.SearchSubject"u8;

    /// <summary>The endpoint role for the Subject Search API (<see href="https://openid.net/specs/authorization-api-1_0.html">AuthZEN Authorization API 1.0 §7</see>).</summary>
    public static string AuthZenSearchSubject { get; } = Utf8Constants.ToInternedString(AuthZenSearchSubjectUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthZenSearchResource"/>.</summary>
    public static ReadOnlySpan<byte> AuthZenSearchResourceUtf8 => "AuthZen.SearchResource"u8;

    /// <summary>The endpoint role for the Resource Search API (<see href="https://openid.net/specs/authorization-api-1_0.html">AuthZEN Authorization API 1.0 §7</see>).</summary>
    public static string AuthZenSearchResource { get; } = Utf8Constants.ToInternedString(AuthZenSearchResourceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthZenSearchAction"/>.</summary>
    public static ReadOnlySpan<byte> AuthZenSearchActionUtf8 => "AuthZen.SearchAction"u8;

    /// <summary>The endpoint role for the Action Search API (<see href="https://openid.net/specs/authorization-api-1_0.html">AuthZEN Authorization API 1.0 §7</see>).</summary>
    public static string AuthZenSearchAction { get; } = Utf8Constants.ToInternedString(AuthZenSearchActionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthZenConfiguration"/>.</summary>
    public static ReadOnlySpan<byte> AuthZenConfigurationUtf8 => "AuthZen.Configuration"u8;

    /// <summary>The endpoint role for the Policy Decision Point metadata document (<see href="https://openid.net/specs/authorization-api-1_0.html">AuthZEN Authorization API 1.0 §9.1</see>).</summary>
    public static string AuthZenConfiguration { get; } = Utf8Constants.ToInternedString(AuthZenConfigurationUtf8);

    //Shared Signals Framework 1.0: the Transmitter Configuration Metadata document
    //a Receiver fetches from /.well-known/ssf-configuration (SSF §7.2.1).
    /// <summary>The UTF-8 source literal of <see cref="SsfConfiguration"/>.</summary>
    public static ReadOnlySpan<byte> SsfConfigurationUtf8 => "Ssf.Configuration"u8;

    /// <summary>The endpoint role for the Transmitter Configuration Metadata document (<see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.2.1">OpenID Shared Signals Framework 1.0 §7.2.1</see>).</summary>
    public static string SsfConfiguration { get; } = Utf8Constants.ToInternedString(SsfConfigurationUtf8);

    //Shared Signals Framework 1.0 Stream Management (SSF §8.1.1): one role per
    //HTTP method on the single Configuration Endpoint URL — create (POST), read
    //(GET, ?stream_id or list), update (PATCH), replace (PUT), and delete (DELETE).
    /// <summary>The UTF-8 source literal of <see cref="SsfStreamCreate"/>.</summary>
    public static ReadOnlySpan<byte> SsfStreamCreateUtf8 => "Ssf.Stream.Create"u8;

    /// <summary>The endpoint role for the stream-create (POST) operation on the Configuration Endpoint (<see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1">OpenID Shared Signals Framework 1.0 §8.1.1</see>).</summary>
    public static string SsfStreamCreate { get; } = Utf8Constants.ToInternedString(SsfStreamCreateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SsfStreamRead"/>.</summary>
    public static ReadOnlySpan<byte> SsfStreamReadUtf8 => "Ssf.Stream.Read"u8;

    /// <summary>The endpoint role for the stream-read (GET) operation on the Configuration Endpoint (<see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1">OpenID Shared Signals Framework 1.0 §8.1.1</see>).</summary>
    public static string SsfStreamRead { get; } = Utf8Constants.ToInternedString(SsfStreamReadUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SsfStreamUpdate"/>.</summary>
    public static ReadOnlySpan<byte> SsfStreamUpdateUtf8 => "Ssf.Stream.Update"u8;

    /// <summary>The endpoint role for the stream-update (PATCH) operation on the Configuration Endpoint (<see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1">OpenID Shared Signals Framework 1.0 §8.1.1</see>).</summary>
    public static string SsfStreamUpdate { get; } = Utf8Constants.ToInternedString(SsfStreamUpdateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SsfStreamReplace"/>.</summary>
    public static ReadOnlySpan<byte> SsfStreamReplaceUtf8 => "Ssf.Stream.Replace"u8;

    /// <summary>The endpoint role for the stream-replace (PUT) operation on the Configuration Endpoint (<see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1">OpenID Shared Signals Framework 1.0 §8.1.1</see>).</summary>
    public static string SsfStreamReplace { get; } = Utf8Constants.ToInternedString(SsfStreamReplaceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SsfStreamDelete"/>.</summary>
    public static ReadOnlySpan<byte> SsfStreamDeleteUtf8 => "Ssf.Stream.Delete"u8;

    /// <summary>The endpoint role for the stream-delete (DELETE) operation on the Configuration Endpoint (<see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1">OpenID Shared Signals Framework 1.0 §8.1.1</see>).</summary>
    public static string SsfStreamDelete { get; } = Utf8Constants.ToInternedString(SsfStreamDeleteUtf8);

    //Shared Signals Framework 1.0 stream control (SSF §8.1.2–§8.1.4): status read
    //(GET) and update (POST) on the Status Endpoint, subject add/remove, and the
    //verification trigger.
    /// <summary>The UTF-8 source literal of <see cref="SsfStatusRead"/>.</summary>
    public static ReadOnlySpan<byte> SsfStatusReadUtf8 => "Ssf.Status.Read"u8;

    /// <summary>The endpoint role for the status-read (GET) operation on the Status Endpoint (<see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2">OpenID Shared Signals Framework 1.0 §8.1.2</see>).</summary>
    public static string SsfStatusRead { get; } = Utf8Constants.ToInternedString(SsfStatusReadUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SsfStatusUpdate"/>.</summary>
    public static ReadOnlySpan<byte> SsfStatusUpdateUtf8 => "Ssf.Status.Update"u8;

    /// <summary>The endpoint role for the status-update (POST) operation on the Status Endpoint (<see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2">OpenID Shared Signals Framework 1.0 §8.1.2</see>).</summary>
    public static string SsfStatusUpdate { get; } = Utf8Constants.ToInternedString(SsfStatusUpdateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SsfSubjectAdd"/>.</summary>
    public static ReadOnlySpan<byte> SsfSubjectAddUtf8 => "Ssf.Subject.Add"u8;

    /// <summary>The endpoint role for the add-subject operation (<see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.3">OpenID Shared Signals Framework 1.0 §8.1.3</see>).</summary>
    public static string SsfSubjectAdd { get; } = Utf8Constants.ToInternedString(SsfSubjectAddUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SsfSubjectRemove"/>.</summary>
    public static ReadOnlySpan<byte> SsfSubjectRemoveUtf8 => "Ssf.Subject.Remove"u8;

    /// <summary>The endpoint role for the remove-subject operation (<see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.3">OpenID Shared Signals Framework 1.0 §8.1.3</see>).</summary>
    public static string SsfSubjectRemove { get; } = Utf8Constants.ToInternedString(SsfSubjectRemoveUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SsfVerification"/>.</summary>
    public static ReadOnlySpan<byte> SsfVerificationUtf8 => "Ssf.Verification"u8;

    /// <summary>The endpoint role for the verification-trigger operation (<see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4">OpenID Shared Signals Framework 1.0 §8.1.4</see>).</summary>
    public static string SsfVerification { get; } = Utf8Constants.ToInternedString(SsfVerificationUtf8);

    //OID4VCI 1.0 §7 Nonce Endpoint — issues the c_nonce challenge.
    /// <summary>The UTF-8 source literal of <see cref="Oid4VciNonce"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VciNonceUtf8 => "Oid4Vci.Nonce"u8;

    /// <summary>The endpoint role for the Nonce Endpoint, which issues the <c>c_nonce</c> challenge (<see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI 1.0 §7</see>).</summary>
    public static string Oid4VciNonce { get; } = Utf8Constants.ToInternedString(Oid4VciNonceUtf8);

    //OID4VCI 1.0 §6 Pre-Authorized Code grant — shares the token endpoint URL,
    //disjoint from the other token grants by the grant_type filter.
    /// <summary>The UTF-8 source literal of <see cref="Oid4VciPreAuthorizedToken"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VciPreAuthorizedTokenUtf8 => "Oid4Vci.PreAuthorizedToken"u8;

    /// <summary>The endpoint role for the pre-authorized code grant on the token endpoint (<see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI 1.0 §6</see>).</summary>
    public static string Oid4VciPreAuthorizedToken { get; } = Utf8Constants.ToInternedString(Oid4VciPreAuthorizedTokenUtf8);

    //OID4VCI 1.0 §8 Credential Endpoint — the protected endpoint that issues one
    //or more Credentials of the same configuration on presentation of the access
    //token, advertised in the Credential Issuer Metadata as credential_endpoint.
    /// <summary>The UTF-8 source literal of <see cref="Oid4VciCredential"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VciCredentialUtf8 => "Oid4Vci.Credential"u8;

    /// <summary>The endpoint role for the Credential Endpoint, advertised as <c>credential_endpoint</c> (<see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI 1.0 §8</see>).</summary>
    public static string Oid4VciCredential { get; } = Utf8Constants.ToInternedString(Oid4VciCredentialUtf8);

    //OID4VCI 1.0 §12.2 Credential Issuer Metadata — the document a Wallet fetches
    //from the well-known location formed by INSERTING /.well-known/openid-credential-issuer
    //into the Credential Issuer Identifier (§12.2.2), like RFC 9728 ProtectedResourceMetadata.
    /// <summary>The UTF-8 source literal of <see cref="Oid4VciCredentialIssuerMetadata"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VciCredentialIssuerMetadataUtf8 => "Oid4Vci.CredentialIssuerMetadata"u8;

    /// <summary>The endpoint role for the Credential Issuer Metadata document (<see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI 1.0 §12.2.2</see>).</summary>
    public static string Oid4VciCredentialIssuerMetadata { get; } = Utf8Constants.ToInternedString(Oid4VciCredentialIssuerMetadataUtf8);

    //OID4VCI 1.0 §9 Deferred Credential Endpoint — the protected endpoint that delivers
    //Credentials whose issuance the Credential Endpoint deferred with a transaction_id,
    //advertised in the Credential Issuer Metadata as deferred_credential_endpoint.
    /// <summary>The UTF-8 source literal of <see cref="Oid4VciDeferredCredential"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VciDeferredCredentialUtf8 => "Oid4Vci.DeferredCredential"u8;

    /// <summary>The endpoint role for the Deferred Credential Endpoint, advertised as <c>deferred_credential_endpoint</c> (<see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI 1.0 §9</see>).</summary>
    public static string Oid4VciDeferredCredential { get; } = Utf8Constants.ToInternedString(Oid4VciDeferredCredentialUtf8);

    //OID4VCI 1.0 §11 Notification Endpoint — the protected endpoint the Wallet reports
    //issuance outcomes to per notification_id, advertised in the Credential Issuer
    //Metadata as notification_endpoint.
    /// <summary>The UTF-8 source literal of <see cref="Oid4VciNotification"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VciNotificationUtf8 => "Oid4Vci.Notification"u8;

    /// <summary>The endpoint role for the Notification Endpoint, advertised as <c>notification_endpoint</c> (<see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI 1.0 §11</see>).</summary>
    public static string Oid4VciNotification { get; } = Utf8Constants.ToInternedString(Oid4VciNotificationUtf8);

    //OID4VCI 1.0 §4.1.3 Credential Offer Endpoint — the unprotected GET that serves a stored
    //Credential Offer object by its id, referenced by the credential_offer_uri the Wallet
    //fetched out of a by-reference deep link.
    /// <summary>The UTF-8 source literal of <see cref="Oid4VciCredentialOffer"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VciCredentialOfferUtf8 => "Oid4Vci.CredentialOffer"u8;

    /// <summary>The endpoint role for the Credential Offer Endpoint, which serves a stored Credential Offer by id (<see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI 1.0 §4.1.3</see>).</summary>
    public static string Oid4VciCredentialOffer { get; } = Utf8Constants.ToInternedString(Oid4VciCredentialOfferUtf8);

    //OAuth 2.0 Protected Resource Metadata (RFC 9728 §3): the document a
    //consumer fetches from the well-known location formed by inserting
    /// <summary>The UTF-8 source literal of <see cref="ProtectedResourceMetadata"/>.</summary>
    public static ReadOnlySpan<byte> ProtectedResourceMetadataUtf8 => "ProtectedResource.Metadata"u8;

    ///.well-known/oauth-protected-resource into the resource identifier.
    public static string ProtectedResourceMetadata { get; } = Utf8Constants.ToInternedString(ProtectedResourceMetadataUtf8);
}
