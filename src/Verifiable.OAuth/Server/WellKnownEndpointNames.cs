using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Stable endpoint role identifiers used as the lookup key by
/// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
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
[DebuggerDisplay("WellKnownEndpointNames")]
public static class WellKnownEndpointNames
{
    //AuthCode family
    /// <summary>The UTF-8 source literal of <see cref="AuthCodePar"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeParUtf8 => "AuthCode.Par"u8;

    public static readonly string AuthCodePar = Utf8Constants.ToInternedString(AuthCodeParUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeJarPar"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeJarParUtf8 => "AuthCode.JarPar"u8;

    public static readonly string AuthCodeJarPar = Utf8Constants.ToInternedString(AuthCodeJarParUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeAuthorize"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeAuthorizeUtf8 => "AuthCode.Authorize"u8;

    public static readonly string AuthCodeAuthorize = Utf8Constants.ToInternedString(AuthCodeAuthorizeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeDirectAuthorize"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeDirectAuthorizeUtf8 => "AuthCode.DirectAuthorize"u8;

    public static readonly string AuthCodeDirectAuthorize = Utf8Constants.ToInternedString(AuthCodeDirectAuthorizeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeAuthorizeJarByValue"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeAuthorizeJarByValueUtf8 => "AuthCode.AuthorizeJarByValue"u8;

    public static readonly string AuthCodeAuthorizeJarByValue = Utf8Constants.ToInternedString(AuthCodeAuthorizeJarByValueUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeRequestObjectConflict"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeRequestObjectConflictUtf8 => "AuthCode.RequestObjectConflict"u8;

    public static readonly string AuthCodeRequestObjectConflict = Utf8Constants.ToInternedString(AuthCodeRequestObjectConflictUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeToken"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeTokenUtf8 => "AuthCode.Token"u8;

    public static readonly string AuthCodeToken = Utf8Constants.ToInternedString(AuthCodeTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeRefreshToken"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeRefreshTokenUtf8 => "AuthCode.RefreshToken"u8;

    public static readonly string AuthCodeRefreshToken = Utf8Constants.ToInternedString(AuthCodeRefreshTokenUtf8);
    //The client_credentials grant (RFC 6749 §4.4) shares the token endpoint URL;
    //the grant_type field disambiguates, as it does for the refresh grant.
    /// <summary>The UTF-8 source literal of <see cref="ClientCredentialsToken"/>.</summary>
    public static ReadOnlySpan<byte> ClientCredentialsTokenUtf8 => "ClientCredentials.Token"u8;

    public static readonly string ClientCredentialsToken = Utf8Constants.ToInternedString(ClientCredentialsTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeRevoke"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeRevokeUtf8 => "AuthCode.Revoke"u8;

    public static readonly string AuthCodeRevoke = Utf8Constants.ToInternedString(AuthCodeRevokeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthCodeIntrospect"/>.</summary>
    public static ReadOnlySpan<byte> AuthCodeIntrospectUtf8 => "AuthCode.Introspect"u8;

    public static readonly string AuthCodeIntrospect = Utf8Constants.ToInternedString(AuthCodeIntrospectUtf8);

    //Global Token Revocation (draft-parecki-oauth-global-token-revocation): an
    //authenticated JSON command that revokes all of a subject's tokens by
    //RFC 9493 Subject Identifier.
    /// <summary>The UTF-8 source literal of <see cref="GlobalTokenRevocation"/>.</summary>
    public static ReadOnlySpan<byte> GlobalTokenRevocationUtf8 => "GlobalTokenRevocation"u8;

    public static readonly string GlobalTokenRevocation = Utf8Constants.ToInternedString(GlobalTokenRevocationUtf8);

    //OID4VP family
    /// <summary>The UTF-8 source literal of <see cref="Oid4VpPar"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VpParUtf8 => "Oid4Vp.Par"u8;

    public static readonly string Oid4VpPar = Utf8Constants.ToInternedString(Oid4VpParUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Oid4VpJarRequest"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VpJarRequestUtf8 => "Oid4Vp.JarRequest"u8;

    public static readonly string Oid4VpJarRequest = Utf8Constants.ToInternedString(Oid4VpJarRequestUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Oid4VpDirectPost"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VpDirectPostUtf8 => "Oid4Vp.DirectPost"u8;

    public static readonly string Oid4VpDirectPost = Utf8Constants.ToInternedString(Oid4VpDirectPostUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SiopRequestObject"/>.</summary>
    public static ReadOnlySpan<byte> SiopRequestObjectUtf8 => "Siop.RequestObject"u8;

    /// <summary>The SIOPv2 RP-internal request-preparation endpoint (the PAR-equivalent that starts the flow).</summary>
    public static readonly string SiopRequestObject = Utf8Constants.ToInternedString(SiopRequestObjectUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SiopRequestObjectByReference"/>.</summary>
    public static ReadOnlySpan<byte> SiopRequestObjectByReferenceUtf8 => "Siop.RequestObjectByReference"u8;

    /// <summary>
    /// The SIOPv2 §9 signed Request Object endpoint served at the <c>request_uri</c>. The Wallet
    /// dereferences this URL with HTTP GET to fetch the signed Request Object (the SIOP parallel of
    /// the OID4VP JAR-fetch endpoint <see cref="Oid4VpJarRequest"/>).
    /// </summary>
    public static readonly string SiopRequestObjectByReference = Utf8Constants.ToInternedString(SiopRequestObjectByReferenceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SiopResponse"/>.</summary>
    public static ReadOnlySpan<byte> SiopResponseUtf8 => "Siop.Response"u8;

    /// <summary>The SIOPv2 §10.2 Authorization Response endpoint that receives the Wallet's <c>id_token</c> POST.</summary>
    public static readonly string SiopResponse = Utf8Constants.ToInternedString(SiopResponseUtf8);

    //Metadata family
    /// <summary>The UTF-8 source literal of <see cref="MetadataJwks"/>.</summary>
    public static ReadOnlySpan<byte> MetadataJwksUtf8 => "Metadata.Jwks"u8;

    public static readonly string MetadataJwks = Utf8Constants.ToInternedString(MetadataJwksUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MetadataDiscovery"/>.</summary>
    public static ReadOnlySpan<byte> MetadataDiscoveryUtf8 => "Metadata.Discovery"u8;

    public static readonly string MetadataDiscovery = Utf8Constants.ToInternedString(MetadataDiscoveryUtf8);

    //Federation family
    /// <summary>The UTF-8 source literal of <see cref="FederationEntityConfiguration"/>.</summary>
    public static ReadOnlySpan<byte> FederationEntityConfigurationUtf8 => "Federation.EntityConfiguration"u8;

    public static readonly string FederationEntityConfiguration = Utf8Constants.ToInternedString(FederationEntityConfigurationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FederationFetch"/>.</summary>
    public static ReadOnlySpan<byte> FederationFetchUtf8 => "Federation.Fetch"u8;

    public static readonly string FederationFetch = Utf8Constants.ToInternedString(FederationFetchUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FederationList"/>.</summary>
    public static ReadOnlySpan<byte> FederationListUtf8 => "Federation.List"u8;

    public static readonly string FederationList = Utf8Constants.ToInternedString(FederationListUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FederationResolve"/>.</summary>
    public static ReadOnlySpan<byte> FederationResolveUtf8 => "Federation.Resolve"u8;

    public static readonly string FederationResolve = Utf8Constants.ToInternedString(FederationResolveUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FederationRegistration"/>.</summary>
    public static ReadOnlySpan<byte> FederationRegistrationUtf8 => "Federation.Registration"u8;

    public static readonly string FederationRegistration = Utf8Constants.ToInternedString(FederationRegistrationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FederationHistoricalKeys"/>.</summary>
    public static ReadOnlySpan<byte> FederationHistoricalKeysUtf8 => "Federation.HistoricalKeys"u8;

    public static readonly string FederationHistoricalKeys = Utf8Constants.ToInternedString(FederationHistoricalKeysUtf8);

    //Registration family
    /// <summary>The UTF-8 source literal of <see cref="RegistrationRegister"/>.</summary>
    public static ReadOnlySpan<byte> RegistrationRegisterUtf8 => "Registration.Register"u8;

    public static readonly string RegistrationRegister = Utf8Constants.ToInternedString(RegistrationRegisterUtf8);

    //OIDC family
    /// <summary>The UTF-8 source literal of <see cref="UserInfo"/>.</summary>
    public static ReadOnlySpan<byte> UserInfoUtf8 => "Oidc.UserInfo"u8;

    public static readonly string UserInfo = Utf8Constants.ToInternedString(UserInfoUtf8);
    //OIDC RP-Initiated Logout 1.0 end-session endpoint.
    /// <summary>The UTF-8 source literal of <see cref="EndSession"/>.</summary>
    public static ReadOnlySpan<byte> EndSessionUtf8 => "Oidc.EndSession"u8;

    public static readonly string EndSession = Utf8Constants.ToInternedString(EndSessionUtf8);

    //AuthZEN family
    /// <summary>The UTF-8 source literal of <see cref="AuthZenAccessEvaluation"/>.</summary>
    public static ReadOnlySpan<byte> AuthZenAccessEvaluationUtf8 => "AuthZen.AccessEvaluation"u8;

    public static readonly string AuthZenAccessEvaluation = Utf8Constants.ToInternedString(AuthZenAccessEvaluationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthZenAccessEvaluations"/>.</summary>
    public static ReadOnlySpan<byte> AuthZenAccessEvaluationsUtf8 => "AuthZen.AccessEvaluations"u8;

    public static readonly string AuthZenAccessEvaluations = Utf8Constants.ToInternedString(AuthZenAccessEvaluationsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthZenSearchSubject"/>.</summary>
    public static ReadOnlySpan<byte> AuthZenSearchSubjectUtf8 => "AuthZen.SearchSubject"u8;

    public static readonly string AuthZenSearchSubject = Utf8Constants.ToInternedString(AuthZenSearchSubjectUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthZenSearchResource"/>.</summary>
    public static ReadOnlySpan<byte> AuthZenSearchResourceUtf8 => "AuthZen.SearchResource"u8;

    public static readonly string AuthZenSearchResource = Utf8Constants.ToInternedString(AuthZenSearchResourceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthZenSearchAction"/>.</summary>
    public static ReadOnlySpan<byte> AuthZenSearchActionUtf8 => "AuthZen.SearchAction"u8;

    public static readonly string AuthZenSearchAction = Utf8Constants.ToInternedString(AuthZenSearchActionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthZenConfiguration"/>.</summary>
    public static ReadOnlySpan<byte> AuthZenConfigurationUtf8 => "AuthZen.Configuration"u8;

    public static readonly string AuthZenConfiguration = Utf8Constants.ToInternedString(AuthZenConfigurationUtf8);

    //Shared Signals Framework 1.0: the Transmitter Configuration Metadata document
    //a Receiver fetches from /.well-known/ssf-configuration (SSF §7.2.1).
    /// <summary>The UTF-8 source literal of <see cref="SsfConfiguration"/>.</summary>
    public static ReadOnlySpan<byte> SsfConfigurationUtf8 => "Ssf.Configuration"u8;

    public static readonly string SsfConfiguration = Utf8Constants.ToInternedString(SsfConfigurationUtf8);

    //Shared Signals Framework 1.0 Stream Management (SSF §8.1.1): one role per
    //HTTP method on the single Configuration Endpoint URL — create (POST), read
    //(GET, ?stream_id or list), update (PATCH), replace (PUT), and delete (DELETE).
    /// <summary>The UTF-8 source literal of <see cref="SsfStreamCreate"/>.</summary>
    public static ReadOnlySpan<byte> SsfStreamCreateUtf8 => "Ssf.Stream.Create"u8;

    public static readonly string SsfStreamCreate = Utf8Constants.ToInternedString(SsfStreamCreateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SsfStreamRead"/>.</summary>
    public static ReadOnlySpan<byte> SsfStreamReadUtf8 => "Ssf.Stream.Read"u8;

    public static readonly string SsfStreamRead = Utf8Constants.ToInternedString(SsfStreamReadUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SsfStreamUpdate"/>.</summary>
    public static ReadOnlySpan<byte> SsfStreamUpdateUtf8 => "Ssf.Stream.Update"u8;

    public static readonly string SsfStreamUpdate = Utf8Constants.ToInternedString(SsfStreamUpdateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SsfStreamReplace"/>.</summary>
    public static ReadOnlySpan<byte> SsfStreamReplaceUtf8 => "Ssf.Stream.Replace"u8;

    public static readonly string SsfStreamReplace = Utf8Constants.ToInternedString(SsfStreamReplaceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SsfStreamDelete"/>.</summary>
    public static ReadOnlySpan<byte> SsfStreamDeleteUtf8 => "Ssf.Stream.Delete"u8;

    public static readonly string SsfStreamDelete = Utf8Constants.ToInternedString(SsfStreamDeleteUtf8);

    //Shared Signals Framework 1.0 stream control (SSF §8.1.2–§8.1.4): status read
    //(GET) and update (POST) on the Status Endpoint, subject add/remove, and the
    //verification trigger.
    /// <summary>The UTF-8 source literal of <see cref="SsfStatusRead"/>.</summary>
    public static ReadOnlySpan<byte> SsfStatusReadUtf8 => "Ssf.Status.Read"u8;

    public static readonly string SsfStatusRead = Utf8Constants.ToInternedString(SsfStatusReadUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SsfStatusUpdate"/>.</summary>
    public static ReadOnlySpan<byte> SsfStatusUpdateUtf8 => "Ssf.Status.Update"u8;

    public static readonly string SsfStatusUpdate = Utf8Constants.ToInternedString(SsfStatusUpdateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SsfSubjectAdd"/>.</summary>
    public static ReadOnlySpan<byte> SsfSubjectAddUtf8 => "Ssf.Subject.Add"u8;

    public static readonly string SsfSubjectAdd = Utf8Constants.ToInternedString(SsfSubjectAddUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SsfSubjectRemove"/>.</summary>
    public static ReadOnlySpan<byte> SsfSubjectRemoveUtf8 => "Ssf.Subject.Remove"u8;

    public static readonly string SsfSubjectRemove = Utf8Constants.ToInternedString(SsfSubjectRemoveUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SsfVerification"/>.</summary>
    public static ReadOnlySpan<byte> SsfVerificationUtf8 => "Ssf.Verification"u8;

    public static readonly string SsfVerification = Utf8Constants.ToInternedString(SsfVerificationUtf8);

    //OID4VCI 1.0 §7 Nonce Endpoint — issues the c_nonce challenge.
    /// <summary>The UTF-8 source literal of <see cref="Oid4VciNonce"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VciNonceUtf8 => "Oid4Vci.Nonce"u8;

    public static readonly string Oid4VciNonce = Utf8Constants.ToInternedString(Oid4VciNonceUtf8);

    //OID4VCI 1.0 §6 Pre-Authorized Code grant — shares the token endpoint URL,
    //disjoint from the other token grants by the grant_type filter.
    /// <summary>The UTF-8 source literal of <see cref="Oid4VciPreAuthorizedToken"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VciPreAuthorizedTokenUtf8 => "Oid4Vci.PreAuthorizedToken"u8;

    public static readonly string Oid4VciPreAuthorizedToken = Utf8Constants.ToInternedString(Oid4VciPreAuthorizedTokenUtf8);

    //OID4VCI 1.0 §8 Credential Endpoint — the protected endpoint that issues one
    //or more Credentials of the same configuration on presentation of the access
    //token, advertised in the Credential Issuer Metadata as credential_endpoint.
    /// <summary>The UTF-8 source literal of <see cref="Oid4VciCredential"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VciCredentialUtf8 => "Oid4Vci.Credential"u8;

    public static readonly string Oid4VciCredential = Utf8Constants.ToInternedString(Oid4VciCredentialUtf8);

    //OID4VCI 1.0 §12.2 Credential Issuer Metadata — the document a Wallet fetches
    //from the well-known location formed by INSERTING /.well-known/openid-credential-issuer
    //into the Credential Issuer Identifier (§12.2.2), like RFC 9728 ProtectedResourceMetadata.
    /// <summary>The UTF-8 source literal of <see cref="Oid4VciCredentialIssuerMetadata"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VciCredentialIssuerMetadataUtf8 => "Oid4Vci.CredentialIssuerMetadata"u8;

    public static readonly string Oid4VciCredentialIssuerMetadata = Utf8Constants.ToInternedString(Oid4VciCredentialIssuerMetadataUtf8);

    //OID4VCI 1.0 §9 Deferred Credential Endpoint — the protected endpoint that delivers
    //Credentials whose issuance the Credential Endpoint deferred with a transaction_id,
    //advertised in the Credential Issuer Metadata as deferred_credential_endpoint.
    /// <summary>The UTF-8 source literal of <see cref="Oid4VciDeferredCredential"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VciDeferredCredentialUtf8 => "Oid4Vci.DeferredCredential"u8;

    public static readonly string Oid4VciDeferredCredential = Utf8Constants.ToInternedString(Oid4VciDeferredCredentialUtf8);

    //OID4VCI 1.0 §11 Notification Endpoint — the protected endpoint the Wallet reports
    //issuance outcomes to per notification_id, advertised in the Credential Issuer
    //Metadata as notification_endpoint.
    /// <summary>The UTF-8 source literal of <see cref="Oid4VciNotification"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VciNotificationUtf8 => "Oid4Vci.Notification"u8;

    public static readonly string Oid4VciNotification = Utf8Constants.ToInternedString(Oid4VciNotificationUtf8);

    //OID4VCI 1.0 §4.1.3 Credential Offer Endpoint — the unprotected GET that serves a stored
    //Credential Offer object by its id, referenced by the credential_offer_uri the Wallet
    //fetched out of a by-reference deep link.
    /// <summary>The UTF-8 source literal of <see cref="Oid4VciCredentialOffer"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VciCredentialOfferUtf8 => "Oid4Vci.CredentialOffer"u8;

    public static readonly string Oid4VciCredentialOffer = Utf8Constants.ToInternedString(Oid4VciCredentialOfferUtf8);

    //OAuth 2.0 Protected Resource Metadata (RFC 9728 §3): the document a
    //consumer fetches from the well-known location formed by inserting
    /// <summary>The UTF-8 source literal of <see cref="ProtectedResourceMetadata"/>.</summary>
    public static ReadOnlySpan<byte> ProtectedResourceMetadataUtf8 => "ProtectedResource.Metadata"u8;

    ///.well-known/oauth-protected-resource into the resource identifier.
    public static readonly string ProtectedResourceMetadata = Utf8Constants.ToInternedString(ProtectedResourceMetadataUtf8);
}
