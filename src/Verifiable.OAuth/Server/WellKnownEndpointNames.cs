using System.Diagnostics;

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
    public static readonly string AuthCodePar = "AuthCode.Par";
    public static readonly string AuthCodeJarPar = "AuthCode.JarPar";
    public static readonly string AuthCodeAuthorize = "AuthCode.Authorize";
    public static readonly string AuthCodeDirectAuthorize = "AuthCode.DirectAuthorize";
    public static readonly string AuthCodeAuthorizeJarByValue = "AuthCode.AuthorizeJarByValue";
    public static readonly string AuthCodeRequestObjectConflict = "AuthCode.RequestObjectConflict";
    public static readonly string AuthCodeToken = "AuthCode.Token";
    public static readonly string AuthCodeRefreshToken = "AuthCode.RefreshToken";
    //The client_credentials grant (RFC 6749 §4.4) shares the token endpoint URL;
    //the grant_type field disambiguates, as it does for the refresh grant.
    public static readonly string ClientCredentialsToken = "ClientCredentials.Token";
    public static readonly string AuthCodeRevoke = "AuthCode.Revoke";
    public static readonly string AuthCodeIntrospect = "AuthCode.Introspect";

    //Global Token Revocation (draft-parecki-oauth-global-token-revocation): an
    //authenticated JSON command that revokes all of a subject's tokens by
    //RFC 9493 Subject Identifier.
    public static readonly string GlobalTokenRevocation = "GlobalTokenRevocation";

    //OID4VP family
    public static readonly string Oid4VpPar = "Oid4Vp.Par";
    public static readonly string Oid4VpJarRequest = "Oid4Vp.JarRequest";
    public static readonly string Oid4VpDirectPost = "Oid4Vp.DirectPost";

    //Metadata family
    public static readonly string MetadataJwks = "Metadata.Jwks";
    public static readonly string MetadataDiscovery = "Metadata.Discovery";

    //Federation family
    public static readonly string FederationEntityConfiguration = "Federation.EntityConfiguration";
    public static readonly string FederationFetch = "Federation.Fetch";
    public static readonly string FederationList = "Federation.List";
    public static readonly string FederationResolve = "Federation.Resolve";
    public static readonly string FederationRegistration = "Federation.Registration";
    public static readonly string FederationHistoricalKeys = "Federation.HistoricalKeys";

    //Registration family
    public static readonly string RegistrationRegister = "Registration.Register";

    //OIDC family
    public static readonly string UserInfo = "Oidc.UserInfo";
    //OIDC RP-Initiated Logout 1.0 end-session endpoint.
    public static readonly string EndSession = "Oidc.EndSession";

    //AuthZEN family
    public static readonly string AuthZenAccessEvaluation = "AuthZen.AccessEvaluation";
    public static readonly string AuthZenAccessEvaluations = "AuthZen.AccessEvaluations";
    public static readonly string AuthZenSearchSubject = "AuthZen.SearchSubject";
    public static readonly string AuthZenSearchResource = "AuthZen.SearchResource";
    public static readonly string AuthZenSearchAction = "AuthZen.SearchAction";
    public static readonly string AuthZenConfiguration = "AuthZen.Configuration";

    //Shared Signals Framework 1.0: the Transmitter Configuration Metadata document
    //a Receiver fetches from /.well-known/ssf-configuration (SSF §7.2.1).
    public static readonly string SsfConfiguration = "Ssf.Configuration";

    //Shared Signals Framework 1.0 Stream Management (SSF §8.1.1): one role per
    //HTTP method on the single Configuration Endpoint URL — create (POST), read
    //(GET, ?stream_id or list), update (PATCH), replace (PUT), and delete (DELETE).
    public static readonly string SsfStreamCreate = "Ssf.Stream.Create";
    public static readonly string SsfStreamRead = "Ssf.Stream.Read";
    public static readonly string SsfStreamUpdate = "Ssf.Stream.Update";
    public static readonly string SsfStreamReplace = "Ssf.Stream.Replace";
    public static readonly string SsfStreamDelete = "Ssf.Stream.Delete";

    //Shared Signals Framework 1.0 stream control (SSF §8.1.2–§8.1.4): status read
    //(GET) and update (POST) on the Status Endpoint, subject add/remove, and the
    //verification trigger.
    public static readonly string SsfStatusRead = "Ssf.Status.Read";
    public static readonly string SsfStatusUpdate = "Ssf.Status.Update";
    public static readonly string SsfSubjectAdd = "Ssf.Subject.Add";
    public static readonly string SsfSubjectRemove = "Ssf.Subject.Remove";
    public static readonly string SsfVerification = "Ssf.Verification";

    //OAuth 2.0 Protected Resource Metadata (RFC 9728 §3): the document a
    //consumer fetches from the well-known location formed by inserting
    ///.well-known/oauth-protected-resource into the resource identifier.
    public static readonly string ProtectedResourceMetadata = "ProtectedResource.Metadata";
}
