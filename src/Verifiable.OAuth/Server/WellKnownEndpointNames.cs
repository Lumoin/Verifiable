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
/// <see cref="ServerCapabilityName.AuthorizationCode"/> capability exposes
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
    public static readonly string AuthCodeAuthorize = "AuthCode.Authorize";
    public static readonly string AuthCodeDirectAuthorize = "AuthCode.DirectAuthorize";
    public static readonly string AuthCodeToken = "AuthCode.Token";
    public static readonly string AuthCodeRefreshToken = "AuthCode.RefreshToken";
    public static readonly string AuthCodeRevoke = "AuthCode.Revoke";
    public static readonly string AuthCodeIntrospect = "AuthCode.Introspect";

    //OID4VP family
    public static readonly string Oid4VpPar = "Oid4Vp.Par";
    public static readonly string Oid4VpJarRequest = "Oid4Vp.JarRequest";
    public static readonly string Oid4VpDirectPost = "Oid4Vp.DirectPost";

    //Metadata family
    public static readonly string MetadataJwks = "Metadata.Jwks";
    public static readonly string MetadataDiscovery = "Metadata.Discovery";

    //Registration family
    public static readonly string RegistrationRegister = "Registration.Register";
}
