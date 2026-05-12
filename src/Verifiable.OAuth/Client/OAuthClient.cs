using System.Diagnostics;

namespace Verifiable.OAuth.Client;

/// <summary>
/// The OAuth 2.0 client facade. A thin handle around
/// <see cref="OAuthClientInfrastructure"/> from which protocol-specific
/// sub-clients (Authorization Code, OID4VP Wallet, future Logout / UserInfo)
/// are reached via extension blocks.
/// </summary>
/// <remarks>
/// <para>
/// Construct one <see cref="OAuthClient"/> per application infrastructure at
/// startup. Every protocol call threads a <see cref="ClientRegistration"/> as
/// its first parameter, so one client serves many registrations — different
/// authorization servers, different relying-party identities, different
/// tenants — without any per-AS bound state on the client itself.
/// </para>
/// <para>
/// <strong>Extension surface.</strong> Sub-clients attach to
/// <see cref="OAuthClient"/> via Pattern 5 extension blocks in their own
/// files (<c>AuthCodeClientExtensions.cs</c>,
/// <c>Oid4VpWalletClientExtensions.cs</c>, and so on). Adding a new
/// protocol surface — say RP-Initiated Logout — is one new extension file,
/// not a code change here. The base type stays closed at one property so
/// the surface is uniform and unambiguous regardless of how many protocols
/// the application activates.
/// </para>
/// <para>
/// <strong>Usage.</strong>
/// </para>
/// <code>
/// OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
///     sendFormPostAsync: ...,
///     saveStateAsync: ...,
///     loadStateAsync: ...,
///     loadStateByRequestUriAsync: ...,
///     parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
///     parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
///     parseAuthorizationServerMetadataAsync: ...,
///     parseRegistrationResponseAsync: ...,
///     resolveAuthorizationServerMetadataAsync: ...,
///     resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
///     base64UrlEncoder: ...,
///     timeProvider: TimeProvider.System);
///
/// OAuthClient client = new(infrastructure);
///
/// ClientRegistration registration = LoadFromStore(clientId);
/// AuthCodeFlowEndpointResult redirect = await client.AuthCode.StartParAsync(
///     registration, OAuthFormEncodedFields.Empty, ct);
/// </code>
/// </remarks>
[DebuggerDisplay("OAuthClient")]
public sealed class OAuthClient
{
    /// <summary>
    /// The long-lived infrastructure carrying every I/O delegate this client
    /// uses. Reached by extension-block properties (<c>AuthCode</c>,
    /// <c>Oid4VpWallet</c>) to construct per-call sub-client structs.
    /// </summary>
    public OAuthClientInfrastructure Infrastructure { get; }


    /// <summary>
    /// Creates a new OAuth client over the supplied infrastructure.
    /// </summary>
    /// <param name="infrastructure">
    /// The validated infrastructure carrying transport, persistence, parsing,
    /// resolution, and policy delegates.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="infrastructure"/> is <see langword="null"/>.
    /// </exception>
    public OAuthClient(OAuthClientInfrastructure infrastructure)
    {
        ArgumentNullException.ThrowIfNull(infrastructure);

        Infrastructure = infrastructure;
    }
}
