using System.Diagnostics;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Oid4Vp.Wallet;

namespace Verifiable.OAuth.Client;

/// <summary>
/// The OAuth 2.0 client facade. Drives PKCE-protected Authorization Code
/// flows via <see cref="AuthCode"/>.
/// </summary>
/// <remarks>
/// <para>
/// Construct one <see cref="OAuthClient"/> per relying-party identity at
/// startup, register it in the dependency injection container, and access
/// flows via the per-flow sub-clients (<see cref="AuthCode"/>). All
/// long-lived state — endpoints, transport delegate, parsers, validators —
/// is held on <see cref="OAuthClientOptions"/>.
/// </para>
/// <code>
/// var client = new OAuthClient(OAuthClientOptions.Create(
///     clientId: "my-app",
///     endpoints: discoveredEndpoints,
///     sendFormPostAsync: async (endpoint, fields, ct) =>
///     {
///         var content = new FormUrlEncodedContent(fields);
///         var response = await httpClient.PostAsync(endpoint, content, ct);
///         return new HttpResponseData
///         {
///             Body = await response.Content.ReadAsStringAsync(ct),
///             StatusCode = (int)response.StatusCode
///         };
///     },
///     ...));
///
/// var redirect = await client.AuthCode.StartParAsync(
///     OAuthFormEncodedFields.Empty, ct);
/// </code>
/// <para>
/// The transport is a delegate. The client never knows whether it talks to the
/// authorization server over HTTP, a named pipe, an in-process method call, or
/// any other channel. OAuth is an HTTP protocol — the URIs and status codes
/// are protocol-level, not transport-level — so the delegate shape fits all
/// backends.
/// </para>
/// </remarks>
[DebuggerDisplay("OAuthClient ClientId={Options.ClientId}")]
public sealed class OAuthClient
{
    /// <summary>
    /// The validated long-lived options carrying every delegate this client
    /// uses.
    /// </summary>
    public OAuthClientOptions Options { get; }


    /// <summary>
    /// The Authorization Code sub-client — drives PAR, callback handling,
    /// token exchange, refresh, and revocation flows.
    /// </summary>
    public AuthCodeClient AuthCode { get; }


    /// <summary>
    /// The OID4VP Wallet sub-client for SD-JWT VC presentations. Non-null when
    /// <see cref="OAuthClientOptions.DefaultSdJwtVcWalletConfiguration"/> is
    /// wired; <see langword="null"/> otherwise. Applications that need a
    /// different <c>TCredential</c> construct
    /// <see cref="Oid4VpWalletClient{TCredential}"/> directly.
    /// </summary>
    public Oid4VpWalletClient<SdJwtVcCredential>? Oid4VpWallet { get; }


    /// <summary>
    /// Creates a new OAuth client with the supplied options.
    /// </summary>
    /// <param name="options">
    /// The validated client options carrying transport, persistence, and
    /// validation delegates.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="options"/> is <see langword="null"/>.
    /// </exception>
    public OAuthClient(OAuthClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        Options = options;
        AuthCode = new AuthCodeClient(options);
        Oid4VpWallet = options.DefaultSdJwtVcWalletConfiguration is null
            ? null
            : new Oid4VpWalletClient<SdJwtVcCredential>(
                options, options.DefaultSdJwtVcWalletConfiguration);
    }
}
