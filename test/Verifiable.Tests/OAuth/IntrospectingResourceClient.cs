using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// A protected resource's OAuth client for introspection rows: the <see cref="OAuthClient"/> composed by
/// <see cref="TestHostShell.CreateRewritingOAuthClientAndRegistrationAsync"/> over an <see cref="HttpClient"/> whose
/// outermost handler is an <see cref="IntrospectionExchangeRecorder"/> over a single-hop handler pinned to the listeners
/// the rows dial, and the resource's <see cref="ClientRegistration"/> carrying the client authentication the row names.
/// </summary>
[DebuggerDisplay("IntrospectingResourceClient ClientId={Registration.ClientId}")]
internal sealed class IntrospectingResourceClient: IDisposable
{
    /// <summary>The resource's OAuth client.</summary>
    public OAuthClient Client { get; }

    /// <summary>The resource's registration at the authorization server, with its client authentication.</summary>
    public ClientRegistration Registration { get; }

    /// <summary>The recording handler every exchange of the resource passes through.</summary>
    public IntrospectionExchangeRecorder Recorder { get; }

    /// <summary>The outbound client the infrastructure sends through; it owns <see cref="Recorder"/>.</summary>
    private HttpClient OutboundClient { get; }


    /// <summary>Creates the client over its parts.</summary>
    /// <param name="client">The resource's OAuth client.</param>
    /// <param name="registration">The resource's registration.</param>
    /// <param name="recorder">The recording handler.</param>
    /// <param name="outboundClient">The outbound client owning the recorder.</param>
    private IntrospectingResourceClient(
        OAuthClient client, ClientRegistration registration, IntrospectionExchangeRecorder recorder, HttpClient outboundClient)
    {
        Client = client;
        Registration = registration;
        Recorder = recorder;
        OutboundClient = outboundClient;
    }


    /// <summary>
    /// Composes the resource's client against <paramref name="host"/>'s listener for <paramref name="material"/>'s
    /// registration: the outbound client is the recorder over the single-hop handler pinned to
    /// <paramref name="pinnedCertificates"/>, the metadata the composed one rewritten by <paramref name="alterMetadata"/>,
    /// and the registration authenticates by <paramref name="method"/> with <paramref name="authenticationKeyMaterial"/>.
    /// </summary>
    /// <param name="host">The authorization server's fixture; its listener is started.</param>
    /// <param name="material">The resource's registration at the authorization server.</param>
    /// <param name="method">The client authentication method the resource's requests carry.</param>
    /// <param name="authenticationKeyMaterial">The shared secret or signing key, or <see langword="null"/> for <c>none</c>.</param>
    /// <param name="pinnedCertificates">The certificates of the listeners the resource dials.</param>
    /// <param name="alterMetadata">Rewrites the metadata the client resolves, or <see langword="null"/> to keep it.</param>
    /// <param name="cancellationToken">Cancellation of the listener start.</param>
    /// <param name="dpopKey">The DPoP key the resource's infrastructure wires for its own token requests, or <see langword="null"/> for none.</param>
    /// <returns>The resource's client; the caller disposes it.</returns>
    public static async Task<IntrospectingResourceClient> CreateAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        ClientAuthenticationMethod method,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>? authenticationKeyMaterial,
        IReadOnlyCollection<X509Certificate2> pinnedCertificates,
        Func<AuthorizationServerMetadata, AuthorizationServerMetadata>? alterMetadata,
        CancellationToken cancellationToken,
        DpopKey? dpopKey = null)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(material);
        ArgumentNullException.ThrowIfNull(pinnedCertificates);

        IntrospectionExchangeRecorder recorder = IntrospectionExchangeRecorder.OverPinnedSingleHop(pinnedCertificates);
        HttpClient outboundClient = new(recorder);
        try
        {
            (OAuthClient client, ClientRegistration registration, _) = await host.CreateRewritingOAuthClientAndRegistrationAsync(
                material.Registration,
                "https://introspection.client.test/callback",
                profile: null,
                rewriteFormPostResponse: null,
                cancellationToken,
                transportHttpClient: outboundClient,
                alterMetadata: alterMetadata,
                dpopKey: dpopKey).ConfigureAwait(false);

            return new IntrospectingResourceClient(
                client,
                registration with
                {
                    AuthenticationMethod = method,
                    AuthenticationKeyMaterial = authenticationKeyMaterial
                },
                recorder,
                outboundClient);
        }
        catch
        {
            outboundClient.Dispose();
            throw;
        }
    }


    /// <summary>The resource server's introspection mode over this client.</summary>
    /// <param name="clientAssertionOptions">The <c>private_key_jwt</c> signing inputs, or <see langword="null"/>.</param>
    /// <returns>The mode the resource server's application introspects through.</returns>
    public ResourceServerIntrospection ToResourceServerIntrospection(ClientAssertionOptions? clientAssertionOptions) => new()
    {
        Client = Client,
        Registration = Registration,
        ClientAssertionOptions = clientAssertionOptions,
        Recorder = Recorder
    };


    /// <summary>Disposes the outbound client and with it the recorder and the pinned handler.</summary>
    public void Dispose() => OutboundClient.Dispose();
}
