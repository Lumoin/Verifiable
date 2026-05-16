using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.OAuth.Hosting;

/// <summary>
/// Test-side resource server host. Parallel of
/// <see cref="Verifiable.Tests.OAuth.TestHostShell"/>; hosts a single
/// <c>/protected</c> endpoint via minimal Kestrel +
/// <see cref="ResourceServerHttpApplication"/>. Tests bring up this host
/// alongside <see cref="Verifiable.Tests.OAuth.TestHostShell"/> (AS) to
/// exercise the full AS → token → RS flow over real HTTP.
/// </summary>
[DebuggerDisplay("TestResourceServerShell BaseAddress={HttpBaseAddress}")]
internal sealed class TestResourceServerShell: IAsyncDisposable
{
    private global::Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServer? KestrelServer { get; set; }
    private bool Disposed { get; set; }

    public ResourceServerIntegration Integration { get; }
    public VerificationDelegate VerifySignature { get; }

    public Uri? HttpBaseAddress { get; private set; }

    /// <summary>
    /// Per-request JTI tracker. Maps jti → expiry instant. Tests inspect
    /// this directly to verify replay-defense behaviour.
    /// </summary>
    public ConcurrentDictionary<string, DateTimeOffset> SeenDpopJtis { get; } =
        new(StringComparer.Ordinal);


    public TestResourceServerShell(
        Uri trustedIssuer,
        string expectedAudience,
        ServerVerificationKeyResolverDelegate resolveVerificationKey,
        VerificationDelegate verifySignature,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(trustedIssuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedAudience);
        ArgumentNullException.ThrowIfNull(resolveVerificationKey);
        ArgumentNullException.ThrowIfNull(verifySignature);
        ArgumentNullException.ThrowIfNull(timeProvider);

        VerifySignature = verifySignature;

        Integration = new ResourceServerIntegration
        {
            TrustedIssuer = trustedIssuer,
            ExpectedAudience = expectedAudience,
            ResolveVerificationKeyAsync = resolveVerificationKey,
            TimeProvider = timeProvider,
            IsDpopProofJtiSeenAsync = (jti, ctx, ct) =>
                ValueTask.FromResult(SeenDpopJtis.ContainsKey(jti)),
            PersistDpopProofJtiAsync = (jti, expiresAt, ctx, ct) =>
            {
                SeenDpopJtis[jti] = expiresAt;
                return ValueTask.CompletedTask;
            }
        };
    }


    public async Task StartHttpHostAsync(CancellationToken cancellationToken = default)
    {
        if(KestrelServer is not null)
        {
            return;
        }

        global::Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions kestrelOptions = new();
        kestrelOptions.Listen(IPAddress.Loopback, port: 0);

        global::Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets.SocketTransportOptions socketOptions = new();
        global::Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets.SocketTransportFactory socketFactory = new(
            global::Microsoft.Extensions.Options.Options.Create(socketOptions),
            global::Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance);

        global::Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServer kestrel = new(
            global::Microsoft.Extensions.Options.Options.Create(kestrelOptions),
            socketFactory,
            global::Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance);

        ResourceServerHttpApplication app = new(Integration, VerifySignature);
        await kestrel.StartAsync(app, cancellationToken).ConfigureAwait(false);

        global::Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature? addresses =
            kestrel.Features.Get<global::Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>();
        if(addresses is null || addresses.Addresses.Count == 0)
        {
            throw new InvalidOperationException(
                "Kestrel started but no server addresses were exposed via IServerAddressesFeature.");
        }

        KestrelServer = kestrel;
        HttpBaseAddress = new Uri(addresses.Addresses.First());
    }


    public async ValueTask DisposeAsync()
    {
        if(Disposed)
        {
            return;
        }

        Disposed = true;

        if(KestrelServer is not null)
        {
            await KestrelServer.StopAsync(CancellationToken.None).ConfigureAwait(false);
            KestrelServer.Dispose();
            KestrelServer = null;
        }
    }
}
