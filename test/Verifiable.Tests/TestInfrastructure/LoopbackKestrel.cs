using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The one place every loopback-hosted Kestrel test fixture in this repository configures its listener
/// and its logging pipeline (<see cref="ConfigureLoopbackListener(KestrelServerOptions, X509Certificate2)"/>, <see cref="ConfigureLoopbackLogging"/>),
/// so a box under heavy parallel test load gets timeouts sized for a loopback fixture instead of
/// Kestrel's public-internet defaults (<c>HttpsConnectionAdapterOptions.HandshakeTimeout</c>
/// 10 seconds, <see cref="KestrelServerLimits.RequestHeadersTimeout"/> 30 seconds,
/// <see cref="KestrelServerLimits.KeepAliveTimeout"/> 130 seconds, and the
/// <see cref="KestrelServerLimits.MinRequestBodyDataRate"/> / <see cref="KestrelServerLimits.MinResponseDataRate"/>
/// slow-loris guards). A listener bound only to <see cref="IPAddress.Loopback"/> and dialed only from
/// the same process has no slow-loris threat model, so disabling the minimum-data-rate guards and
/// widening the wall-clock ones changes no security property of the fixture — it only stops a starved
/// ThreadPool from turning into a protocol-level abort of an otherwise healthy connection.
/// </summary>
internal static class LoopbackKestrel
{
    /// <summary>
    /// The TLS handshake budget every loopback listener presents via
    /// <c>HttpsConnectionAdapterOptions.HandshakeTimeout</c> —
    /// long enough that a starved ThreadPool never turns a completed-but-not-yet-scheduled handshake
    /// into a closed connection.
    /// </summary>
    internal static TimeSpan HandshakeTimeout { get; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// The request-headers budget every loopback listener presents via
    /// <see cref="KestrelServerLimits.RequestHeadersTimeout"/>, matching <see cref="HandshakeTimeout"/>
    /// so no earlier Kestrel timer becomes the limiting one on the same connection.
    /// </summary>
    internal static TimeSpan RequestHeadersTimeout { get; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// The idle-connection budget every loopback listener presents via
    /// <see cref="KestrelServerLimits.KeepAliveTimeout"/> — generous enough for a shell that reuses one
    /// listener across several requests within the same test method.
    /// </summary>
    internal static TimeSpan KeepAliveTimeout { get; } = TimeSpan.FromMinutes(5);


    /// <summary>
    /// Configures <paramref name="options"/> for a loopback HTTPS listener bound to
    /// <see cref="IPAddress.Loopback"/> on an OS-assigned port, presenting <paramref name="certificate"/>:
    /// disables the minimum-data-rate guards, widens <see cref="KestrelServerLimits.RequestHeadersTimeout"/>
    /// and <see cref="KestrelServerLimits.KeepAliveTimeout"/> to <see cref="RequestHeadersTimeout"/> and
    /// <see cref="KeepAliveTimeout"/>, and widens the TLS handshake budget to <see cref="HandshakeTimeout"/>.
    /// Every loopback host bootstrap in this repository calls this instead of a bare
    /// <c>Listen</c>/<c>UseHttps</c> pair, so none of them individually re-derives Kestrel's
    /// public-internet defaults for a fixture that has no public-internet threat model.
    /// </summary>
    /// <param name="options">The listener's <see cref="KestrelServerOptions"/>, from <c>ConfigureKestrel</c>.</param>
    /// <param name="certificate">The self-signed leaf this listener presents, e.g. from <see cref="LoopbackTls.CreateServerCertificate"/>.</param>
    internal static void ConfigureLoopbackListener(KestrelServerOptions options, X509Certificate2 certificate) =>
        ConfigureLoopbackListener(options, certificate, connectionMiddleware: null);


    /// <summary>
    /// Configures <paramref name="options"/> the same way as
    /// <see cref="ConfigureLoopbackListener(KestrelServerOptions, X509Certificate2)"/>, additionally
    /// installing <paramref name="connectionMiddleware"/> ahead of TLS when supplied, so a test can hold
    /// the raw connection deterministically (e.g. on a closed gate) before the handshake even starts.
    /// A <see langword="null"/> middleware installs nothing, leaving the pipeline identical to the
    /// two-argument overload every other loopback host bootstrap uses.
    /// </summary>
    /// <param name="options">The listener's <see cref="KestrelServerOptions"/>, from <c>ConfigureKestrel</c>.</param>
    /// <param name="certificate">The self-signed leaf this listener presents, e.g. from <see cref="LoopbackTls.CreateServerCertificate"/>.</param>
    /// <param name="connectionMiddleware">
    /// An optional connection gate: given the accepted <see cref="ConnectionContext"/> and the delegate
    /// continuing to TLS and the rest of the pipeline, it decides when (or whether) that continuation runs.
    /// </param>
    internal static void ConfigureLoopbackListener(KestrelServerOptions options, X509Certificate2 certificate,
        Func<ConnectionContext, Func<Task>, Task>? connectionMiddleware)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(certificate);

        options.Limits.MinRequestBodyDataRate = null;
        options.Limits.MinResponseDataRate = null;
        options.Limits.RequestHeadersTimeout = RequestHeadersTimeout;
        options.Limits.KeepAliveTimeout = KeepAliveTimeout;

        options.Listen(IPAddress.Loopback, port: 0, listen =>
        {
            if(connectionMiddleware is not null)
            {
                _ = listen.Use(next => context => connectionMiddleware(context, () => next(context)));
            }

            _ = listen.UseHttps(certificate, https => https.HandshakeTimeout = HandshakeTimeout);
        });
    }


    /// <summary>
    /// Configures <paramref name="logging"/> the same way every loopback host bootstrap does: clears
    /// the default providers, then attaches the shared <see cref="LoopbackKestrelDiagnostics.Provider"/>
    /// so a Warning-or-above Kestrel diagnostic — the ones that name why a connection was aborted —
    /// survives into the run's captured console output instead of being discarded silently. The
    /// filters keep everything below <see cref="LogLevel.Warning"/> from reaching the provider at all.
    /// </summary>
    /// <param name="logging">The host builder's <see cref="ILoggingBuilder"/>.</param>
    internal static void ConfigureLoopbackLogging(ILoggingBuilder logging)
    {
        ArgumentNullException.ThrowIfNull(logging);

        _ = logging.ClearProviders();
        _ = logging.AddProvider(LoopbackKestrelDiagnostics.Provider);
        _ = logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
        _ = logging.AddFilter("Microsoft.Hosting", LogLevel.Warning);
    }
}
