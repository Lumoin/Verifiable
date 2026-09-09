using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Proves <see cref="LoopbackKestrel"/>'s two guarantees for every loopback-hosted Kestrel fixture in
/// this repository: the configured listener actually carries the widened limits
/// (<see cref="ConfiguredLimitsDisableDataRateGuardsAndWidenTheWallClockTimeouts"/>) and tolerates a peer
/// stalled past Kestrel's UNCONFIGURED default handshake budget rather than aborting the connection
/// (<see cref="ListenerToleratesAPeerStalledPastKestrelsDefaultHandshakeBudget"/>); and
/// <see cref="LoopbackKestrelDiagnostics"/>'s capture contract
/// (<see cref="CapturingLoggerRecordsWarningAndAboveButNotInformation"/>). These are infrastructure-
/// contract tests for test-fixture plumbing, not a protocol or format this repository implements, so —
/// like the TPM simulator's own hygiene tests — they carry no normative <c>&lt;see href&gt;</c> clause
/// anchor.
/// </summary>
[TestClass]
internal sealed class LoopbackKestrelTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Proves that <see cref="LoopbackKestrel.ConfigureLoopbackListener"/> actually reaches the
    /// listener's <see cref="KestrelServerLimits"/>: the minimum-data-rate guards are disabled and the
    /// request-headers/keep-alive timeouts are widened to <see cref="LoopbackKestrel.RequestHeadersTimeout"/>
    /// and <see cref="LoopbackKestrel.KeepAliveTimeout"/>. Reads the limits back through
    /// <see cref="IOptions{TOptions}"/> off a built (but not started) host, since a freestanding
    /// <see cref="KestrelServerOptions"/> has no <see cref="KestrelServerOptions.ApplicationServices"/>
    /// for <c>UseHttps</c> to resolve against and throws before the listener is ever registered — the
    /// widened TLS handshake budget itself has no public accessor at all and is proven on the wire by
    /// <see cref="ListenerToleratesAPeerStalledPastKestrelsDefaultHandshakeBudget"/> instead.
    /// </summary>
    [TestMethod]
    public async Task ConfiguredLimitsDisableDataRateGuardsAndWidenTheWallClockTimeouts()
    {
        using X509Certificate2 certificate = LoopbackTls.CreateServerCertificate("loopback-kestrel-limits-probe-host");

        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        LoopbackKestrel.ConfigureLoopbackLogging(builder.Logging);
        builder.WebHost.ConfigureKestrel(options => LoopbackKestrel.ConfigureLoopbackListener(options, certificate));

        await using WebApplication app = builder.Build();
        KestrelServerLimits limits = app.Services.GetRequiredService<IOptions<KestrelServerOptions>>().Value.Limits;

        Assert.IsNull(limits.MinRequestBodyDataRate,
            "A loopback fixture has no slow-loris threat model; MinRequestBodyDataRate must be disabled.");
        Assert.IsNull(limits.MinResponseDataRate,
            "A loopback fixture has no slow-loris threat model; MinResponseDataRate must be disabled.");
        Assert.AreEqual(LoopbackKestrel.RequestHeadersTimeout, limits.RequestHeadersTimeout,
            "RequestHeadersTimeout must be widened to LoopbackKestrel.RequestHeadersTimeout, not Kestrel's 30-second default.");
        Assert.AreEqual(LoopbackKestrel.KeepAliveTimeout, limits.KeepAliveTimeout,
            "KeepAliveTimeout must be widened to LoopbackKestrel.KeepAliveTimeout, not Kestrel's 130-second default.");
    }


    /// <summary>
    /// Proves the TLS handshake budget on the wire: opens a raw <see cref="TcpClient"/> to a
    /// <see cref="MinimalHttpHost"/>, waits 12 seconds WITHOUT sending a TLS ClientHello — longer than
    /// Kestrel's unconfigured 10-second default <c>HttpsConnectionAdapterOptions.HandshakeTimeout</c> —
    /// and only then completes the handshake and sends one GET over the SAME socket. Under the
    /// framework default this connection would already have been closed with a clean, zero-byte FIN;
    /// under <see cref="LoopbackKestrel.ConfigureLoopbackListener"/>'s widened
    /// <see cref="LoopbackKestrel.HandshakeTimeout"/> the listener must still accept the handshake and
    /// answer the request.
    /// </summary>
    [TestMethod]
    public async Task ListenerToleratesAPeerStalledPastKestrelsDefaultHandshakeBudget()
    {
        await using MinimalHttpHost host = await MinimalHttpHost.StartAsync(
            (request, cancellationToken) => Task.FromResult(new MinimalHttpResponse
            {
                StatusCode = 200,
                ContentType = "text/plain",
                Body = "loopback-ok"
            }),
            TestContext.CancellationToken).ConfigureAwait(false);

        using TcpClient tcpClient = new();
        await tcpClient.ConnectAsync(IPAddress.Loopback, host.BaseAddress.Port, TestContext.CancellationToken)
            .ConfigureAwait(false);

        //Longer than Kestrel's unconfigured 10-second HandshakeTimeout default, and no ClientHello is
        //sent until after this wait, so a listener still on the framework default would already have
        //closed this connection with a clean, zero-byte FIN by the time the handshake starts.
        await Task.Delay(TimeSpan.FromSeconds(12), TestContext.CancellationToken).ConfigureAwait(false);

        NetworkStream socketStream = tcpClient.GetStream();
        WebSocketCertificatePinning pinning = new(host.Certificate);
        using SslStream sslStream = new(socketStream, leaveInnerStreamOpen: false, pinning.Create());

        await sslStream.AuthenticateAsClientAsync(
            new SslClientAuthenticationOptions { TargetHost = "127.0.0.1" },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pinning.DidMatchPinnedCertificate,
            "The stalled-then-completed handshake must still present the host's own pinned certificate.");

        byte[] requestBytes = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        await sslStream.WriteAsync(requestBytes, TestContext.CancellationToken).ConfigureAwait(false);
        await sslStream.FlushAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using StreamReader responseReader = new(sslStream, Encoding.ASCII, leaveOpen: true);
        string? statusLine = await responseReader.ReadLineAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(statusLine,
            "The listener must not have aborted the stalled handshake: a status line must arrive.");
        Assert.IsTrue(statusLine.StartsWith("HTTP/", StringComparison.Ordinal),
            $"Expected an HTTP status line after the stalled-then-completed handshake. Actual: '{statusLine}'.");
    }


    /// <summary>
    /// Proves <see cref="LoopbackKestrelDiagnostics"/>'s capture contract: a <see cref="LogLevel.Warning"/>
    /// call (with an <see cref="EventId"/> and an exception) is captured with its category, event id,
    /// message, and exception summary all present in the one line it produces, while a
    /// <see cref="LogLevel.Information"/> call on the SAME logger is captured nowhere — only the
    /// diagnostics that can name an abort reason (Warning and above) are worth carrying. Logs through
    /// an instance from <see cref="LoopbackKestrelDiagnostics.CreateIsolated"/> and asserts on that
    /// instance's own <see cref="LoopbackKestrelDiagnostics.Captured"/>, so the assertions never share
    /// the process-wide <see cref="LoopbackKestrelDiagnostics.Provider"/> ring with the concurrently
    /// running hosts that also write into it.
    /// </summary>
    [TestMethod]
    public void CapturingLoggerRecordsWarningAndAboveButNotInformation()
    {
        using LoopbackKestrelDiagnostics diagnostics = LoopbackKestrelDiagnostics.CreateIsolated();
        const string category = "Verifiable.Tests.LoopbackKestrelDiagnosticsProbe";
        ILogger logger = diagnostics.CreateLogger(category);

        EventId warningEventId = new(4217, "ProbeHandshakeAborted");
        InvalidOperationException exception = new("simulated abort reason");
        logger.Log(LogLevel.Warning, warningEventId, "probe", exception,
            static (state, _) => $"the handshake for {state} was aborted");

        EventId infoEventId = new(1, "ProbeInformation");
        logger.Log(LogLevel.Information, infoEventId, "probe", null,
            static (state, _) => $"an informational line for {state}");

        Assert.HasCount(1, diagnostics.Captured,
            "Exactly the Warning call must be captured; the Information call on the same logger must not reach the ring at all.");

        string capturedLine = diagnostics.Captured[0];
        Assert.IsTrue(capturedLine.Contains(category, StringComparison.Ordinal),
            $"The captured line must carry the logging category. Actual: '{capturedLine}'.");
        Assert.IsTrue(capturedLine.Contains(warningEventId.ToString(), StringComparison.Ordinal),
            $"The captured line must carry the event id. Actual: '{capturedLine}'.");
        Assert.IsTrue(capturedLine.Contains("the handshake for probe was aborted", StringComparison.Ordinal),
            $"The captured line must carry the formatted message. Actual: '{capturedLine}'.");
        Assert.IsTrue(capturedLine.Contains(nameof(InvalidOperationException), StringComparison.Ordinal),
            $"The captured line must carry the exception's type name. Actual: '{capturedLine}'.");
        Assert.IsTrue(capturedLine.Contains(exception.Message, StringComparison.Ordinal),
            $"The captured line must carry the exception's message. Actual: '{capturedLine}'.");
    }
}
