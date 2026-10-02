using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Proves <see cref="LoopbackKestrel"/>'s two guarantees for every loopback-hosted Kestrel fixture in
/// this repository: the configured listener actually carries the widened limits
/// (<see cref="ConfiguredLimitsDisableDataRateGuardsAndWidenTheWallClockTimeouts"/>) and tolerates a peer
/// stalled past Kestrel's UNCONFIGURED default handshake budget rather than aborting the connection
/// (<see cref="ListenerToleratesAPeerStalledPastKestrelsDefaultHandshakeBudget"/>); and
/// <see cref="LoopbackKestrelDiagnostics"/>'s capture contract
/// (<see cref="CapturingLoggerRecordsWarningAndAboveButNotInformation"/>). On the client side,
/// <see cref="ConnectFromALocalPortWhoseFourTupleIsInTimeWaitFailsWithAddressAlreadyInUse"/> pins that a
/// connect whose four-tuple rests in TIME_WAIT fails with <see cref="SocketError.AddressAlreadyInUse"/>, and
/// <see cref="ConnectRetriesOnAFreshSocketWhenTheFirstAttemptMeetsAFourTupleInTimeWait"/> proves
/// <see cref="LoopbackConnect"/> connects on a fresh socket after such an attempt, both pinning the
/// behaviour observed on Windows.
/// <see cref="PinnedClientGetsTheResponseWhenItsFirstConnectMeetsAFourTupleInTimeWait"/> proves a client
/// <see cref="LoopbackTls"/> builds connects through that body, and
/// <see cref="PinnedClientWithOneConnectAttemptFailsWithAddressAlreadyInUseOnAFourTupleInTimeWait"/> shows
/// the same request failing when the body is allowed a single attempt.
/// <see cref="ConnectWithOneAttemptLeavesAddressAlreadyInUseWithoutARetry"/> and
/// <see cref="ConnectToALoopbackPortNothingListensOnLeavesConnectionRefusedAtTheFirstAttempt"/> prove the
/// failures the body leaves unchanged, and
/// <see cref="PinnedClientRefusesAHostPresentingACertificateItIsNotPinnedTo"/> proves the pinned client
/// refuses a leaf it is not pinned to. These are infrastructure-
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
    /// Proves that <see cref="LoopbackKestrel.ConfigureLoopbackListener(KestrelServerOptions, X509Certificate2)"/> actually reaches the
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
        _ = builder.WebHost.ConfigureKestrel(options => LoopbackKestrel.ConfigureLoopbackListener(options, certificate));

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
    /// under <see cref="LoopbackKestrel.ConfigureLoopbackListener(KestrelServerOptions, X509Certificate2)"/>'s widened
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


    /// <summary>
    /// Pins the operating system behaviour a loopback client meets when a listener port and a local
    /// port are both reused within the TIME_WAIT period: a client socket connects to a loopback
    /// listener, exchanges one byte and closes first, so the four-tuple of that connection rests in
    /// TIME_WAIT on the client side; a second socket bound to the same local port then connects to the
    /// same listener, and the attempt fails with <see cref="SocketError.AddressAlreadyInUse"/>. The row
    /// pins the Windows behaviour: on Windows the bind succeeds and the connect is the call that fails.
    /// </summary>
    [TestMethod]
    [OSCondition(OperatingSystems.Windows)]
    public async Task ConnectFromALocalPortWhoseFourTupleIsInTimeWaitFailsWithAddressAlreadyInUse()
    {
        using Socket listener = CreateLoopbackListener();
        IPEndPoint timeWaitLocalEndPoint = await LeaveFourTupleInTimeWaitAsync(listener, TestContext.CancellationToken)
            .ConfigureAwait(false);

        using Socket secondClient = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        secondClient.Bind(timeWaitLocalEndPoint);
        SocketException failure = await Assert.ThrowsExactlyAsync<SocketException>(
            async () => await secondClient.ConnectAsync(listener.LocalEndPoint!, TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);

        Assert.AreEqual(SocketError.AddressAlreadyInUse, failure.SocketErrorCode,
            $"A connect whose four-tuple rests in TIME_WAIT must fail with AddressAlreadyInUse. Actual: '{failure.Message}'.");
    }


    /// <summary>
    /// Proves <see cref="LoopbackConnect.ConnectAsync(EndPoint, int, Action{Socket, int}?, LoopbackKestrelDiagnostics, CancellationToken)"/>
    /// survives the state <see cref="ConnectFromALocalPortWhoseFourTupleIsInTimeWaitFailsWithAddressAlreadyInUse"/>
    /// pins: its first attempt is bound to a local port whose four-tuple with the listener rests in
    /// TIME_WAIT and fails with <see cref="SocketError.AddressAlreadyInUse"/>; a later attempt, on a
    /// fresh socket, connects, and one byte crosses the connection. The row pins the Windows behaviour
    /// the body answers. A fresh socket's local port is the operating system's choice and may itself meet
    /// a four-tuple in TIME_WAIT, so the row asserts the invariant of
    /// <see cref="AssertRetriedAfterTheFirstAttempt"/> rather than an exact total.
    /// </summary>
    [TestMethod]
    [OSCondition(OperatingSystems.Windows)]
    public async Task ConnectRetriesOnAFreshSocketWhenTheFirstAttemptMeetsAFourTupleInTimeWait()
    {
        using Socket listener = CreateLoopbackListener();
        IPEndPoint listenerEndPoint = (IPEndPoint)listener.LocalEndPoint!;
        IPEndPoint timeWaitLocalEndPoint = await LeaveFourTupleInTimeWaitAsync(listener, TestContext.CancellationToken)
            .ConfigureAwait(false);

        using LoopbackKestrelDiagnostics diagnostics = LoopbackKestrelDiagnostics.CreateIsolated();
        List<int> preparedAttempts = [];
        using Socket connected = await LoopbackConnect.ConnectAsync(
            listenerEndPoint,
            LoopbackConnect.DefaultMaxAttempts,
            RecordAttemptsAndBindTheFirstTo(timeWaitLocalEndPoint, preparedAttempts),
            diagnostics,
            TestContext.CancellationToken).ConfigureAwait(false);
        using Socket accepted = await listener.AcceptAsync(TestContext.CancellationToken).ConfigureAwait(false);

        byte[] exchanged = [0x2A];
        int sentCount = await connected.SendAsync(exchanged, SocketFlags.None, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] received = new byte[1];
        int receivedCount = await accepted.ReceiveAsync(received, SocketFlags.None, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, sentCount, "The connected socket must send its one byte.");
        Assert.AreEqual(1, receivedCount, "The listener's accepted side must read the one byte.");
        Assert.AreEqual(exchanged[0], received[0], "The listener's accepted side must read the byte that was sent.");
        Assert.AreNotEqual(timeWaitLocalEndPoint.Port, ((IPEndPoint)connected.LocalEndPoint!).Port,
            "The connected socket must hold a local port other than the one whose four-tuple rests in TIME_WAIT.");
        AssertRetriedAfterTheFirstAttempt(preparedAttempts, diagnostics.Captured, listenerEndPoint.ToString());
    }


    /// <summary>
    /// Proves the client <see cref="LoopbackTls"/> builds opens its TCP connection through
    /// <see cref="LoopbackConnect"/>: a real HTTPS GET to a <see cref="MinimalHttpHost"/> through a client
    /// from <see cref="LoopbackTls.CreatePinnedHttpClient(IReadOnlyCollection{X509Certificate2}, int, Action{Socket, int}?, LoopbackKestrelDiagnostics)"/>
    /// whose first connect attempt is bound to a local port whose four-tuple with the host's port rests in
    /// TIME_WAIT. The first attempt fails with <see cref="SocketError.AddressAlreadyInUse"/>, a fresh
    /// socket connects, and the host's answer arrives; the retry is observed through the client's
    /// <see cref="LoopbackKestrelDiagnostics"/> by the invariant of
    /// <see cref="AssertRetriedAfterTheFirstAttempt"/>. The row pins the Windows behaviour.
    /// <see cref="PinnedClientWithOneConnectAttemptFailsWithAddressAlreadyInUseOnAFourTupleInTimeWait"/>
    /// is the same request with a single attempt allowed.
    /// </summary>
    [TestMethod]
    [OSCondition(OperatingSystems.Windows)]
    public async Task PinnedClientGetsTheResponseWhenItsFirstConnectMeetsAFourTupleInTimeWait()
    {
        await using MinimalHttpHost host = await StartLoopbackOkHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        IPEndPoint hostEndPoint = new(IPAddress.Loopback, host.BaseAddress.Port);
        IPEndPoint timeWaitLocalEndPoint = await LeaveFourTupleInTimeWaitAsync(hostEndPoint, listener: null, TestContext.CancellationToken)
            .ConfigureAwait(false);

        using LoopbackKestrelDiagnostics diagnostics = LoopbackKestrelDiagnostics.CreateIsolated();
        List<int> preparedAttempts = [];
        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(
            [host.Certificate],
            LoopbackConnect.DefaultMaxAttempts,
            RecordAttemptsAndBindTheFirstTo(timeWaitLocalEndPoint, preparedAttempts),
            diagnostics);

        using HttpResponseMessage response = await client.GetAsync(host.BaseAddress, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, "The host's answer must arrive over the connection the retry opened.");
        Assert.AreEqual(LoopbackOkBody, body, "The host's answer must carry the body the host wrote.");
        AssertRetriedAfterTheFirstAttempt(preparedAttempts, diagnostics.Captured, $"{host.BaseAddress.Host}:{host.BaseAddress.Port}");
    }


    /// <summary>
    /// The same request as <see cref="PinnedClientGetsTheResponseWhenItsFirstConnectMeetsAFourTupleInTimeWait"/>
    /// through a client that allows <see cref="LoopbackConnect"/> a single connect attempt: that attempt,
    /// bound to the local port whose four-tuple with the host's port rests in TIME_WAIT, fails, and the
    /// client surfaces an <see cref="HttpRequestException"/> whose inner <see cref="SocketException"/> is
    /// <see cref="SocketError.AddressAlreadyInUse"/>, the failure a test client meets without the retry.
    /// No retry line is written and no second socket is prepared. The row pins the Windows behaviour.
    /// </summary>
    [TestMethod]
    [OSCondition(OperatingSystems.Windows)]
    public async Task PinnedClientWithOneConnectAttemptFailsWithAddressAlreadyInUseOnAFourTupleInTimeWait()
    {
        await using MinimalHttpHost host = await StartLoopbackOkHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        IPEndPoint hostEndPoint = new(IPAddress.Loopback, host.BaseAddress.Port);
        IPEndPoint timeWaitLocalEndPoint = await LeaveFourTupleInTimeWaitAsync(hostEndPoint, listener: null, TestContext.CancellationToken)
            .ConfigureAwait(false);

        using LoopbackKestrelDiagnostics diagnostics = LoopbackKestrelDiagnostics.CreateIsolated();
        List<int> preparedAttempts = [];
        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(
            [host.Certificate],
            maxConnectAttempts: 1,
            RecordAttemptsAndBindTheFirstTo(timeWaitLocalEndPoint, preparedAttempts),
            diagnostics);

        HttpRequestException failure = await Assert.ThrowsExactlyAsync<HttpRequestException>(
            async () => await client.GetAsync(host.BaseAddress, TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);

        SocketException socketFailure = Assert.IsInstanceOfType<SocketException>(failure.InnerException,
            $"The request must fail at the connect. Actual: '{failure}'.");
        Assert.AreEqual(SocketError.AddressAlreadyInUse, socketFailure.SocketErrorCode,
            $"A single connect attempt over a four-tuple in TIME_WAIT must fail with AddressAlreadyInUse. Actual: '{socketFailure.Message}'.");
        Assert.HasCount(1, preparedAttempts, "A single attempt must be prepared.");
        Assert.AreEqual(1, preparedAttempts[0], "The prepared socket must be the first attempt.");
        Assert.IsEmpty(diagnostics.Captured, "No retry line may be written when no retry is allowed.");
    }


    /// <summary>
    /// Proves the last attempt's failure leaves <see cref="LoopbackConnect.ConnectAsync(EndPoint, int, Action{Socket, int}?, LoopbackKestrelDiagnostics, CancellationToken)"/>
    /// unchanged: with one attempt allowed and that attempt bound to a local port whose four-tuple with
    /// the listener rests in TIME_WAIT, the <see cref="SocketException"/> with
    /// <see cref="SocketError.AddressAlreadyInUse"/> leaves the body, the preparation sees the first
    /// attempt only, and no retry line is written. The row pins the Windows behaviour.
    /// </summary>
    [TestMethod]
    [OSCondition(OperatingSystems.Windows)]
    public async Task ConnectWithOneAttemptLeavesAddressAlreadyInUseWithoutARetry()
    {
        using Socket listener = CreateLoopbackListener();
        IPEndPoint listenerEndPoint = (IPEndPoint)listener.LocalEndPoint!;
        IPEndPoint timeWaitLocalEndPoint = await LeaveFourTupleInTimeWaitAsync(listener, TestContext.CancellationToken)
            .ConfigureAwait(false);

        using LoopbackKestrelDiagnostics diagnostics = LoopbackKestrelDiagnostics.CreateIsolated();
        List<int> preparedAttempts = [];
        SocketException failure = await Assert.ThrowsExactlyAsync<SocketException>(
            async () =>
            {
                using Socket connected = await LoopbackConnect.ConnectAsync(
                    listenerEndPoint,
                    maxAttempts: 1,
                    RecordAttemptsAndBindTheFirstTo(timeWaitLocalEndPoint, preparedAttempts),
                    diagnostics,
                    TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

        Assert.AreEqual(SocketError.AddressAlreadyInUse, failure.SocketErrorCode,
            $"The last attempt's failure must leave unchanged. Actual: '{failure.Message}'.");
        Assert.HasCount(1, preparedAttempts, "A single attempt must be prepared.");
        Assert.AreEqual(1, preparedAttempts[0], "The prepared socket must be the first attempt.");
        Assert.IsEmpty(diagnostics.Captured, "No retry line may be written for the last attempt's failure.");
    }


    /// <summary>
    /// Proves a failure other than <see cref="SocketError.AddressAlreadyInUse"/> leaves
    /// <see cref="LoopbackConnect.ConnectAsync(EndPoint, int, Action{Socket, int}?, LoopbackKestrelDiagnostics, CancellationToken)"/>
    /// at the attempt it occurs on, whatever the attempt count: a connect to a loopback port that nothing
    /// listens on, allowed <see cref="LoopbackConnect.DefaultMaxAttempts"/> attempts, leaves a
    /// <see cref="SocketException"/> with <see cref="SocketError.ConnectionRefused"/> at the first
    /// attempt, with no retry line. The port is held by a socket that is bound and never listens, so no
    /// other listener can take it while the row runs.
    /// </summary>
    [TestMethod]
    public async Task ConnectToALoopbackPortNothingListensOnLeavesConnectionRefusedAtTheFirstAttempt()
    {
        using Socket portHolder = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        portHolder.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        IPEndPoint closedEndPoint = (IPEndPoint)portHolder.LocalEndPoint!;

        using LoopbackKestrelDiagnostics diagnostics = LoopbackKestrelDiagnostics.CreateIsolated();
        List<int> preparedAttempts = [];
        SocketException failure = await Assert.ThrowsExactlyAsync<SocketException>(
            async () =>
            {
                using Socket connected = await LoopbackConnect.ConnectAsync(
                    closedEndPoint,
                    LoopbackConnect.DefaultMaxAttempts,
                    (_, attempt) => preparedAttempts.Add(attempt),
                    diagnostics,
                    TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

        Assert.AreEqual(SocketError.ConnectionRefused, failure.SocketErrorCode,
            $"A connect to a port nothing listens on must leave ConnectionRefused. Actual: '{failure.Message}'.");
        Assert.HasCount(1, preparedAttempts, "A refused connect must not be retried.");
        Assert.AreEqual(1, preparedAttempts[0], "The refused connect must be the first attempt.");
        Assert.IsEmpty(diagnostics.Captured, "No retry line may be written for a failure other than AddressAlreadyInUse.");
    }


    /// <summary>
    /// Proves the pinning of <see cref="LoopbackTls.CreatePinnedHandler(IReadOnlyCollection{X509Certificate2}, int, Action{Socket, int}?, LoopbackKestrelDiagnostics)"/>
    /// refuses a leaf it is not pinned to: a client pinned to a certificate from
    /// <see cref="LoopbackTls.CreateDistinctServerCertificate"/> dials a <see cref="MinimalHttpHost"/> that
    /// presents another certificate, and the request fails with an <see cref="HttpRequestException"/>
    /// whose inner exception is an <see cref="AuthenticationException"/>. The client refuses any leaf
    /// that is not pinned and reads no policy error, so no certificate authority and no disabled
    /// validation can stand in for the pin.
    /// </summary>
    [TestMethod]
    public async Task PinnedClientRefusesAHostPresentingACertificateItIsNotPinnedTo()
    {
        await using MinimalHttpHost host = await StartLoopbackOkHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using X509Certificate2 otherCertificate = LoopbackTls.CreateDistinctServerCertificate("loopback-pinning-refusal-probe");
        Assert.IsFalse(otherCertificate.RawData.AsSpan().SequenceEqual(host.Certificate.RawData),
            "The pinned certificate must differ from the one the host presents.");

        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(otherCertificate);
        HttpRequestException failure = await Assert.ThrowsExactlyAsync<HttpRequestException>(
            async () => await client.GetAsync(host.BaseAddress, TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);

        _ = Assert.IsInstanceOfType<AuthenticationException>(failure.InnerException,
            $"A host presenting a leaf the client is not pinned to must fail the TLS handshake. Actual: '{failure}'.");
    }


    /// <summary>
    /// Opens a TCP listener on <see cref="IPAddress.Loopback"/> at a port the operating system assigns.
    /// </summary>
    private static Socket CreateLoopbackListener()
    {
        Socket listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen();

        return listener;
    }


    /// <summary>
    /// Connects a client socket to <paramref name="listener"/>, sends one byte the accepted side reads,
    /// and closes the client side first, through
    /// <see cref="LeaveFourTupleInTimeWaitAsync(IPEndPoint, Socket?, CancellationToken)"/>.
    /// </summary>
    /// <param name="listener">The loopback listener the client connects to.</param>
    /// <param name="cancellationToken">The test's cancellation token.</param>
    /// <returns>The client's local endpoint, whose four-tuple with the listener rests in TIME_WAIT.</returns>
    private static Task<IPEndPoint> LeaveFourTupleInTimeWaitAsync(Socket listener, CancellationToken cancellationToken) =>
        LeaveFourTupleInTimeWaitAsync((IPEndPoint)listener.LocalEndPoint!, listener, cancellationToken);


    /// <summary>
    /// Connects a client socket bound to a loopback port the operating system assigns to
    /// <paramref name="destination"/> and closes the client side first, so the four-tuple of the
    /// connection rests in TIME_WAIT on the client side when this method returns. With a
    /// <paramref name="listener"/>, this method drives the accepted side: the client sends one byte the
    /// accepted side reads, shuts down its send direction, the accepted side reads the end of the stream
    /// and shuts down its own, and the client reads that end. Without one, the destination is a
    /// <see cref="MinimalHttpHost"/>: the client shuts down its send direction before any TLS ClientHello,
    /// the host ends its handshake on the end of the stream and closes its side, and the client reads
    /// that end. Either way the client is the active closer.
    /// </summary>
    /// <param name="destination">The loopback endpoint the client connects to.</param>
    /// <param name="listener">
    /// The raw listener behind <paramref name="destination"/> whose accepted side this method drives, or
    /// <see langword="null"/> when a host behind it closes its own side.
    /// </param>
    /// <param name="cancellationToken">The test's cancellation token.</param>
    /// <returns>The client's local endpoint, whose four-tuple with the destination rests in TIME_WAIT.</returns>
    private static async Task<IPEndPoint> LeaveFourTupleInTimeWaitAsync(IPEndPoint destination, Socket? listener, CancellationToken cancellationToken)
    {
        using Socket client = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        await client.ConnectAsync(destination, cancellationToken).ConfigureAwait(false);
        using Socket? accepted = listener is null ? null : await listener.AcceptAsync(cancellationToken).ConfigureAwait(false);

        byte[] received = new byte[1];
        if(accepted is not null)
        {
            byte[] exchanged = [0x2A];
            int sentCount = await client.SendAsync(exchanged, SocketFlags.None, cancellationToken).ConfigureAwait(false);
            int receivedCount = await accepted.ReceiveAsync(received, SocketFlags.None, cancellationToken).ConfigureAwait(false);
            Assert.AreEqual(1, sentCount, "The client must send its one byte.");
            Assert.AreEqual(1, receivedCount, "The accepted side must read the client's one byte.");
            Assert.AreEqual(exchanged[0], received[0], "The accepted side must read the byte the client sent.");
        }

        //The client closes first, which makes it the side that holds the four-tuple in TIME_WAIT.
        client.Shutdown(SocketShutdown.Send);
        if(accepted is not null)
        {
            int acceptedEndCount = await accepted.ReceiveAsync(received, SocketFlags.None, cancellationToken).ConfigureAwait(false);
            Assert.AreEqual(0, acceptedEndCount, "The accepted side must read the end of the client's stream.");
            accepted.Shutdown(SocketShutdown.Send);
        }

        int clientEndCount = await client.ReceiveAsync(received, SocketFlags.None, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(0, clientEndCount, "The client must read the end of the peer's stream.");

        return (IPEndPoint)client.LocalEndPoint!;
    }


    /// <summary>
    /// The preparation every row that meets a four-tuple in TIME_WAIT hands
    /// <see cref="LoopbackConnect.ConnectAsync(EndPoint, int, Action{Socket, int}?, LoopbackKestrelDiagnostics, CancellationToken)"/>:
    /// records each attempt's number in <paramref name="preparedAttempts"/> and binds the first
    /// attempt's socket to <paramref name="timeWaitLocalEndPoint"/>; later attempts are left to the
    /// operating system's choice of local port.
    /// </summary>
    /// <param name="timeWaitLocalEndPoint">The local endpoint whose four-tuple with the destination rests in TIME_WAIT.</param>
    /// <param name="preparedAttempts">Receives the number of every prepared attempt, in order.</param>
    /// <returns>The preparation delegate.</returns>
    private static Action<Socket, int> RecordAttemptsAndBindTheFirstTo(IPEndPoint timeWaitLocalEndPoint, List<int> preparedAttempts) =>
        (socket, attempt) =>
        {
            preparedAttempts.Add(attempt);
            if(attempt == 1)
            {
                socket.Bind(timeWaitLocalEndPoint);
            }
        };


    /// <summary>
    /// Asserts the invariant of a connect whose first attempt met a four-tuple in TIME_WAIT and that
    /// connected on a later attempt: the attempts start with 1 and 2 and run in order; their count is
    /// at most <see cref="LoopbackConnect.DefaultMaxAttempts"/>; the captured lines number one fewer
    /// than the attempts; and the first line carries the retry event's name, the destination, and
    /// attempt 1 of <see cref="LoopbackConnect.DefaultMaxAttempts"/>. A fresh socket's local port may
    /// itself meet a four-tuple in TIME_WAIT, so no exact total is asserted.
    /// </summary>
    /// <param name="preparedAttempts">The attempt numbers the preparation saw, in order.</param>
    /// <param name="capturedLines">The lines the connect's diagnostics captured.</param>
    /// <param name="destinationText">The text the retry line names the destination by.</param>
    private static void AssertRetriedAfterTheFirstAttempt(List<int> preparedAttempts, IReadOnlyList<string> capturedLines, string destinationText)
    {
        Assert.IsGreaterThanOrEqualTo(2, preparedAttempts.Count,
            "The first attempt must fail on the four-tuple in TIME_WAIT and a later attempt must connect.");
        Assert.IsLessThanOrEqualTo(LoopbackConnect.DefaultMaxAttempts, preparedAttempts.Count,
            "The attempts must not exceed the body's bound.");
        for(int index = 0; index < preparedAttempts.Count; index++)
        {
            Assert.AreEqual(index + 1, preparedAttempts[index], "The prepared attempts must run 1, 2, and on in order.");
        }

        Assert.HasCount(preparedAttempts.Count - 1, capturedLines, "Every attempt before the connecting one must write one retry line.");
        string firstLine = capturedLines[0];
        Assert.IsTrue(firstLine.Contains(LoopbackConnect.RetriedAfterAddressInUseEventId.Name!, StringComparison.Ordinal),
            $"The retry line must carry the retry event's name. Actual: '{firstLine}'.");
        Assert.IsTrue(firstLine.Contains(destinationText, StringComparison.Ordinal),
            $"The retry line must name the destination. Actual: '{firstLine}'.");
        Assert.IsTrue(firstLine.Contains($"attempt 1 of {LoopbackConnect.DefaultMaxAttempts}", StringComparison.Ordinal),
            $"The first retry line must name the first attempt. Actual: '{firstLine}'.");
    }


    /// <summary>The body the host of <see cref="StartLoopbackOkHostAsync"/> answers every request with.</summary>
    private static string LoopbackOkBody { get; } = "loopback-ok";


    /// <summary>
    /// Starts a <see cref="MinimalHttpHost"/> that answers every request with status 200 and
    /// <see cref="LoopbackOkBody"/>, presenting the shared certificate of
    /// <see cref="LoopbackTls.CreateServerCertificate"/>.
    /// </summary>
    /// <param name="cancellationToken">The test's cancellation token.</param>
    /// <returns>The started host, owned by the caller.</returns>
    private static Task<MinimalHttpHost> StartLoopbackOkHostAsync(CancellationToken cancellationToken) =>
        MinimalHttpHost.StartAsync(
            (request, requestCancellationToken) => Task.FromResult(new MinimalHttpResponse
            {
                StatusCode = 200,
                ContentType = "text/plain",
                Body = LoopbackOkBody
            }),
            cancellationToken);
}
