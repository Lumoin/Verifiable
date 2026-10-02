using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The one home for the loopback HTTPS machinery every Kestrel-hosted test fixture in this repository
/// shares: minting an ephemeral, in-memory self-signed server certificate for an
/// <c>https://127.0.0.1:{port}</c> listener (<see cref="CreateServerCertificate"/>), and building the
/// byte-exact pinned <see cref="HttpClient"/> that dials it (<see cref="CreatePinnedHandler(X509Certificate2)"/>,
/// <see cref="CreatePinnedHttpClient(X509Certificate2, Uri?)"/>), whose TCP connections open through
/// <see cref="LoopbackConnect"/>. <see cref="X509Certificate2"/> here is TLS transport
/// infrastructure for test hosts, not project cryptography — it never touches the
/// <c>Verifiable.Cryptography</c> key-material surface.
/// </summary>
internal static class LoopbackTls
{
    /// <summary>
    /// The ONE PKCS#12 export every non-distinct loopback host in the process loads its
    /// <see cref="CreateServerCertificate"/> instance from — minted lazily and thread-safely on the
    /// first call, so the whole suite pays for one P-256 keygen and one self-signed-leaf/PKCS#12
    /// round-trip instead of one per host.
    /// </summary>
    private static Lazy<byte[]> SharedPkcs12 { get; } = new(() => MintPkcs12Bytes("loopback-shared-test-host"));


    /// <summary>
    /// Loads a fresh <see cref="X509Certificate2"/> instance from <see cref="SharedPkcs12"/> — the
    /// certificate every non-distinct loopback HTTPS listener in this repository presents. No CA chain
    /// backs it: every client in this topology pins the leaf certificate's bytes directly
    /// (<see cref="CreatePinnedHandler(X509Certificate2)"/>) rather than validating a chain to a trust
    /// anchor, so every caller presenting the SAME leaf bytes changes no security property of the
    /// fixture. Each call returns its own disposable instance; the underlying bytes are minted once.
    /// </summary>
    /// <param name="commonName">
    /// Validated non-empty for call-site parity with <see cref="CreateDistinctServerCertificate"/>; the
    /// shared certificate's own subject was fixed when <see cref="SharedPkcs12"/> was first minted, so
    /// this argument does not select the returned certificate's identity. A caller whose topology needs
    /// a certificate distinct from every other host's calls <see cref="CreateDistinctServerCertificate"/>
    /// instead, where the common name does select the subject.
    /// </param>
    internal static X509Certificate2 CreateServerCertificate(string commonName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(commonName);

        return X509CertificateLoader.LoadPkcs12(SharedPkcs12.Value, password: null, X509KeyStorageFlags.Exportable);
    }


    /// <summary>
    /// Mints a genuinely fresh self-signed leaf certificate on every call, subject <c>CN={commonName}</c>
    /// — for a host type of which one test method may start several instances that must remain mutually
    /// distinct TLS identities (a pinning-rejection proof needs a genuinely untrusted second party; a
    /// multi-party topology needs each of its several same-type parties to differ from one another), or
    /// for a single shell's opt-in to a distinct per-host identity
    /// (<see cref="Verifiable.Tests.OAuth.TestHostShell.AddHost(string, bool)"/> with
    /// <c>useDistinctCertificate: true</c>) — rather than sharing <see cref="CreateServerCertificate"/>'s
    /// single process-wide leaf. Otherwise identical to <see cref="CreateServerCertificate"/>: same SAN
    /// forms, same key usage, same validity window.
    /// </summary>
    /// <param name="commonName">The certificate subject's common name, e.g. <c>oauth-loopback-as2</c>.</param>
    internal static X509Certificate2 CreateDistinctServerCertificate(string commonName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(commonName);

        return X509CertificateLoader.LoadPkcs12(MintPkcs12Bytes(commonName), password: null, X509KeyStorageFlags.Exportable);
    }


    /// <summary>
    /// Builds one self-signed leaf certificate's PKCS#12 bytes, subject <c>CN={commonName}</c>, covering
    /// both SAN forms a loopback client may dial (the <c>localhost</c> DNS name and the <c>127.0.0.1</c>
    /// IP address), with digital-signature/key-encipherment key usage, a server-auth EKU, and validity
    /// anchored to <see cref="TestClock.CanonicalEpoch"/>. Shared by <see cref="SharedPkcs12"/> (minted
    /// once) and <see cref="CreateDistinctServerCertificate"/> (minted fresh every call).
    /// </summary>
    /// <param name="commonName">The certificate subject's common name.</param>
    /// <remarks>
    /// <see cref="CertificateRequest.CreateSelfSigned"/> returns a certificate backed by an EPHEMERAL,
    /// in-memory CNG key; the platform TLS stack refuses to use an ephemeral key as a SERVER credential
    /// ("the platform does not support ephemeral keys"). Round-tripping the certificate through a
    /// PKCS#12 export/reload gives it a persisted key container Kestrel's
    /// <see cref="System.Net.Security.SslStream"/> server authentication can actually use.
    /// </remarks>
    private static byte[] MintPkcs12Bytes(string commonName)
    {
        //Cert-factory carve-out: CertificateRequest requires a framework AsymmetricAlgorithm
        //to sign the self-signed leaf certificate; this key is never converted to library
        //PrivateKeyMemory, so it stays framework-native for its whole lifetime.
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new($"CN={commonName}", key, HashAlgorithmName.SHA256);

        SubjectAlternativeNameBuilder sanBuilder = new();
        sanBuilder.AddDnsName("localhost");
        sanBuilder.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(sanBuilder.Build(critical: false));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));

        OidCollection serverAuthEku = [new Oid("1.3.6.1.5.5.7.3.1")];
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(serverAuthEku, critical: false));

        DateTimeOffset now = TestClock.CanonicalEpoch;

        using X509Certificate2 ephemeral = request.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(1));

        return ephemeral.Export(X509ContentType.Pfx);
    }


    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> whose TLS validation pins to
    /// <paramref name="pinnedCertificate"/> byte-for-byte rather than trusting a certificate authority,
    /// and whose TCP connections open through <see cref="LoopbackConnect.ConnectAsync(EndPoint, CancellationToken)"/>.
    /// There is no CA in this loopback test topology, and validation is never disabled: the callback
    /// always runs and answers strictly from the pinned certificate's raw bytes
    /// (<see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>),
    /// never from <c>sslPolicyErrors</c>.
    /// </summary>
    /// <param name="pinnedCertificate">The exact certificate the loopback listener presents.</param>
    internal static SocketsHttpHandler CreatePinnedHandler(X509Certificate2 pinnedCertificate)
    {
        ArgumentNullException.ThrowIfNull(pinnedCertificate);

        return CreatePinnedHandler([pinnedCertificate]);
    }


    /// <summary>
    /// Builds a <see cref="SocketsHttpHandler"/> whose TLS validation pins to any ONE of
    /// <paramref name="pinnedCertificates"/> byte-for-byte, the multi-party counterpart to
    /// <see cref="CreatePinnedHandler(X509Certificate2)"/> for a single test-side client that dials
    /// several distinct loopback listeners, each presenting its own leaf certificate. Every candidate
    /// is checked by exact byte comparison; no CA and no disabled validation, exactly like the
    /// single-certificate overload. The handler's <see cref="SocketsHttpHandler.ConnectCallback"/> opens
    /// each connection through <see cref="ConnectThroughLoopbackAsync"/> with
    /// <see cref="LoopbackConnect.DefaultMaxAttempts"/>, no preparation and
    /// <see cref="LoopbackKestrelDiagnostics.Provider"/>: a listener port and a local port are both reused
    /// within the operating system's TIME_WAIT period, so a connect can meet a four-tuple that rests in
    /// it, and <see cref="LoopbackConnect"/> answers that with an immediate attempt on a fresh socket.
    /// Every other setting is the handler's default.
    /// </summary>
    /// <param name="pinnedCertificates">The exact certificates the loopback listeners present.</param>
    internal static SocketsHttpHandler CreatePinnedHandler(IReadOnlyCollection<X509Certificate2> pinnedCertificates) =>
        CreatePinnedHandler(pinnedCertificates, LoopbackConnect.DefaultMaxAttempts, prepareConnectAttempt: null, LoopbackKestrelDiagnostics.Provider);


    /// <summary>
    /// The one body of every pinned handler this class builds: a <see cref="SocketsHttpHandler"/> whose
    /// TLS validation pins to any ONE of <paramref name="pinnedCertificates"/> byte-for-byte and whose
    /// <see cref="SocketsHttpHandler.ConnectCallback"/> opens each TCP connection through
    /// <see cref="LoopbackConnect.ConnectAsync(EndPoint, int, Action{Socket, int}?, LoopbackKestrelDiagnostics, CancellationToken)"/>
    /// with the given connect options. <see cref="CreatePinnedHandler(IReadOnlyCollection{X509Certificate2})"/>
    /// passes <see cref="LoopbackConnect.DefaultMaxAttempts"/>, no preparation and
    /// <see cref="LoopbackKestrelDiagnostics.Provider"/>; a row that proves the handler's connect passes
    /// its own attempt count, a preparation that binds an attempt's socket, and an isolated
    /// <see cref="LoopbackKestrelDiagnostics"/> it reads back. The pinning rule is the same for every
    /// option: a missing certificate fails, a byte-exact match against a pinned leaf passes, and
    /// <c>sslPolicyErrors</c> is never read.
    /// </summary>
    /// <param name="pinnedCertificates">The exact certificates the loopback listeners present.</param>
    /// <param name="maxConnectAttempts">The number of attempts each connect makes, at least one.</param>
    /// <param name="prepareConnectAttempt">
    /// Prepares an attempt's socket before its connect, given the socket and the one-based attempt
    /// number; <see langword="null"/> prepares nothing.
    /// </param>
    /// <param name="connectDiagnostics">Receives the line each connect retry writes.</param>
    internal static SocketsHttpHandler CreatePinnedHandler(
        IReadOnlyCollection<X509Certificate2> pinnedCertificates,
        int maxConnectAttempts,
        Action<Socket, int>? prepareConnectAttempt,
        LoopbackKestrelDiagnostics connectDiagnostics)
    {
        ArgumentNullException.ThrowIfNull(pinnedCertificates);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxConnectAttempts, 1);
        ArgumentNullException.ThrowIfNull(connectDiagnostics);

        return new SocketsHttpHandler
        {
            ConnectCallback = (context, cancellationToken) =>
                ConnectThroughLoopbackAsync(context, maxConnectAttempts, prepareConnectAttempt, connectDiagnostics, cancellationToken),
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
                {
                    if(certificate is null)
                    {
                        return false;
                    }

                    byte[] presentedBytes = certificate.GetRawCertData();
                    foreach(X509Certificate2 pinnedCertificate in pinnedCertificates)
                    {
                        if(CryptographicOperations.FixedTimeEquals(presentedBytes, pinnedCertificate.RawData))
                        {
                            return true;
                        }
                    }

                    return false;
                }
            }
        };
    }


    /// <summary>
    /// The <see cref="SocketsHttpHandler.ConnectCallback"/> of every handler
    /// <see cref="CreatePinnedHandler(IReadOnlyCollection{X509Certificate2}, int, Action{Socket, int}?, LoopbackKestrelDiagnostics)"/>
    /// builds: opens the TCP connection to the request's <see cref="SocketsHttpConnectionContext.DnsEndPoint"/>
    /// through <see cref="LoopbackConnect.ConnectAsync(EndPoint, int, Action{Socket, int}?, LoopbackKestrelDiagnostics, CancellationToken)"/>
    /// with the handler's connect options and hands the handler a <see cref="NetworkStream"/> that owns
    /// the socket, which is what the handler builds itself when no callback is set.
    /// </summary>
    /// <param name="context">The connection's context, carrying the destination.</param>
    /// <param name="maxConnectAttempts">The number of attempts the connect makes.</param>
    /// <param name="prepareConnectAttempt">Prepares an attempt's socket before its connect, or <see langword="null"/>.</param>
    /// <param name="connectDiagnostics">Receives the line each retry writes.</param>
    /// <param name="cancellationToken">Cancels the connect.</param>
    /// <returns>The stream over the connected socket.</returns>
    private static async ValueTask<Stream> ConnectThroughLoopbackAsync(
        SocketsHttpConnectionContext context,
        int maxConnectAttempts,
        Action<Socket, int>? prepareConnectAttempt,
        LoopbackKestrelDiagnostics connectDiagnostics,
        CancellationToken cancellationToken)
    {
        Socket socket = await LoopbackConnect.ConnectAsync(
            context.DnsEndPoint, maxConnectAttempts, prepareConnectAttempt, connectDiagnostics, cancellationToken).ConfigureAwait(false);

        return new NetworkStream(socket, ownsSocket: true);
    }


    /// <summary>
    /// Builds an <see cref="HttpClient"/> pinned to <paramref name="pinnedCertificate"/> via
    /// <see cref="CreatePinnedHandler(X509Certificate2)"/>. When <paramref name="baseAddress"/> is supplied it
    /// becomes the client's <see cref="HttpClient.BaseAddress"/>, so callers can issue relative-URI requests
    /// against the loopback host.
    /// </summary>
    /// <param name="pinnedCertificate">The exact certificate the loopback listener presents.</param>
    /// <param name="baseAddress">The loopback host's base address, or <see langword="null"/> to leave it unset.</param>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "HttpClient takes ownership of the handler (default disposeHandler: true) and disposes it when the returned client is disposed.")]
    internal static HttpClient CreatePinnedHttpClient(X509Certificate2 pinnedCertificate, Uri? baseAddress = null)
    {
        HttpClient client = new(CreatePinnedHandler(pinnedCertificate));
        if(baseAddress is not null)
        {
            client.BaseAddress = baseAddress;
        }

        return client;
    }


    /// <summary>
    /// Builds an <see cref="HttpClient"/> pinned to <paramref name="pinnedCertificate"/> with
    /// auto-redirect disabled, satisfying the single-hop contract on
    /// <see cref="Verifiable.Core.Outbound.OutboundTransportDelegate"/>: the guarded
    /// <c>OutboundFetch</c> chokepoint must be the only redirect authority, so the framework must
    /// never silently follow a 3xx before the policy sees it. Use this for clients wrapped by
    /// <c>GuardedHttpClientTransport.BuildSingleHopTransport</c>.
    /// </summary>
    /// <param name="pinnedCertificate">The exact certificate the loopback listener presents.</param>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "HttpClient takes ownership of the handler (default disposeHandler: true) and disposes it when the returned client is disposed.")]
    internal static HttpClient CreateSingleHopPinnedHttpClient(X509Certificate2 pinnedCertificate)
    {
        SocketsHttpHandler handler = CreatePinnedHandler(pinnedCertificate);
        handler.AllowAutoRedirect = false;

        return new HttpClient(handler);
    }


    /// <summary>
    /// Builds an <see cref="HttpClient"/> pinned to any ONE of <paramref name="pinnedCertificates"/> via
    /// <see cref="CreatePinnedHandler(IReadOnlyCollection{X509Certificate2})"/> — for a single test-side client
    /// that dials several distinct loopback listeners (for example an Issuer and a Discloser party in the same
    /// multi-server flow), each presenting its own leaf certificate.
    /// </summary>
    /// <param name="pinnedCertificates">The exact certificates the loopback listeners present.</param>
    internal static HttpClient CreatePinnedHttpClient(IReadOnlyCollection<X509Certificate2> pinnedCertificates) =>
        CreatePinnedHttpClient(pinnedCertificates, LoopbackConnect.DefaultMaxAttempts, prepareConnectAttempt: null, LoopbackKestrelDiagnostics.Provider);


    /// <summary>
    /// Builds an <see cref="HttpClient"/> over
    /// <see cref="CreatePinnedHandler(IReadOnlyCollection{X509Certificate2}, int, Action{Socket, int}?, LoopbackKestrelDiagnostics)"/>,
    /// pinned to any ONE of <paramref name="pinnedCertificates"/> and connecting with the given connect
    /// options; <see cref="CreatePinnedHttpClient(IReadOnlyCollection{X509Certificate2})"/> calls it with
    /// the defaults.
    /// </summary>
    /// <param name="pinnedCertificates">The exact certificates the loopback listeners present.</param>
    /// <param name="maxConnectAttempts">The number of attempts each connect makes, at least one.</param>
    /// <param name="prepareConnectAttempt">Prepares an attempt's socket before its connect, or <see langword="null"/>.</param>
    /// <param name="connectDiagnostics">Receives the line each connect retry writes.</param>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "HttpClient takes ownership of the handler (default disposeHandler: true) and disposes it when the returned client is disposed.")]
    internal static HttpClient CreatePinnedHttpClient(
        IReadOnlyCollection<X509Certificate2> pinnedCertificates,
        int maxConnectAttempts,
        Action<Socket, int>? prepareConnectAttempt,
        LoopbackKestrelDiagnostics connectDiagnostics) =>
        new(CreatePinnedHandler(pinnedCertificates, maxConnectAttempts, prepareConnectAttempt, connectDiagnostics));


    /// <summary>
    /// Builds an <see cref="HttpClient"/> pinned to any ONE of <paramref name="pinnedCertificates"/> with
    /// auto-redirect disabled — the multi-listener counterpart to
    /// <see cref="CreateSingleHopPinnedHttpClient(X509Certificate2)"/>, for a client that dials several
    /// distinct loopback listeners while every 3xx must surface to the caller: a guarded
    /// <c>OutboundFetch</c> transport whose policy is the only redirect authority, or a browser stand-in
    /// whose test parses the redirect <c>Location</c> itself.
    /// </summary>
    /// <param name="pinnedCertificates">The exact certificates the loopback listeners present.</param>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "HttpClient takes ownership of the handler (default disposeHandler: true) and disposes it when the returned client is disposed.")]
    internal static HttpClient CreateSingleHopPinnedHttpClient(IReadOnlyCollection<X509Certificate2> pinnedCertificates)
    {
        SocketsHttpHandler handler = CreatePinnedHandler(pinnedCertificates);
        handler.AllowAutoRedirect = false;

        return new HttpClient(handler);
    }
}
