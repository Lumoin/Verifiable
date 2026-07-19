using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The one home for the loopback HTTPS machinery every Kestrel-hosted test fixture in this repository
/// shares: minting an ephemeral, in-memory self-signed server certificate for an
/// <c>https://127.0.0.1:{port}</c> listener (<see cref="CreateServerCertificate"/>), and building the
/// byte-exact pinned <see cref="HttpClient"/> that dials it (<see cref="CreatePinnedHandler"/>,
/// <see cref="CreatePinnedHttpClient"/>). <see cref="X509Certificate2"/> here is TLS transport
/// infrastructure for test hosts, not project cryptography — it never touches the
/// <c>Verifiable.Cryptography</c> key-material surface.
/// </summary>
internal static class LoopbackTls
{
    /// <summary>
    /// Mints a fresh, minimal self-signed leaf certificate for a loopback HTTPS listener, subject
    /// <c>CN={commonName}</c>, covering both SAN forms a loopback client may dial (the <c>localhost</c>
    /// DNS name and the <c>127.0.0.1</c> IP address). No CA chain is minted: every client in this
    /// topology pins the leaf certificate's bytes directly (<see cref="CreatePinnedHandler"/>) rather
    /// than validating a chain to a trust anchor — there is no CA in a loopback test topology.
    /// </summary>
    /// <param name="commonName">The certificate subject's common name, e.g. <c>oauth-loopback-test-host</c>.</param>
    /// <remarks>
    /// <see cref="CertificateRequest.CreateSelfSigned"/> returns a certificate backed by an EPHEMERAL,
    /// in-memory CNG key; the platform TLS stack refuses to use an ephemeral key as a SERVER credential
    /// ("the platform does not support ephemeral keys"). Round-tripping the certificate through a
    /// PKCS#12 export/reload gives it a persisted key container Kestrel's
    /// <see cref="System.Net.Security.SslStream"/> server authentication can actually use.
    /// </remarks>
    internal static X509Certificate2 CreateServerCertificate(string commonName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(commonName);

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

        OidCollection serverAuthEku = new() { new Oid("1.3.6.1.5.5.7.3.1") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(serverAuthEku, critical: false));

        DateTimeOffset now = TestClock.CanonicalEpoch;

        using X509Certificate2 ephemeral = request.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(1));
        byte[] pfxBytes = ephemeral.Export(X509ContentType.Pfx);

        return X509CertificateLoader.LoadPkcs12(pfxBytes, password: null, X509KeyStorageFlags.Exportable);
    }


    /// <summary>
    /// Builds an <see cref="HttpClientHandler"/> whose TLS validation pins to
    /// <paramref name="pinnedCertificate"/> byte-for-byte rather than trusting a certificate authority.
    /// There is no CA in this loopback test topology, and validation is never disabled: the callback
    /// always runs and answers strictly from the pinned certificate's raw bytes
    /// (<see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>),
    /// never from <c>sslPolicyErrors</c>.
    /// </summary>
    /// <param name="pinnedCertificate">The exact certificate the loopback listener presents.</param>
    internal static HttpClientHandler CreatePinnedHandler(X509Certificate2 pinnedCertificate)
    {
        ArgumentNullException.ThrowIfNull(pinnedCertificate);

        return CreatePinnedHandler([pinnedCertificate]);
    }


    /// <summary>
    /// Builds an <see cref="HttpClientHandler"/> whose TLS validation pins to any ONE of
    /// <paramref name="pinnedCertificates"/> byte-for-byte — the multi-party counterpart to
    /// <see cref="CreatePinnedHandler(X509Certificate2)"/> for a single test-side client that dials
    /// several distinct loopback listeners, each presenting its own leaf certificate. Every candidate
    /// is still checked by exact byte comparison; no CA and no disabled validation, exactly like the
    /// single-certificate overload.
    /// </summary>
    /// <param name="pinnedCertificates">The exact certificates the loopback listeners present.</param>
    internal static HttpClientHandler CreatePinnedHandler(IReadOnlyCollection<X509Certificate2> pinnedCertificates)
    {
        ArgumentNullException.ThrowIfNull(pinnedCertificates);

        return new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (requestMessage, certificate, chain, sslPolicyErrors) =>
            {
                if(certificate is null)
                {
                    return false;
                }

                foreach(X509Certificate2 pinnedCertificate in pinnedCertificates)
                {
                    if(CryptographicOperations.FixedTimeEquals(certificate.RawData, pinnedCertificate.RawData))
                    {
                        return true;
                    }
                }

                return false;
            }
        };
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
    /// <see cref="Verifiable.Core.OutboundFetch.OutboundTransportDelegate"/>: the guarded
    /// <c>OutboundFetch</c> chokepoint must be the only redirect authority, so the framework must
    /// never silently follow a 3xx before the policy sees it. Use this for clients wrapped by
    /// <c>GuardedHttpClientTransport.BuildSingleHopTransport</c>.
    /// </summary>
    /// <param name="pinnedCertificate">The exact certificate the loopback listener presents.</param>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "HttpClient takes ownership of the handler (default disposeHandler: true) and disposes it when the returned client is disposed.")]
    internal static HttpClient CreateSingleHopPinnedHttpClient(X509Certificate2 pinnedCertificate)
    {
        HttpClientHandler handler = CreatePinnedHandler(pinnedCertificate);
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
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "HttpClient takes ownership of the handler (default disposeHandler: true) and disposes it when the returned client is disposed.")]
    internal static HttpClient CreatePinnedHttpClient(IReadOnlyCollection<X509Certificate2> pinnedCertificates) =>
        new(CreatePinnedHandler(pinnedCertificates));


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
        HttpClientHandler handler = CreatePinnedHandler(pinnedCertificates);
        handler.AllowAutoRedirect = false;

        return new HttpClient(handler);
    }
}
