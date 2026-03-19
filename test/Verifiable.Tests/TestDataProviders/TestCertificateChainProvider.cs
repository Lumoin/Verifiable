using System.Buffers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;

namespace Verifiable.Tests.TestDataProviders;

/// <summary>
/// Provides X.509 certificate chain material for tests. Each call generates a new
/// chain using the supplied <see cref="TimeProvider"/> so that certificate validity
/// windows are always anchored to the test's notion of current time.
/// </summary>
/// <remarks>
/// <para>
/// Unlike <see cref="TestKeyMaterialProvider"/>, chains are not cached. Certificate
/// generation is inexpensive and caching would require a fixed clock assumption.
/// </para>
/// <para>
/// The DER bytes are loaded through <see cref="MicrosoftX509Functions.ParseX5c"/> —
/// the library's own loading facilities — rather than being held as raw arrays.
/// This mirrors how an application would load trust anchors from configuration or
/// a trust store at startup.
/// </para>
/// </remarks>
internal static class TestCertificateChainProvider
{
    /// <summary>
    /// DNS name used in the default P-256 test chain's Subject Alternative Name extension.
    /// </summary>
    public const string P256DnsName = "verifier.example.com";


    /// <summary>
    /// Generates a fresh P-256 single-CA chain with a leaf certificate carrying
    /// <see cref="P256DnsName"/> as its DNS SAN entry.
    /// </summary>
    /// <param name="timeProvider">
    /// Provides the current time for certificate validity windows. Pass the same
    /// <see cref="TimeProvider"/> used throughout the test so that the generated
    /// certificates are valid at the time the chain validator will evaluate them.
    /// </param>
    public static CertificateChainMaterial CreateP256ChainMaterial(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);

        (byte[] caDer, byte[] leafDer, byte[] leafPrivKeyBytes) =
            GenerateP256Chain(P256DnsName, timeProvider);
        return BuildMaterial(caDer, leafDer, leafPrivKeyBytes, P256DnsName);
    }


    /// <summary>
    /// Generates a fresh P-256 chain with the given DNS name. Use when tests require
    /// a chain distinct from the default, for example for wrong-SAN scenarios.
    /// </summary>
    /// <param name="dnsName">The DNS name to embed in the leaf certificate's SAN extension.</param>
    /// <param name="timeProvider">Provides the current time for certificate validity windows.</param>
    public static CertificateChainMaterial CreateFreshP256ChainMaterial(
        string dnsName,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(dnsName);
        ArgumentNullException.ThrowIfNull(timeProvider);

        (byte[] caDer, byte[] leafDer, byte[] leafPrivKeyBytes) =
            GenerateP256Chain(dnsName, timeProvider);
        return BuildMaterial(caDer, leafDer, leafPrivKeyBytes, dnsName);
    }


    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability",
        "CA2000:Dispose objects before losing scope",
        Justification = "privateKeyOwner ownership is transferred to PrivateKeyMemory which disposes it.")]
    private static CertificateChainMaterial BuildMaterial(
        byte[] caDer,
        byte[] leafDer,
        byte[] leafPrivKeyBytes,
        string dnsName)
    {
        //Load through the library's own facilities — ParseX5c is how an application
        //would supply the x5c chain at startup from configuration.
        IReadOnlyList<PkiCertificateMemory> caChain =
            MicrosoftX509Functions.ParseX5c(
                [Convert.ToBase64String(caDer)],
                SensitiveMemoryPool<byte>.Shared);

        IReadOnlyList<PkiCertificateMemory> leafChain;
        try
        {
            leafChain = MicrosoftX509Functions.ParseX5c(
                [Convert.ToBase64String(leafDer)],
                SensitiveMemoryPool<byte>.Shared);
        }
        catch
        {
            caChain[0].Dispose();
            throw;
        }

        IMemoryOwner<byte> privateKeyOwner =
            SensitiveMemoryPool<byte>.Shared.Rent(leafPrivKeyBytes.Length);
        leafPrivKeyBytes.CopyTo(privateKeyOwner.Memory);
        PrivateKeyMemory signingKey =
            new(privateKeyOwner, CryptoTags.P256PrivateKey);

        return new CertificateChainMaterial(
            CaDerBytes: caChain[0],
            LeafDerBytes: leafChain[0],
            LeafSigningKey: signingKey,
            DnsName: dnsName);
    }


    private static (byte[] CaDer, byte[] LeafDer, byte[] LeafPrivateKeyBytes)
        GenerateP256Chain(string dnsName, TimeProvider timeProvider)
    {
        DateTimeOffset now = timeProvider.GetUtcNow();

        using ECDsa caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        CertificateRequest caRequest = new(
            "CN=Test CA, O=Verifiable Test Infrastructure",
            caKey,
            HashAlgorithmName.SHA256);

        caRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: true,
                hasPathLengthConstraint: true,
                pathLengthConstraint: 0,
                critical: true));

        caRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                critical: true));

        var caSubjectKeyId = new X509SubjectKeyIdentifierExtension(
            caRequest.PublicKey,
            X509SubjectKeyIdentifierHashAlgorithm.Sha256,
            critical: false);
        caRequest.CertificateExtensions.Add(caSubjectKeyId);

        using X509Certificate2 caCert = caRequest.CreateSelfSigned(
            notBefore: now.AddDays(-1).UtcDateTime,
            notAfter: now.AddYears(10).UtcDateTime);

        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        CertificateRequest leafRequest = new(
            $"CN={dnsName}, O=Verifiable Test Infrastructure",
            leafKey,
            HashAlgorithmName.SHA256);

        SubjectAlternativeNameBuilder sanBuilder = new();
        sanBuilder.AddDnsName(dnsName);
        leafRequest.CertificateExtensions.Add(sanBuilder.Build(critical: false));

        leafRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: false));

        leafRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature,
                critical: true));

        leafRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(
                leafRequest.PublicKey,
                X509SubjectKeyIdentifierHashAlgorithm.Sha256,
                critical: false));

        leafRequest.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(caSubjectKeyId));

        byte[] serialNumber = RandomNumberGenerator.GetBytes(8);

        using X509Certificate2 leafCertPublicOnly = leafRequest.Create(
            caCert,
            notBefore: now.AddDays(-1).UtcDateTime,
            notAfter: now.AddYears(10).UtcDateTime,
            serialNumber);

        byte[] caDer = caCert.RawData;
        byte[] leafDer = leafCertPublicOnly.RawData;
        //Export the raw D scalar — the library's signing functions expect the bare EC
        //private key scalar, not DER-encoded SEC1. ExportParameters gives it directly.
        byte[] leafPrivKeyBytes =
            leafKey.ExportParameters(includePrivateParameters: true).D!;

        return (caDer, leafDer, leafPrivKeyBytes);
    }
}
