using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.TestDataProviders;

/// <summary>
/// Holds the DER-encoded certificates and signing key for a test certificate chain.
/// Returned by <see cref="TestCertificateChainProvider"/>. The caller owns all
/// instances and must dispose them.
/// </summary>
/// <param name="CaDerBytes">
/// DER-encoded root CA certificate. Used as the trust anchor.
/// </param>
/// <param name="LeafDerBytes">
/// DER-encoded leaf certificate. Carries the DNS SAN and is signed by the CA.
/// </param>
/// <param name="LeafSigningKey">
/// The leaf certificate's private signing key. Used to sign JARs in tests.
/// </param>
/// <param name="DnsName">
/// The DNS name in the leaf certificate's Subject Alternative Name extension.
/// </param>
internal sealed record CertificateChainMaterial(
    PkiCertificateMemory CaDerBytes,
    PkiCertificateMemory LeafDerBytes,
    PrivateKeyMemory LeafSigningKey,
    string DnsName): IDisposable
{
    private bool disposed;

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            CaDerBytes.Dispose();
            LeafDerBytes.Dispose();
            LeafSigningKey.Dispose();
            disposed = true;
        }
    }
}
