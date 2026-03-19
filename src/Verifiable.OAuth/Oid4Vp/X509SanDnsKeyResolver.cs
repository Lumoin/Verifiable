using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Resolves the Verifier's JAR signing public key from the <c>x5c</c> JOSE header
/// for the <c>x509_san_dns:</c> Client Identifier Prefix per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3">OID4VP 1.0 §5.9.3</see>.
/// </summary>
/// <remarks>
/// <para>
/// Orchestrates three delegate-based operations supplied by the application:
/// </para>
/// <list type="number">
///   <item><description>
///     <see cref="ParseX5cDelegate"/> — decodes the base64 DER strings from the
///     JOSE header into <see cref="PkiCertificateMemory"/> instances.
///   </description></item>
///   <item><description>
///     <see cref="ValidateCertificateChainDelegate"/> — validates the chain to a
///     trusted root and extracts the leaf certificate's public key.
///   </description></item>
///   <item><description>
///     <see cref="VerifyDnsSanDelegate"/> — checks that the leaf certificate's DNS
///     SAN matches the expected name derived from the <c>client_id</c>.
///   </description></item>
/// </list>
/// <para>
/// Concrete implementations of all three delegates are provided by the platform
/// driver libraries. Typical wiring in application setup:
/// </para>
/// <code>
/// ResolveKeyFromX509SanDnsDelegate resolver =
///     (x5c, expectedDns, trustAnchors, time, pool, ct) =>
///         X509SanDnsKeyResolver.ResolveAsync(
///             x5c, expectedDns, trustAnchors, time,
///             MicrosoftX509Functions.ParseX5c,
///             MicrosoftX509Functions.ValidateChain,
///             MicrosoftX509Functions.VerifyDnsSan,
///             pool, ct);
/// </code>
/// </remarks>
public static class X509SanDnsKeyResolver
{
    /// <summary>
    /// Parses and validates the <c>x5c</c> certificate chain, verifies the DNS SAN,
    /// and returns the leaf certificate's public key for JAR signature verification.
    /// </summary>
    /// <param name="x5cValues">
    /// The base64-encoded DER certificate strings from the <c>x5c</c> JOSE header.
    /// Leaf certificate first per RFC 7515 §4.1.6.
    /// </param>
    /// <param name="expectedDnsName">
    /// The DNS name the leaf certificate's SAN must contain. This is the <c>client_id</c>
    /// with the <c>x509_san_dns:</c> prefix stripped.
    /// </param>
    /// <param name="trustAnchors">
    /// Trust anchor certificates for chain validation.
    /// </param>
    /// <param name="validationTime">
    /// The UTC time at which to evaluate certificate validity.
    /// </param>
    /// <param name="parseX5c">Delegate for parsing the DER-encoded certificate chain.</param>
    /// <param name="validateChain">Delegate for chain validation and leaf key extraction.</param>
    /// <param name="verifyDnsSan">Delegate for DNS SAN verification.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The leaf certificate's public key. The caller owns the returned
    /// <see cref="PublicKeyMemory"/> and must dispose it.
    /// </returns>
    /// <exception cref="System.Security.SecurityException">
    /// Thrown when chain validation fails or the DNS SAN does not match.
    /// </exception>
    public static ValueTask<PublicKeyMemory> ResolveAsync(
        IReadOnlyList<string> x5cValues,
        string expectedDnsName,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        DateTimeOffset validationTime,
        ParseX5cDelegate parseX5c,
        ValidateCertificateChainDelegate validateChain,
        VerifyDnsSanDelegate verifyDnsSan,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(x5cValues);
        ArgumentNullException.ThrowIfNull(expectedDnsName);
        ArgumentNullException.ThrowIfNull(trustAnchors);
        ArgumentNullException.ThrowIfNull(parseX5c);
        ArgumentNullException.ThrowIfNull(validateChain);
        ArgumentNullException.ThrowIfNull(verifyDnsSan);
        ArgumentNullException.ThrowIfNull(pool);

        IReadOnlyList<PkiCertificateMemory> chain = parseX5c(x5cValues, pool);

        try
        {
            PublicKeyMemory leafKey = validateChain(chain, trustAnchors, validationTime, pool);

            try
            {
                verifyDnsSan(chain[0], expectedDnsName);
            }
            catch
            {
                leafKey.Dispose();
                throw;
            }

            return ValueTask.FromResult(leafKey);
        }
        finally
        {
            foreach(PkiCertificateMemory cert in chain)
            {
                cert.Dispose();
            }
        }
    }
}
