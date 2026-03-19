using System.Buffers;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Parses base64-encoded DER certificate strings from a JOSE <c>x5c</c> header
/// into <see cref="PkiCertificateMemory"/> instances.
/// </summary>
/// <param name="x5cValues">
/// The array of base64-encoded DER strings. The first entry is the leaf certificate
/// per RFC 7515 §4.1.6.
/// </param>
/// <param name="pool">Memory pool for DER byte allocations.</param>
/// <returns>
/// A list of <see cref="PkiCertificateMemory"/> in chain order, leaf first.
/// The caller owns all returned instances and must dispose them.
/// </returns>
/// <exception cref="System.FormatException">
/// Thrown when any entry is not valid base64 or is empty.
/// </exception>
public delegate IReadOnlyList<PkiCertificateMemory> ParseX5cDelegate(
    IReadOnlyList<string> x5cValues,
    MemoryPool<byte> pool);


/// <summary>
/// Validates an X.509 certificate chain and extracts the leaf certificate's public key.
/// </summary>
/// <param name="chain">
/// The certificate chain in order: leaf first, intermediates following, root last.
/// </param>
/// <param name="trustAnchors">
/// Trust anchor certificates for chain validation. For EUDI Wallet deployments these
/// are national CA certificates obtained from the EUDI Trust List.
/// </param>
/// <param name="validationTime">The UTC time at which to evaluate certificate validity.</param>
/// <param name="pool">Memory pool for key material allocation.</param>
/// <returns>
/// The leaf certificate's public key. The caller owns the returned
/// <see cref="PublicKeyMemory"/> and must dispose it.
/// </returns>
/// <exception cref="System.Security.SecurityException">
/// Thrown when chain validation fails for any reason.
/// </exception>
public delegate PublicKeyMemory ValidateCertificateChainDelegate(
    IReadOnlyList<PkiCertificateMemory> chain,
    IReadOnlyList<PkiCertificateMemory> trustAnchors,
    DateTimeOffset validationTime,
    MemoryPool<byte> pool);


/// <summary>
/// Verifies that the leaf certificate's Subject Alternative Name contains a
/// <c>dNSName</c> entry that matches the expected DNS name.
/// </summary>
/// <param name="leafCertificate">
/// The leaf <see cref="PkiCertificateMemory"/> from the validated chain.
/// </param>
/// <param name="expectedDnsName">
/// The DNS name that must appear in the certificate's SAN extension. For the
/// <c>x509_san_dns:</c> Client Identifier Prefix this is the <c>client_id</c>
/// value with the prefix stripped.
/// </param>
/// <exception cref="System.Security.SecurityException">
/// Thrown when no SAN extension is present or no DNS SAN entry matches.
/// </exception>
public delegate void VerifyDnsSanDelegate(
    PkiCertificateMemory leafCertificate,
    string expectedDnsName);
