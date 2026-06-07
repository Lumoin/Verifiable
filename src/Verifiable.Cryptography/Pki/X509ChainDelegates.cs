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
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The leaf certificate's public key. The caller owns the returned
/// <see cref="PublicKeyMemory"/> and must dispose it.
/// </returns>
/// <remarks>
/// The seam is asynchronous because production chain validation can require I/O —
/// revocation checking (OCSP/CRL fetch), remote trust-anchor resolution, or a
/// trust-list refresh. Implementations that validate purely in-memory complete
/// synchronously (returning a completed <see cref="ValueTask{TResult}"/>); the async
/// shape is what lets the same seam serve TPM-attestation and AdES long-term
/// validation without a later signature break.
/// </remarks>
/// <exception cref="System.Security.SecurityException">
/// Thrown when chain validation fails for any reason.
/// </exception>
public delegate ValueTask<PublicKeyMemory> ValidateCertificateChainAsyncDelegate(
    IReadOnlyList<PkiCertificateMemory> chain,
    IReadOnlyList<PkiCertificateMemory> trustAnchors,
    DateTimeOffset validationTime,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);


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


/// <summary>
/// Reports whether a certificate is self-signed, i.e. whether its Issuer
/// distinguished name equals its Subject distinguished name.
/// </summary>
/// <param name="certificate">The <see cref="PkiCertificateMemory"/> to inspect.</param>
/// <returns>
/// <see langword="true"/> when the certificate is self-signed (Issuer equals
/// Subject); otherwise <see langword="false"/>.
/// </returns>
/// <remarks>
/// This is a neutral certificate predicate: it makes no policy decision and throws
/// no domain exception. Callers that forbid self-signed certificates in a given
/// context (for example a request-signing certificate under the OID4VP
/// <c>x509_hash:</c> Client Identifier Prefix, which HAIP 1.0 §5.2 prohibits) apply
/// that policy themselves on the boolean result.
/// </remarks>
public delegate bool IsSelfSignedCertificateDelegate(
    PkiCertificateMemory certificate);


/// <summary>
/// Reads the certificate's AuthorityKeyIdentifier <c>KeyIdentifier</c> (RFC 5280 §4.2.1.1)
/// and returns it base64url-encoded — the value a DCQL <c>trusted_authorities</c> entry of
/// type <c>aki</c> matches per OID4VP 1.0 §6.1.1.1. Returns <see langword="null"/> when the
/// certificate carries no AuthorityKeyIdentifier extension or that extension omits the
/// KeyIdentifier (identifying the issuer by name + serial instead).
/// </summary>
/// <param name="certificate">The certificate to read — typically the leaf of an mdoc IssuerAuth x5chain.</param>
/// <param name="base64UrlEncoder">
/// Encoder producing the base64url string form. The AuthorityKeyIdentifier is public
/// certificate metadata, so it is returned as an encoded string rather than a sensitive
/// carrier.
/// </param>
/// <returns>The base64url-encoded AuthorityKeyIdentifier KeyIdentifier, or <see langword="null"/>.</returns>
public delegate string? ExtractAuthorityKeyIdentifierDelegate(
    PkiCertificateMemory certificate,
    EncodeDelegate base64UrlEncoder);
