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
/// <param name="checkRevocation">
/// An optional revocation-status seam. When it is <see langword="null"/> (the default) no revocation source is
/// configured and only chain building is performed. When it is supplied, an implementation of this delegate MUST
/// consult it for the chain leaf and fail closed — a <see cref="CertificateRevocationStatus.Revoked"/> or
/// <see cref="CertificateRevocationStatus.Unknown"/> result MUST throw
/// <see cref="System.Security.SecurityException"/> — so a caller relying on revocation gets it from any conforming
/// implementation. The two library backends (<c>MicrosoftX509Functions.ValidateChainAsync</c> and
/// <c>BouncyCastleX509Functions.ValidateChainAsync</c>) honour this contract; a custom implementation that accepts
/// the parameter but ignores it silently forgoes revocation, exactly as a custom implementation that skipped chain
/// building would forgo trust. Supplying the checker is how a caller configures a revocation source; the library
/// ships the seam and the fail-closed policy, not an OCSP/CRL client.
/// </param>
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
/// Thrown when chain validation fails for any reason, including when <paramref name="checkRevocation"/> reports the
/// leaf as revoked or of indeterminate status.
/// </exception>
public delegate ValueTask<PublicKeyMemory> ValidateCertificateChainAsyncDelegate(
    IReadOnlyList<PkiCertificateMemory> chain,
    IReadOnlyList<PkiCertificateMemory> trustAnchors,
    DateTimeOffset validationTime,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken,
    CheckCertificateRevocationStatusAsyncDelegate? checkRevocation = null);


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


/// <summary>
/// Reads the profile-relevant constraints of an X.509 certificate — the Key Usage bits and the
/// Basic Constraints CA flag — as backend-neutral booleans, so a caller can enforce a certificate
/// profile without depending on any provider's certificate type.
/// </summary>
/// <param name="certificate">The certificate to inspect.</param>
/// <returns>
/// The certificate's <see cref="X509CertificateProfile"/>. A constraint whose extension is absent
/// reads as <see langword="false"/>, which lets a profile that requires a bit reject a certificate
/// that omits it.
/// </returns>
/// <remarks>
/// The seam returns neutral booleans rather than a provider enum (for example
/// <c>X509KeyUsageFlags</c>) so a certificate-profile policy is expressible against the seam alone.
/// The eMRTD Passive Authentication path uses it to enforce the ICAO Doc 9303 Part 12 §7.1 Document
/// Signer certificate profile: the signer MUST assert Key Usage <c>digitalSignature</c> (RFC 5280
/// §4.2.1.3) and MUST NOT be a certificate authority — neither asserting <c>keyCertSign</c> nor marked
/// <c>cA=TRUE</c> in Basic Constraints (RFC 5280 §4.2.1.9) — so a Document Signer cannot also act as a
/// Country Signing CA and issue further certificates.
/// <para>
/// A malformed certificate that includes more than one instance of a single extension — which RFC 5280
/// §4.2 forbids and which would make the extracted profile depend on which instance is read — is rejected
/// by throwing rather than having its profile derived from an arbitrarily chosen instance; both provided
/// backends fail closed on such a certificate by throwing
/// <see cref="System.Security.Cryptography.CryptographicException"/>.
/// </para>
/// </remarks>
/// <exception cref="System.Security.Cryptography.CryptographicException">
/// Thrown when the certificate is malformed — for example it includes more than one instance of a single
/// extension, which RFC 5280 §4.2 forbids.
/// </exception>
public delegate X509CertificateProfile ReadCertificateProfileDelegate(
    PkiCertificateMemory certificate);


/// <summary>
/// The profile-relevant constraints of an X.509 certificate, extracted as backend-neutral booleans:
/// the two Key Usage bits (RFC 5280 §4.2.1.3) and the Basic Constraints CA flag (RFC 5280 §4.2.1.9)
/// a certificate-profile policy checks. A certificate whose relevant extension is absent reads every
/// affected constraint as <see langword="false"/>.
/// </summary>
public sealed record X509CertificateProfile
{
    /// <summary>
    /// Gets whether the certificate's Key Usage asserts <c>digitalSignature</c>;
    /// <see langword="false"/> when the Key Usage extension is absent.
    /// </summary>
    public required bool AssertsDigitalSignature { get; init; }

    /// <summary>
    /// Gets whether the certificate's Key Usage asserts <c>keyCertSign</c> — the bit that permits the
    /// key to sign other certificates; <see langword="false"/> when the Key Usage extension is absent.
    /// </summary>
    public required bool AssertsKeyCertSign { get; init; }

    /// <summary>
    /// Gets whether the certificate's Basic Constraints mark it as a certificate authority
    /// (<c>cA=TRUE</c>); <see langword="false"/> when the Basic Constraints extension is absent or
    /// sets <c>cA=FALSE</c>.
    /// </summary>
    public required bool IsCertificateAuthority { get; init; }
}


/// <summary>
/// Determines the revocation status of a certificate against the revocation source a deployment configures
/// (an OCSP responder or CRL distribution point). This is the seam a caller supplies to make chain trust
/// revocation-aware; the library ships the seam and the fail-closed policy, not an OCSP/CRL client.
/// </summary>
/// <param name="certificate">The certificate whose revocation status is being determined (for example an eMRTD Document Signer).</param>
/// <param name="issuerCandidates">
/// The certificates that may be <paramref name="certificate"/>'s issuer — for eMRTD Passive Authentication the
/// Country Signing CA trust anchors — from which a checker selects the issuer needed to build an OCSP request
/// (RFC 6960) or locate the issuing CRL (RFC 5280 §5).
/// </param>
/// <param name="validationTime">The UTC time at which to evaluate revocation (for example the CRL <c>thisUpdate</c>/<c>nextUpdate</c> window).</param>
/// <param name="pool">Memory pool for any allocation the checker performs.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The <see cref="CertificateRevocationStatus"/>. The implementation reports status only; whether
/// <see cref="CertificateRevocationStatus.Revoked"/> or <see cref="CertificateRevocationStatus.Unknown"/> is
/// fatal is the caller's fail-closed policy decision, not the checker's.
/// </returns>
/// <remarks>
/// The seam is asynchronous because determining revocation status is an I/O operation (an OCSP round-trip or a
/// CRL fetch); an implementation backed by a cached CRL completes synchronously via a completed
/// <see cref="ValueTask{TResult}"/>. It returns a status rather than throwing so the caller can distinguish a
/// definite <see cref="CertificateRevocationStatus.Revoked"/> from an indeterminate
/// <see cref="CertificateRevocationStatus.Unknown"/> (responder unreachable, no CRL) and apply its own policy.
/// </remarks>
public delegate ValueTask<CertificateRevocationStatus> CheckCertificateRevocationStatusAsyncDelegate(
    PkiCertificateMemory certificate,
    IReadOnlyList<PkiCertificateMemory> issuerCandidates,
    DateTimeOffset validationTime,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);


/// <summary>
/// The revocation status of a certificate, carrying the same three outcomes as the RFC 6960 OCSP
/// <c>CertStatus</c> (good / revoked / unknown).
/// </summary>
/// <remarks>
/// <see cref="Unknown"/> is deliberately the first (default) member, so an unset or default-initialised status
/// is the fail-closed value rather than <see cref="Good"/>: a checker that neglects to set an outcome cannot
/// accidentally report a certificate as not revoked. The numeric values are internal to this seam — a checker
/// maps its OCSP response or CRL lookup onto them — so they carry no wire meaning and are free to be ordered for
/// this safety property.
/// </remarks>
public enum CertificateRevocationStatus
{
    /// <summary>
    /// The revocation status could not be determined — for example the OCSP responder was unreachable, no CRL
    /// was available, or the source does not know the certificate. This is the default value, so a fail-closed
    /// policy treats an unset status as fatal.
    /// </summary>
    Unknown,

    /// <summary>The revocation source affirmatively reports the certificate is not revoked.</summary>
    Good,

    /// <summary>The revocation source reports the certificate has been revoked.</summary>
    Revoked
}
