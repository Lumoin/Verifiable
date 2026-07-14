using System.Buffers;
using System.Linq;

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
/// <param name="checkRevocation">
/// An optional revocation-status seam. When it is <see langword="null"/> (the default) no revocation source is
/// configured and only chain building is performed. When it is supplied, an implementation of this delegate MUST
/// consult it for every certificate in <paramref name="chain"/> that is not byte-equal to a supplied trust
/// anchor — the leaf AND every intermediate CA certificate the chain carries, per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web Authentication Level 3,
/// section 7.1: Registering a New Credential</see>'s "the Relying Party MUST have access to certificate status
/// information for the intermediate CA certificates" — and fail closed: a
/// <see cref="CertificateRevocationStatus.Revoked"/> or <see cref="CertificateRevocationStatus.Unknown"/> result
/// for any checked certificate MUST throw <see cref="System.Security.SecurityException"/>. For each certificate
/// checked, the issuer candidates passed to <paramref name="checkRevocation"/> are the OTHER certificates in
/// <paramref name="chain"/> plus <paramref name="trustAnchors"/>, so a checker can locate the leaf's intermediate
/// issuer as well as an intermediate's own (root) issuer. The two library backends
/// (<c>MicrosoftX509Functions.ValidateChainAsync</c> and <c>BouncyCastleX509Functions.ValidateChainAsync</c>)
/// honour this contract; a custom implementation that accepts the parameter but ignores it silently forgoes
/// revocation, exactly as a custom implementation that skipped chain building would forgo trust. Supplying the
/// checker is how a caller configures a revocation source; the library ships the seam and the fail-closed policy,
/// not an OCSP/CRL client.
/// </param>
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
/// Thrown when chain validation fails for any reason, including when <paramref name="checkRevocation"/> reports the
/// leaf as revoked or of indeterminate status.
/// </exception>
public delegate ValueTask<PublicKeyMemory> ValidateCertificateChainAsyncDelegate(
    IReadOnlyList<PkiCertificateMemory> chain,
    IReadOnlyList<PkiCertificateMemory> trustAnchors,
    DateTimeOffset validationTime,
    MemoryPool<byte> pool,
    CheckCertificateRevocationStatusAsyncDelegate? checkRevocation = null,
    CancellationToken cancellationToken = default);


/// <summary>
/// Completes a partial X.509 certificate chain by acquiring any missing intermediate certificates, so that a
/// certificate path whose carrier omitted intermediates (the client did not provide them) can still be validated.
/// </summary>
/// <param name="partialChain">
/// The certificate chain as supplied on the wire: leaf first, zero or more intermediates following, possibly
/// already reaching a trust anchor.
/// </param>
/// <param name="trustAnchors">The trust anchor certificates the completed chain must reach.</param>
/// <param name="pool">Memory pool for any acquired certificate's byte allocation.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// <paramref name="partialChain"/> unchanged when it already reaches a trust anchor; otherwise
/// <paramref name="partialChain"/> with the acquired intermediate certificates appended, in issuance order (the
/// certificate whose issuer is <paramref name="partialChain"/>'s last entry comes first). Every certificate beyond
/// <paramref name="partialChain"/>'s own entries was newly acquired by this call and is owned by the CALLER of
/// this delegate, which must dispose it once validation is complete; <paramref name="partialChain"/>'s own
/// entries remain owned exactly as before the call.
/// </returns>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web Authentication Level 3,
/// section 7.1: Registering a New Credential</see>: "The Relying Party MUST also be able to build the attestation
/// certificate chain if the client did not provide this chain in the attestation information." A typical
/// acquisition source is the certificate's Authority Information Access extension's <c>id-ad-caIssuers</c> access
/// method (<see href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1">RFC 5280 section
/// 4.2.2.1</see>); an offline deployment may instead hold a store of known intermediates, as
/// <c>CertificateChainCompleter</c> (Verifiable.BouncyCastle) does. The seam is asynchronous because production
/// chain completion typically requires I/O (an AIA fetch); an offline, in-memory implementation completes
/// synchronously via a completed <see cref="ValueTask{TResult}"/>.
/// </remarks>
/// <exception cref="System.Security.SecurityException">
/// Thrown when the chain cannot be completed to any of the supplied trust anchors.
/// </exception>
public delegate ValueTask<IReadOnlyList<PkiCertificateMemory>> CompleteCertificateChainAsyncDelegate(
    IReadOnlyList<PkiCertificateMemory> partialChain,
    IReadOnlyList<PkiCertificateMemory> trustAnchors,
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
/// a certificate-profile policy checks, together with the certificate's version (RFC 5280 §4.1.2.1)
/// and its Subject Organizational Unit (OID 2.5.4.11), Country (OID 2.5.4.6), Organization
/// (OID 2.5.4.10), and Common Name (OID 2.5.4.3) values (RFC 5280 §4.1.2.4) — the additional
/// fields <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements">
/// WebAuthn Level 3 §8.2.1 "Certificate Requirements for Packed Attestation Statements"</see> checks.
/// A certificate whose relevant extension is absent reads every affected constraint as
/// <see langword="false"/>.
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

    /// <summary>
    /// Gets the certificate's version (RFC 5280 §4.1.2.1) — <c>3</c> for a version-3 certificate,
    /// the version a certificate profile that relies on version-3-only extensions requires.
    /// </summary>
    public required int Version { get; init; }

    /// <summary>
    /// Gets the certificate Subject's Organizational Unit (<c>OU</c>, OID 2.5.4.11) attribute values
    /// (RFC 5280 §4.1.2.4), in the order they appear in the Subject field. Empty when the Subject
    /// carries no Organizational Unit attribute.
    /// </summary>
    public required IReadOnlyList<string> SubjectOrganizationalUnits { get; init; }

    /// <summary>
    /// Gets the certificate Subject's Country (<c>C</c>, OID 2.5.4.6) attribute values
    /// (RFC 5280 §4.1.2.4), in the order they appear in the Subject field. Empty when the Subject
    /// carries no Country attribute.
    /// </summary>
    public required IReadOnlyList<string> SubjectCountries { get; init; }

    /// <summary>
    /// Gets the certificate Subject's Organization (<c>O</c>, OID 2.5.4.10) attribute values
    /// (RFC 5280 §4.1.2.4), in the order they appear in the Subject field. Empty when the Subject
    /// carries no Organization attribute.
    /// </summary>
    public required IReadOnlyList<string> SubjectOrganizations { get; init; }

    /// <summary>
    /// Gets the certificate Subject's Common Name (<c>CN</c>, OID 2.5.4.3) attribute values
    /// (RFC 5280 §4.1.2.4), in the order they appear in the Subject field. Empty when the Subject
    /// carries no Common Name attribute.
    /// </summary>
    public required IReadOnlyList<string> SubjectCommonNames { get; init; }

    /// <summary>
    /// Gets whether the certificate's Subject field (RFC 5280 §4.1.2.4, an RDNSequence) carries no
    /// relative distinguished names at all — the "Subject field MUST be set to empty" constraint
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-cert-requirements">WebAuthn Level 3
    /// §8.3.1</see> imposes on a TPM attestation key certificate, whose identity is carried entirely
    /// in its Subject Alternative Name instead. Distinct from <see cref="SubjectOrganizationalUnits"/>
    /// and its siblings being empty: those report only four specific attribute types, while this
    /// reports whether the Subject carries ANY relative distinguished name of any type.
    /// </summary>
    public required bool HasEmptySubject { get; init; }

    /// <summary>
    /// Determines whether this profile and <paramref name="other"/> report the same constraints. The
    /// compiler-synthesized record equality compares the Subject attribute lists by reference, which
    /// would report two independently-read profiles with identical Subject attribute sequences as
    /// unequal; this override compares each sequence by value instead.
    /// </summary>
    /// <param name="other">The other profile to compare against.</param>
    /// <returns>
    /// <see langword="true"/> when every constraint matches, including a value-wise (not reference-wise)
    /// comparison of <see cref="SubjectOrganizationalUnits"/>, <see cref="SubjectCountries"/>,
    /// <see cref="SubjectOrganizations"/>, and <see cref="SubjectCommonNames"/>.
    /// </returns>
    public bool Equals(X509CertificateProfile? other) =>
        other is not null
        && AssertsDigitalSignature == other.AssertsDigitalSignature
        && AssertsKeyCertSign == other.AssertsKeyCertSign
        && IsCertificateAuthority == other.IsCertificateAuthority
        && Version == other.Version
        && HasEmptySubject == other.HasEmptySubject
        && SubjectOrganizationalUnits.SequenceEqual(other.SubjectOrganizationalUnits)
        && SubjectCountries.SequenceEqual(other.SubjectCountries)
        && SubjectOrganizations.SequenceEqual(other.SubjectOrganizations)
        && SubjectCommonNames.SequenceEqual(other.SubjectCommonNames);

    /// <summary>
    /// Computes a hash code consistent with <see cref="Equals(X509CertificateProfile?)"/> — combining the
    /// boolean constraints, the version, and each Subject attribute list's values in order — so two
    /// value-equal profiles never disagree in a hash-based collection.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(AssertsDigitalSignature);
        hash.Add(AssertsKeyCertSign);
        hash.Add(IsCertificateAuthority);
        hash.Add(Version);
        hash.Add(HasEmptySubject);
        foreach(string organizationalUnit in SubjectOrganizationalUnits)
        {
            hash.Add(organizationalUnit, StringComparer.Ordinal);
        }

        foreach(string country in SubjectCountries)
        {
            hash.Add(country, StringComparer.Ordinal);
        }

        foreach(string organization in SubjectOrganizations)
        {
            hash.Add(organization, StringComparer.Ordinal);
        }

        foreach(string commonName in SubjectCommonNames)
        {
            hash.Add(commonName, StringComparer.Ordinal);
        }

        return hash.ToHashCode();
    }
}


/// <summary>
/// The value of a single X.509 certificate extension, read as backend-neutral bytes.
/// </summary>
/// <param name="Value">
/// The DER contents of the extension's <c>extnValue</c> (RFC 5280 §4.2), exactly as the underlying
/// platform exposes the extension's raw data — for example the DER OCTET STRING payload of a private
/// extension, still requiring its own ASN.1 decoding by the caller.
/// </param>
/// <param name="IsCritical">The extension's <c>critical</c> flag (RFC 5280 §4.2).</param>
public sealed record X509ExtensionValue(ReadOnlyMemory<byte> Value, bool IsCritical);


/// <summary>
/// Reads a single named extension of an X.509 certificate as backend-neutral bytes, so a caller can
/// decode a private extension (for example the WebAuthn Level 3 §8.2.1 attestation certificate AAGUID
/// extension, OID <c>1.3.6.1.4.1.45724.1.1.4</c>) without depending on any provider's certificate type.
/// </summary>
/// <param name="certificate">The certificate to inspect.</param>
/// <param name="oid">The dotted-decimal object identifier of the extension to read.</param>
/// <returns>
/// The <see cref="X509ExtensionValue"/> for <paramref name="oid"/>, or <see langword="null"/> when the
/// certificate carries no extension with that identifier.
/// </returns>
/// <remarks>
/// Mirrors <see cref="ReadCertificateProfileDelegate"/>'s fail-closed duplicate-extension rule: RFC 5280
/// §4.2 forbids a certificate from including more than one instance of any single extension, and a
/// malformed certificate that does so is rejected outright — before <paramref name="oid"/> is even looked
/// up — rather than resolving <paramref name="oid"/> from an arbitrarily chosen instance among the
/// duplicates.
/// </remarks>
/// <exception cref="System.Security.Cryptography.CryptographicException">
/// Thrown when the certificate is malformed — for example it includes more than one instance of a single
/// extension (of any OID, not only <paramref name="oid"/>), which RFC 5280 §4.2 forbids.
/// </exception>
public delegate X509ExtensionValue? ReadCertificateExtensionValueDelegate(
    PkiCertificateMemory certificate,
    string oid);


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
