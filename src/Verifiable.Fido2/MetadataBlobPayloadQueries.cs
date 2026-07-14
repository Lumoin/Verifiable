using System.Buffers;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Fido2;

/// <summary>
/// The deciding outcome of evaluating a <see cref="MetadataBlobPayloadEntry"/>'s status reports
/// against a trust-terminating policy.
/// </summary>
/// <param name="Accepted">
/// <see langword="true"/> when <see cref="DecidingStatusReport"/>'s status is not in the applied
/// trust-terminating set; otherwise <see langword="false"/>.
/// </param>
/// <param name="DecidingStatusReport">
/// The status report <see cref="MetadataBlobPayloadQueries.EvaluateStatus"/> selected as current,
/// or <see langword="null"/> when the entry carries no status reports at all.
/// </param>
[DebuggerDisplay("MetadataStatusEvaluation(Accepted={Accepted}, Status={DecidingStatusReport.Status,nq})")]
public sealed record MetadataStatusEvaluation(bool Accepted, MetadataStatusReport? DecidingStatusReport);


/// <summary>
/// Query helpers over a verified <see cref="MetadataBlobPayload"/>: entry lookup by the FIDO2 and
/// U2F matching rules, status-report trust evaluation, and attestation trust-anchor extraction.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-pe">FIDO
/// Metadata Service v3.1, section 3.1.1: Metadata BLOB Payload Entry dictionary.</see>
/// </remarks>
public static class MetadataBlobPayloadQueries
{
    /// <summary>The SHA-1 digest tag RFC 5280 §4.2.1.2 method 1 mandates for a key identifier — the convenience digest tags in <see cref="CryptoTags"/> omit SHA-1 by design, so it is composed inline here.</summary>
    private static Tag Sha1DigestTag { get; } = Tag.Create(HashAlgorithmName.SHA1).With(Purpose.Digest).With(EncodingScheme.Raw);


    /// <summary>
    /// Finds the entry matching a FIDO2 registration's AAGUID — the entry-matching rule
    /// <see href="https://www.w3.org/TR/webauthn-3/#reg-ceremony-attestation-trust-anchors">W3C Web
    /// Authentication Level 3, section 7.1, step 23</see> points at when it names the FIDO Metadata
    /// Service as a source of acceptable trust anchors, keyed on <c>aaguid</c>.
    /// </summary>
    /// <param name="payload">The verified payload to search.</param>
    /// <param name="aaguid">The attested credential data's AAGUID.</param>
    /// <param name="entry">The matching entry, or <see langword="null"/> when none matches.</param>
    /// <returns><see langword="true"/> when a matching entry was found; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="payload"/> is <see langword="null"/>.</exception>
    public static bool TryFindEntryByAaguid(MetadataBlobPayload payload, Guid aaguid, out MetadataBlobPayloadEntry? entry)
    {
        ArgumentNullException.ThrowIfNull(payload);

        foreach(MetadataBlobPayloadEntry candidate in payload.Entries)
        {
            if(candidate.Aaguid == aaguid)
            {
                entry = candidate;
                return true;
            }
        }

        entry = null;
        return false;
    }


    /// <summary>
    /// Finds the entry matching a U2F attestation certificate's key identifier — the entry-matching
    /// rule for authenticators that carry neither an <c>aaid</c> nor an <c>aaguid</c>, per
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-pe">FIDO
    /// Metadata Service v3.1, section 3.1.1</see>: "This field MUST be set if neither aaid nor
    /// aaguid are set… FIDO U2F authenticators do not support AAID nor AAGUID, but they use
    /// attestation certificates dedicated to a single authenticator model."
    /// </summary>
    /// <param name="payload">The verified payload to search.</param>
    /// <param name="hexSki">
    /// The presented attestation certificate's RFC 5280 §4.2.1.2 method-1 key identifier, hex
    /// encoded. Compared ordinally against each entry's lowercase hex identifiers — the
    /// specification requires a producer to emit lowercase hex, so this comparison does not itself
    /// lowercase either side; a caller comparing a differently-cased identifier will not match.
    /// </param>
    /// <param name="entry">The matching entry, or <see langword="null"/> when none matches.</param>
    /// <returns><see langword="true"/> when a matching entry was found; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="payload"/> or <paramref name="hexSki"/> is <see langword="null"/>.</exception>
    public static bool TryFindEntryByAttestationCertificateKeyIdentifier(MetadataBlobPayload payload, string hexSki, out MetadataBlobPayloadEntry? entry)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(hexSki);

        foreach(MetadataBlobPayloadEntry candidate in payload.Entries)
        {
            if(candidate.AttestationCertificateKeyIdentifiers is { } identifiers)
            {
                foreach(string identifier in identifiers)
                {
                    if(string.Equals(identifier, hexSki, StringComparison.Ordinal))
                    {
                        entry = candidate;
                        return true;
                    }
                }
            }
        }

        entry = null;
        return false;
    }


    /// <summary>
    /// Finds the entry matching an attestation certificate's own key identifier, DERIVED from the
    /// certificate itself rather than trusted as a caller-computed string — the consumer-side mirror
    /// of <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-pe">FIDO
    /// Metadata Service v3.1, section 3.1.1</see>'s requirement that
    /// <c>attestationCertificateKeyIdentifiers</c> values "MUST be calculated according to method 1
    /// for computing the keyIdentifier as defined in [RFC5280] section 4.2.1.2." RFC 5280 §4.2.1.2
    /// method 1 defines that identifier as the 160-bit SHA-1 hash of the value of the certificate's
    /// SubjectPublicKeyInfo BIT STRING (excluding the tag, length, and unused-bits count octet) —
    /// this method extracts exactly that BIT STRING from <paramref name="certificate"/>'s DER
    /// encoding, hashes it, lowercase-hex-encodes the result, and delegates the actual search to
    /// <see cref="TryFindEntryByAttestationCertificateKeyIdentifier(MetadataBlobPayload, string, out MetadataBlobPayloadEntry?)"/>.
    /// </summary>
    /// <param name="payload">The verified payload to search.</param>
    /// <param name="certificate">The presented attestation certificate, DER encoded.</param>
    /// <param name="pool">The memory pool the transient digest buffer rents from — the certificate is public data, so no pinned allocation is required.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests, propagated to the registered digest function.</param>
    /// <returns>
    /// <see langword="true"/> in <c>IsFound</c> with the matching entry in <c>Entry</c> when one is
    /// found; otherwise <see langword="false"/> and a <see langword="null"/> <c>Entry</c>.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="payload"/>, <paramref name="certificate"/>, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static async ValueTask<(bool IsFound, MetadataBlobPayloadEntry? Entry)> TryFindEntryByAttestationCertificateKeyIdentifierAsync(
        MetadataBlobPayload payload,
        PkiCertificateMemory certificate,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(pool);

        string hexSki = await ComputeAttestationCertificateKeyIdentifierAsync(certificate, pool, cancellationToken).ConfigureAwait(false);
        bool isFound = TryFindEntryByAttestationCertificateKeyIdentifier(payload, hexSki, out MetadataBlobPayloadEntry? entry);

        return (isFound, entry);
    }


    /// <summary>
    /// Computes <paramref name="certificate"/>'s RFC 5280 §4.2.1.2 method-1 key identifier: the
    /// lowercase-hex-encoded SHA-1 hash of its SubjectPublicKeyInfo BIT STRING value. SHA-1 is
    /// dispatched only because this specific, external RFC 5280 formula mandates it (the same
    /// narrow, spec-mandated carve-out <c>BasicAccessControl</c>'s eMRTD key derivation uses) —
    /// routed through the registered async <see cref="ComputeDigestDelegate"/> because SHA-1 has no
    /// synchronous <see cref="HashFunctionDelegate"/> registration in this library (by design; see
    /// <see cref="EntropyDelegates"/>'s remarks on the sync/async digest split).
    /// </summary>
    private static async ValueTask<string> ComputeAttestationCertificateKeyIdentifierAsync(
        PkiCertificateMemory certificate, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] subjectPublicKeyBitString = ExtractSubjectPublicKeyBitString(certificate.AsReadOnlyMemory());

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            subjectPublicKeyBitString, WellKnownHashAlgorithms.Sha1SizeBytes, Sha1DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return Convert.ToHexStringLower(digest.AsReadOnlySpan());
    }


    /// <summary>
    /// Walks a DER-encoded X.509 certificate's TBSCertificate down to its SubjectPublicKeyInfo and
    /// returns the raw BIT STRING content (the "value of the BIT STRING subjectPublicKey" RFC 5280
    /// §4.2.1.2 method 1 hashes), independent of the underlying key algorithm — mirrors
    /// <c>ManagedCertificate.Parse</c>'s TBSCertificate field walk, stopping one field earlier since
    /// only the raw, undecoded public key bits are needed here rather than a per-algorithm decoded key.
    /// </summary>
    private static byte[] ExtractSubjectPublicKeyBitString(ReadOnlyMemory<byte> certificateDer)
    {
        var certificate = new AsnReader(certificateDer, AsnEncodingRules.DER);
        AsnReader tbs = certificate.ReadSequence().ReadSequence();

        //version [0] EXPLICIT INTEGER DEFAULT v1, present in practically every certificate.
        if(tbs.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            _ = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        }

        _ = tbs.ReadIntegerBytes();     //serialNumber
        _ = tbs.ReadSequence();         //signature AlgorithmIdentifier
        _ = tbs.ReadEncodedValue();     //issuer Name (raw DER)
        _ = tbs.ReadSequence();         //validity
        _ = tbs.ReadEncodedValue();     //subject Name

        AsnReader subjectPublicKeyInfo = tbs.ReadSequence();
        _ = subjectPublicKeyInfo.ReadSequence();     //algorithm AlgorithmIdentifier

        return subjectPublicKeyInfo.ReadBitString(out _);
    }


    /// <summary>
    /// Decides whether <paramref name="entry"/> is currently trusted, from its status reports.
    /// </summary>
    /// <param name="entry">The entry to evaluate.</param>
    /// <param name="trustTerminating">
    /// The status set that terminates trust, or <see langword="null"/> to apply
    /// <see cref="WellKnownAuthenticatorStatuses.DefaultTrustTerminating"/>.
    /// </param>
    /// <returns>The deciding evaluation.</returns>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-stat-rep">FIDO
    /// Metadata Service v3.1, section 3.1.3: StatusReport dictionary</see>: "The latest StatusReport
    /// entry MUST reflect the 'current' status." This method selects the report with the greatest
    /// <see cref="MetadataStatusReport.EffectiveDate"/> — treating a report with no effective date
    /// as effective from the earliest possible date, per that section's "if no date is given, the
    /// status is assumed to be effective while present" — and, among reports tied on that ordering
    /// (including when no report carries a date at all), the one appearing LAST in
    /// <see cref="MetadataBlobPayloadEntry.StatusReports"/>' wire order, matching the specification's
    /// own "latest… entry" phrasing literally when dates cannot distinguish them.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="entry"/> is <see langword="null"/>.</exception>
    public static MetadataStatusEvaluation EvaluateStatus(MetadataBlobPayloadEntry entry, IReadOnlySet<string>? trustTerminating = null)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if(entry.StatusReports.Count == 0)
        {
            return new MetadataStatusEvaluation(Accepted: true, DecidingStatusReport: null);
        }

        IReadOnlySet<string> effectiveTrustTerminating = trustTerminating ?? WellKnownAuthenticatorStatuses.DefaultTrustTerminating;

        MetadataStatusReport deciding = entry.StatusReports[0];
        DateOnly decidingEffectiveDate = deciding.EffectiveDate ?? DateOnly.MinValue;
        for(int index = 1; index < entry.StatusReports.Count; index++)
        {
            MetadataStatusReport candidate = entry.StatusReports[index];
            DateOnly candidateEffectiveDate = candidate.EffectiveDate ?? DateOnly.MinValue;
            if(candidateEffectiveDate >= decidingEffectiveDate)
            {
                deciding = candidate;
                decidingEffectiveDate = candidateEffectiveDate;
            }
        }

        bool accepted = !effectiveTrustTerminating.Contains(deciding.Status);

        return new MetadataStatusEvaluation(accepted, deciding);
    }


    /// <summary>
    /// Copies <paramref name="entry"/>'s <see cref="MetadataBlobPayloadEntry.AttestationRootCertificates"/>
    /// into fresh, independently-owned carriers — the WebAuthn L3 §7.1 step 23 "list of acceptable
    /// trust anchors" for the matched AAGUID/AAID/ACKI's attestation chain.
    /// </summary>
    /// <param name="entry">The entry whose attestation root certificates to copy.</param>
    /// <param name="pool">The memory pool the fresh carriers rent from.</param>
    /// <returns>
    /// The fresh <see cref="PkiCertificateMemory"/> carriers, owned by the caller — empty when
    /// <paramref name="entry"/> carries no attestation root certificates. A fresh copy is required
    /// because these trust anchors are expected to outlive the <see cref="MetadataBlob"/>
    /// <paramref name="entry"/> came from (a relying party feeds them into an
    /// <see cref="AttestationVerificationRequest"/> built after the BLOB itself may have been
    /// disposed), mirroring the <see cref="Fido2CredentialRecord.Id"/> fresh-copy precedent.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="entry"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static IReadOnlyList<PkiCertificateMemory> GetAttestationTrustAnchors(MetadataBlobPayloadEntry entry, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(pool);

        if(entry.AttestationRootCertificates is not { Count: > 0 } rootCertificates)
        {
            return [];
        }

        var freshCopies = new PkiCertificateMemory[rootCertificates.Count];
        for(int index = 0; index < rootCertificates.Count; index++)
        {
            ReadOnlySpan<byte> source = rootCertificates[index].AsReadOnlySpan();
            IMemoryOwner<byte> owner = pool.Rent(source.Length);
            source.CopyTo(owner.Memory.Span);
            freshCopies[index] = new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
        }

        return freshCopies;
    }
}
