using System.Diagnostics;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Fido2;

/// <summary>
/// A single entry from a FIDO Metadata Service BLOB payload's <c>entries</c> array — the typed
/// subset of the <c>MetadataBLOBPayloadEntry</c> dictionary this library models.
/// </summary>
/// <param name="Aaguid">
/// The <c>aaguid</c> member, parsed as a canonical GUID string, or <see langword="null"/> when
/// absent — set when the authenticator implements FIDO2, per
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-pe">FIDO
/// Metadata Service v3.1, section 3.1.1: Metadata BLOB Payload Entry dictionary</see>. The FIDO2
/// entry-lookup key, per <see cref="MetadataBlobPayloadQueries.TryFindEntryByAaguid"/>.
/// </param>
/// <param name="Aaid">
/// The <c>aaid</c> member, or <see langword="null"/> when absent — set when the authenticator
/// implements FIDO UAF, per the same section. FIDO2 authenticators never carry this.
/// </param>
/// <param name="AttestationCertificateKeyIdentifiers">
/// The <c>attestationCertificateKeyIdentifiers</c> member — lowercase hex-encoded RFC 5280 §4.2.1.2
/// method-1 key identifiers, per the same section — or <see langword="null"/> when absent. Set when
/// neither <see cref="Aaid"/> nor <see cref="Aaguid"/> is set: the U2F entry-lookup key, per
/// <see cref="MetadataBlobPayloadQueries.TryFindEntryByAttestationCertificateKeyIdentifier"/>. The
/// reader enforces the producer format at parse time — each element must be non-empty, hex-only, and
/// all-lowercase — so every identifier carried here is already in canonical form; the query performs
/// an ordinal comparison against it.
/// </param>
/// <param name="StatusReports">
/// The <c>statusReports</c> member, in wire order — the array
/// <see cref="MetadataBlobPayloadQueries.EvaluateStatus"/> decides trust from.
/// </param>
/// <param name="TimeOfLastStatusChange">
/// The <c>timeOfLastStatusChange</c> member, if present.
/// </param>
/// <param name="AttestationRootCertificates">
/// The entry's <c>metadataStatement.attestationRootCertificates</c> array, lifted out of the
/// otherwise-opaque metadata statement and typed as certificate carriers — the WebAuthn L3 §7.1
/// step 23 "list of acceptable trust anchors" this AAGUID/AAID/ACKI's attestation chain validates
/// against, per <see cref="MetadataBlobPayloadQueries.GetAttestationTrustAnchors"/>. The full
/// metadata statement schema is a separate specification this wave does not model; only this field
/// is typed. <see langword="null"/> when the entry's metadata statement carries no such array.
/// Owned by this entry; disposed alongside it.
/// </param>
/// <param name="RawMetadataStatement">
/// The entry's <c>metadataStatement</c> value, as the raw encoded JSON bytes — the escape hatch for
/// every metadata statement field this wave does not type. An independent, GC-managed copy (not a
/// pooled carrier and not an alias into any other buffer), mirroring
/// <c>PackedAttestationStatement.Signature</c>'s plain-array shape — it needs no explicit disposal
/// and remains valid for this entry's own lifetime.
/// </param>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob-pe">FIDO
/// Metadata Service v3.1, section 3.1.1: Metadata BLOB Payload Entry dictionary.</see>
/// <para>
/// <strong>Ownership.</strong> This entry owns <see cref="AttestationRootCertificates"/> and
/// disposes it (a single-owner tree: the enclosing <see cref="MetadataBlobPayload"/> owns its
/// entries, each entry owns its own certificate list); <see cref="RawMetadataStatement"/> needs no
/// disposal at all, per its own remarks.
/// </para>
/// </remarks>
[DebuggerDisplay("MetadataBlobPayloadEntry(Aaguid={Aaguid}, Aaid={Aaid,nq}, StatusReports={StatusReports.Count})")]
public sealed record MetadataBlobPayloadEntry(
    Guid? Aaguid,
    string? Aaid,
    IReadOnlyList<string>? AttestationCertificateKeyIdentifiers,
    IReadOnlyList<MetadataStatusReport> StatusReports,
    DateOnly? TimeOfLastStatusChange,
    IReadOnlyList<PkiCertificateMemory>? AttestationRootCertificates,
    ReadOnlyMemory<byte> RawMetadataStatement): IDisposable
{
    /// <summary>
    /// Determines whether this entry and <paramref name="other"/> report the same content. The
    /// compiler-synthesized record equality would compare every list-typed member and
    /// <see cref="RawMetadataStatement"/> by reference/identity, which would report two
    /// independently-parsed entries carrying byte-identical content as unequal; this override
    /// compares each list element-wise and <see cref="RawMetadataStatement"/> by byte content
    /// instead.
    /// </summary>
    /// <param name="other">The other entry to compare against.</param>
    /// <returns>
    /// <see langword="true"/> when every member matches, including value-wise comparisons of the
    /// list-typed and byte-memory members.
    /// </returns>
    public bool Equals(MetadataBlobPayloadEntry? other) =>
        other is not null
        && Aaguid == other.Aaguid
        && Aaid == other.Aaid
        && SequenceEqualOrBothNull(AttestationCertificateKeyIdentifiers, other.AttestationCertificateKeyIdentifiers, StringComparer.Ordinal)
        && StatusReports.SequenceEqual(other.StatusReports)
        && TimeOfLastStatusChange == other.TimeOfLastStatusChange
        && SequenceEqualOrBothNull(AttestationRootCertificates, other.AttestationRootCertificates, EqualityComparer<PkiCertificateMemory>.Default)
        && RawMetadataStatement.Span.SequenceEqual(other.RawMetadataStatement.Span);


    /// <summary>
    /// Computes a hash code consistent with <see cref="Equals(MetadataBlobPayloadEntry?)"/>.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(Aaguid);
        hash.Add(Aaid, StringComparer.Ordinal);
        hash.Add(TimeOfLastStatusChange);
        if(AttestationCertificateKeyIdentifiers is not null)
        {
            foreach(string identifier in AttestationCertificateKeyIdentifiers)
            {
                hash.Add(identifier, StringComparer.Ordinal);
            }
        }

        foreach(MetadataStatusReport report in StatusReports)
        {
            hash.Add(report);
        }

        if(AttestationRootCertificates is not null)
        {
            foreach(PkiCertificateMemory certificate in AttestationRootCertificates)
            {
                hash.Add(certificate);
            }
        }

        hash.AddBytes(RawMetadataStatement.Span);

        return hash.ToHashCode();
    }


    /// <summary>
    /// Releases <see cref="AttestationRootCertificates"/>, if present. Does not release the buffer
    /// <see cref="RawMetadataStatement"/> aliases — see the type-level ownership remarks.
    /// </summary>
    public void Dispose()
    {
        if(AttestationRootCertificates is not null)
        {
            foreach(PkiCertificateMemory certificate in AttestationRootCertificates)
            {
                certificate.Dispose();
            }
        }
    }


    /// <summary>
    /// Compares two possibly-<see langword="null"/> lists for element-wise equality using
    /// <paramref name="comparer"/>, treating two <see langword="null"/> lists as equal.
    /// </summary>
    private static bool SequenceEqualOrBothNull<T>(IReadOnlyList<T>? left, IReadOnlyList<T>? right, IEqualityComparer<T> comparer)
    {
        if(left is null || right is null)
        {
            return left is null && right is null;
        }

        return left.SequenceEqual(right, comparer);
    }
}
