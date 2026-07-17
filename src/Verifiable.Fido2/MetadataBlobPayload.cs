using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// The typed <c>MetadataBLOBPayload</c> a verified Metadata BLOB's JWS payload segment decodes to.
/// </summary>
/// <param name="LegalHeader">
/// The <c>legalHeader</c> member, or <see langword="null"/> when absent, per
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-payload-blob">FIDO
/// Metadata Service v3.1, section 3.1.6: Metadata BLOB Payload dictionary</see>: "MUST be in each
/// BLOB, is an indication of the acceptance of the relevant legal agreement". This library exposes
/// the member's presence as data rather than enforcing that MUST itself — accepting or acting on a
/// legal agreement is not a verification-procedure concern.
/// </param>
/// <param name="No">
/// The <c>no</c> member — the BLOB's serial number, per the same section: "This serial number MUST
/// be incremented whenever the contents of the BLOB changes. Serial numbers MUST be consecutive and
/// strictly monotonic." Already checked for monotonicity by <see cref="MetadataBlobVerification"/>.
/// </param>
/// <param name="NextUpdate">
/// The <c>nextUpdate</c> member — the ISO-8601 date by which a fresh BLOB SHOULD be downloaded, per
/// the same section. Already checked against the verification request's validation time by
/// <see cref="MetadataBlobVerification"/>.
/// </param>
/// <param name="Entries">
/// The <c>entries</c> member, in wire order — the list <see cref="MetadataBlobPayloadQueries"/>'s
/// lookup functions search.
/// </param>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-payload-blob">FIDO
/// Metadata Service v3.1, section 3.1.6: Metadata BLOB Payload dictionary.</see>
/// <para>
/// The trust position is <em>verified payload</em>: constructed only by
/// <see cref="UnverifiedMetadataBlobPayload.ToVerified"/>, once the enclosing BLOB's full
/// verification procedure has passed. <see cref="MetadataBlobPayloadQueries"/> is typed on this
/// verified payload precisely so a query cannot run against entries whose enclosing BLOB signature
/// was never checked.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This payload owns <see cref="Entries"/> and disposes each one — a
/// single-owner tree: each entry separately owns its own
/// <see cref="MetadataBlobPayloadEntry.AttestationRootCertificates"/> list.
/// <see cref="MetadataBlobPayloadEntry.RawMetadataStatement"/> is an independent, GC-managed copy
/// (mirroring <c>PackedAttestationStatement.Signature</c>'s plain-array shape), so it needs no
/// pooled-buffer disposal of its own.
/// </para>
/// </remarks>
[DebuggerDisplay("MetadataBlobPayload(No={No}, NextUpdate={NextUpdate}, Entries={Entries.Count})")]
public sealed record MetadataBlobPayload(
    string? LegalHeader,
    long No,
    DateOnly NextUpdate,
    IReadOnlyList<MetadataBlobPayloadEntry> Entries): IDisposable
{
    /// <summary>
    /// Determines whether this payload and <paramref name="other"/> report the same content. The
    /// compiler-synthesized record equality would compare <see cref="Entries"/> by reference; this
    /// override compares it element-wise instead.
    /// </summary>
    /// <param name="other">The other payload to compare against.</param>
    /// <returns><see langword="true"/> when every member matches, including an element-wise comparison of <see cref="Entries"/>.</returns>
    public bool Equals(MetadataBlobPayload? other) =>
        other is not null
        && LegalHeader == other.LegalHeader
        && No == other.No
        && NextUpdate == other.NextUpdate
        && Entries.SequenceEqual(other.Entries);


    /// <summary>
    /// Computes a hash code consistent with <see cref="Equals(MetadataBlobPayload?)"/>.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(LegalHeader, StringComparer.Ordinal);
        hash.Add(No);
        hash.Add(NextUpdate);
        foreach(MetadataBlobPayloadEntry entry in Entries)
        {
            hash.Add(entry);
        }

        return hash.ToHashCode();
    }


    /// <summary>
    /// Releases every entry in <see cref="Entries"/>.
    /// </summary>
    public void Dispose()
    {
        foreach(MetadataBlobPayloadEntry entry in Entries)
        {
            entry.Dispose();
        }
    }
}
