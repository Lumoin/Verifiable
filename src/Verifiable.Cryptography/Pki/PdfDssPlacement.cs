using System;
using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One Signature VRI dictionary a <see cref="PdfDssPlacementRequest"/> asks <see cref="PdfIncrementalUpdateWriter.AppendValidationData"/>
/// to write (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1</see> clause 5.4.2.3): the subset of the enclosing request's own <see cref="PdfDssPlacementRequest.Certificates"/>/
/// <see cref="PdfDssPlacementRequest.CertificateRevocationLists"/>/<see cref="PdfDssPlacementRequest.OcspResponses"/>
/// this one signature's validation used, named by index rather than duplicated — the shape that makes
/// PA-5.4.2.3-17 ("Any values in a Signature VRI dictionary's Cert/CRL/OCSP arrays shall also be present in the
/// DSS dictionary") true by construction, since a VRI entry can only ever reference an object the same call
/// already placed in the DSS-level arrays.
/// </summary>
/// <remarks>
/// PA-5.4.2.3-14/-15 steer away from <see cref="TimeUpdated"/>/<see cref="TimeStampToken"/> ("The TU key should
/// not be used" / "The TS key should not be used") in favour of a subsequent document-time-stamp — this type
/// still models both, since PA-5.4.2.3-16 requires exactly one of the three claimed-time mechanisms and a caller
/// may have a concrete reason to use TU or TS. <see cref="PdfIncrementalUpdateWriter.AppendValidationData"/>
/// enforces PA-5.4.2.3-10/-13 (mutual exclusion) fail-closed.
/// </remarks>
public sealed record PdfVriEntryRequest
{
    /// <summary>Gets the zero-based indices into the enclosing request's <see cref="PdfDssPlacementRequest.Certificates"/> this entry's own <c>Cert</c> array references.</summary>
    public IReadOnlyList<int> CertificateIndices { get; init; } = [];

    /// <summary>Gets the zero-based indices into the enclosing request's <see cref="PdfDssPlacementRequest.CertificateRevocationLists"/> this entry's own <c>CRL</c> array references.</summary>
    public IReadOnlyList<int> CrlIndices { get; init; } = [];

    /// <summary>Gets the zero-based indices into the enclosing request's <see cref="PdfDssPlacementRequest.OcspResponses"/> this entry's own <c>OCSP</c> array references.</summary>
    public IReadOnlyList<int> OcspIndices { get; init; } = [];

    /// <summary>Gets the <c>TU</c> claimed-generation time, or <see langword="null"/> to omit it. Mutually exclusive with <see cref="TimeStampToken"/> (PA-5.4.2.3-10/-13).</summary>
    public DateTimeOffset? TimeUpdated { get; init; }

    /// <summary>Gets the <c>TS</c> DER-encoded RFC 3161 time-stamp token, or <see langword="null"/> to omit it. Mutually exclusive with <see cref="TimeUpdated"/> (PA-5.4.2.3-10/-13). Borrowed: not disposed by anything here.</summary>
    public PkiCertificateMemory? TimeStampToken { get; init; }
}


/// <summary>
/// What one <see cref="PdfIncrementalUpdateWriter.AppendValidationData"/> call needs to mint a document's DSS
/// dictionary (clause 5.4.2.2) and, optionally, its Signature VRI dictionaries (clause 5.4.2.3) in one
/// incremental-update revision.
/// </summary>
/// <remarks>
/// The carriers named here belong to the caller for the whole call and are not disposed by anything in this
/// library — the same ownership convention <see cref="CAdESValidationMaterial"/> states for its own certificate
/// lists.
/// </remarks>
public sealed record PdfDssPlacementRequest
{
    /// <summary>Gets the whole bytes of the revision the DSS is layered on top of.</summary>
    public required ReadOnlyMemory<byte> PriorDocument { get; init; }

    /// <summary>Gets where the prior revision's own cross-reference chain sits and the next free object number.</summary>
    public required PdfIncrementalUpdateAnchor Anchor { get; init; }

    /// <summary>Gets where the document catalog sits (<see cref="PdfByteSurfaceReader.TryLocateCatalog"/>) — the catalog is rewritten to add the <c>DSS</c> entry ISO 32000-1 table 28 names (PA-5.4.2.1-T1), its own existing entries copied byte-for-byte.</summary>
    public required PdfCatalogLocation Catalog { get; init; }

    /// <summary>Gets the DER-encoded X.509 certificates placed in the DSS <c>Certs</c> array (PA-5.4.2.2-06).</summary>
    public IReadOnlyList<PkiCertificateMemory> Certificates { get; init; } = [];

    /// <summary>Gets the DER-encoded CRLs placed in the DSS <c>CRLs</c> array (PA-5.4.2.2-08).</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateRevocationLists { get; init; } = [];

    /// <summary>Gets the DER-encoded OCSP responses placed in the DSS <c>OCSPs</c> array (PA-5.4.2.2-07).</summary>
    public IReadOnlyList<PkiCertificateMemory> OcspResponses { get; init; } = [];

    /// <summary>Gets the Signature VRI dictionaries to place, keyed by the base-16 uppercase SHA-1 digest <see cref="PdfVriKey"/> computes (PA-5.4.2.2-T2), or <see langword="null"/> to place none.</summary>
    public IReadOnlyDictionary<string, PdfVriEntryRequest>? VriEntries { get; init; }
}


/// <summary>
/// The result of <see cref="PdfIncrementalUpdateWriter.AppendValidationData"/>: the whole document carrying the
/// new DSS revision, and the object numbers a further incremental update (a document-time-stamp over this
/// validation data, PA-6.3-x1) needs to chain onto it.
/// </summary>
public sealed record PdfDssPlacementResult
{
    /// <summary>Gets the whole document's bytes, the new DSS revision appended.</summary>
    public required byte[] Bytes { get; init; }

    /// <summary>Gets the byte offset of this revision's own <c>xref</c> keyword, for chaining a further incremental update's own <c>/Prev</c>.</summary>
    public required int XrefOffset { get; init; }

    /// <summary>Gets the new DSS dictionary's own object number.</summary>
    public required int DssObjectNumber { get; init; }

    /// <summary>Gets the new Signature VRI dictionaries' own object numbers, keyed the same way <see cref="PdfDssPlacementRequest.VriEntries"/> was.</summary>
    public required IReadOnlyDictionary<string, int> VriObjectNumbers { get; init; }

    /// <summary>Gets one past the highest object number this revision uses — the next call's own <see cref="PdfIncrementalUpdateAnchor.PriorObjectCount"/>.</summary>
    public required int NextObjectNumber { get; init; }

    /// <summary>Gets the anchor a further incremental update built on top of this one supplies to its own next call.</summary>
    /// <param name="rootObjectNumber">The document catalog's own object number — unchanged by this call, since the catalog's object number is reused, only its content rewritten.</param>
    /// <param name="rootGeneration">The document catalog's own generation number.</param>
    public PdfIncrementalUpdateAnchor NextAnchor(int rootObjectNumber, int rootGeneration = 0) => new()
    {
        PriorXrefOffset = XrefOffset,
        PriorObjectCount = NextObjectNumber,
        RootObjectNumber = rootObjectNumber,
        RootGeneration = rootGeneration
    };
}
