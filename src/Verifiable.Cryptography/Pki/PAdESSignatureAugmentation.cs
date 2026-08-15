using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What one <see cref="PAdESSignatureAugmentation.AugmentToBLT"/> call needs: the prior document revision, and
/// the validation material to place in its new DSS dictionary (clause 5.4.2.2). Ownership of every carrier named
/// here belongs to the caller for the whole call — the same convention <see cref="PdfDssPlacementRequest"/> and
/// <see cref="CAdESValidationMaterial"/> state for their own certificate/CRL/OCSP lists.
/// </summary>
public sealed record PAdESBLTAugmentationRequest
{
    /// <summary>Gets the whole bytes of the revision the DSS is layered on top of — a signed (B-B or B-T) document.</summary>
    public required ReadOnlyMemory<byte> PriorDocument { get; init; }

    /// <summary>Gets where the prior revision's own cross-reference chain sits and the next free object number.</summary>
    public required PdfIncrementalUpdateAnchor Anchor { get; init; }

    /// <summary>Gets the DER-encoded X.509 certificates placed in the DSS <c>Certs</c> array (PA-6.3-r2/u).</summary>
    public IReadOnlyList<PkiCertificateMemory> Certificates { get; init; } = [];

    /// <summary>Gets the DER-encoded CRLs placed in the DSS <c>CRLs</c> array (PA-6.3-t/u).</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateRevocationLists { get; init; } = [];

    /// <summary>Gets the DER-encoded OCSP responses placed in the DSS <c>OCSPs</c> array (PA-6.3-t/u).</summary>
    public IReadOnlyList<PkiCertificateMemory> OcspResponses { get; init; } = [];
}


/// <summary>
/// The LTV augmentation ladder verbs (ETSI EN 319 142-1 V1.2.1, RP-6's own deliverable): <see cref="AugmentToBLT"/>
/// raises a signed document to PAdES-B-LT by placing its first DSS dictionary, and <see cref="AugmentToBLTAAsync"/>
/// raises a B-LT document to PAdES-B-LTA by placing a Document Time-stamp — each composing s1's own PDF-native
/// machinery (<see cref="PdfIncrementalUpdateWriter.AppendValidationData"/>, <see cref="PAdESDocTimeStampCreation"/>)
/// unchanged, plus a fail-closed structural gate that runs BEFORE either verb writes a byte or (for
/// <see cref="AugmentToBLTAAsync"/>) contacts a Time-Stamping Authority.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why PAdES's own LTV ladder never touches the CMS.</strong> Unlike CAdES's own B-LT/B-LTA (unsigned
/// <c>certificate-values</c>/<c>revocation-values</c>/<c>archive-time-stamp-v3</c> attributes of the SAME
/// <c>SignedData</c>), Table 1's own T26-T30 place PAdES's equivalent material entirely at the PDF level: SPO DSS
/// (clause 5.4.2.2) and SPO document-time-stamp (clause 5.4.3) are separate incremental-update objects, never CMS
/// attributes. Both verbs below therefore never open or re-sign the original signature's own <c>Contents</c> —
/// they only append new PDF revisions on top of it, exactly as <see cref="PAdESSignatureCreation"/>'s own remarks
/// state for the B-B→B-T step.
/// </para>
/// <para>
/// <strong>Letter v) honored as a default, not merely permitted.</strong> PA-5.4.2.3-14/-15/-16 steer away from
/// the VRI dictionary's own <c>TU</c>/<c>TS</c> claimed-time entries toward "a subsequent document-time-stamp" as
/// the preferred claimed-time mechanism — <see cref="AugmentToBLT"/> never places a <see cref="PdfDssPlacementRequest.VriEntries"/>
/// entry, so a B-LTA document produced by chaining both verbs together always ends up on that preferred path.
/// </para>
/// </remarks>
public static class PAdESSignatureAugmentation
{
    /// <summary>
    /// Raises a signed document to PAdES-B-LT by placing its first DSS dictionary (PA-6.3-T27).
    /// </summary>
    /// <param name="request">The prior document and the validation material to place.</param>
    /// <param name="pool">The memory pool the structural gate's own signature-location scan rents from.</param>
    /// <returns>The new revision's bytes and the object numbers a further incremental update (<see cref="AugmentToBLTAAsync"/>) chains onto.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="request"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When the prior document carries no located Signature Dictionary (a DSS is meaningless PA-6.3-T27 material
    /// with no signature to validate — the structural half of this verb's own gate), when the document catalog
    /// cannot be located, or when the catalog already carries a <c>DSS</c> entry (see <see cref="PdfIncrementalUpdateWriter.AppendValidationData"/>).
    /// </exception>
    /// <remarks>
    /// PA-6.3-T27's own <c>&gt;= 1</c> cardinality at B-LT/B-LTA (PA-6.2.2-22: "The signature shall incorporate one
    /// or more instances of the attribute or signature field") is a count over INSTANCES of the SPO: DSS row
    /// itself — i.e. of DSS dictionaries, never a count over the <c>Certs</c>/<c>CRLs</c>/<c>OCSPs</c> entries one
    /// DSS dictionary carries. This method always writes exactly one DSS dictionary when it runs, satisfying that
    /// cardinality trivially by construction; PA-5.4.2.2's own table lists <c>Certs</c>, <c>CRLs</c>, <c>OCSPs</c>
    /// and <c>VRI</c> as each independently "(Optional)" — an empty DSS dictionary (no certificate, CRL or OCSP
    /// response at all) is a syntactically legitimate PA-5.4.2.2 object, so this method places no gate over
    /// <see cref="PAdESBLTAugmentationRequest.Certificates"/>/<see cref="PAdESBLTAugmentationRequest.CertificateRevocationLists"/>/
    /// <see cref="PAdESBLTAugmentationRequest.OcspResponses"/>'s own counts.
    /// </remarks>
    public static PdfDssPlacementResult AugmentToBLT(PAdESBLTAugmentationRequest request, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(pool);

        using PdfByteSurfaceParseResult located = PdfByteSurfaceReader.Locate(request.PriorDocument, pool);
        if(!located.IsSuccess || located.SignatureDictionaries!.Count == 0)
        {
            throw new ArgumentException(
                "PA-6.3-T27 gate: the prior document carries no located Signature Dictionary — a DSS dictionary names validation material 'for a specific signature' (clause 5.4.2.3-01) that does not yet exist.",
                nameof(request));
        }

        if(!PdfByteSurfaceReader.TryLocateCatalog(request.PriorDocument, out PdfCatalogLocation? catalog, out string? error))
        {
            throw new ArgumentException($"Could not locate the document catalog: {error}", nameof(request));
        }

        return PdfIncrementalUpdateWriter.AppendValidationData(new PdfDssPlacementRequest
        {
            PriorDocument = request.PriorDocument,
            Anchor = request.Anchor,
            Catalog = catalog!,
            Certificates = request.Certificates,
            CertificateRevocationLists = request.CertificateRevocationLists,
            OcspResponses = request.OcspResponses
        });
    }


    /// <summary>
    /// Raises a B-LT document to PAdES-B-LTA by placing a Document Time-stamp (PA-6.3-T30), gated by PA-6.3-x1's
    /// own pre-billing check: "before generating and incorporating a document-time-stamp attribute, applications
    /// shall include all the validation material ... required for validating the signature". This method reads
    /// the prior document's own DSS dictionary BEFORE contacting <see cref="PAdESDocTimeStampRequest.FetchResponse"/>'s
    /// Time-Stamping Authority — a paid, external operation this method refuses to reach for on a document that
    /// would fail PA-6.3-x1 regardless of what the authority answers.
    /// </summary>
    /// <param name="request">The Document Time-stamp creation request — the same shape <see cref="PAdESDocTimeStampCreation.CreateAsync"/> takes; this method composes it unchanged once its own gate passes.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The signed document and where the new Document Time-stamp landed.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="request"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">
    /// PA-6.3-x1's own gate: when the prior document carries no <c>DSS</c> dictionary at all, or a <c>DSS</c>
    /// dictionary whose <c>Certs</c>/<c>CRLs</c>/<c>OCSPs</c> arrays are all empty — either shape means the
    /// validation material PA-6.3-t/PA-6.3-x1 require was never included, so no Document Time-stamp is minted and
    /// no request ever reaches <see cref="PAdESDocTimeStampRequest.FetchResponse"/>.
    /// </exception>
    /// <exception cref="TimestampAcquisitionException">When the gate passes but the authority could not be reached, or the token it returned does not verify.</exception>
    public static async ValueTask<PAdESDocTimeStampResult> AugmentToBLTAAsync(
        PAdESDocTimeStampRequest request,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        using PdfDssParseResult dss = PdfDssReader.Locate(request.PriorDocument, pool);
        if(!dss.IsSuccess || !dss.HasDss || IsEmptyOfValidationMaterial(dss.Dss!))
        {
            throw new InvalidOperationException(
                "PA-6.3-x1: 'Before generating and incorporating a document-time-stamp attribute, applications " +
                "shall include all the validation material, which are not already in the signature, required " +
                "for validating the signature.' The prior document carries no DSS dictionary with at least one " +
                "certificate, CRL or OCSP response, so no Document Time-stamp was requested from the Time-Stamping Authority.");
        }

        return await PAdESDocTimeStampCreation.CreateAsync(request, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Reports whether a located DSS dictionary's own three material arrays are all empty.</summary>
    private static bool IsEmptyOfValidationMaterial(PdfDssDictionary dss) =>
        dss.Certificates.Count == 0 && dss.CertificateRevocationLists.Count == 0 && dss.OcspResponses.Count == 0;
}
