using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// The application-stored record a VCALM 1.0 §3.5.4 <c>GET /presentations/{id}</c> returns and a
/// §3.5.5 <c>DELETE /presentations/{id}</c> soft-deletes — the secured presentation's verbatim JSON
/// plus the §3.5.4 / §3.5.5 410-Gone soft-delete marker. The library never owns the store; the
/// application returns this from its load seam (see <see cref="LoadVcalmPresentationDelegate"/>).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="PresentationId"/> keys the record in the §3.5.3 listing and §3.5.4 retrieval;
/// <see cref="VerifiablePresentationJson"/> is the §3.5.2 response body's secured presentation —
/// either a Data-Integrity-secured presentation object or an <c>EnvelopedVerifiablePresentation</c> —
/// stored verbatim so the §3.5.3 / §3.5.4 retrieval echoes the exact bytes created.
/// </para>
/// <para>
/// <see cref="IsDeleted"/> distinguishes the §3.5.4 / §3.5.5 410 ("Gone! There is no data here") from
/// the 404 ("Presentation not found"): a presentation that was soft-deleted (§3.5.5, a 202 by default)
/// but whose tombstone the store retained is 410, whereas an id the store never held is 404. B.3
/// governs what a delete actually does to the underlying record — that is the application's concern
/// behind the delete seam.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmStoredPresentation PresentationId={PresentationId} IsDeleted={IsDeleted}")]
public sealed record VcalmStoredPresentation
{
    /// <summary>The id keying this presentation in the §3.5.3 listing and §3.5.4 retrieval.</summary>
    public required string PresentationId { get; init; }

    /// <summary>
    /// The verbatim JSON of the secured presentation (a Data Integrity presentation object or an
    /// <c>EnvelopedVerifiablePresentation</c>) the §3.5.3 / §3.5.4 retrieval returns.
    /// </summary>
    public required string VerifiablePresentationJson { get; init; }

    /// <summary>
    /// Whether this presentation has been soft-deleted (§3.5.5). When <see langword="true"/> the
    /// §3.5.4 retrieval responds 410 Gone rather than returning the presentation; when
    /// <see langword="false"/> it returns the presentation with 200.
    /// </summary>
    public bool IsDeleted { get; init; }
}
