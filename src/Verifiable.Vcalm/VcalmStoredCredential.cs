using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// The application-stored record a VCALM 1.0 §3.2.2 <c>GET /credentials/{id}</c> returns and a
/// §3.2.3 <c>DELETE /credentials/{id}</c> soft-deletes — the secured credential's verbatim JSON plus
/// the §3.2.2 410-Gone soft-delete marker. The library never owns the store; the application returns
/// this from its load seam (see <see cref="LoadVcalmIssuedCredentialDelegate"/>).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="VerifiableCredentialJson"/> is the §3.2.1 response body's <c>verifiableCredential</c>
/// member — either a Data-Integrity-secured VC object or an <c>EnvelopedVerifiableCredential</c> —
/// stored verbatim so the §3.2.2 retrieval echoes the exact bytes issued.
/// </para>
/// <para>
/// <see cref="IsDeleted"/> distinguishes the §3.2.2 410 ("Gone! There is no data here") from the 404
/// ("Credential not found"): a credential that was soft-deleted (§3.2.3, a 202 by default) but whose
/// tombstone the store retained is 410, whereas an id the store never held is 404. B.3 governs what a
/// delete actually does to the underlying record and any status side-effects (partial vs complete
/// deletion, revocation/suspension bits) — that is the application's concern behind the delete seam.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmStoredCredential IsDeleted={IsDeleted}")]
public sealed record VcalmStoredCredential
{
    /// <summary>
    /// The verbatim JSON of the secured credential (a Data Integrity VC object or an
    /// <c>EnvelopedVerifiableCredential</c>) the §3.2.2 retrieval returns under
    /// <c>verifiableCredential</c>.
    /// </summary>
    public required string VerifiableCredentialJson { get; init; }

    /// <summary>
    /// Whether this credential has been soft-deleted (§3.2.3). When <see langword="true"/> the
    /// §3.2.2 retrieval responds 410 Gone rather than returning the credential; when
    /// <see langword="false"/> it returns the credential with 200.
    /// </summary>
    public bool IsDeleted { get; init; }
}
