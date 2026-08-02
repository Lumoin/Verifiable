using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>sigRTst</c> unsigned header parameter (label <c>5</c> within <c>uHeaders</c>, Table 8) — one or
/// more electronic time-stamps protecting the COSE signature value together with the signature time-stamp
/// and the references to validation data, when present, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, Annex A.1.2.1.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// CDDL (Annex A.1.2.1.1):
/// </para>
/// <code>
/// sigRTst = tstContainer
/// </code>
/// <para>
/// The CDDL is a straight type alias — <c>sigRTst</c> carries exactly the same shape as
/// <see cref="CBAdESTimestampContainer"/> (clause 5.4.3.3), reused verbatim across every time-stamp-token
/// container this document defines. This type exists to give the <c>sigRTst</c> occurrence of that shape
/// its own identity — a B-B/B-T-only unsigned component (Table 14: hard-forbidden from B-LT on) whose
/// message imprint has its own bespoke scope and algorithm (Annex A.1.2.1.2), distinct from both
/// <c>sigTst</c>'s fixed-field imprint and <c>arcTst</c>'s 12-step concatenation.
/// </para>
/// <para>
/// <strong>Protected scope (CB-A.1.2.1-01/02).</strong> "The <c>sigRTst</c> CBOR map shall encapsulate
/// electronic time-stamps on the COSE signature value, the signature time-stamp, if present, and the
/// CB-AdES components containing references to validation data" — i.e. the raw COSE signature-value bytes,
/// <c>sigTst</c> when present (<see cref="CBAdESSignatureTimestamp"/>), and <c>refs</c> when present. The
/// exact byte-construction rule (Annex A.1.2.1.2: initialize an array, append the signature-value bytes,
/// then append <c>sigTst</c>/<c>refs</c> in wire order from the appropriate COSE layer — signer layer under
/// <c>COSE_Sign</c>, body layer under <c>COSE_Sign1</c> — and encode the result to a byte string) is
/// implemented at the CBOR layer against the concrete COSE wire structure, not by this type.
/// </para>
/// <para>
/// <strong>Generation gate is a creation-time rule owned elsewhere (CB-A.1.2.1-03).</strong> "If the
/// component <c>refs</c> is not present, the <c>sigRTst</c> CBOR map shall not be generated." This type
/// cannot see the signature it would be attached to — it has no visibility into whether a <c>refs</c>
/// component is present alongside it — so the gate is recorded here for the creation-path orchestrator that
/// assembles <c>uHeaders</c> to enforce, not as a constructor guard on this type.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns <see cref="TimestampContainer"/>; disposing this instance
/// disposes it. No separate disposed-flag field is kept here — matching
/// <see cref="CBAdESPayloadTimestamp"/>'s rationale — so <see cref="Dispose"/> forwards unconditionally and
/// relies on <see cref="CBAdESTimestampContainer"/>'s own <c>Dispose</c> being idempotent.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESSignatureAndReferencesTimestamp: {TimestampContainer}")]
public sealed record CBAdESSignatureAndReferencesTimestamp: IDisposable
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CBAdESSignatureAndReferencesTimestamp"/> class.
    /// Ownership of <paramref name="timestampContainer"/> transfers to this instance; disposing this
    /// instance disposes it.
    /// </summary>
    /// <param name="timestampContainer">
    /// The encapsulated container of one or more signature-and-references time-stamp tokens
    /// (CB-A.1.2.1-01/02).
    /// </param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="timestampContainer"/> is <see langword="null"/>.</exception>
    public CBAdESSignatureAndReferencesTimestamp(CBAdESTimestampContainer timestampContainer)
    {
        ArgumentNullException.ThrowIfNull(timestampContainer);

        TimestampContainer = timestampContainer;
    }


    /// <summary>
    /// Gets the encapsulated time-stamp token container. Owned by this instance; disposed via
    /// <see cref="Dispose"/>.
    /// </summary>
    public CBAdESTimestampContainer TimestampContainer { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        TimestampContainer.Dispose();
    }
}
