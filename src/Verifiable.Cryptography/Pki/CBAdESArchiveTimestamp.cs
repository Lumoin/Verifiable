using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>arcTst</c> unsigned header parameter (label <c>3</c> within <c>uHeaders</c>, Table 8) — one or
/// more archive electronic time-stamps protecting the long-term availability and integrity of the CB-AdES
/// signature's validation material, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.3.5.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// CDDL (clause 5.3.5.1):
/// </para>
/// <code>
/// arcTst = tstContainer
/// </code>
/// <para>
/// The CDDL is a straight type alias — <c>arcTst</c> carries exactly the same shape as
/// <see cref="CBAdESTimestampContainer"/> (clause 5.4.3.3, CB-5.3.5.1-04), reused verbatim by the signed
/// <c>adoTst</c> (<see cref="CBAdESPayloadTimestamp"/>) and the unsigned <c>sigTst</c>
/// (<see cref="CBAdESSignatureTimestamp"/>). This type exists to give the <c>arcTst</c> occurrence of that
/// shape its own identity — an append-only, order-dependent element of <c>uHeaders</c> (CB-5.3.1-03, label
/// <c>3</c>) whose message imprint prefix-slices every unsigned component that precedes it at generation
/// time.
/// </para>
/// <para>
/// <strong>Imprint scope (CB-5.3.5.1-01).</strong> "The <c>arcTst</c> CBOR map shall encapsulate electronic
/// time-stamps computed on the COSE Payload, the protected headers map or maps (depending on the used
/// signature structure), the COSE signature value, the externally supplied data, when present, and the
/// <c>uHeaders</c> CBOR array within the unprotected headers map at the time of generating each electronic
/// time-stamp." This sentence is the semantic summary; the operative, precise byte-construction rule is the
/// 12-step message-imprint algorithm of clause 5.3.5.3 (generation variant) and its prefix-only validation
/// variant — implemented at the CBOR layer against the concrete COSE wire structure, not by this type (D1,
/// contract R-6: the algorithm's closing sentence cites "step 11)" for the byte string it means to name;
/// only step 12 produces one — read as step 12).
/// </para>
/// <para>
/// <strong>Counter-signature precondition and caution (CB-5.3.5.1-02/03).</strong> "If the CB-AdES signature
/// incorporates a counter signature element, all the required material for conducting the validation of the
/// counter signature shall be incorporated into the CB-AdES signature before generating the first
/// <c>arcTst</c> CBOR map" (CB-5.3.5.1-02) — an ordering precondition owned by the generation orchestrator
/// of clause 5.3.5.2, not this type. "The contents of the counter signature element should not be changed,
/// once it has been time-stamped by the <c>arcTst</c>" (CB-5.3.5.1-03, SHOULD NOT): mutating a counter
/// signature after archive-timestamping breaks that <c>arcTst</c>'s validation (NOTE 3) — a caution for
/// producers, not an invariant this type can enforce.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns <see cref="TimestampContainer"/>; disposing this instance
/// disposes it. No separate disposed-flag field is kept here — matching
/// <see cref="CBAdESPayloadTimestamp"/>'s rationale — so <see cref="Dispose"/> forwards unconditionally and
/// relies on <see cref="CBAdESTimestampContainer"/>'s own <c>Dispose</c> being idempotent.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESArchiveTimestamp: {TimestampContainer}")]
public sealed record CBAdESArchiveTimestamp: IDisposable
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CBAdESArchiveTimestamp"/> class. Ownership of
    /// <paramref name="timestampContainer"/> transfers to this instance; disposing this instance disposes it.
    /// </summary>
    /// <param name="timestampContainer">
    /// The encapsulated container of one or more archive time-stamp tokens (CB-5.3.5.1-04).
    /// </param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="timestampContainer"/> is <see langword="null"/>.</exception>
    public CBAdESArchiveTimestamp(CBAdESTimestampContainer timestampContainer)
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
