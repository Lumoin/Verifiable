using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>sigTst</c> unsigned header parameter (label <c>1</c> within <c>uHeaders</c>, Table 8) — one or
/// more electronic time-stamps time-stamping the COSE signature value, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.3.3</see>.
/// </summary>
/// <remarks>
/// <para>
/// CDDL (clause 5.3.3):
/// </para>
/// <code>
/// sigTst = tstContainer
/// </code>
/// <para>
/// The CDDL is a straight type alias — <c>sigTst</c> carries exactly the same shape as
/// <see cref="CBAdESTimestampContainer"/> (clause 5.4.3.3), reused verbatim by the signed <c>adoTst</c>
/// (<see cref="CBAdESPayloadTimestamp"/>) and the unsigned <c>arcTst</c>
/// (<see cref="CBAdESArchiveTimestamp"/>). This type exists to give the <c>sigTst</c> occurrence of that
/// shape its own identity — an unsigned, signature-value-qualifying component placed in <c>uHeaders</c>
/// (CB-5.3.1-05/06, label <c>1</c>) — rather than reusing <see cref="CBAdESTimestampContainer"/> bare with
/// no way to tell, from the type alone, which unsigned header parameter a given instance belongs to.
/// </para>
/// <para>
/// (CB-5.3.3-01) "The <c>sigTst</c> CBOR map shall encapsulate one or more electronic time-stamps
/// time-stamping the COSE signature value."
/// </para>
/// <para>
/// <strong>Message-imprint input is a fixed field, not a concatenation algorithm (CB-5.3.3-02).</strong>
/// "The input of the message imprint computation for the time-stamp tokens encapsulated by <c>sigTst</c>
/// CBOR map shall be the COSE signature value present within the CB-AdES signature" — i.e. the
/// <c>signature</c> byte-string member of <c>COSE_Signature</c>/<c>COSE_Sign1</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.1">IETF RFC 9052, clause 4.1</see>), a
/// single fixed byte range with no concatenation algorithm of its own. Contrast with <c>arcTst</c>'s 12-step
/// concatenation (clause 5.3.5.3), implemented at the CBOR layer, not here.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns <see cref="TimestampContainer"/>; disposing this instance
/// disposes it. No separate disposed-flag field is kept here — matching
/// <see cref="CBAdESPayloadTimestamp"/>'s rationale — so <see cref="Dispose"/> forwards unconditionally and
/// relies on <see cref="CBAdESTimestampContainer"/>'s own <c>Dispose</c> being idempotent.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESSignatureTimestamp: {TimestampContainer}")]
public sealed record CBAdESSignatureTimestamp: IDisposable
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CBAdESSignatureTimestamp"/> class. Ownership of
    /// <paramref name="timestampContainer"/> transfers to this instance; disposing this instance disposes it.
    /// </summary>
    /// <param name="timestampContainer">
    /// The encapsulated container of one or more signature-value time-stamp tokens (CB-5.3.3-01).
    /// </param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="timestampContainer"/> is <see langword="null"/>.</exception>
    public CBAdESSignatureTimestamp(CBAdESTimestampContainer timestampContainer)
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
