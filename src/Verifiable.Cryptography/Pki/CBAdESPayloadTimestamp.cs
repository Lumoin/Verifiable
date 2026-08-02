using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>adoTst</c> signed header parameter — one or more electronic time-stamps generated over the COSE
/// Payload before signature production, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.2.6</see>.
/// </summary>
/// <remarks>
/// <para>
/// <c>adoTst</c> qualifies the COSE Payload (CB-5.2.6-01) and, in a <c>COSE_Sign</c> structure, is placed at
/// the signer layer (CB-5.2.6-08). Its wire label is <c>265</c>
/// (<c>adoTst</c>, clause 5.2.1 Table 1).
/// </para>
/// <para>
/// CDDL (clause 5.2.6):
/// </para>
/// <code>
/// adoTst = tstContainer
/// </code>
/// <para>
/// The CDDL is a straight type alias — <c>adoTst</c> carries exactly the same shape as
/// <see cref="CBAdESTimestampContainer"/> (clause 5.4.3.3), the container reused verbatim by the unsigned
/// <c>sigTst</c> and <c>arcTst</c> header parameters (clause 5.3). This type exists to give the <c>adoTst</c>
/// occurrence of that shape its own signed-header identity — label, protected-header placement, and
/// payload-qualifying scope (as opposed to <c>sigTst</c>'s signature-qualifying scope or <c>arcTst</c>'s, both
/// carried unsigned) — rather than reusing <see cref="CBAdESTimestampContainer"/> bare at three call sites
/// with no way to tell, from the type alone, which header parameter a given instance belongs to.
/// </para>
/// <para>
/// <strong>Message-imprint input is not this type's concern.</strong> The message-imprint computation input
/// for the time-stamp token(s) this type encapsulates is the COSE Payload (CB-5.2.6-04), reconstructed by a
/// three-branch dispatch keyed off <c>sigD</c> presence and, when present, its mechanism identifier
/// (CB-5.2.6-05/06/07 — see <see cref="CBAdESDetachedObjects"/> and <see cref="CBAdESDetachedMechanisms"/>).
/// That builder is a mechanism-dispatch seam shared with <c>arcTst</c>'s imprint computation (clause 5.3.5.3)
/// and belongs to a later CB-AdES stage; this type only carries the resulting tokens.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns <see cref="TimestampContainer"/>; disposing this instance
/// disposes it. No separate disposed-flag field is kept here — a private field would participate in this
/// record's compiler-synthesized equality, making two otherwise-equal instances compare unequal once one of
/// them is disposed — so <see cref="Dispose"/> forwards unconditionally and relies on
/// <see cref="CBAdESTimestampContainer"/>'s own <c>Dispose</c> being idempotent, the same carrier-disposal
/// convention this library's other disposable carriers follow.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESPayloadTimestamp: {TimestampContainer}")]
public sealed record CBAdESPayloadTimestamp: IDisposable
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CBAdESPayloadTimestamp"/> class. Ownership of
    /// <paramref name="timestampContainer"/> transfers to this instance; disposing this instance disposes it.
    /// </summary>
    /// <param name="timestampContainer">
    /// The encapsulated container of one or more pre-signing time-stamp tokens (CB-5.2.6-03).
    /// </param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="timestampContainer"/> is <see langword="null"/>.</exception>
    public CBAdESPayloadTimestamp(CBAdESTimestampContainer timestampContainer)
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
