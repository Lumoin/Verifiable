using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What the format checking building block concluded, together with the facts its parse produced.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> <see cref="Facts"/> transfers to the caller, which disposes it once the whole
/// validation run is complete — every later building block reads it.
/// </remarks>
[DebuggerDisplay("FormatCheckingResult: {Conclusion.Indication}")]
public sealed record FormatCheckingResult
{
    /// <summary>The block's conclusion: <c>PASSED</c> when the signature is conformant, <c>FAILED</c> when it is not.</summary>
    public required BuildingBlockConclusion Conclusion { get; init; }

    /// <summary>The facts the format binding extracted, owned by the caller. On <c>FAILED</c> these carry <see cref="SignatureFactsStatus.FormatFailure"/> and own nothing.</summary>
    public required SignatureFacts Facts { get; init; }
}


/// <summary>
/// The format checking building block of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.2.2</see>: it checks that the signature to validate is conformant to the
/// applicable base format "to the extent that its inner contents would at least allow to be processed by the
/// cryptographic verification building block".
/// </summary>
/// <remarks>
/// <para>
/// The check is the format binding's parse. Clause 5.2.2.1 defines conformance by what the cryptographic
/// verification building block needs, and what that block needs is exactly what
/// <see cref="ExtractSignatureFactsAsyncDelegate"/> produces, so a binding that can extract the facts has
/// demonstrated the conformance this clause asks about and one that cannot has demonstrated its absence. The
/// facts are produced once and read by every later block rather than each block re-parsing.
/// </para>
/// <para>
/// The NOTE of clause 5.2.2.1 is respected: nothing here checks conformance to a signature profile or to a
/// signature level. Those belong to the signature acceptance validation building block (clause 5.2.8) driven by
/// the signature elements constraints.
/// </para>
/// </remarks>
public static class FormatChecking
{
    /// <summary>
    /// Runs the format check over one Signed Data Object.
    /// </summary>
    /// <param name="context">Table 8's mandatory Signed Data Object input, together with any Signer's Documents the Driving Application supplied.</param>
    /// <param name="format">The base format being checked against — <see cref="SignatureFormatSeam.Format"/>.</param>
    /// <param name="extractFacts">The format binding's fact extraction — <see cref="SignatureFormatSeam.ExtractFacts"/>.</param>
    /// <param name="pool">The memory pool the extracted carriers are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// The conclusion of clause 5.2.2.3 — <c>PASSED</c> for a conformant signature, <c>FAILED</c> with
    /// <c>FORMAT_FAILURE</c> and a <see cref="FormatFailureReportData"/> for one that is not — and the facts the
    /// caller disposes.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the extracted facts transfers to the returned result, which the caller disposes once every later building block has read them.")]
    public static async ValueTask<FormatCheckingResult> CheckAsync(
        SignatureFactsExtractionContext context,
        SignatureFormatIdentifier format,
        ExtractSignatureFactsAsyncDelegate extractFacts,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(extractFacts);
        ArgumentNullException.ThrowIfNull(pool);

        SignatureFacts facts;
        try
        {
            facts = await extractFacts(context, pool, cancellationToken).ConfigureAwait(false);
        }
        catch(Exception exception) when(exception is not OperationCanceledException)
        {
            //A binding is contracted to report a format failure rather than throw, but the Signed Data Object is
            //attacker-reachable and clause 5.2.2.3 defines an indication for every non-conformant input: a
            //binding that throws anyway still yields FAILED/FORMAT_FAILURE, never an escaping exception.
            facts = SignatureFacts.FormatFailure(format, exception.Message);
        }

        BuildingBlockConclusion conclusion = facts.IsExtracted
            ? BuildingBlockConclusion.Passed
            : BuildingBlockConclusion.Failed(
                SignatureValidationSubIndication.FormatFailure,
                [new FormatFailureReportData(facts.FormatFailureReason ?? "The signature is not conformant to its base format.")]);

        return new FormatCheckingResult { Conclusion = conclusion, Facts = facts };
    }
}
