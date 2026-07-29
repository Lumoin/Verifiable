using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Which validation process the Driving Application requires of the Signature Validation Application — step 1)
/// of clause 5.1.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>.
/// </summary>
public enum SignatureValidationProcessSelection
{
    /// <summary>
    /// Step 1)a): the Driving Application does not require a specific validation process, so the most capable
    /// process the Signature Validation Application supports is selected. The value of an unset field, and the
    /// value that treats every class of signature correctly.
    /// </summary>
    Automatic = 0,

    /// <summary>Step 1)b): the validation process for Basic Signatures of clause 5.3.</summary>
    BasicSignatures = 1,

    /// <summary>Step 1)c): the validation process for Signatures with Time and Signatures with Long-Term Validation Material of clause 5.5.</summary>
    SignaturesWithTime = 2,

    /// <summary>Step 1)d): the validation process for Signatures providing Long Term Availability and Integrity of Validation Material of clause 5.6.3.</summary>
    LongTermAvailability = 3
}


/// <summary>
/// Which validation processes a Signature Validation Application supports, which clause 5.1.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> makes steps 2) and 3) branch on.
/// </summary>
/// <remarks>
/// The clause makes the validation process for Basic Signatures mandatory for every Signature Validation
/// Application, so it has no member here: it is always supported and step 4) always reachable.
/// </remarks>
[DebuggerDisplay("SignatureValidationCapabilities: with time {SupportsSignaturesWithTime}, long term {SupportsLongTermAvailability}")]
public sealed record SignatureValidationCapabilities
{
    /// <summary>Whether the validation process for Signatures with Time and Signatures with Long-Term Validation Material of clause 5.5 is supported.</summary>
    public bool SupportsSignaturesWithTime { get; init; } = true;

    /// <summary>Whether the validation process for Signatures providing Long Term Availability and Integrity of Validation Material of clause 5.6.3 is supported.</summary>
    public bool SupportsLongTermAvailability { get; init; } = true;


    /// <summary>Every process of clause 5 — the capability set this library ships.</summary>
    public static SignatureValidationCapabilities All { get; } = new();

    /// <summary>Only the validation process for Basic Signatures, which clause 5.1.2 makes mandatory.</summary>
    public static SignatureValidationCapabilities BasicSignaturesOnly { get; } = new()
    {
        SupportsSignaturesWithTime = false,
        SupportsLongTermAvailability = false
    };
}


/// <summary>
/// One completed signature validation run: the conclusion clause 5.1.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> requires the Signature Validation Application to provide to the Driving
/// Application, together with the carriers the run created and therefore owns.
/// </summary>
/// <remarks>
/// <para>
/// Disposing this releases every carrier the run created — the signature's extracted facts, the certificates the
/// chain completion seam acquired, the time-stamp facts and the object-identity digests. <see cref="Conclusion"/>
/// references those carriers and must not be read after disposal; a Driving Application that keeps the
/// conclusion beyond the run copies out what it needs first.
/// </para>
/// </remarks>
[DebuggerDisplay("SignatureValidationOutcome: {Conclusion.Indication}")]
public sealed class SignatureValidationOutcome: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>The conclusion of clause 5.1.3, in the process-level vocabulary of Table 5.</summary>
    public required SignatureValidationConclusion Conclusion { get; init; }

    /// <summary>The carriers the run created, released by <see cref="Dispose"/>.</summary>
    public required SignatureValidationResources Resources { get; init; }

    /// <summary>What the validation process for Basic Signatures made of the signature; never <see langword="null"/>, because every process of clause 5 runs it.</summary>
    public required BasicSignatureValidationResult BasicValidation { get; init; }

    /// <summary>What the validation process for Signatures with Time made of the signature, when that process ran; <see langword="null"/> when the run selected the Basic Signatures process.</summary>
    public SignatureWithTimeValidationResult? SignatureWithTimeValidation { get; init; }

    /// <summary>What the validation process for Signatures providing Long Term Availability and Integrity of Validation Material made of the signature, when that process ran; <see langword="null"/> otherwise.</summary>
    public LongTermValidationResult? LongTermValidation { get; init; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;
        Resources.Dispose();
    }
}


/// <summary>
/// The entry point of the signature validation algorithm of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5</see>: it selects a validation process per clause 5.1.2, runs it, and
/// reports the status indication and the information clause 5.1.3 requires.
/// </summary>
/// <remarks>
/// <para>
/// This is the one composition root of the algorithm, and the only place a current time enters it. Every process,
/// every building block and every seam below takes the instant as an explicit argument, which is what makes
/// clause 5.1.3's determinism rule — "any execution of an SVA with the same inputs shall return
/// <c>TOTAL-PASSED</c> or <c>TOTAL-FAILED</c>, respectively" — hold by construction rather than by convention.
/// The overload taking a <see cref="TimeProvider"/> reads it exactly once and threads the value down.
/// </para>
/// <para>
/// Clause 5.1.2's steps 5), 6) and 7) map the selected process's <c>PASSED</c> / <c>FAILED</c> /
/// <c>INDETERMINATE</c> onto the main status indication of Table 5, which is what
/// <see cref="BuildingBlockIndicationMapping.ToProcessIndication"/> does.
/// </para>
/// </remarks>
public static class SignatureValidation
{
    /// <summary>
    /// Validates one signature, reading the current time once from a time provider.
    /// </summary>
    /// <param name="inputs">The Driving Application's inputs.</param>
    /// <param name="seams">The format binding and the certificate seams the algorithm composes.</param>
    /// <param name="selection">Which validation process the Driving Application requires, per step 1) of clause 5.1.2.</param>
    /// <param name="capabilities">Which validation processes the Signature Validation Application supports, per steps 2) and 3).</param>
    /// <param name="timeProvider">The time provider the current time is read from, once.</param>
    /// <param name="pool">The memory pool the run rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The outcome, which the caller disposes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static ValueTask<SignatureValidationOutcome> ValidateAsync(
        SignatureValidationInputs inputs,
        SignatureValidationSeams seams,
        SignatureValidationProcessSelection selection,
        SignatureValidationCapabilities capabilities,
        TimeProvider timeProvider,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);

        return ValidateAsync(inputs, seams, selection, capabilities, timeProvider.GetUtcNow(), pool, cancellationToken);
    }


    /// <summary>
    /// Validates one signature at a stated current time.
    /// </summary>
    /// <param name="inputs">The Driving Application's inputs.</param>
    /// <param name="seams">The format binding and the certificate seams the algorithm composes.</param>
    /// <param name="selection">Which validation process the Driving Application requires, per step 1) of clause 5.1.2.</param>
    /// <param name="capabilities">Which validation processes the Signature Validation Application supports, per steps 2) and 3).</param>
    /// <param name="currentTime">The current time, which clause 5.1.3 NOTE 1 makes the date and time the validation status is determined for.</param>
    /// <param name="pool">The memory pool the run rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The outcome, which the caller disposes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the resource ledger transfers to the returned outcome, which the caller disposes; it is released here only when the run itself fails.")]
    public static async ValueTask<SignatureValidationOutcome> ValidateAsync(
        SignatureValidationInputs inputs,
        SignatureValidationSeams seams,
        SignatureValidationProcessSelection selection,
        SignatureValidationCapabilities capabilities,
        DateTimeOffset currentTime,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(seams);
        ArgumentNullException.ThrowIfNull(capabilities);
        ArgumentNullException.ThrowIfNull(pool);

        var resources = new SignatureValidationResources();
        try
        {
            SignatureValidationProcessSelection selected = SelectProcess(selection, capabilities);

            return selected switch
            {
                SignatureValidationProcessSelection.LongTermAvailability =>
                    await RunLongTermAsync(inputs, seams, currentTime, resources, pool, cancellationToken).ConfigureAwait(false),
                SignatureValidationProcessSelection.SignaturesWithTime =>
                    await RunWithTimeAsync(inputs, seams, currentTime, resources, pool, cancellationToken).ConfigureAwait(false),
                _ => await RunBasicAsync(inputs, seams, currentTime, resources, pool, cancellationToken).ConfigureAwait(false)
            };
        }
        catch
        {
            resources.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Chooses the validation process, per steps 1) to 4) of clause 5.1.2.
    /// </summary>
    /// <param name="selection">What the Driving Application requires.</param>
    /// <param name="capabilities">What the Signature Validation Application supports.</param>
    /// <returns>The process to run, which is never <see cref="SignatureValidationProcessSelection.Automatic"/>.</returns>
    private static SignatureValidationProcessSelection SelectProcess(
        SignatureValidationProcessSelection selection,
        SignatureValidationCapabilities capabilities) => selection switch
        {
            //Step 1)b): the Driving Application requires the validation process for Basic Signatures, which every
            //Signature Validation Application supports, so step 4) runs it.
            SignatureValidationProcessSelection.BasicSignatures => SignatureValidationProcessSelection.BasicSignatures,

            //Step 1)c) goes to step 3), which falls through to step 4) when the process is not supported.
            SignatureValidationProcessSelection.SignaturesWithTime => capabilities.SupportsSignaturesWithTime
                ? SignatureValidationProcessSelection.SignaturesWithTime
                : SignatureValidationProcessSelection.BasicSignatures,

            //Steps 1)a) and 1)d) both go to step 2), which falls through to step 3) and then to step 4).
            _ => capabilities.SupportsLongTermAvailability
                ? SignatureValidationProcessSelection.LongTermAvailability
                : capabilities.SupportsSignaturesWithTime
                    ? SignatureValidationProcessSelection.SignaturesWithTime
                    : SignatureValidationProcessSelection.BasicSignatures
        };


    /// <summary>
    /// Runs the validation process for Basic Signatures and shapes its result into a conclusion.
    /// </summary>
    /// <param name="inputs">The Driving Application's inputs.</param>
    /// <param name="seams">The seams the algorithm composes.</param>
    /// <param name="currentTime">The current time.</param>
    /// <param name="resources">The run's resource ledger.</param>
    /// <param name="pool">The memory pool the run rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The outcome.</returns>
    private static async ValueTask<SignatureValidationOutcome> RunBasicAsync(
        SignatureValidationInputs inputs,
        SignatureValidationSeams seams,
        DateTimeOffset currentTime,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        BasicSignatureValidationResult basic = await BasicSignatureValidation.ValidateAsync(
            inputs, seams, validateTimestampToken: null, currentTime, resources, pool, cancellationToken).ConfigureAwait(false);

        return new SignatureValidationOutcome
        {
            Conclusion = Conclude(basic, SignatureValidationProcessIdentifier.Basic, currentTime, bestSignatureTime: null, inputs),
            Resources = resources,
            BasicValidation = basic
        };
    }


    /// <summary>
    /// Runs the validation process for Signatures with Time and Signatures with Long-Term Validation Material and
    /// shapes its result into a conclusion.
    /// </summary>
    /// <param name="inputs">The Driving Application's inputs.</param>
    /// <param name="seams">The seams the algorithm composes.</param>
    /// <param name="currentTime">The current time.</param>
    /// <param name="resources">The run's resource ledger.</param>
    /// <param name="pool">The memory pool the run rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The outcome.</returns>
    private static async ValueTask<SignatureValidationOutcome> RunWithTimeAsync(
        SignatureValidationInputs inputs,
        SignatureValidationSeams seams,
        DateTimeOffset currentTime,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        SignatureWithTimeValidationResult withTime = await SignatureWithTimeValidation.ValidateAsync(
            inputs, seams, currentTime, resources, pool, cancellationToken).ConfigureAwait(false);

        return new SignatureValidationOutcome
        {
            Conclusion = Conclude(
                withTime.BasicValidation with { Conclusion = withTime.Conclusion },
                SignatureValidationProcessIdentifier.LongTermValidationMaterial,
                currentTime,
                withTime.BestSignatureTime,
                inputs),
            Resources = resources,
            BasicValidation = withTime.BasicValidation,
            SignatureWithTimeValidation = withTime
        };
    }


    /// <summary>
    /// Runs the validation process for Signatures providing Long Term Availability and Integrity of Validation
    /// Material and shapes its result into a conclusion.
    /// </summary>
    /// <param name="inputs">The Driving Application's inputs.</param>
    /// <param name="seams">The seams the algorithm composes.</param>
    /// <param name="currentTime">The current time.</param>
    /// <param name="resources">The run's resource ledger.</param>
    /// <param name="pool">The memory pool the run rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The outcome.</returns>
    private static async ValueTask<SignatureValidationOutcome> RunLongTermAsync(
        SignatureValidationInputs inputs,
        SignatureValidationSeams seams,
        DateTimeOffset currentTime,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        LongTermValidationResult longTerm = await LongTermValidation.ValidateAsync(
            inputs, seams, currentTime, resources, pool, cancellationToken).ConfigureAwait(false);

        return new SignatureValidationOutcome
        {
            Conclusion = Conclude(
                longTerm.SignatureWithTimeValidation.BasicValidation with { Conclusion = longTerm.Conclusion },
                SignatureValidationProcessIdentifier.LongTermAvailability,
                currentTime,
                longTerm.BestSignatureTime,
                inputs),
            Resources = resources,
            BasicValidation = longTerm.SignatureWithTimeValidation.BasicValidation,
            SignatureWithTimeValidation = longTerm.SignatureWithTimeValidation,
            LongTermValidation = longTerm
        };
    }


    /// <summary>
    /// Shapes a process result into the conclusion clause 5.1.3 requires: the main status indication of Table 5,
    /// the sub-indications and associated validation report data of Table 6, the policy validated against, the
    /// date and time the status was determined for, the validation data used, and the process that was used.
    /// </summary>
    /// <param name="result">The process result, whose conclusion is the process's own.</param>
    /// <param name="processIdentifier">The process that produced it.</param>
    /// <param name="currentTime">The current time.</param>
    /// <param name="bestSignatureTime">Best-signature-time, for a process that determines one; otherwise <see langword="null"/>.</param>
    /// <param name="inputs">The Driving Application's inputs, for the constraints identity a run that never reached the validation context initialization building block reports.</param>
    /// <returns>The conclusion.</returns>
    private static SignatureValidationConclusion Conclude(
        BasicSignatureValidationResult result,
        SignatureValidationProcessIdentifier processIdentifier,
        DateTimeOffset currentTime,
        DateTimeOffset? bestSignatureTime,
        SignatureValidationInputs inputs)
    {
        SignatureValidationConstraints constraints = result.Constraints ?? inputs.Constraints;
        List<PkiCertificateMemory> validationDataUsed = [.. result.CertificateValidationData];
        for(int i = 0; i < result.RevocationStatusInformationUsed.Count; ++i)
        {
            PkiCertificateMemory revocationData = result.RevocationStatusInformationUsed[i].RevocationData;
            if(!validationDataUsed.Contains(revocationData))
            {
                validationDataUsed.Add(revocationData);
            }
        }

        return new SignatureValidationConclusion
        {
            Indication = BuildingBlockIndicationMapping.ToProcessIndication(result.Conclusion.Indication),
            SubIndications = result.Conclusion.SubIndications,
            ReportData = result.Conclusion.ReportData,
            ValidationTime = currentTime,
            PolicyIdentifier = constraints.Identifier,
            ProcessIdentifier = processIdentifier,
            ValidatedCertificateChain = result.ChainKind == CertificateChainReportKind.Validated ? result.CertificateChain : [],
            ValidationDataUsed = validationDataUsed,
            ConstraintEvaluations = result.ConstraintEvaluations,
            ChecksDisabledByPolicy = constraints.ChecksDisabledByPolicy,
            BestSignatureTime = bestSignatureTime
        };
    }
}
