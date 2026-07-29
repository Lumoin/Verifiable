using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The identity of the validation process that produced a conclusion — the output
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.3</see> requires in all cases ("the validation process (clauses 5.3,
/// 5.5 and 5.6.3) that has been used in validation"), carried as the URI
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1 clause 4.3.11.1</see> assigns it.
/// </summary>
/// <remarks>
/// <para>
/// A wire-value wrapper rather than an enumeration, because clause 4.3.11.1 explicitly admits "any other URI
/// indicating the validation process when none of these processes has been applied". No such library-defined
/// value is minted here: the only conclusion this model produces outside the three named processes is the one
/// of the time-stamp validation building block of EN 319 102-1 clause 5.4, and step 1) of clause 5.4.4 has
/// that block perform the validation process for Basic Signatures on the token, so <see cref="Basic"/> is the
/// process it ran.
/// </para>
/// </remarks>
/// <param name="Value">The process URI.</param>
[DebuggerDisplay("SignatureValidationProcessIdentifier: {Value}")]
public readonly record struct SignatureValidationProcessIdentifier(string Value)
{
    /// <summary>The validation process for Basic Signatures of EN 319 102-1 clause 5.3.</summary>
    public static SignatureValidationProcessIdentifier Basic { get; } = new(SignatureValidationWellKnown.ValidationProcessBasic);

    /// <summary>The validation process for Signatures with Time and Signatures with Long-Term Validation Material of EN 319 102-1 clause 5.5.</summary>
    public static SignatureValidationProcessIdentifier LongTermValidationMaterial { get; } = new(SignatureValidationWellKnown.ValidationProcessLongTermValidationMaterial);

    /// <summary>The validation process for Signatures providing Long Term Availability and Integrity of Validation Material of EN 319 102-1 clause 5.6.3.</summary>
    public static SignatureValidationProcessIdentifier LongTermAvailability { get; } = new(SignatureValidationWellKnown.ValidationProcessLongTermAvailability);

    /// <summary>Returns <see langword="true"/> when this is <see cref="Basic"/>.</summary>
    public bool IsBasic => string.Equals(Value, Basic.Value, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when this is <see cref="LongTermValidationMaterial"/>.</summary>
    public bool IsLongTermValidationMaterial => string.Equals(Value, LongTermValidationMaterial.Value, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when this is <see cref="LongTermAvailability"/>.</summary>
    public bool IsLongTermAvailability => string.Equals(Value, LongTermAvailability.Value, StringComparison.Ordinal);
}


/// <summary>
/// What one basic building block of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.2</see> concluded: its indication, the sub-indications explaining a
/// non-passing one, and the associated validation report data its output table mandates.
/// </summary>
/// <remarks>
/// <para>
/// Every block's own result record embeds one of these and adds whatever its output table additionally names
/// — the X.509 certificate validation block adds the chain, the time-stamp validation block adds the
/// generation time and message imprint. Keeping the shared part one type is what lets the processes of
/// clauses 5.3, 5.5 and 5.6.3 propagate "the indication and sub-indication returned by" a block without each
/// block inventing its own vocabulary.
/// </para>
/// <para>
/// Clause 5.1.3 allows more than one sub-indication, and
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1 clause 4.3.4.1</see>'s NOTE states outright that "there can be more than one
/// sub-indication element when the SVA needs to report multiple problems", so
/// <see cref="SubIndications"/> is a list and not a single value.
/// </para>
/// </remarks>
[DebuggerDisplay("BuildingBlockConclusion: {Indication}, {SubIndications.Count} sub-indications")]
public sealed record BuildingBlockConclusion
{
    /// <summary>The block's indication.</summary>
    public required BuildingBlockIndication Indication { get; init; }

    /// <summary>The sub-indications explaining the indication; empty when the block passed.</summary>
    public required IReadOnlyList<SignatureValidationSubIndication> SubIndications { get; init; }

    /// <summary>The associated validation report data the block's output table mandates for its indication and sub-indications.</summary>
    public required IReadOnlyList<SignatureValidationReportData> ReportData { get; init; }

    /// <summary>
    /// The outcome of each validation constraint the block took into account, which Table 5 of clause 5.1.3
    /// requires the process to report for constraints with a negative or indeterminate result; empty when the
    /// block took none into account.
    /// </summary>
    public IReadOnlyList<ValidationConstraintEvaluation> ConstraintEvaluations { get; init; } = [];


    /// <summary>A <c>PASSED</c> conclusion with no sub-indications and no report data.</summary>
    public static BuildingBlockConclusion Passed { get; } = new()
    {
        Indication = BuildingBlockIndication.Passed,
        SubIndications = [],
        ReportData = []
    };


    /// <summary>
    /// Creates a <c>PASSED</c> conclusion carrying report data — for example the certificate chain Table 13 of
    /// clause 5.2.6.3 mandates the X.509 certificate validation block output on <c>PASSED</c>.
    /// </summary>
    /// <param name="reportData">The report data to carry.</param>
    /// <returns>The conclusion.</returns>
    public static BuildingBlockConclusion PassedWith(IReadOnlyList<SignatureValidationReportData> reportData)
    {
        ArgumentNullException.ThrowIfNull(reportData);

        return new BuildingBlockConclusion
        {
            Indication = BuildingBlockIndication.Passed,
            SubIndications = [],
            ReportData = reportData
        };
    }


    /// <summary>Creates a <c>FAILED</c> conclusion.</summary>
    /// <param name="subIndication">The sub-indication explaining the failure.</param>
    /// <param name="reportData">The report data Table 6 mandates for that sub-indication.</param>
    /// <returns>The conclusion.</returns>
    public static BuildingBlockConclusion Failed(SignatureValidationSubIndication subIndication, IReadOnlyList<SignatureValidationReportData> reportData)
    {
        ArgumentNullException.ThrowIfNull(reportData);

        return new BuildingBlockConclusion
        {
            Indication = BuildingBlockIndication.Failed,
            SubIndications = [subIndication],
            ReportData = reportData
        };
    }


    /// <summary>Creates an <c>INDETERMINATE</c> conclusion.</summary>
    /// <param name="subIndication">The sub-indication explaining why the block could not decide.</param>
    /// <param name="reportData">The report data Table 6 mandates for that sub-indication.</param>
    /// <returns>The conclusion.</returns>
    public static BuildingBlockConclusion Indeterminate(SignatureValidationSubIndication subIndication, IReadOnlyList<SignatureValidationReportData> reportData)
    {
        ArgumentNullException.ThrowIfNull(reportData);

        return new BuildingBlockConclusion
        {
            Indication = BuildingBlockIndication.Indeterminate,
            SubIndications = [subIndication],
            ReportData = reportData
        };
    }
}


/// <summary>
/// What a signature validation process concluded — the complete output
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.3</see> requires of the processes of clauses 5.3, 5.5 and 5.6.3, and
/// the material a validation report is built from.
/// </summary>
/// <remarks>
/// <para>
/// Clause 5.1.3 requires four outputs in all cases, and each has its own member here: the status indication
/// (<see cref="Indication"/>), an indication of the policy or set of constraints validated against
/// (<see cref="PolicyIdentifier"/>), the date and time the validation status was determined for together with
/// the validation data used (<see cref="ValidationTime"/> and <see cref="ValidationDataUsed"/>), and the
/// validation process used (<see cref="ProcessIdentifier"/>). The sub-indication and the associated validation
/// report data of Tables 5 and 6 follow in <see cref="SubIndications"/> and <see cref="ReportData"/>.
/// </para>
/// <para>
/// <strong>Determinism.</strong> Clause 5.1.3's rules for <c>TOTAL-PASSED</c> and <c>TOTAL-FAILED</c> require
/// that the same inputs always yield the same result and that additional validation data never changes it,
/// while additional proofs of existence may. That is why <see cref="ValidationTime"/> is a value the process
/// was given rather than one it read: nothing in this model reaches for an ambient clock, and every time this
/// record reports is one that was an input to the run or was derived from the material under validation.
/// </para>
/// <para>
/// <strong>Ownership.</strong> The certificates a conclusion carries are non-owning references to memory the
/// validation run owns; a conclusion must not outlive them.
/// </para>
/// </remarks>
[DebuggerDisplay("SignatureValidationConclusion: {Indication}, {SubIndications.Count} sub-indications, at {ValidationTime}")]
public sealed record SignatureValidationConclusion
{
    /// <summary>The main status indication of Table 5.</summary>
    public required SignatureValidationIndication Indication { get; init; }

    /// <summary>
    /// The sub-indications of Table 6 explaining the indication. Clause 5.1.3 makes returning one mandatory on
    /// <c>TOTAL-FAILED</c>, and on <c>INDETERMINATE</c> requires either a mapped Table 6 value or a custom
    /// diagnostic reported under <see cref="SignatureValidationSubIndication.Custom"/>.
    /// </summary>
    public required IReadOnlyList<SignatureValidationSubIndication> SubIndications { get; init; }

    /// <summary>The associated validation report data Tables 5 and 6 name for the reported indication and sub-indications.</summary>
    public required IReadOnlyList<SignatureValidationReportData> ReportData { get; init; }

    /// <summary>
    /// The date and time the validation status was determined for. NOTE 1 of clause 5.1.3 makes this the
    /// current time for Basic Signature validation, and either the current time or a point in the past for the
    /// other two processes. Always a value supplied to or derived by the process, never read from an ambient
    /// clock.
    /// </summary>
    public required DateTimeOffset ValidationTime { get; init; }

    /// <summary>The policy, or the set of constraints, the signature was validated against.</summary>
    public required SignatureValidationPolicyIdentifier PolicyIdentifier { get; init; }

    /// <summary>The validation process that produced this conclusion.</summary>
    public required SignatureValidationProcessIdentifier ProcessIdentifier { get; init; }

    /// <summary>
    /// The validated certificate chain including the signing certificate, which Table 5 requires the process
    /// to output on <c>TOTAL-PASSED</c>; empty when no chain was validated.
    /// </summary>
    public IReadOnlyList<PkiCertificateMemory> ValidatedCertificateChain { get; init; } = [];

    /// <summary>
    /// The validation data used for the determination, which clause 5.1.3 requires alongside the date and
    /// time: the certificates, CRLs, OCSP responses and time-stamp tokens the run consulted. Each carries its
    /// own <see cref="PkiObjectKind"/> discriminator.
    /// </summary>
    public IReadOnlyList<PkiCertificateMemory> ValidationDataUsed { get; init; } = [];

    /// <summary>
    /// The outcome of each validation constraint taken into account. Table 5 makes reporting these mandatory
    /// for the constraints with a negative result on <c>TOTAL-FAILED</c> and for those with an indeterminate
    /// result on <c>INDETERMINATE</c>, and optional on <c>TOTAL-PASSED</c>.
    /// </summary>
    public IReadOnlyList<ValidationConstraintEvaluation> ConstraintEvaluations { get; init; } = [];

    /// <summary>
    /// The checks the constraint set stated were not required and that the process therefore skipped, which
    /// clause 5.1.4.1 requires the SVA to return in its final report to the Driving Application.
    /// </summary>
    public IReadOnlyList<ValidationConstraintIdentifier> ChecksDisabledByPolicy { get; init; } = [];

    /// <summary>
    /// The earliest time proven that the signature has existed, which clause 5.5.3 requires the validation
    /// process for Signatures with Time to output and clause 5.5.4 step 11) returns as best-signature-time;
    /// <see langword="null"/> for a process that determines no such time.
    /// </summary>
    public DateTimeOffset? BestSignatureTime { get; init; }
}
