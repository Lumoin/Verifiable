using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The POE Provisioning of clause 4.4.7 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: information on the objects a validation object provides a proof of
/// existence for, at a stated time.
/// </summary>
/// <remarks>
/// Clause 4.4.7's XML shape also allows a <c>SignatureReference</c> (clause 4.1.1.5), naming a signature rather
/// than another validation object, for the multi-signature case where one time-stamp covers several
/// signatures. This wave validates one signature at a time and no engine block produces such a reference, so
/// only <see cref="CoveredObjects"/> is modelled; this is a stated reduction, not a silent gap.
/// <para>
/// <strong>Ownership.</strong> Every carrier here is a non-owning reference to memory the validation run owns.
/// </para>
/// </remarks>
[DebuggerDisplay("ProofOfExistenceProvisioning: at {ProofTime}, {CoveredObjects.Count} objects")]
public sealed record ProofOfExistenceProvisioning
{
    /// <summary>The time value of the proof.</summary>
    public required DateTimeOffset ProofTime { get; init; }

    /// <summary>The validation objects covered by the proof.</summary>
    public IReadOnlyList<SensitiveMemory> CoveredObjects { get; init; } = [];
}


/// <summary>
/// One Signature Validation Object of clause 4.4 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: one object used during the validation of one or more signatures — a
/// certificate, a CRL, an OCSP response, a time-stamp token, or the signed data itself.
/// </summary>
/// <remarks>
/// <para>
/// Clause 4.4.5.1 lets the object be carried directly, base64-encoded, as a digest, or as a URI. This model
/// always carries the object directly, as the same non-owning carrier reference the engine holds
/// (<see cref="Representation"/>): a pure C# object reference already <em>is</em> "the object itself" of clause
/// 4.4.5.1 item 1), and coding it as an XML choice of representations is a concern of the (deferred) XML
/// binding, not of this serialization-agnostic model.
/// </para>
/// <para>
/// <strong>Ownership.</strong> <see cref="Representation"/> is a non-owning reference to memory the validation
/// run owns.
/// </para>
/// </remarks>
[DebuggerDisplay("ValidationObject: {ObjectType}")]
public sealed record ValidationObject
{
    /// <summary>The type of the object (clause 4.4.4).</summary>
    public required ValidationObjectKind ObjectType { get; init; }

    /// <summary>The object itself (clause 4.4.5).</summary>
    public required SensitiveMemory Representation { get; init; }

    /// <summary>The proof for the earliest time of the existence of the object (clause 4.4.6), when one was established; <see langword="null"/> otherwise.</summary>
    public ProofOfExistence? ProofOfExistence { get; init; }

    /// <summary>The proofs of existence this object itself provides for other objects (clause 4.4.7) — populated only for a time-stamp token or evidence record.</summary>
    public IReadOnlyList<ProofOfExistenceProvisioning> ProvidesProofOfExistenceFor { get; init; } = [];

    /// <summary>
    /// The validation report on this object's own validation (clause 4.4.8), when the object is itself a
    /// signed object that was separately validated (for example a countersignature); <see langword="null"/>
    /// otherwise. No block of this wave's engine populates this member.
    /// </summary>
    public SignatureValidationReportElement? ValidationReport { get; init; }
}


/// <summary>
/// The Validator Information Element of clause 4.5 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: identifies the entity validating the signature and creating the validation
/// report.
/// </summary>
/// <remarks>
/// Clause 4.5.2 carries the digital identity as a <c>tsl:DigitalIdentityType</c> of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.5.3</see> — exactly the shape <see cref="ServiceDigitalIdentity"/> already
/// models for the trusted-list wave, and is reused here rather than duplicated (the same reuse principle
/// contract ruling R-8 states for Table 6 evidence).
/// </remarks>
[DebuggerDisplay("SignatureValidatorInformation: {DigitalIdentities.Count} identities")]
public sealed record SignatureValidatorInformation
{
    /// <summary>The digital identity or identities of the validation service.</summary>
    public required IReadOnlyList<ServiceDigitalIdentity> DigitalIdentities { get; init; }
}


/// <summary>
/// The Validation-Report-Element of clause 4.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: the wrapper for reports on the validation of one or more signatures — the
/// root of the model this file, <c>SignatureValidationReport.cs</c> and <c>SignatureValidationReportBuilder.cs</c>
/// build.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ReportSignature"/> models clause 4.6, the signature over the report itself. Producing that
/// signature is signature <em>creation</em> (EN 319 102-1 clause 4), which is out of scope for this validation
/// wave per the wave contract (creation is chartered as W4); this member exists for the shape's completeness
/// and is always <see langword="null"/> from <c>SignatureValidationReportBuilder</c>.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Every carrier here is a non-owning reference to memory the validation run owns.
/// </para>
/// </remarks>
[DebuggerDisplay("ValidationReport: {SignatureValidationReports.Count} signatures, {SignatureValidationObjects.Count} objects")]
public sealed record ValidationReport
{
    /// <summary>One report per validated signature (clause 4.3); at least one.</summary>
    public required IReadOnlyList<SignatureValidationReportElement> SignatureValidationReports { get; init; }

    /// <summary>The objects used during validation (clause 4.4), de-duplicated across every signature report above.</summary>
    public IReadOnlyList<ValidationObject> SignatureValidationObjects { get; init; } = [];

    /// <summary>The entity that produced this report (clause 4.5), when the caller supplies one.</summary>
    public SignatureValidatorInformation? Validator { get; init; }

    /// <summary>The signature over this report (clause 4.6); see the remarks on why this is always <see langword="null"/> from the builder.</summary>
    public SensitiveMemory? ReportSignature { get; init; }
}
