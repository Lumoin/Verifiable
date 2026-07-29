using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// A generic type-value tuple, mirroring the <c>TypedDataType</c> of clause 4.1.1.3 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: "a generic data structure that can be used for representing any Type-Value
/// tuple".
/// </summary>
/// <remarks>
/// Clause 4.1.1.3.2 types the value as <c>xs:anyType</c>. This model carries it as text, which is the
/// serialization-agnostic reduction stated by the wave contract: the specific structured shapes this library
/// knows how to state precisely — a certificate chain, a revocation status, an algorithm assessment — get their
/// own record (<see cref="AssociatedValidationReportDataElement"/>'s dedicated members); this type is reserved for the
/// residual free-text information of clause 4.3.5.4's constraint parameters and clause 4.3.12.8's catch-all.
/// </remarks>
/// <param name="Type">A URI, or a stable local identifier when no URI applies, naming what <see cref="Value"/> is.</param>
/// <param name="Value">The information itself, rendered as text.</param>
[DebuggerDisplay("TypedReportData: {Type} = {Value}")]
public sealed record TypedReportData(string Type, string Value);


/// <summary>
/// The Signature Identification Element of clause 4.3.3 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: identifies the signature that was the scope of the validation.
/// </summary>
/// <remarks>
/// <para>
/// Clause 4.3.3.1 mandates the Data To Be Signed Representation (DTBSR) together with its hash algorithm. The
/// format-facts seam of this wave (<see cref="SignatureFacts"/>) does not yet surface that value as a
/// standalone digest — it is consumed internally by the cryptographic verification building block rather than
/// retained — so <see cref="DigestAlgorithm"/> and <see cref="Digest"/> are <see langword="null"/> until a
/// later wave adds that member. This is a stated reduction, not a silent gap.
/// </para>
/// <para>
/// <strong>Ownership.</strong> <see cref="SignatureValue"/> and <see cref="Digest"/> are non-owning references
/// to carriers the validation run owns.
/// </para>
/// </remarks>
[DebuggerDisplay("SignatureIdentifierElement: hashOnly {HashOnly}, docHashOnly {DocHashOnly}")]
public sealed record SignatureIdentifierElement
{
    /// <summary>The hash algorithm the DTBSR was computed under; <see langword="null"/> until the format-facts seam surfaces the DTBSR (see remarks).</summary>
    public AlgorithmIdentifier? DigestAlgorithm { get; init; }

    /// <summary>The DTBSR itself; <see langword="null"/> for the same reason as <see cref="DigestAlgorithm"/>.</summary>
    public DigestValue? Digest { get; init; }

    /// <summary>The digital signature value, when the format binding isolated it (clause 4.3.3.2's optional <c>ds:SignatureValue</c>).</summary>
    public SensitiveMemory? SignatureValue { get; init; }

    /// <summary>Whether only the DTBSR, and not the DTBSF, was processed by the SVA.</summary>
    public required bool HashOnly { get; init; }

    /// <summary>Whether only the Signer's Document Representation, and not the Signer's Document, was processed by the SVA.</summary>
    public required bool DocHashOnly { get; init; }

    /// <summary>An identifier the Driving Application provided for the signature, when it did.</summary>
    public string? DrivingApplicationIdentifier { get; init; }
}


/// <summary>
/// The Signature Validation Status Indication of clause 4.3.4 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>, mirroring the schema's <c>ValidationStatusType</c>. This one type serves
/// every clause that reuses the same XML shape: the top-level status of clause 4.3.4 itself, the per-constraint
/// result of clause 4.3.5.4, and the status of a validation object's own report of clause 4.4.8.
/// </summary>
/// <remarks>
/// The main indication is carried as its wire URI rather than as
/// <see cref="SignatureValidationIndication"/>/<see cref="BuildingBlockIndication"/> because clause 4.3.4.2
/// assigns two different URI sets to the same element depending on context (<see cref="FromProcessConclusion"/>
/// uses the <c>TOTAL-*</c> set, <see cref="FromBuildingBlockConclusion"/> the <c>PASSED</c>/<c>FAILED</c> set),
/// and a single strongly-typed member could not carry both without re-adding the ambiguity the two engine
/// enumerations exist to avoid.
/// </remarks>
[DebuggerDisplay("ValidationStatus: {MainIndication}, {SubIndications.Count} sub-indications")]
public sealed record ValidationStatus
{
    /// <summary>The main status indication URI (clause 4.3.4.2).</summary>
    public required string MainIndication { get; init; }

    /// <summary>The sub-indication URIs (clause 4.3.4.3); empty when the main indication needed none.</summary>
    public IReadOnlyList<string> SubIndications { get; init; } = [];

    /// <summary>The associated validation report data supporting the indication and sub-indications (clause 4.3.12).</summary>
    public IReadOnlyList<AssociatedValidationReportDataElement> AssociatedValidationReportData { get; init; } = [];


    /// <summary>
    /// Builds the status a validation report of a signature carries, from the process-level conclusion of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
    /// ETSI EN 319 102-1 V1.4.1 clause 5.1.3</see>.
    /// </summary>
    /// <param name="conclusion">The process's conclusion.</param>
    /// <returns>The status.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="conclusion"/> is <see langword="null"/>.</exception>
    public static ValidationStatus FromProcessConclusion(SignatureValidationConclusion conclusion)
    {
        ArgumentNullException.ThrowIfNull(conclusion);

        return new ValidationStatus
        {
            MainIndication = SignatureValidationIndicationMapping.ToWireValue(conclusion.Indication),
            SubIndications = SubIndicationUris(conclusion.SubIndications),
            AssociatedValidationReportData = ProjectReportData(conclusion.ReportData)
        };
    }


    /// <summary>
    /// Builds the status an individual validation constraint report element, or the validation report of a
    /// validation object, carries, from a building block's conclusion of clause 5.1.3.
    /// </summary>
    /// <param name="conclusion">The building block's conclusion.</param>
    /// <returns>The status.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="conclusion"/> is <see langword="null"/>.</exception>
    public static ValidationStatus FromBuildingBlockConclusion(BuildingBlockConclusion conclusion)
    {
        ArgumentNullException.ThrowIfNull(conclusion);

        return new ValidationStatus
        {
            MainIndication = BuildingBlockIndicationMapping.ToWireValue(conclusion.Indication),
            SubIndications = SubIndicationUris(conclusion.SubIndications),
            AssociatedValidationReportData = ProjectReportData(conclusion.ReportData)
        };
    }


    /// <summary>Maps every sub-indication of a conclusion to its wire URI.</summary>
    /// <param name="subIndications">The sub-indications to map.</param>
    /// <returns>The URIs, in the same order.</returns>
    private static List<string> SubIndicationUris(IReadOnlyList<SignatureValidationSubIndication> subIndications)
    {
        var uris = new List<string>(subIndications.Count);
        for(int i = 0; i < subIndications.Count; ++i)
        {
            uris.Add(SignatureValidationSubIndicationMapping.ToWireValue(subIndications[i]));
        }

        return uris;
    }


    /// <summary>Projects every item of a conclusion's Table 6 evidence onto the clause 4.3.12 shape.</summary>
    /// <param name="reportData">The evidence to project.</param>
    /// <returns>The projections, in the same order.</returns>
    private static List<AssociatedValidationReportDataElement> ProjectReportData(IReadOnlyList<SignatureValidationReportData> reportData)
    {
        var projected = new List<AssociatedValidationReportDataElement>(reportData.Count);
        for(int i = 0; i < reportData.Count; ++i)
        {
            projected.Add(AssociatedValidationReportDataElement.From(reportData[i]));
        }

        return projected;
    }
}


/// <summary>
/// The Formal Policy Element of clause 4.3.5.3 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: identifies a formal signature validation policy per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910201/01.01.01_60/ts_11910201v010101p.pdf">
/// ETSI TS 119 172-1</see> that drove the validation.
/// </summary>
/// <remarks>
/// Contract R-3 states that a TS 119 172-1 policy-file parser is out of scope for this wave; no block of this
/// library's engine ever populates this type, which exists so the report shape is complete for a caller that
/// resolves a formal policy of its own and wants to state it.
/// </remarks>
[DebuggerDisplay("FormalSignatureValidationPolicy: {PolicyIdentifier.Value}")]
public sealed record FormalSignatureValidationPolicy
{
    /// <summary>The identifier uniquely identifying the formal signature validation policy.</summary>
    public required SignatureValidationPolicyIdentifier PolicyIdentifier { get; init; }

    /// <summary>A human-readable policy name, when one is available.</summary>
    public string? PolicyName { get; init; }

    /// <summary>A URI where the formal policy specification can be retrieved, when one is available.</summary>
    public Uri? FormalPolicyUri { get; init; }

    /// <summary>A URI where a human readable policy equivalent to the applied formal policy can be retrieved, when one is available.</summary>
    public Uri? ReadablePolicyUri { get; init; }
}


/// <summary>
/// The Individual Validation Constraint Report Element of clause 4.3.5.4 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: the outcome of one signature validation constraint applied, disabled or
/// overridden during validation.
/// </summary>
[DebuggerDisplay("IndividualValidationConstraintReport: {ConstraintIdentifier.Value}, {Status}")]
public sealed record IndividualValidationConstraintReport
{
    /// <summary>The identifier uniquely identifying the constraint.</summary>
    public required ValidationConstraintIdentifier ConstraintIdentifier { get; init; }

    /// <summary>Whether the constraint was applied, disabled, or overridden by another constraint.</summary>
    public required ConstraintApplicationStatus Status { get; init; }

    /// <summary>The constraint that overrode this one, when <see cref="Status"/> is <see cref="ConstraintApplicationStatus.Overridden"/>; <see langword="null"/> otherwise.</summary>
    public ValidationConstraintIdentifier? OverriddenBy { get; init; }

    /// <summary>The validation result for the constraint; present exactly when <see cref="Status"/> is <see cref="ConstraintApplicationStatus.Applied"/>, per clause 4.3.5.4.1.</summary>
    public ValidationStatus? Result { get; init; }

    /// <summary>Any parameters the validation constraint requires, for example the constraint's own configuration.</summary>
    public IReadOnlyList<TypedReportData> Parameters { get; init; } = [];
}


/// <summary>
/// The Validation Constraints Evaluation Report of clause 4.3.5 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: the set of validation constraints that drove the validation process,
/// irrespective of how they were defined (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.4.1</see>).
/// </summary>
[DebuggerDisplay("ValidationConstraintsEvaluationReport: {ValidationConstraints.Count} constraints")]
public sealed record ValidationConstraintsEvaluationReport
{
    /// <summary>The formal signature validation policy that drove the validation, when a formal policy was explicitly or implicitly selected; <see langword="null"/> otherwise (see <see cref="FormalSignatureValidationPolicy"/>).</summary>
    public FormalSignatureValidationPolicy? SignatureValidationPolicy { get; init; }

    /// <summary>Every constraint the validation applied, disabled, or overrode.</summary>
    public required IReadOnlyList<IndividualValidationConstraintReport> ValidationConstraints { get; init; }
}


/// <summary>
/// The Signature Validation Time Info of clause 4.3.6 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: the date and time the validation was performed, and the proof of existence
/// for which the validation status was determined.
/// </summary>
[DebuggerDisplay("ValidationTimeInfo: validated at {ValidationTime}")]
public sealed record ValidationTimeInfo
{
    /// <summary>The date and time the validation was performed, in UTC.</summary>
    public required DateTimeOffset ValidationTime { get; init; }

    /// <summary>
    /// The proof of existence for which the validation status was determined — the current time for the
    /// validation process for Basic Signatures, or best-signature-time for the other two processes, per the
    /// NOTE of clause 4.3.6.1.
    /// </summary>
    public required ProofOfExistence BestSignatureTime { get; init; }
}


/// <summary>
/// The Signer's Document Element of clause 4.3.7 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: identifies the document covered by the signature.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> <see cref="Representation"/> is a non-owning reference to a carrier the
/// validation run owns.
/// </remarks>
[DebuggerDisplay("SignersDocument")]
public sealed record SignersDocument
{
    /// <summary>The hash algorithm the Signer's Document Representation was computed under, when the format-facts seam states one (see the reduction noted on <see cref="SignatureIdentifierElement"/>).</summary>
    public AlgorithmIdentifier? DigestAlgorithm { get; init; }

    /// <summary>The Signer's Document Representation as a hash value, when one is available.</summary>
    public DigestValue? Digest { get; init; }

    /// <summary>The Signer's Document, or the Signer's Document Representation, when the run holds its bytes.</summary>
    public SensitiveMemory? Representation { get; init; }
}


/// <summary>
/// One Signature Attribute Element of clause 4.3.8 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: one attribute the validated signature carried.
/// </summary>
/// <remarks>
/// Annex A of the specification defines attribute-dependent detail for the specific attributes CAdES, PAdES,
/// XAdES and JAdES name. Modelling every Annex A shape is out of scope for this wave; this record carries the
/// identity, scope and well-formedness clause 4.3.8.1 makes mandatory, which is exactly what
/// <see cref="SignatureAttributeFacts"/> supplies.
/// </remarks>
/// <param name="Identifier">The attribute's identity, in its format's own vocabulary.</param>
/// <param name="Signed">Whether the attribute was a signed attribute.</param>
/// <param name="IsWellFormed">Whether the format binding could decode the attribute.</param>
[DebuggerDisplay("SignatureAttributeElement: {Identifier}, signed {Signed}")]
public sealed record SignatureAttributeElement(string Identifier, bool Signed, bool IsWellFormed);


/// <summary>
/// The Signer Information Element of clause 4.3.9 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: information on the signer.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> <see cref="SignerCertificate"/> is a non-owning reference to a carrier the
/// validation run owns.
/// </remarks>
[DebuggerDisplay("SignerInformationElement: {Signer}")]
public sealed record SignerInformationElement
{
    /// <summary>The certificate identified as the signer's certificate.</summary>
    public required PkiCertificateMemory SignerCertificate { get; init; }

    /// <summary>A human readable representation of the signer, for example a rendered distinguished name; <see langword="null"/> when none was rendered.</summary>
    public string? Signer { get; init; }

    /// <summary>Whether a pseudonym was used at the time of signing.</summary>
    public bool UsesPseudonym { get; init; }
}


/// <summary>
/// The Signature Quality Element of clause 4.3.10 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: one or more URIs indicating the quality of the signature, for example
/// "qualified electronic signature".
/// </summary>
/// <remarks>
/// Clause 4.3.10.1's NOTE states that defining the quality URIs themselves is out of scope of that
/// specification; the natural URIs for this library's own repertoire are the qualification determinations of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615</see> (<c>TrustedListQualification.cs</c>), whose wiring into this element is a deferred
/// integration point rather than this wave's concern: no block of this wave's engine populates it.
/// </remarks>
/// <param name="QualityIndicators">The quality URIs.</param>
[DebuggerDisplay("SignatureQuality: {QualityIndicators.Count} indicators")]
public sealed record SignatureQuality(IReadOnlyList<string> QualityIndicators);


/// <summary>
/// The Signature Validation Process Information Element of clause 4.3.11 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: information on the validation process performed.
/// </summary>
[DebuggerDisplay("SignatureValidationProcessInfo: {ProcessIdentifier.Value}")]
public sealed record SignatureValidationProcessInfo
{
    /// <summary>The URI identifying the validation process used (clause 4.3.11.1).</summary>
    public required SignatureValidationProcessIdentifier ProcessIdentifier { get; init; }

    /// <summary>The URI identifying the validation service policy, when applicable.</summary>
    public Uri? ValidationServicePolicyUri { get; init; }

    /// <summary>The URI identifying the validation service practice statement, when applicable.</summary>
    public Uri? ValidationServicePracticeStatementUri { get; init; }
}


/// <summary>
/// The Revocation Status Information Element of clause 4.3.12.6 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: present when a certificate has been found to be revoked.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> Every carrier here is a non-owning reference to memory the validation run owns.
/// </remarks>
[DebuggerDisplay("RevocationStatusInformationReportElement: revoked at {RevocationTime}")]
public sealed record RevocationStatusInformationReportElement
{
    /// <summary>The certificate found to be revoked.</summary>
    public required PkiCertificateMemory RevokedCertificate { get; init; }

    /// <summary>The time of revocation, or <see langword="null"/> when the source that reported the revocation stated no date.</summary>
    public required DateTimeOffset? RevocationTime { get; init; }

    /// <summary>The RFC 5280 §5.3.1 <c>CRLReason</c> value, when the revocation data carried one; <see langword="null"/> otherwise.</summary>
    public int? RevocationReason { get; init; }

    /// <summary>The CRL or OCSP response used for determining the revocation status, when the run retained it as a distinct object; <see langword="null"/> when it did not (<see cref="CertificateRevocationReportData"/> does not carry it — see the buildlog).</summary>
    public PkiCertificateMemory? RevocationObject { get; init; }
}


/// <summary>
/// The Crypto Information Element of clause 4.3.12.7 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: details on a cryptographic algorithm the validation process determined is no
/// longer reliable.
/// </summary>
/// <remarks>
/// Clause 4.3.12.7.2's <c>ValidationObjectId</c> references an object in the Signature Validation Objects
/// element or the Signature Identification Element. The engine's own <see cref="AlgorithmUse"/> names the
/// concerned material as descriptive text rather than as a structured reference (a model-stage decision,
/// because signature-algorithm identities are read from the material under validation rather than curated), so
/// <see cref="Material"/> carries that same text.
/// </remarks>
[DebuggerDisplay("CryptoInformationElement: {Material} uses {Algorithm.Oid}, secure {SecureAlgorithm}")]
public sealed record CryptoInformationElement
{
    /// <summary>What used the algorithm, in terms a Driving Application can present (<see cref="AlgorithmUse.MaterialIdentifier"/>).</summary>
    public required string Material { get; init; }

    /// <summary>The algorithm used.</summary>
    public required AlgorithmIdentifier Algorithm { get; init; }

    /// <summary>Whether the algorithm and its parameters were considered secure.</summary>
    public required bool SecureAlgorithm { get; init; }

    /// <summary>The time up to which the algorithm or algorithm-parameters were considered secure, when known.</summary>
    public DateTimeOffset? NotAfter { get; init; }
}


/// <summary>
/// The Additional Validation Report Data of clause 4.3.12.8 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: any additional information the validation process provides that does not
/// fit one of clauses 4.3.12.3 to 4.3.12.7's dedicated shapes.
/// </summary>
/// <param name="Items">The additional information, as type-value tuples.</param>
[DebuggerDisplay("AdditionalValidationReportData: {Items.Count} items")]
public sealed record AdditionalValidationReportData(IReadOnlyList<TypedReportData> Items);


/// <summary>
/// The Associated Validation Report Data Element of clause 4.3.12 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: additional information on the validation of the signature or a signature
/// validation constraint, projected from one item of a conclusion's Table 6 evidence
/// (<see cref="SignatureValidationReportData"/> of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.3</see>).
/// </summary>
/// <remarks>
/// <para>
/// Per contract ruling R-8, this record does not duplicate the fields of the engine's Table 6 evidence — it
/// keeps a reference to the source item (<see cref="Source"/>) and adds only the clause 4.3.12 <em>view</em>
/// onto it: the sub-elements clause 4.3.12.1 lists (trust anchor, certificate chain, related validation
/// objects, revocation status, crypto information) where the source's shape carries the data for one, and the
/// catch-all of clause 4.3.12.8 otherwise. A caller wanting the untransformed evidence reads <see cref="Source"/>
/// directly and switches over it exhaustively, exactly as an engine consumer would.
/// </para>
/// <para>
/// Clause 4.3.12.2's XML schema allows at most one <c>CryptoInformation</c> child per element, while
/// <see cref="CryptographicConstraintsFailureReportData"/> names a list of offending materials; this projection
/// keeps <see cref="CryptoInformation"/> a list rather than manufacture one <see cref="AssociatedValidationReportDataElement"/>
/// per entry, and an eventual XML serializer fans the list out into one <c>AssociatedValidationReportData</c>
/// element per entry — the XML representation clauses bind names, not this model's shape.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Every carrier here is a non-owning reference to memory the validation run owns.
/// </para>
/// </remarks>
[DebuggerDisplay("AssociatedValidationReportDataElement: {Source}")]
public sealed record AssociatedValidationReportDataElement
{
    /// <summary>The Table 6 evidence item this projection was built from.</summary>
    public required SignatureValidationReportData Source { get; init; }

    /// <summary>The trust anchor the validation process terminated at (clause 4.3.12.3), when <see cref="CertificateChain"/> carries one — its last element, per clause 4.3.12.4.1.</summary>
    public PkiCertificateMemory? TrustAnchor { get; init; }

    /// <summary>The certificate chain (clause 4.3.12.4), signing certificate first; empty when <see cref="Source"/> carries none.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateChain { get; init; } = [];

    /// <summary>The data objects related to the reported sub-indication (clause 4.3.12.5) — for example the time-stamps of a <c>TIMESTAMP_ORDER_FAILURE</c>, or the revocation data of a <c>TRY_LATER</c>; empty when <see cref="Source"/> names none.</summary>
    public IReadOnlyList<PkiCertificateMemory> RelatedValidationObjects { get; init; } = [];

    /// <summary>The revocation status (clause 4.3.12.6), when <see cref="Source"/> is about a certificate found revoked; <see langword="null"/> otherwise.</summary>
    public RevocationStatusInformationReportElement? RevocationStatusInformation { get; init; }

    /// <summary>The unreliable algorithm assessments (clause 4.3.12.7), when <see cref="Source"/> is a cryptographic constraints failure; empty otherwise.</summary>
    public IReadOnlyList<CryptoInformationElement> CryptoInformation { get; init; } = [];

    /// <summary>The catch-all additional information (clause 4.3.12.8), for a <see cref="Source"/> shape none of the dedicated members above cover.</summary>
    public AdditionalValidationReportData? AdditionalData { get; init; }


    /// <summary>
    /// Projects one item of Table 6 evidence onto its clause 4.3.12 view.
    /// </summary>
    /// <param name="reportData">The evidence item.</param>
    /// <returns>The projection.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="reportData"/> is <see langword="null"/>.</exception>
    public static AssociatedValidationReportDataElement From(SignatureValidationReportData reportData)
    {
        ArgumentNullException.ThrowIfNull(reportData);

        return reportData switch
        {
            CertificateChainReportData d => new AssociatedValidationReportDataElement
            {
                Source = d,
                CertificateChain = d.CertificateChain,
                TrustAnchor = LastOrNull(d.CertificateChain)
            },
            CertificateRevocationReportData d => new AssociatedValidationReportDataElement
            {
                Source = d,
                CertificateChain = d.CertificateChain,
                TrustAnchor = LastOrNull(d.CertificateChain),
                RevocationStatusInformation = new RevocationStatusInformationReportElement
                {
                    RevokedCertificate = d.RevokedCertificate,
                    RevocationTime = d.RevocationTime,
                    RevocationReason = d.RevocationReason
                }
            },
            ChainConstraintsFailureReportData d => new AssociatedValidationReportDataElement
            {
                Source = d,
                CertificateChain = d.CertificateChain,
                AdditionalData = ConstraintsData(d.UnsatisfiedConstraints)
            },
            CertificateChainGeneralFailureReportData d => new AssociatedValidationReportDataElement
            {
                Source = d,
                CertificateChain = d.CertificateChain,
                AdditionalData = TextData("reason", d.Reason)
            },
            CryptographicConstraintsFailureReportData d => new AssociatedValidationReportDataElement
            {
                Source = d,
                CryptoInformation = BuildCryptoInformation(d.UnreliableAlgorithms)
            },
            TimestampOrderFailureReportData d => new AssociatedValidationReportDataElement
            {
                Source = d,
                RelatedValidationObjects = d.TimestampTokens
            },
            RevocationOutOfBoundsReportData d => new AssociatedValidationReportDataElement
            {
                Source = d,
                CertificateChain = d.CertificateChain,
                RelatedValidationObjects = d.RevocationData
            },
            TryLaterReportData d => new AssociatedValidationReportDataElement
            {
                Source = d,
                CertificateChain = d.CertificateChain,
                RelatedValidationObjects = d.RevocationData,
                AdditionalData = d.SuggestedRetryTime is DateTimeOffset retryTime
                    ? TextData("suggested-retry-time", retryTime.ToString("O"))
                    : null
            },
            UnsatisfiedSignatureConstraintsReportData d => new AssociatedValidationReportDataElement
            {
                Source = d,
                AdditionalData = ConstraintsData(d.UnsatisfiedConstraints)
            },
            SigningCertificateReportData d => new AssociatedValidationReportDataElement
            {
                Source = d,
                RelatedValidationObjects = [d.SigningCertificate]
            },
            FormatFailureReportData d => new AssociatedValidationReportDataElement { Source = d, AdditionalData = TextData("reason", d.Reason) },
            PolicyProcessingErrorReportData d => new AssociatedValidationReportDataElement { Source = d, AdditionalData = TextData("problem", d.Problem) },
            HashFailureReportData d => new AssociatedValidationReportDataElement { Source = d, AdditionalData = ListData("failing-object", d.FailingObjectIdentifiers) },
            SignedDataNotFoundReportData d => new AssociatedValidationReportDataElement { Source = d, AdditionalData = ListData("signed-data-identifier", d.SignedDataIdentifiers) },
            MissingProofOfExistenceReportData d => new AssociatedValidationReportDataElement
            {
                Source = d,
                AdditionalData = TextData("additional-information", d.AdditionalInformation ?? $"{d.ObjectsMissingProofs.Count} objects missing proofs of existence")
            },
            CustomDiagnosticReportData d => new AssociatedValidationReportDataElement { Source = d, AdditionalData = TextData("diagnostic", d.Diagnostic) },
            _ => new AssociatedValidationReportDataElement { Source = reportData }
        };


        //Wraps a single labelled string as the catch-all of clause 4.3.12.8.
        static AdditionalValidationReportData TextData(string label, string value) =>
            new([new TypedReportData(label, value)]);

        //Wraps a labelled list of strings, one TypedReportData per entry, as the catch-all of clause 4.3.12.8.
        static AdditionalValidationReportData ListData(string label, IReadOnlyList<string> values)
        {
            var items = new List<TypedReportData>(values.Count);
            for(int i = 0; i < values.Count; ++i)
            {
                items.Add(new TypedReportData(label, values[i]));
            }

            return new AdditionalValidationReportData(items);
        }

        //Renders a set of unmet validation constraint outcomes as the catch-all of clause 4.3.12.8: the
        //authoritative view is ValidationConstraintsEvaluationReport at the top of the report, this is a
        //convenience so the failing constraints are also visible alongside the evidence item that names them.
        static AdditionalValidationReportData ConstraintsData(IReadOnlyList<ValidationConstraintEvaluation> constraints)
        {
            var items = new List<TypedReportData>(constraints.Count);
            for(int i = 0; i < constraints.Count; ++i)
            {
                items.Add(new TypedReportData(constraints[i].Identifier.Value, constraints[i].Description ?? constraints[i].Indication.ToString()));
            }

            return new AdditionalValidationReportData(items);
        }

        //Projects unreliable algorithm assessments onto clause 4.3.12.7's shape.
        static IReadOnlyList<CryptoInformationElement> BuildCryptoInformation(IReadOnlyList<AlgorithmReliabilityAssessment> assessments)
        {
            var elements = new List<CryptoInformationElement>(assessments.Count);
            for(int i = 0; i < assessments.Count; ++i)
            {
                elements.Add(new CryptoInformationElement
                {
                    Material = assessments[i].Use.MaterialIdentifier,
                    Algorithm = assessments[i].Use.Algorithm,
                    SecureAlgorithm = assessments[i].IsReliable,
                    NotAfter = assessments[i].TrustedUntil
                });
            }

            return elements;
        }

        //Clause 4.3.12.4.1: "the trust anchor as the last element" of a certificate chain.
        static PkiCertificateMemory? LastOrNull(IReadOnlyList<PkiCertificateMemory> chain) =>
            chain.Count > 0 ? chain[^1] : null;
    }
}


/// <summary>
/// The Signature-Validation-Report-Element of clause 4.3 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>: the validation information for a single signature.
/// </summary>
/// <remarks>
/// <see cref="Status"/> is the only member clause 4.3.1 makes mandatory; every other member is conditional or
/// optional per its own clause and is populated by <c>SignatureValidationReportBuilder</c> exactly when the
/// engine evidence it is built from is available.
/// </remarks>
[DebuggerDisplay("SignatureValidationReportElement: {Status.MainIndication}")]
public sealed record SignatureValidationReportElement
{
    /// <summary>The Signature Identification Element (clause 4.3.3); absent when the main status indication is <c>TOTAL-FAILED</c>/<c>FORMAT_FAILURE</c> per clause 4.3.3.1's conditional presence rule.</summary>
    public SignatureIdentifierElement? SignatureIdentifier { get; init; }

    /// <summary>The Validation Constraints Evaluation Report (clause 4.3.5).</summary>
    public ValidationConstraintsEvaluationReport? ValidationConstraintsEvaluationReport { get; init; }

    /// <summary>The Signature Validation Time Info (clause 4.3.6).</summary>
    public ValidationTimeInfo? ValidationTimeInfo { get; init; }

    /// <summary>The Signer's Document Element (clause 4.3.7).</summary>
    public SignersDocument? SignersDocument { get; init; }

    /// <summary>The Signature Attribute Elements (clause 4.3.8); empty when the facts were never extracted.</summary>
    public IReadOnlyList<SignatureAttributeElement> SignatureAttributes { get; init; } = [];

    /// <summary>The Signer Information Element (clause 4.3.9); present when a signing certificate was identified.</summary>
    public SignerInformationElement? SignerInformation { get; init; }

    /// <summary>The Signature Quality Element (clause 4.3.10); see the reduction noted on <see cref="Verifiable.Cryptography.Pki.SignatureQuality"/>.</summary>
    public SignatureQuality? SignatureQuality { get; init; }

    /// <summary>The Signature Validation Process Information Element (clause 4.3.11).</summary>
    public SignatureValidationProcessInfo? SignatureValidationProcessInfo { get; init; }

    /// <summary>The Signature Validation Status Indication (clause 4.3.4); the one element clause 4.3.1 makes mandatory.</summary>
    public required ValidationStatus Status { get; init; }
}
