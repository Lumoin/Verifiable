using System;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The wire URIs
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1 clause 4</see> assigns to the report structures of clause 4 that are not already
/// covered by <see cref="SignatureValidationWellKnown"/>: the validation object type URIs of clause 4.4.4, the
/// proof-of-existence type URIs of clause 4.4.6.2, the constraint status URIs of clause 4.3.5.4.2, and the
/// revocation reason URIs of clause 4.3.12.6.2.
/// </summary>
/// <remarks>
/// These are pure wire-name lookups over the report model of <c>SignatureValidationReport.cs</c>; the model
/// itself carries the strongly-typed engine enumerations (<see cref="ValidationObjectKind"/>,
/// <see cref="ProofOfExistenceOrigin"/>) and these mappings only apply where a caller needs the specification's
/// own URI form, for example when staging an eventual XML binding.
/// </remarks>
public static class SignatureValidationReportWellKnown
{
    /// <summary>The URI for the <c>certificate</c> validation object type (clause 4.4.4).</summary>
    public static string ValidationObjectCertificate { get; } = "urn:etsi:019102:validationObject:certificate";

    /// <summary>The URI for the <c>CRL</c> validation object type (clause 4.4.4).</summary>
    public static string ValidationObjectCrl { get; } = "urn:etsi:019102:validationObject:CRL";

    /// <summary>The URI for the <c>OCSPResponse</c> validation object type (clause 4.4.4).</summary>
    public static string ValidationObjectOcspResponse { get; } = "urn:etsi:019102:validationObject:OCSPResponse";

    /// <summary>The URI for the <c>timestamp</c> validation object type (clause 4.4.4).</summary>
    public static string ValidationObjectTimestamp { get; } = "urn:etsi:019102:validationObject:timestamp";

    /// <summary>The URI for the <c>evidencerecord</c> validation object type (clause 4.4.4).</summary>
    public static string ValidationObjectEvidenceRecord { get; } = "urn:etsi:019102:validationObject:evidencerecord";

    /// <summary>The URI for the <c>publicKey</c> validation object type (clause 4.4.4).</summary>
    public static string ValidationObjectPublicKey { get; } = "urn:etsi:019102:validationObject:publicKey";

    /// <summary>The URI for the <c>signedData</c> validation object type (clause 4.4.4).</summary>
    public static string ValidationObjectSignedData { get; } = "urn:etsi:019102:validationObject:signedData";

    /// <summary>The URI for the <c>other</c> validation object type (clause 4.4.4).</summary>
    public static string ValidationObjectOther { get; } = "urn:etsi:019102:validationObject:other";

    /// <summary>The URI for a proof of existence derived during validation (clause 4.4.6.2).</summary>
    public static string ProofOfExistenceTypeValidation { get; } = "urn:etsi:019102:poetype:validation";

    /// <summary>The URI for a proof of existence provided to the SVA as an input (clause 4.4.6.2).</summary>
    public static string ProofOfExistenceTypeProvided { get; } = "urn:etsi:019102:poetype:provided";

    /// <summary>The URI for a proof of existence derived by the validation policy (clause 4.4.6.2).</summary>
    public static string ProofOfExistenceTypePolicy { get; } = "urn:etsi:019102:poetype:policy";

    /// <summary>The URI for a validation constraint that was applied (clause 4.3.5.4.2).</summary>
    public static string ConstraintStatusApplied { get; } = "urn:etsi:019102:constraintStatus:applied";

    /// <summary>The URI for a validation constraint that was disabled by the validation policy in use (clause 4.3.5.4.2).</summary>
    public static string ConstraintStatusDisabled { get; } = "urn:etsi:019102:constraintStatus:disabled";

    /// <summary>The URI for a validation constraint that was overridden by another constraint (clause 4.3.5.4.2).</summary>
    public static string ConstraintStatusOverridden { get; } = "urn:etsi:019102:constraintStatus:overridden";

    /// <summary>The URI for RFC 5280 §5.3.1 <c>CRLReason</c> value 0, <c>unspecified</c> (clause 4.3.12.6.2).</summary>
    public static string RevocationReasonUnspecified { get; } = "urn:etsi:019102:revocationReason:unspecified";

    /// <summary>The URI for RFC 5280 §5.3.1 <c>CRLReason</c> value 1, <c>keyCompromise</c> (clause 4.3.12.6.2).</summary>
    public static string RevocationReasonKeyCompromise { get; } = "urn:etsi:019102:revocationReason:keyCompromise";

    /// <summary>The URI for RFC 5280 §5.3.1 <c>CRLReason</c> value 2, <c>cACompromise</c> (clause 4.3.12.6.2).</summary>
    public static string RevocationReasonCertificationAuthorityCompromise { get; } = "urn:etsi:019102:revocationReason:cACompromise";

    /// <summary>The URI for RFC 5280 §5.3.1 <c>CRLReason</c> value 3, <c>affiliationChanged</c> (clause 4.3.12.6.2).</summary>
    public static string RevocationReasonAffiliationChanged { get; } = "urn:etsi:019102:revocationReason:affiliationChanged";

    /// <summary>The URI for RFC 5280 §5.3.1 <c>CRLReason</c> value 4, <c>superseded</c> (clause 4.3.12.6.2).</summary>
    public static string RevocationReasonSuperseded { get; } = "urn:etsi:019102:revocationReason:superseded";

    /// <summary>The URI for RFC 5280 §5.3.1 <c>CRLReason</c> value 5, <c>cessationOfOperation</c> (clause 4.3.12.6.2).</summary>
    public static string RevocationReasonCessationOfOperation { get; } = "urn:etsi:019102:revocationReason:cessationOfOperation";

    /// <summary>The URI for RFC 5280 §5.3.1 <c>CRLReason</c> value 6, <c>certificateHold</c> (clause 4.3.12.6.2).</summary>
    public static string RevocationReasonCertificateHold { get; } = "urn:etsi:019102:revocationReason:certificateHold";

    /// <summary>The URI for RFC 5280 §5.3.1 <c>CRLReason</c> value 8, <c>removeFromCRL</c> (clause 4.3.12.6.2).</summary>
    public static string RevocationReasonRemoveFromCrl { get; } = "urn:etsi:019102:revocationReason:removeFromCRL";

    /// <summary>The URI for RFC 5280 §5.3.1 <c>CRLReason</c> value 9, <c>privilegeWithdrawn</c> (clause 4.3.12.6.2).</summary>
    public static string RevocationReasonPrivilegeWithdrawn { get; } = "urn:etsi:019102:revocationReason:privilegeWithdrawn";

    /// <summary>The URI for RFC 5280 §5.3.1 <c>CRLReason</c> value 10, <c>aACompromise</c> (clause 4.3.12.6.2).</summary>
    public static string RevocationReasonAttributeAuthorityCompromise { get; } = "urn:etsi:019102:revocationReason:aACompromise";
}


/// <summary>
/// Maps a validation object's kind to the <c>ObjectType</c> URI of clause 4.4.4 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>.
/// </summary>
public static class ValidationObjectKindMapping
{
    /// <summary>Maps a <see cref="ValidationObjectKind"/> to its <c>ObjectType</c> URI.</summary>
    /// <param name="kind">The kind to map.</param>
    /// <returns>The URI. <see cref="ValidationObjectKind.SignatureValue"/>, <see cref="ValidationObjectKind.Signature"/> and <see cref="ValidationObjectKind.SignatureAttribute"/> have no dedicated row in clause 4.4.4's list and map to <see cref="SignatureValidationReportWellKnown.ValidationObjectOther"/>, as does an unrecognized value.</returns>
    public static string ToWireValue(ValidationObjectKind kind) => kind switch
    {
        ValidationObjectKind.Certificate => SignatureValidationReportWellKnown.ValidationObjectCertificate,
        ValidationObjectKind.RevocationData => SignatureValidationReportWellKnown.ValidationObjectOcspResponse,
        ValidationObjectKind.TimestampToken => SignatureValidationReportWellKnown.ValidationObjectTimestamp,
        ValidationObjectKind.EvidenceRecord => SignatureValidationReportWellKnown.ValidationObjectEvidenceRecord,
        ValidationObjectKind.SignedDataObject => SignatureValidationReportWellKnown.ValidationObjectSignedData,
        _ => SignatureValidationReportWellKnown.ValidationObjectOther
    };


    /// <summary>
    /// Maps a <see cref="PkiObjectKind"/> carrier discriminator to the <see cref="ValidationObjectKind"/> the
    /// report model uses, so a <see cref="PkiCertificateMemory"/> gathered from a conclusion can be classified
    /// without inspecting its DER bytes.
    /// </summary>
    /// <param name="kind">The carrier's own discriminator.</param>
    /// <returns>The matching validation object kind; <see cref="ValidationObjectKind.Unknown"/> for an OCSP request, which is a request rather than a validation object, and for an unrecognized value.</returns>
    public static ValidationObjectKind FromPkiObjectKind(PkiObjectKind kind) => kind switch
    {
        PkiObjectKind.X509Certificate => ValidationObjectKind.Certificate,
        PkiObjectKind.X509Crl => ValidationObjectKind.RevocationData,
        PkiObjectKind.OcspResponse => ValidationObjectKind.RevocationData,
        PkiObjectKind.TimestampToken => ValidationObjectKind.TimestampToken,
        _ => ValidationObjectKind.Unknown
    };
}


/// <summary>
/// Maps a proof of existence's origin to the <c>TypeOfProof</c> URI of clause 4.4.6.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>.
/// </summary>
/// <remarks>
/// Clause 4.4.6.2 names three origins, coarser than the five of <see cref="ProofOfExistenceOrigin"/>: everything
/// the engine derived while validating — a time-stamp token, an evidence record, or an indirect derivation —
/// is "derived during validation"; a Driving Application assertion is "provided to the SVA as an input"; no
/// engine block derives a proof "by the policy", so that URI is reachable only for a caller-constructed
/// <see cref="ProofOfExistence"/>.
/// </remarks>
public static class ProofOfExistenceOriginMapping
{
    /// <summary>Maps a <see cref="ProofOfExistenceOrigin"/> to its <c>TypeOfProof</c> URI.</summary>
    /// <param name="origin">The origin to map.</param>
    /// <returns>The URI. <see cref="ProofOfExistenceOrigin.Unknown"/> and an unrecognized value map to <see cref="SignatureValidationReportWellKnown.ProofOfExistenceTypeValidation"/>, the reading that best fits a proof the SVA itself determined without a stated origin (for example the current time on a Basic Signature validation, per NOTE of clause 4.3.6.1).</returns>
    public static string ToWireValue(ProofOfExistenceOrigin origin) => origin switch
    {
        ProofOfExistenceOrigin.TimestampToken => SignatureValidationReportWellKnown.ProofOfExistenceTypeValidation,
        ProofOfExistenceOrigin.EvidenceRecord => SignatureValidationReportWellKnown.ProofOfExistenceTypeValidation,
        ProofOfExistenceOrigin.IndirectDerivation => SignatureValidationReportWellKnown.ProofOfExistenceTypeValidation,
        ProofOfExistenceOrigin.DrivingApplicationAssertion => SignatureValidationReportWellKnown.ProofOfExistenceTypeProvided,
        _ => SignatureValidationReportWellKnown.ProofOfExistenceTypeValidation
    };
}


/// <summary>
/// Whether an individual validation constraint report element (clause 4.3.5.4) reports its constraint as
/// applied, disabled, or overridden by another constraint.
/// </summary>
/// <remarks>
/// <see cref="Applied"/> occupies zero because it is the ordinary case: a constraint the algorithm actually
/// evaluated, per <see cref="SignatureValidationConclusion.ConstraintEvaluations"/>.
/// </remarks>
public enum ConstraintApplicationStatus
{
    /// <summary>The constraint was evaluated by the validation algorithm.</summary>
    Applied = 0,

    /// <summary>The constraint was disabled by the validation policy in use, per <see cref="SignatureValidationConstraints.ChecksDisabledByPolicy"/>.</summary>
    Disabled = 1,

    /// <summary>
    /// The constraint was overridden by another constraint. No block of this library's engine tracks which
    /// constraint overrides which, so this value is reachable only for a caller-constructed
    /// <see cref="IndividualValidationConstraintReport"/>.
    /// </summary>
    Overridden = 2
}


/// <summary>
/// Maps a <see cref="ConstraintApplicationStatus"/> to the <c>ConstraintStatus.Status</c> URI of clause 4.3.5.4.2
/// of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>.
/// </summary>
public static class ConstraintApplicationStatusMapping
{
    /// <summary>Maps a <see cref="ConstraintApplicationStatus"/> to its URI.</summary>
    /// <param name="status">The status to map.</param>
    /// <returns>The URI. An unrecognized value maps to <see cref="SignatureValidationReportWellKnown.ConstraintStatusApplied"/>, the value that carries the most information for a Driving Application to act on.</returns>
    public static string ToWireValue(ConstraintApplicationStatus status) => status switch
    {
        ConstraintApplicationStatus.Disabled => SignatureValidationReportWellKnown.ConstraintStatusDisabled,
        ConstraintApplicationStatus.Overridden => SignatureValidationReportWellKnown.ConstraintStatusOverridden,
        _ => SignatureValidationReportWellKnown.ConstraintStatusApplied
    };
}


/// <summary>
/// Maps an RFC 5280 §5.3.1 <c>CRLReason</c> code to the <c>RevocationReason</c> URI of clause 4.3.12.6.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see>.
/// </summary>
public static class RevocationReasonMapping
{
    /// <summary>Maps a <c>CRLReason</c> code to its URI.</summary>
    /// <param name="reasonCode">The RFC 5280 §5.3.1 <c>CRLReason</c> enumerated value, for example the value <see cref="CertificateRevocationReportData.RevocationReason"/> carries.</param>
    /// <param name="wireValue">The URI when this method returns <see langword="true"/>.</param>
    /// <returns><see langword="true"/> when the code is one of the ten values clause 4.3.12.6.2 lists (value 7 is unused by RFC 5280 and has no URI).</returns>
    public static bool TryToWireValue(int reasonCode, out string wireValue)
    {
        string? mapped = reasonCode switch
        {
            0 => SignatureValidationReportWellKnown.RevocationReasonUnspecified,
            1 => SignatureValidationReportWellKnown.RevocationReasonKeyCompromise,
            2 => SignatureValidationReportWellKnown.RevocationReasonCertificationAuthorityCompromise,
            3 => SignatureValidationReportWellKnown.RevocationReasonAffiliationChanged,
            4 => SignatureValidationReportWellKnown.RevocationReasonSuperseded,
            5 => SignatureValidationReportWellKnown.RevocationReasonCessationOfOperation,
            6 => SignatureValidationReportWellKnown.RevocationReasonCertificateHold,
            8 => SignatureValidationReportWellKnown.RevocationReasonRemoveFromCrl,
            9 => SignatureValidationReportWellKnown.RevocationReasonPrivilegeWithdrawn,
            10 => SignatureValidationReportWellKnown.RevocationReasonAttributeAuthorityCompromise,
            _ => null
        };

        wireValue = mapped ?? string.Empty;

        return mapped is not null;
    }
}
