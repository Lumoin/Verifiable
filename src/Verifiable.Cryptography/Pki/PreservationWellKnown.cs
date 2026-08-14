using System;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The wire values the preservation protocol of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> fixes — its two namespaces, the three preservation goals, the three storage
/// models, the closed enumerations of clauses 5.4.2, 5.4.8 and 5.4.9, the eight operation names, the two policy
/// types and the four preservation-scheme identifiers of Annex F — together with the recognition helpers a
/// dispatch site uses instead of comparing string literals at the call site.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Comparison is ordinal and case-sensitive.</strong> Every value here is either an XML enumeration facet
/// or a URI the specification prints literally, and an enumeration facet matches by exact character sequence: a
/// request stating <c>withstorage</c> is not schema-valid and must not be read as though it were.
/// </para>
/// <para>
/// <strong>The three default-value rules are stated here, once.</strong> Clauses 5.3.2.1.1, 5.3.4.1.1 and
/// 5.3.5.1.1 each say that an omitted optional element means a specific value rather than nothing —
/// <see cref="DefaultStatus"/>, <see cref="DefaultSubjectOfRetrieval"/> and <see cref="DefaultDeletionMode"/>.
/// A model that treated those three as merely optional would read a conformant request differently from the
/// service that sent it.
/// </para>
/// <para>
/// <strong>Values this class deliberately does not state.</strong> The <c>Result</c> component's major status
/// codes, the <c>OptionalInputs</c>/<c>OptionalOutputs</c> vocabulary and the <c>Policy</c>, <c>Operation</c>,
/// <c>Format</c> and <c>Extension</c> shapes belong to the external base specifications this document extends by
/// reference rather than redefines, and their text is not part of it. Nothing is invented here to fill that gap;
/// what this document states is stated, and what it delegates is carried verbatim.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "These are wire identifiers compared and written as exact character sequences; System.Uri normalises case, escaping and trailing separators, which would make two identifiers that name different goals, schemes or policies compare equal. Nothing here is dereferenced.")]
[SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
    Justification = "The recognition helpers compare a value read off the wire against an exact character sequence, for the reason given on the properties.")]
public static class PreservationWellKnown
{
    /// <summary>
    /// The protocol's own XML namespace, <c>http://uri.etsi.org/19512/v1.2.1#</c>, which Annex C.1 names as the
    /// target namespace of the schema document defining every type of clause 5.
    /// </summary>
    public static string PreservationNamespace { get; } = "http://uri.etsi.org/19512/v1.2.1#";

    /// <summary>
    /// The evidence-exchange XML namespace, <c>http://uri.etsi.org/19512/exchange/v1.2.1#</c>, which Annex C.2
    /// names as the target namespace of the schema document defining the Annex G exchange structure.
    /// </summary>
    public static string PreservationExchangeNamespace { get; } = "http://uri.etsi.org/19512/exchange/v1.2.1#";


    /// <summary>
    /// The preservation goal "Preservation of General Data", <c>http://uri.etsi.org/19512/goal/pgd</c> — a proof
    /// of existence over long periods of time for the submitted data object (clause 4.2).
    /// </summary>
    public static string GeneralDataGoal { get; } = "http://uri.etsi.org/19512/goal/pgd";

    /// <summary>
    /// The preservation goal "Preservation of Digital Signatures", <c>http://uri.etsi.org/19512/goal/pds</c> —
    /// extending the ability to validate a digital signature and to obtain a proof of existence of the signed
    /// data (clause 4.2).
    /// </summary>
    public static string DigitalSignatureGoal { get; } = "http://uri.etsi.org/19512/goal/pds";

    /// <summary>
    /// The preservation goal "Augmentation", <c>http://uri.etsi.org/19512/goal/aug</c> — the service accepts
    /// externally produced preservation evidences for augmentation (clause 4.2).
    /// </summary>
    public static string AugmentationGoal { get; } = "http://uri.etsi.org/19512/goal/aug";


    /// <summary>
    /// The storage model "with storage", <c>WithStorage</c> — the service stores submitted data objects and the
    /// evidences over them permanently (clauses 4.3.1 and 5.4.6).
    /// </summary>
    public static string WithStorageModel { get; } = "WithStorage";

    /// <summary>
    /// The storage model "with temporary storage", <c>WithTemporaryStorage</c> — the service keeps the submitted
    /// data objects only long enough to produce an evidence, which it then retains for a stated retention period
    /// (clauses 4.3.2 and 5.4.6).
    /// </summary>
    public static string WithTemporaryStorageModel { get; } = "WithTemporaryStorage";

    /// <summary>
    /// The storage model "without storage", <c>WithoutStorage</c> — the service stores nothing and produces the
    /// evidence synchronously (clauses 4.3.3 and 5.4.6).
    /// </summary>
    public static string WithoutStorageModel { get; } = "WithoutStorage";


    /// <summary>The <c>Status</c> value <c>active</c> (clause 5.4.8): only profiles in force are meant.</summary>
    public static string ActiveStatus { get; } = "active";

    /// <summary>The <c>Status</c> value <c>inactive</c> (clause 5.4.8): only profiles no longer in force are meant.</summary>
    public static string InactiveStatus { get; } = "inactive";

    /// <summary>
    /// The <c>Status</c> value <c>all</c> (clause 5.4.8): both active and inactive profiles are to be returned.
    /// </summary>
    /// <remarks>
    /// <strong>A documented interpretation of a spec-body inconsistency.</strong> Clause 5.4.8.1 gives this value
    /// a defined meaning in prose while the <c>StatusType</c> enumeration reproduced in clause 5.4.8.2 lists only
    /// <c>active</c> and <c>inactive</c>. The schema fragments are copied "for information" by the document's own
    /// words and the semantics clauses are its normative body, so the three-value reading is the one stated here;
    /// an implementation following the reproduced enumeration alone would reject a request the body text permits.
    /// </remarks>
    public static string AllStatus { get; } = "all";

    /// <summary>
    /// The value an omitted <c>Status</c> element means in a <c>RetrieveInfo</c> request, <c>active</c>: "If this
    /// optional element is omitted, only active preservation profiles are returned" (clause 5.3.2.1.1).
    /// </summary>
    public static string DefaultStatus { get; } = ActiveStatus;


    /// <summary>The <c>DeletionMode</c> value <c>OnlySubDOs</c> (clause 5.4.2): only the submitted data objects are deleted.</summary>
    public static string OnlySubmittedObjectsDeletionMode { get; } = "OnlySubDOs";

    /// <summary>The <c>DeletionMode</c> value <c>SubDOsAndEvidence</c> (clause 5.4.2): the submitted data objects and the evidences produced over them are deleted.</summary>
    public static string SubmittedObjectsAndEvidenceDeletionMode { get; } = "SubDOsAndEvidence";

    /// <summary>
    /// The value an omitted <c>Mode</c> element means in a <c>DeletePO</c> request, <c>SubDOsAndEvidence</c>:
    /// "If this optional element is omitted, the default <c>SubDOsAndEvidence</c> shall be used" (clause
    /// 5.3.5.1.1).
    /// </summary>
    public static string DefaultDeletionMode { get; } = SubmittedObjectsAndEvidenceDeletionMode;


    /// <summary>The <c>SubjectOfRetrieval</c> value <c>PO</c> (clause 5.4.9): the preservation object alone.</summary>
    public static string PreservationObjectSubject { get; } = "PO";

    /// <summary>The <c>SubjectOfRetrieval</c> value <c>Evidence</c> (clause 5.4.9): the preservation evidence alone.</summary>
    public static string EvidenceSubject { get; } = "Evidence";

    /// <summary>The <c>SubjectOfRetrieval</c> value <c>POwithEmbeddedEvidence</c> (clause 5.4.9): one object carrying its evidence inside it.</summary>
    public static string ObjectWithEmbeddedEvidenceSubject { get; } = "POwithEmbeddedEvidence";

    /// <summary>The <c>SubjectOfRetrieval</c> value <c>POwithDetachedEvidence</c> (clause 5.4.9): the object and its evidence as separate objects.</summary>
    public static string ObjectWithDetachedEvidenceSubject { get; } = "POwithDetachedEvidence";

    /// <summary>
    /// The value an omitted <c>SubjectOfRetrieval</c> element means in a <c>RetrievePO</c> request,
    /// <c>POwithEmbeddedEvidence</c>: "If this element is missing <c>POwithEmbeddedEvidence</c> shall be used as
    /// default value" (clause 5.3.4.1.1).
    /// </summary>
    public static string DefaultSubjectOfRetrieval { get; } = ObjectWithEmbeddedEvidenceSubject;


    /// <summary>
    /// The sentinel a <c>VersionID</c> element carries to ask for every version rather than one, <c>all</c>:
    /// "If the <c>VersionID</c> element is equal to the string <c>all</c> the ... corresponding to all version are
    /// returned" (clause 5.3.4.1.1).
    /// </summary>
    /// <remarks>
    /// It is a magic value inside a repeatable string element rather than a member of an enumeration of its own,
    /// which is why a caller cannot tell "every version" from "the version literally named <c>all</c>" without
    /// this recognition.
    /// </remarks>
    public static string AllVersionsIdentifier { get; } = "all";


    /// <summary>
    /// The <c>Policy</c> type every profile states, <c>http://uri.etsi.org/19512/policy/preservation-evidence</c>
    /// (clause 5.4.7): the policy under which preservation evidences are produced.
    /// </summary>
    public static string PreservationEvidencePolicyType { get; } = "http://uri.etsi.org/19512/policy/preservation-evidence";

    /// <summary>
    /// The <c>Policy</c> type a profile states in addition,
    /// <c>http://uri.etsi.org/19512/policy/signature-validation</c> (clause 5.4.7), when the preservation goal is
    /// the preservation of digital signatures and the validation data is not provided by the client.
    /// </summary>
    public static string SignatureValidationPolicyType { get; } = "http://uri.etsi.org/19512/policy/signature-validation";


    /// <summary>The name of the <c>RetrieveInfo</c> operation (clause 5.3.2), the one operation clause 5.2 makes mandatory for every service.</summary>
    public static string RetrieveInfoOperation { get; } = "RetrieveInfo";

    /// <summary>The name of the <c>PreservePO</c> operation (clause 5.3.3).</summary>
    public static string PreservePreservationObjectOperation { get; } = "PreservePO";

    /// <summary>The name of the <c>RetrievePO</c> operation (clause 5.3.4), which clause 5.3.4.1.1 permits only in a scheme with storage or with temporary storage.</summary>
    public static string RetrievePreservationObjectOperation { get; } = "RetrievePO";

    /// <summary>The name of the <c>DeletePO</c> operation (clause 5.3.5), which clause 5.3.5.1.1 permits only in a scheme with storage.</summary>
    public static string DeletePreservationObjectOperation { get; } = "DeletePO";

    /// <summary>The name of the <c>UpdatePOC</c> operation (clause 5.3.6).</summary>
    public static string UpdatePreservationObjectContainerOperation { get; } = "UpdatePOC";

    /// <summary>The name of the <c>RetrieveTrace</c> operation (clause 5.3.7).</summary>
    public static string RetrieveTraceOperation { get; } = "RetrieveTrace";

    /// <summary>The name of the <c>ValidateEvidence</c> operation (clause 5.3.8).</summary>
    public static string ValidateEvidenceOperation { get; } = "ValidateEvidence";

    /// <summary>The name of the <c>Search</c> operation (clause 5.3.9).</summary>
    public static string SearchOperation { get; } = "Search";


    /// <summary>
    /// The identifier of the preservation scheme with storage based on evidence records,
    /// <c>http://uri.etsi.org/19512/scheme/pds+pgd+aug+wst+ers</c> (clause F.1.1).
    /// </summary>
    /// <remarks>
    /// See <see cref="IsSchemeIdentifier"/> for why this value rather than the one clause F.1.7 restates.
    /// </remarks>
    public static string StorageWithEvidenceRecordsScheme { get; } = "http://uri.etsi.org/19512/scheme/pds+pgd+aug+wst+ers";

    /// <summary>
    /// The identifier of the preservation scheme with temporary storage based on evidence records,
    /// <c>http://uri.etsi.org/19512/scheme/pgd+wts+ers</c> (clause F.2.1, restated identically in clause F.2.7 —
    /// the one scheme of the four whose two statements agree).
    /// </summary>
    public static string TemporaryStorageWithEvidenceRecordsScheme { get; } = "http://uri.etsi.org/19512/scheme/pgd+wts+ers";

    /// <summary>
    /// The identifier of the preservation scheme with signature augmentation and with storage,
    /// <c>http://uri.etsi.org/19512/scheme/pds+wst+aug</c> (clause F.3.1).
    /// </summary>
    /// <remarks>
    /// See <see cref="IsSchemeIdentifier"/> for why this value rather than the one clause F.3.7 restates.
    /// </remarks>
    public static string StorageWithAugmentationScheme { get; } = "http://uri.etsi.org/19512/scheme/pds+wst+aug";

    /// <summary>
    /// The identifier of the preservation scheme with signature augmentation and without storage,
    /// <c>http://uri.etsi.org/19512/scheme/pds+wos+aug</c> (clause F.4.1).
    /// </summary>
    /// <remarks>
    /// See <see cref="IsSchemeIdentifier"/> for why this value rather than the one clause F.4.7 restates.
    /// </remarks>
    public static string NoStorageWithAugmentationScheme { get; } = "http://uri.etsi.org/19512/scheme/pds+wos+aug";


    /// <summary>
    /// The value clause F.1.7 restates as the scheme's identifier,
    /// <c>http://uri.etsi.org/19512/scheme/pds+pgd+wst+ers</c> — the clause F.1.1 identifier without its
    /// <c>+aug</c> segment.
    /// </summary>
    /// <remarks>
    /// Stated so a reader meeting it on the wire can recognise it as the defect it is rather than as an unknown
    /// scheme; see <see cref="IsSchemeIdentifier"/>. Nothing in this library writes it.
    /// </remarks>
    public static string StorageWithEvidenceRecordsSchemeAsRestated { get; } = "http://uri.etsi.org/19512/scheme/pds+pgd+wst+ers";

    /// <summary>
    /// The value clause F.3.7 restates as the scheme's identifier,
    /// <c>http://uri.etsi.org/19512/scheme/pgd+wst+aug</c> — the clause F.3.1 identifier with its goal segment
    /// changed from <c>pds</c> to <c>pgd</c>.
    /// </summary>
    /// <remarks>
    /// Stated for recognition only; see <see cref="IsSchemeIdentifier"/>. Nothing in this library writes it.
    /// </remarks>
    public static string StorageWithAugmentationSchemeAsRestated { get; } = "http://uri.etsi.org/19512/scheme/pgd+wst+aug";

    /// <summary>
    /// The value clause F.4.7 restates as the scheme's identifier,
    /// <c>http://uri.etsi.org/19512/scheme/pgd+wos+aug</c> — the clause F.4.1 identifier with its goal segment
    /// changed from <c>pds</c> to <c>pgd</c>.
    /// </summary>
    /// <remarks>
    /// Stated for recognition only; see <see cref="IsSchemeIdentifier"/>. Nothing in this library writes it.
    /// </remarks>
    public static string NoStorageWithAugmentationSchemeAsRestated { get; } = "http://uri.etsi.org/19512/scheme/pgd+wos+aug";


    /// <summary>Determines whether a value is one of the three preservation goals of clause 4.2.</summary>
    /// <param name="goal">The <c>PreservationGoal</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is a goal the specification states.</returns>
    public static bool IsPreservationGoal(string? goal) =>
        IsOneOf(goal, GeneralDataGoal, DigitalSignatureGoal, AugmentationGoal);


    /// <summary>Determines whether a value is one of the three storage models of clauses 4.3 and 5.4.6.</summary>
    /// <param name="storageModel">The <c>PreservationStorageModel</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is a member of the enumeration.</returns>
    public static bool IsStorageModel(string? storageModel) =>
        IsOneOf(storageModel, WithStorageModel, WithTemporaryStorageModel, WithoutStorageModel);


    /// <summary>
    /// Determines whether a value is one of the three <c>Status</c> values of clause 5.4.8, including the
    /// prose-only <see cref="AllStatus"/>.
    /// </summary>
    /// <param name="status">The <c>Status</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is one the body text gives a meaning to.</returns>
    public static bool IsStatus(string? status) => IsOneOf(status, ActiveStatus, InactiveStatus, AllStatus);


    /// <summary>
    /// Determines whether a value is one of the two <c>Status</c> values the reproduced <c>StatusType</c>
    /// enumeration of clause 5.4.8.2 lists — that is, <see cref="IsStatus"/> minus <see cref="AllStatus"/>.
    /// </summary>
    /// <param name="status">The <c>Status</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is a member of the reproduced enumeration.</returns>
    /// <remarks>
    /// A profile carries one of these two; only a <c>RetrieveInfo</c> request's filter may carry the third. The
    /// distinction exists so a caller can tell the two readings apart rather than having to choose one.
    /// </remarks>
    public static bool IsProfileStatus(string? status) => IsOneOf(status, ActiveStatus, InactiveStatus);


    /// <summary>Determines whether a value is one of the two <c>DeletionMode</c> values of clause 5.4.2.</summary>
    /// <param name="deletionMode">The <c>Mode</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is a member of the enumeration.</returns>
    public static bool IsDeletionMode(string? deletionMode) =>
        IsOneOf(deletionMode, OnlySubmittedObjectsDeletionMode, SubmittedObjectsAndEvidenceDeletionMode);


    /// <summary>Determines whether a value is one of the four <c>SubjectOfRetrieval</c> values of clause 5.4.9.</summary>
    /// <param name="subjectOfRetrieval">The <c>SubjectOfRetrieval</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is a member of the enumeration.</returns>
    public static bool IsSubjectOfRetrieval(string? subjectOfRetrieval) =>
        IsOneOf(
            subjectOfRetrieval,
            PreservationObjectSubject,
            EvidenceSubject,
            ObjectWithEmbeddedEvidenceSubject,
            ObjectWithDetachedEvidenceSubject);


    /// <summary>
    /// Determines whether a <c>VersionID</c> value is the sentinel asking for every version rather than naming
    /// one (clause 5.3.4.1.1).
    /// </summary>
    /// <param name="versionIdentifier">The <c>VersionID</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is exactly <see cref="AllVersionsIdentifier"/>.</returns>
    public static bool IsAllVersionsIdentifier(string? versionIdentifier) =>
        string.Equals(versionIdentifier, AllVersionsIdentifier, StringComparison.Ordinal);


    /// <summary>Determines whether a value is one of the two <c>Policy</c> types of clause 5.4.7.</summary>
    /// <param name="policyType">The <c>Policy</c> element's <c>Type</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is a policy type this document states.</returns>
    public static bool IsPolicyType(string? policyType) =>
        IsOneOf(policyType, PreservationEvidencePolicyType, SignatureValidationPolicyType);


    /// <summary>Determines whether a value is one of the eight operation names of clauses 5.3.2 to 5.3.9.</summary>
    /// <param name="operationName">The <c>Operation</c> element's <c>Name</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value names an operation this document defines.</returns>
    /// <remarks>
    /// A profile announces the operations it implements by name (clause 5.4.7), and a <c>RetrievePO</c> request
    /// resolves its default output format through the <c>Operation</c> element "which <c>Name</c> element is equal
    /// to the string <c>RetrievePO</c>" (clause 5.3.4.1.1) — so the names are wire values, not identifiers this
    /// library chose.
    /// </remarks>
    public static bool IsOperationName(string? operationName) =>
        IsOneOf(
            operationName,
            RetrieveInfoOperation,
            PreservePreservationObjectOperation,
            RetrievePreservationObjectOperation,
            DeletePreservationObjectOperation,
            UpdatePreservationObjectContainerOperation,
            RetrieveTraceOperation,
            ValidateEvidenceOperation,
            SearchOperation);


    /// <summary>
    /// Determines whether a value identifies one of the four preservation schemes of Annex F, by either of the two
    /// values three of those schemes state for themselves.
    /// </summary>
    /// <param name="schemeIdentifier">The <c>SchemeIdentifier</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value names a scheme the annex defines.</returns>
    /// <remarks>
    /// <para>
    /// <strong>Three of the four schemes state two different identifiers for themselves.</strong> Each scheme's
    /// clause <c>F.N.1</c> gives an identifier and its clause <c>F.N.7</c> restates one for the
    /// <c>SchemeIdentifier</c> field a real profile would carry, and the two differ for F.1 (the restatement drops
    /// the <c>+aug</c> segment), F.3 and F.4 (the restatement changes the goal segment from <c>pds</c> to
    /// <c>pgd</c>). Only F.2's two statements agree.
    /// </para>
    /// <para>
    /// <strong>Which one this library writes, and why.</strong> In every one of the three disagreements the
    /// clause <c>F.N.1</c> identifier agrees with the goals the scheme's own clause <c>F.N.2</c> lists — F.1
    /// lists augmentation among its goals, and F.3 and F.4 both list the preservation of digital signatures —
    /// while the restatement contradicts them. The <c>F.N.1</c> values are therefore what
    /// <see cref="StorageWithEvidenceRecordsScheme"/>, <see cref="StorageWithAugmentationScheme"/> and
    /// <see cref="NoStorageWithAugmentationScheme"/> hold and the only ones anything here writes; the restatements
    /// are recognised so that a profile built by copying clause <c>F.N.7</c> literally is understood rather than
    /// rejected as unknown.
    /// </para>
    /// </remarks>
    public static bool IsSchemeIdentifier(string? schemeIdentifier) =>
        IsOneOf(
            schemeIdentifier,
            StorageWithEvidenceRecordsScheme,
            TemporaryStorageWithEvidenceRecordsScheme,
            StorageWithAugmentationScheme,
            NoStorageWithAugmentationScheme,
            StorageWithEvidenceRecordsSchemeAsRestated,
            StorageWithAugmentationSchemeAsRestated,
            NoStorageWithAugmentationSchemeAsRestated);


    /// <summary>
    /// Determines whether a value is a scheme identifier that agrees with the goals its own scheme clause lists —
    /// that is, one of the four clause <c>F.N.1</c> identifiers rather than one of the three restatements.
    /// </summary>
    /// <param name="schemeIdentifier">The <c>SchemeIdentifier</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is one of the four identifiers this library writes.</returns>
    public static bool IsConsistentSchemeIdentifier(string? schemeIdentifier) =>
        IsOneOf(
            schemeIdentifier,
            StorageWithEvidenceRecordsScheme,
            TemporaryStorageWithEvidenceRecordsScheme,
            StorageWithAugmentationScheme,
            NoStorageWithAugmentationScheme);


    /// <summary>
    /// Determines whether an operation is one a service implementing the given storage model may expose at all.
    /// </summary>
    /// <param name="operationName">The operation's name.</param>
    /// <param name="storageModel">The <c>PreservationStorageModel</c> value the service's profile states.</param>
    /// <returns>
    /// <see langword="false"/> when the operation's own clause forbids it under that storage model, and
    /// <see langword="true"/> otherwise — including for a value that names no operation or no storage model, which
    /// this helper does not judge.
    /// </returns>
    /// <remarks>
    /// Two operations carry a scheme gate in their own semantics clause rather than in Annex F: <c>RetrievePO</c>
    /// "may only be provided in preservation schemes with storage ... or with temporary storage" (clause
    /// 5.3.4.1.1) and <c>DeletePO</c> "shall only be supported in the case of a preservation scheme with storage"
    /// (clause 5.3.5.1.1). Every other operation is gated by the profile a service publishes, which is discovery
    /// data rather than a rule of this document.
    /// </remarks>
    public static bool IsOperationPermittedUnderStorageModel(string? operationName, string? storageModel) =>
        operationName switch
        {
            _ when string.Equals(operationName, RetrievePreservationObjectOperation, StringComparison.Ordinal) =>
                IsOneOf(storageModel, WithStorageModel, WithTemporaryStorageModel),
            _ when string.Equals(operationName, DeletePreservationObjectOperation, StringComparison.Ordinal) =>
                IsOneOf(storageModel, WithStorageModel),
            _ => true
        };


    /// <summary>Compares a value against a set of exact character sequences.</summary>
    /// <param name="value">The value read off the wire, or <see langword="null"/>.</param>
    /// <param name="candidates">The values the specification states.</param>
    /// <returns><see langword="true"/> when the value is ordinally equal to one of the candidates.</returns>
    private static bool IsOneOf(string? value, params string[] candidates)
    {
        if(value is null)
        {
            return false;
        }

        foreach(string candidate in candidates)
        {
            if(string.Equals(value, candidate, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
