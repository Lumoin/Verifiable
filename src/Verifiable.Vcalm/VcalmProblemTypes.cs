using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.StatusLists;

namespace Verifiable.Vcalm;

/// <summary>
/// The RFC 9457 ProblemDetails <c>type</c> URLs the W3C VCALM 1.0 verifier service emits.
/// </summary>
/// <remarks>
/// <para>
/// §3.8 mandates that the ProblemDetails <c>type</c> "MUST be present and its value MUST be a
/// URL identifying the type of problem." VCALM 1.0 itself defines one type
/// (<see cref="UnknownOptionProvided"/>); the verification ProblemDetails reuse the
/// VC Data Model 2.0 / VC Data Integrity 1.0 / Bitstring Status List 1.0 catalogues §3.8 points
/// implementers at. Each URL uses the exact prefix specified by its defining catalogue.
/// </para>
/// <para>
/// §3.8 lists, among the ProblemDetails an implementation might report, "Section 3.5: Processing
/// Errors in the Bitstring Status List v1.0 specification": <see cref="StatusRetrievalError"/>,
/// <see cref="StatusVerificationError"/>, and <see cref="StatusListLengthError"/> reuse
/// <see cref="BitstringStatusListConstants.ErrorTypeUrlPrefix"/>, the prefix the Bitstring Status
/// List 1.0 catalogue itself defines; <see cref="RangeError"/> is the RANGE_ERROR the Bitstring
/// Status List 1.0 Validate Algorithm raises, anchored against the VC Data Model 2.0 catalogue like
/// this catalogue's other VC Data Model rows.
/// </para>
/// </remarks>
public static class VcalmProblemTypes
{
    /// <summary>
    /// §3.8: "An option that is unknown to the implementation was provided to the API call."
    /// The single problem type VCALM 1.0 itself defines, paired with the §2.4 MUST that an
    /// endpoint reject options it does not understand; see
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#error-handling">VCALM §3.8</see> and <see cref="VcalmVerifierEndpoints"/>.
    /// </summary>
    public static string UnknownOptionProvided { get; } =
        "https://www.w3.org/TR/vcalm#UNKNOWN_OPTION_PROVIDED";

    /// <summary>
    /// The securing mechanism has detected a modification in the document contents since it was
    /// created; potential tampering detected, as defined by
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#problem-details">VCDM §7.2</see>.
    /// Used by <see cref="VcalmVerificationService"/> only for a failed signature.
    /// </summary>
    public static string CryptographicSecurityError { get; } =
        "https://www.w3.org/TR/vc-data-model#CRYPTOGRAPHIC_SECURITY_ERROR";

    /// <summary>
    /// The value associated with a particular property is malformed, per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#problem-details">VCDM §7.2</see>.
    /// A data-model error makes <see cref="VcalmVerificationOutcome.Verified"/> false.
    /// </summary>
    public static string MalformedValueError { get; } =
        "https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR";

    /// <summary>
    /// The Bitstring Status List 1.0 §3.5 <c>STATUS_RETRIEVAL_ERROR</c>: reported as a §3.8.1
    /// status WARNING when the application's <see cref="ResolveVcalmStatusListDelegate"/> cannot
    /// retrieve the referenced status list — it returns <see langword="null"/>, throws a
    /// <see cref="BitstringStatusListException"/> of kind
    /// <see cref="BitstringStatusListErrorType.StatusRetrieval"/>, throws any other exception, or its fetch ends on its
    /// own budget — and when the verifier never attempts the retrieval because an earlier dependency of the same request
    /// already exhausted its own budget. Every one of these is a warning, as VCALM classifies status, so none by itself
    /// makes <see cref="VcalmVerificationOutcome.Verified"/> false.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/vc-bitstring-status-list/#processing-errors">Bitstring
    /// Status List 1.0 §3.5 Processing Errors</see>: "Retrieval of the status list failed."
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verification-errors-vs-warnings">VCALM §3.8.1</see>: "Warnings are
    /// ProblemDetails relating to status and validity periods".
    /// </remarks>
    public static string StatusRetrievalError { get; } =
        BitstringStatusListConstants.ErrorTypeUrlPrefix + "STATUS_RETRIEVAL_ERROR";

    /// <summary>
    /// The Bitstring Status List 1.0 §3.5 <c>STATUS_VERIFICATION_ERROR</c>: reported as a §3.8.1
    /// status WARNING when a <c>BitstringStatusListEntry</c>'s <c>statusListIndex</c>,
    /// <c>statusListCredential</c>, or <c>statusPurpose</c> is missing or unparseable, or when
    /// <see cref="BitstringStatusListValidation.GetStatus"/> throws a
    /// <see cref="BitstringStatusListException"/> of kind
    /// <see cref="BitstringStatusListErrorType.StatusVerification"/> (a failed proof or purpose
    /// mismatch).
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/vc-bitstring-status-list/#processing-errors">Bitstring
    /// Status List 1.0 §3.5 Processing Errors</see>: "Validation of the status entry failed."
    /// </remarks>
    public static string StatusVerificationError { get; } =
        BitstringStatusListConstants.ErrorTypeUrlPrefix + "STATUS_VERIFICATION_ERROR";

    /// <summary>
    /// The Bitstring Status List 1.0 §3.5 <c>STATUS_LIST_LENGTH_ERROR</c>: reported as a §3.8.1
    /// status WARNING when the referenced status list is shorter than the herd-privacy minimum.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/vc-bitstring-status-list/#processing-errors">Bitstring
    /// Status List 1.0 §3.5 Processing Errors</see>: "The status list length does not satisfy the
    /// minimum length required for herd privacy."
    /// </remarks>
    public static string StatusListLengthError { get; } =
        BitstringStatusListConstants.ErrorTypeUrlPrefix + "STATUS_LIST_LENGTH_ERROR";

    /// <summary>
    /// The VC Data Model 2.0 <c>RANGE_ERROR</c>, "A provided value is outside of the expected range of an associated
    /// value", per <see href="https://www.w3.org/TR/vc-data-model-2.0/#problem-details">VCDM §7.2</see>. The Bitstring
    /// Status List 1.0 Validate Algorithm raises it when a <c>statusListIndex</c> lies outside the bitstring, which
    /// <see cref="BitstringStatusListValidation.GetStatus"/> checks and which is reported as a §3.8.1 status WARNING.
    /// A credential or presentation carrying more proofs than
    /// <see cref="VcalmCredentialVerification.MaxProofsPerDocument"/> admits reports it as an ERROR.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/vc-bitstring-status-list/#validate-algorithm">Bitstring
    /// Status List 1.0 §3.2 Validate Algorithm</see>: "a RANGE_ERROR MUST be raised."
    /// </remarks>
    public static string RangeError { get; } =
        "https://www.w3.org/TR/vc-data-model#RANGE_ERROR";

    /// <summary>
    /// There was an error while parsing input.
    /// Defined by <see href="https://www.w3.org/TR/vc-data-model-2.0/#problem-details"/> and reported by <see cref="VcalmVerificationService"/>.
    /// </summary>
    public static string ParsingError { get; } =
        "https://www.w3.org/TR/vc-data-model#PARSING_ERROR";

    /// <summary>
    /// An error was encountered during proof verification.
    /// Defined by <see href="https://www.w3.org/TR/vc-data-integrity/#processing-errors"/> and reported by <see cref="VcalmVerificationService"/>.
    /// </summary>
    public static string ProofVerificationError { get; } =
        "https://w3id.org/security#PROOF_VERIFICATION_ERROR";

    /// <summary>
    /// An error was encountered during the transformation process.
    /// Defined by <see href="https://www.w3.org/TR/vc-data-integrity/#processing-errors"/> and reported by <see cref="VcalmVerificationService"/>.
    /// </summary>
    public static string ProofTransformationError { get; } =
        "https://w3id.org/security#PROOF_TRANSFORMATION_ERROR";

    /// <summary>
    /// The domain value in a proof did not match the expected value.
    /// Defined by <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof"/> and reported by <see cref="VcalmVerificationService"/>.
    /// </summary>
    public static string InvalidDomainError { get; } =
        "https://w3id.org/security#INVALID_DOMAIN_ERROR";

    /// <summary>
    /// The challenge value in a proof did not match the expected value.
    /// Defined by <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof"/> and reported by <see cref="VcalmVerificationService"/>.
    /// </summary>
    public static string InvalidChallengeError { get; } =
        "https://w3id.org/security#INVALID_CHALLENGE_ERROR";

    /// <summary>
    /// The controller document is not a conforming controlled identifier document.
    /// Defined by <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method"/> and reported by <see cref="VcalmVerificationService"/>.
    /// </summary>
    public static string InvalidControlledIdentifierDocument { get; } =
        "https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT";

    /// <summary>
    /// The controller document id does not match the controller document URL.
    /// Defined by <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method"/> and reported by <see cref="VcalmVerificationService"/>.
    /// </summary>
    public static string InvalidControlledIdentifierDocumentId { get; } =
        "https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID";

    /// <summary>
    /// The verification method identifier is not a valid URL.
    /// Defined by <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method"/> and reported by <see cref="VcalmVerificationService"/>.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "This is the exact RFC 9457 problem-type string, like every other entry in this catalogue.")]
    public static string InvalidVerificationMethodUrl { get; } =
        "https://w3id.org/security#INVALID_VERIFICATION_METHOD_URL";

    /// <summary>
    /// The verification method is nonconforming or its id or controller does not match.
    /// Defined by <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method"/> and reported by <see cref="VcalmVerificationService"/>.
    /// </summary>
    public static string InvalidVerificationMethod { get; } =
        "https://w3id.org/security#INVALID_VERIFICATION_METHOD";

    /// <summary>
    /// The verification method is not associated with the required verification relationship.
    /// Defined by <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method"/> and reported by <see cref="VcalmVerificationService"/>.
    /// </summary>
    public static string InvalidRelationshipForVerificationMethod { get; } =
        "https://w3id.org/security#INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD";

    /// <summary>
    /// The base URL for every library-defined problem type in this catalogue, as permitted by
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-4">RFC 9457 §4</see>; shared by
    /// <see cref="UnsupportedSecuringMechanism"/>, <see cref="ContextValidationError"/>,
    /// <see cref="ValidityPeriodWarning"/>, <see cref="StatusWarning"/>, <see cref="ChallengeNotIssued"/>,
    /// and <see cref="VerificationMethodControllerMismatch"/>.
    /// </summary>
    public static string LibraryProblemTypeBase { get; } = "https://verifiable.lumoin.com/problems#";

    /// <summary>
    /// The securing mechanism is unsupported or has no configured verifier.
    /// This library-defined type uses <see cref="LibraryProblemTypeBase"/> under
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-4">RFC 9457 §4</see>.
    /// </summary>
    public static string UnsupportedSecuringMechanism { get; } = LibraryProblemTypeBase + "UNSUPPORTED_SECURING_MECHANISM";

    /// <summary>
    /// The one fixed detail sentence every <see cref="UnsupportedSecuringMechanism"/> ProblemDetail
    /// carries, regardless of which mechanism (an envelope, a cryptosuite, or the crypto registry)
    /// could not be dispatched: the wired registry's topology is never described.
    /// </summary>
    public static string UnsupportedSecuringMechanismDetail { get; } =
        "The proof's securing mechanism is not supported by this verifier.";

    /// <summary>
    /// Context validation failed after transformation: <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation">Data Integrity §4.6</see>
    /// requires an error but names no type, so this library-defined type uses <see cref="LibraryProblemTypeBase"/>
    /// under <see href="https://www.rfc-editor.org/rfc/rfc9457#section-4">RFC 9457 §4</see>.
    /// </summary>
    public static string ContextValidationError { get; } = LibraryProblemTypeBase + "CONTEXT_VALIDATION_ERROR";

    /// <summary>
    /// The validity-period WARNING (§3.8.1: a validity-period ProblemDetails is recoverable and
    /// does NOT flip <c>verified</c>) — emitted when <c>validFrom</c> is in the future or
    /// <c>validUntil</c> is in the past relative to the verification instant. Neither VCDM §7.2 nor
    /// VCALM §3.8.1 names a code for this warning (<see href="https://www.w3.org/TR/vc-data-model-2.0/#problem-details">VCDM
    /// §7.2</see> defines only PARSING_ERROR, CRYPTOGRAPHIC_SECURITY_ERROR, MALFORMED_VALUE_ERROR and
    /// RANGE_ERROR), so this library-defined type uses <see cref="LibraryProblemTypeBase"/> under
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-4">RFC 9457 §4</see>.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verification-errors-vs-warnings">VCALM §3.8.1</see>
    /// defines warnings as problems relating to status and validity periods; <see cref="VcalmVerificationOutcome.Verified"/> is unchanged.
    /// </summary>
    public static string ValidityPeriodWarning { get; } = LibraryProblemTypeBase + "VALIDITY_PERIOD_WARNING";

    /// <summary>
    /// The status WARNING (§3.8.1: a status ProblemDetails is recoverable and does NOT flip
    /// <c>verified</c>) — emitted when the credential's status resolves to revoked or suspended.
    /// Neither VCDM §7.2 nor VCALM §3.8.1 names a code for this warning (<see href="https://www.w3.org/TR/vc-data-model-2.0/#problem-details">VCDM
    /// §7.2</see> defines only PARSING_ERROR, CRYPTOGRAPHIC_SECURITY_ERROR, MALFORMED_VALUE_ERROR and
    /// RANGE_ERROR), so this library-defined type uses <see cref="LibraryProblemTypeBase"/> under
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-4">RFC 9457 §4</see>.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verification-errors-vs-warnings">VCALM §3.8.1</see>
    /// defines warnings as problems relating to status and validity periods; <see cref="VcalmVerificationOutcome.Verified"/> is unchanged.
    /// </summary>
    public static string StatusWarning { get; } = LibraryProblemTypeBase + "STATUS_WARNING";

    /// <summary>
    /// A presented <c>options.challenge</c> that this verifier instance never issued, or that was
    /// already consumed by an earlier presentation. <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data
    /// Integrity §4.4</see> defines only a challenge that differs from the proof's own bound value
    /// (<see cref="InvalidChallengeError"/>); <see href="https://www.w3.org/TR/vcalm-1.0/#verify-presentation">VCALM
    /// §3.3.3</see> names no code for issuance tracking, so this library-defined type uses
    /// <see cref="LibraryProblemTypeBase"/> under
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-4">RFC 9457 §4</see>.
    /// </summary>
    public static string ChallengeNotIssued { get; } = LibraryProblemTypeBase + "CHALLENGE_NOT_ISSUED";

    /// <summary>
    /// A verification method whose <c>controller</c> does not match the credential's <c>issuer</c> or
    /// the presentation's <c>holder</c>. <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID
    /// §3.3</see> step 9 compares the verification method's <c>id</c> with the requested <c>vmIdentifier</c> and
    /// step 10 its controller with <c>controllerDocumentUrl</c>: "If the absolute URL value of
    /// verificationMethod.controller does not equal controllerDocumentUrl, an error MUST be raised and SHOULD convey
    /// an error type of INVALID_VERIFICATION_METHOD" (<see cref="InvalidVerificationMethod"/>). No pulled
    /// specification text defines the issuer/holder binding this library additionally enforces, so this
    /// library-defined type uses <see cref="LibraryProblemTypeBase"/> under
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-4">RFC 9457 §4</see>.
    /// </summary>
    public static string VerificationMethodControllerMismatch { get; } = LibraryProblemTypeBase + "VERIFICATION_METHOD_CONTROLLER_MISMATCH";
}
