using System;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The result codes the preservation protocol of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> states for the <c>Result/ResultMinor</c> component of a response — fifteen error
/// codes and two warning codes — together with the per-operation lists each operation's own clause gives, and the
/// mapping between a code and the <see cref="PreservationOperationOutcome"/> a seam answers with.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Minor codes only.</strong> <c>Result</c> is a component of the external base specification this
/// document extends by reference, and only the minor codes below are stated by this document itself. The major
/// status codes therefore have no getter here: inventing URIs for them would put values on the wire that no
/// cached normative text states. <see cref="PreservationResult.ResultMajor"/> carries whatever the peer sent,
/// verbatim.
/// </para>
/// <para>
/// <strong>One flat vocabulary, nine informative subsets.</strong> Every code lives in one of the two
/// namespaces below and means the same thing wherever it appears; the per-operation lists clauses 5.3.2 to 5.3.9
/// give are which codes MAY appear in that operation's response, which is what
/// <see cref="IsResultMinorStatedForOperation"/> answers. A code outside its operation's list is not thereby
/// meaningless — it is outside what the operation's clause enumerates, which a strict peer reports and a lenient
/// one tolerates.
/// </para>
/// <para>
/// <strong>Comparison is ordinal and case-sensitive.</strong> Two of the codes carry capitals inside the last
/// segment (<see cref="PreservationObjectFormatError"/> and <see cref="DeltaPocInternalProblem"/>) while every
/// other code begins in lower case, so a case-folding comparison would accept spellings the document does not
/// state.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "A result code is compared and written as an exact character sequence; System.Uri normalises case and escaping, which would make two codes that name different failures compare equal. Nothing here is dereferenced.")]
[SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
    Justification = "The recognition helpers compare a code read off the wire against an exact character sequence, for the reason given on the properties.")]
public static class PreservationResultWellKnown
{
    /// <summary>The namespace every error code shares, <c>http://uri.etsi.org/19512/error/</c>.</summary>
    public static string ErrorCodeNamespace { get; } = "http://uri.etsi.org/19512/error/";

    /// <summary>The namespace every warning code shares, <c>http://uri.etsi.org/19512/warning/</c>.</summary>
    public static string WarningCodeNamespace { get; } = "http://uri.etsi.org/19512/warning/";


    /// <summary>The error code <c>noPermission</c> — the client is not allowed to perform the operation. Stated for every one of the eight operations.</summary>
    public static string NoPermission { get; } = "http://uri.etsi.org/19512/error/noPermission";

    /// <summary>The error code <c>internalError</c> — the service failed for a reason of its own. Stated for every one of the eight operations.</summary>
    public static string InternalError { get; } = "http://uri.etsi.org/19512/error/internalError";

    /// <summary>The error code <c>parameterError</c> — a request parameter is malformed or inconsistent. Stated for every one of the eight operations.</summary>
    public static string ParameterError { get; } = "http://uri.etsi.org/19512/error/parameterError";

    /// <summary>The error code <c>notSupported</c> — the operation or an option of it is not supported. Stated for every one of the eight operations.</summary>
    public static string NotSupported { get; } = "http://uri.etsi.org/19512/error/notSupported";

    /// <summary>The error code <c>transferError</c> (clauses 5.3.3, 5.3.6).</summary>
    public static string TransferError { get; } = "http://uri.etsi.org/19512/error/transferError";

    /// <summary>The error code <c>noSpaceError</c> (clauses 5.3.3, 5.3.6).</summary>
    public static string NoSpaceError { get; } = "http://uri.etsi.org/19512/error/noSpaceError";

    /// <summary>The error code <c>unknownPOFormat</c> (clauses 5.3.3, 5.3.4).</summary>
    public static string UnknownPreservationObjectFormat { get; } = "http://uri.etsi.org/19512/error/unknownPOFormat";

    /// <summary>The error code <c>POFormatError</c> (clause 5.3.3) — one of the two codes whose last segment begins with capitals.</summary>
    public static string PreservationObjectFormatError { get; } = "http://uri.etsi.org/19512/error/POFormatError";

    /// <summary>The error code <c>externalServiceUnavailable</c> (clause 5.3.3) — a service the preservation service depends on, such as a time-stamping authority, could not be reached.</summary>
    public static string ExternalServiceUnavailable { get; } = "http://uri.etsi.org/19512/error/externalServiceUnavailable";

    /// <summary>The error code <c>unknownEvidenceFormat</c> (clause 5.3.4).</summary>
    public static string UnknownEvidenceFormat { get; } = "http://uri.etsi.org/19512/error/unknownEvidenceFormat";

    /// <summary>The error code <c>unknownPOID</c> (clauses 5.3.4, 5.3.5, 5.3.6, 5.3.7).</summary>
    public static string UnknownPreservationObjectIdentifier { get; } = "http://uri.etsi.org/19512/error/unknownPOID";

    /// <summary>The error code <c>unknownVersionID</c> (clause 5.3.4).</summary>
    public static string UnknownVersionIdentifier { get; } = "http://uri.etsi.org/19512/error/unknownVersionID";

    /// <summary>The error code <c>unknownMode</c> (clause 5.3.5) — the <c>Mode</c> element named a deletion mode the enumeration of clause 5.4.2 does not state.</summary>
    public static string UnknownDeletionMode { get; } = "http://uri.etsi.org/19512/error/unknownMode";

    /// <summary>The error code <c>unknownDeltaPOCType</c> (clause 5.3.6).</summary>
    public static string UnknownDeltaContainerType { get; } = "http://uri.etsi.org/19512/error/unknownDeltaPOCType";

    /// <summary>The error code <c>DeltaPOCInternalProblem</c> (clause 5.3.6) — the second of the two codes whose last segment begins with capitals.</summary>
    public static string DeltaContainerInternalProblem { get; } = "http://uri.etsi.org/19512/error/DeltaPOCInternalProblem";

    /// <summary>The warning code <c>lowSpace</c> (clauses 5.3.3, 5.3.6) — the call succeeded and the service is running out of storage.</summary>
    public static string LowSpace { get; } = "http://uri.etsi.org/19512/warning/lowSpace";

    /// <summary>
    /// The warning code <c>requestOnlyPartlySuccessful</c> (clause 5.3.4) — part of what was asked for was
    /// returned, and clause 5.3.4.2.1 recommends that the service put the details in the <c>ResultMessage</c>
    /// component.
    /// </summary>
    public static string RequestOnlyPartlySuccessful { get; } = "http://uri.etsi.org/19512/warning/requestOnlyPartlySuccessful";


    /// <summary>Determines whether a value is one of the fifteen error codes this document states.</summary>
    /// <param name="resultMinor">The <c>Result/ResultMinor</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is an error code.</returns>
    public static bool IsErrorCode(string? resultMinor) => OutcomeFromResultMinor(resultMinor) is not null;


    /// <summary>Determines whether a value is one of the two warning codes this document states.</summary>
    /// <param name="resultMinor">The <c>Result/ResultMinor</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is a warning code.</returns>
    /// <remarks>
    /// A warning accompanies a call that succeeded, so a response carrying one is not a failed operation: the
    /// outcome stays <see cref="PreservationOperationOutcome.Succeeded"/> and the code rides in the response's own
    /// <see cref="PreservationResult.ResultMinor"/>.
    /// </remarks>
    public static bool IsWarningCode(string? resultMinor) =>
        string.Equals(resultMinor, LowSpace, StringComparison.Ordinal)
        || string.Equals(resultMinor, RequestOnlyPartlySuccessful, StringComparison.Ordinal);


    /// <summary>Determines whether a value is any of the seventeen codes this document states.</summary>
    /// <param name="resultMinor">The <c>Result/ResultMinor</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is an error or a warning code.</returns>
    public static bool IsResultMinor(string? resultMinor) => IsErrorCode(resultMinor) || IsWarningCode(resultMinor);


    /// <summary>
    /// Determines whether a code appears in the list the named operation's own clause gives for its response.
    /// </summary>
    /// <param name="operationName">The operation's name, one of <see cref="PreservationWellKnown.IsOperationName"/>'s values.</param>
    /// <param name="resultMinor">The <c>Result/ResultMinor</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the operation's clause enumerates the code.</returns>
    /// <remarks>
    /// <para>
    /// The lists are transcribed from clauses 5.3.2.2.1, 5.3.3.2.1, 5.3.4.2.1, 5.3.5.2, 5.3.6.2.1, 5.3.7.2.1,
    /// 5.3.8.2.1 and 5.3.9.2.1. The last of those introduces its list with the words "within
    /// <c>RetrieveTraceResponse</c>" although it sits inside the <c>Search</c> clause and follows the
    /// <c>RetrieveTrace</c> clause's own identical list — a copy-paste residue. It is read here as
    /// <c>Search</c>'s own list, because a clause states the codes of the operation it defines.
    /// </para>
    /// <para>
    /// An operation name this document does not state answers <see langword="false"/> for every code: a caller
    /// asking about an operation that does not exist has asked a question with no true answer.
    /// </para>
    /// </remarks>
    public static bool IsResultMinorStatedForOperation(string? operationName, string? resultMinor)
    {
        if(resultMinor is null)
        {
            return false;
        }

        bool isCommon = string.Equals(resultMinor, NoPermission, StringComparison.Ordinal)
            || string.Equals(resultMinor, InternalError, StringComparison.Ordinal)
            || string.Equals(resultMinor, ParameterError, StringComparison.Ordinal)
            || string.Equals(resultMinor, NotSupported, StringComparison.Ordinal);

        return operationName switch
        {
            _ when Named(operationName, PreservationWellKnown.RetrieveInfoOperation) => isCommon,
            _ when Named(operationName, PreservationWellKnown.PreservePreservationObjectOperation) =>
                isCommon || IsAnyOf(resultMinor, TransferError, NoSpaceError, UnknownPreservationObjectFormat, PreservationObjectFormatError, ExternalServiceUnavailable, LowSpace),
            _ when Named(operationName, PreservationWellKnown.RetrievePreservationObjectOperation) =>
                isCommon || IsAnyOf(resultMinor, UnknownPreservationObjectFormat, UnknownEvidenceFormat, UnknownPreservationObjectIdentifier, UnknownVersionIdentifier, RequestOnlyPartlySuccessful),
            _ when Named(operationName, PreservationWellKnown.DeletePreservationObjectOperation) =>
                isCommon || IsAnyOf(resultMinor, UnknownPreservationObjectIdentifier, UnknownDeletionMode),
            _ when Named(operationName, PreservationWellKnown.UpdatePreservationObjectContainerOperation) =>
                isCommon || IsAnyOf(resultMinor, TransferError, NoSpaceError, UnknownPreservationObjectIdentifier, UnknownDeltaContainerType, DeltaContainerInternalProblem, LowSpace),
            _ when Named(operationName, PreservationWellKnown.RetrieveTraceOperation) =>
                isCommon || IsAnyOf(resultMinor, UnknownPreservationObjectIdentifier),
            _ when Named(operationName, PreservationWellKnown.ValidateEvidenceOperation) => isCommon,
            _ when Named(operationName, PreservationWellKnown.SearchOperation) => isCommon,
            _ => false
        };

        //Compares an operation name as an exact character sequence, the way every other value of this vocabulary
        //is compared.
        static bool Named(string? candidate, string operationName) =>
            string.Equals(candidate, operationName, StringComparison.Ordinal);

        //Compares a code against the operation-specific codes its clause adds to the four common ones.
        static bool IsAnyOf(string resultMinor, params string[] codes)
        {
            foreach(string code in codes)
            {
                if(string.Equals(resultMinor, code, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>States the error code an outcome is reported as in a response's <c>Result/ResultMinor</c>.</summary>
    /// <param name="outcome">The outcome a seam answered with.</param>
    /// <returns>
    /// The code, or <see langword="null"/> for <see cref="PreservationOperationOutcome.Succeeded"/> and
    /// <see cref="PreservationOperationOutcome.NotEvaluated"/>, neither of which this document gives a minor code.
    /// </returns>
    /// <remarks>
    /// A successful call carrying a warning states that warning in the same component; the warning is a property
    /// of the response rather than of the outcome, which is why no outcome maps to one.
    /// </remarks>
    public static string? ResultMinorFromOutcome(PreservationOperationOutcome outcome) => outcome switch
    {
        PreservationOperationOutcome.NoPermission => NoPermission,
        PreservationOperationOutcome.InternalError => InternalError,
        PreservationOperationOutcome.ParameterError => ParameterError,
        PreservationOperationOutcome.NotSupported => NotSupported,
        PreservationOperationOutcome.TransferError => TransferError,
        PreservationOperationOutcome.NoSpaceError => NoSpaceError,
        PreservationOperationOutcome.UnknownPreservationObjectFormat => UnknownPreservationObjectFormat,
        PreservationOperationOutcome.PreservationObjectFormatError => PreservationObjectFormatError,
        PreservationOperationOutcome.ExternalServiceUnavailable => ExternalServiceUnavailable,
        PreservationOperationOutcome.UnknownEvidenceFormat => UnknownEvidenceFormat,
        PreservationOperationOutcome.UnknownPreservationObjectIdentifier => UnknownPreservationObjectIdentifier,
        PreservationOperationOutcome.UnknownVersionIdentifier => UnknownVersionIdentifier,
        PreservationOperationOutcome.UnknownDeletionMode => UnknownDeletionMode,
        PreservationOperationOutcome.UnknownDeltaContainerType => UnknownDeltaContainerType,
        PreservationOperationOutcome.DeltaContainerInternalProblem => DeltaContainerInternalProblem,
        _ => null
    };


    /// <summary>Reads an error code back into the outcome it reports.</summary>
    /// <param name="resultMinor">The <c>Result/ResultMinor</c> value, or <see langword="null"/>.</param>
    /// <returns>
    /// The outcome, or <see langword="null"/> when the value is not one of the fifteen error codes — which
    /// includes both warning codes and anything this document does not state.
    /// </returns>
    /// <remarks>
    /// This never answers <see cref="PreservationOperationOutcome.Succeeded"/>: a minor code cannot establish that
    /// a call succeeded, and reading an unrecognised code as success is exactly the failure a fail-closed reading
    /// exists to prevent.
    /// </remarks>
    public static PreservationOperationOutcome? OutcomeFromResultMinor(string? resultMinor) => resultMinor switch
    {
        null => null,
        _ when string.Equals(resultMinor, NoPermission, StringComparison.Ordinal) => PreservationOperationOutcome.NoPermission,
        _ when string.Equals(resultMinor, InternalError, StringComparison.Ordinal) => PreservationOperationOutcome.InternalError,
        _ when string.Equals(resultMinor, ParameterError, StringComparison.Ordinal) => PreservationOperationOutcome.ParameterError,
        _ when string.Equals(resultMinor, NotSupported, StringComparison.Ordinal) => PreservationOperationOutcome.NotSupported,
        _ when string.Equals(resultMinor, TransferError, StringComparison.Ordinal) => PreservationOperationOutcome.TransferError,
        _ when string.Equals(resultMinor, NoSpaceError, StringComparison.Ordinal) => PreservationOperationOutcome.NoSpaceError,
        _ when string.Equals(resultMinor, UnknownPreservationObjectFormat, StringComparison.Ordinal) => PreservationOperationOutcome.UnknownPreservationObjectFormat,
        _ when string.Equals(resultMinor, PreservationObjectFormatError, StringComparison.Ordinal) => PreservationOperationOutcome.PreservationObjectFormatError,
        _ when string.Equals(resultMinor, ExternalServiceUnavailable, StringComparison.Ordinal) => PreservationOperationOutcome.ExternalServiceUnavailable,
        _ when string.Equals(resultMinor, UnknownEvidenceFormat, StringComparison.Ordinal) => PreservationOperationOutcome.UnknownEvidenceFormat,
        _ when string.Equals(resultMinor, UnknownPreservationObjectIdentifier, StringComparison.Ordinal) => PreservationOperationOutcome.UnknownPreservationObjectIdentifier,
        _ when string.Equals(resultMinor, UnknownVersionIdentifier, StringComparison.Ordinal) => PreservationOperationOutcome.UnknownVersionIdentifier,
        _ when string.Equals(resultMinor, UnknownDeletionMode, StringComparison.Ordinal) => PreservationOperationOutcome.UnknownDeletionMode,
        _ when string.Equals(resultMinor, UnknownDeltaContainerType, StringComparison.Ordinal) => PreservationOperationOutcome.UnknownDeltaContainerType,
        _ when string.Equals(resultMinor, DeltaContainerInternalProblem, StringComparison.Ordinal) => PreservationOperationOutcome.DeltaContainerInternalProblem,
        _ => null
    };
}
