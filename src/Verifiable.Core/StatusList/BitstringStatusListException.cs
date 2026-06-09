using System;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.StatusList;

/// <summary>
/// The processing-error categories defined by W3C Bitstring Status List §3.5 (plus the
/// <c>RANGE_ERROR</c> and <c>MALFORMED_VALUE_ERROR</c> raised by §3.1–§3.2). Each maps to a
/// type-URL fragment appended to <see cref="BitstringStatusListConstants.ErrorTypeUrlPrefix"/>.
/// </summary>
public enum BitstringStatusListErrorType
{
    /// <summary>Retrieval of the status list failed (<c>STATUS_RETRIEVAL_ERROR</c>).</summary>
    StatusRetrieval,

    /// <summary>Validation of the status entry failed, including proof or purpose mismatch (<c>STATUS_VERIFICATION_ERROR</c>).</summary>
    StatusVerification,

    /// <summary>The status list is shorter than the minimum required for herd privacy (<c>STATUS_LIST_LENGTH_ERROR</c>).</summary>
    StatusListLength,

    /// <summary>The requested index lies outside the bitstring (<c>RANGE_ERROR</c>).</summary>
    Range,

    /// <summary>A value does not comply with a <c>MUST</c> statement of the data model (<c>MALFORMED_VALUE_ERROR</c>).</summary>
    MalformedValue
}


/// <summary>
/// Thrown when W3C Bitstring Status List validation fails, carrying the specific
/// <see cref="BitstringStatusListErrorType"/> so callers can map it to an RFC 9457 problem detail.
/// </summary>
[SuppressMessage("Design", "CA1032:Implement standard exception constructors", Justification = "This exception always carries a BitstringStatusListErrorType; the parameterless and message-only constructors would violate that invariant.")]
public sealed class BitstringStatusListException: Exception
{
    /// <summary>
    /// Gets the category of the failure.
    /// </summary>
    public BitstringStatusListErrorType ErrorType { get; }

    /// <summary>
    /// Gets the specification error code (e.g. <c>STATUS_VERIFICATION_ERROR</c>).
    /// </summary>
    public string ErrorCode => ErrorType switch
    {
        BitstringStatusListErrorType.StatusRetrieval => "STATUS_RETRIEVAL_ERROR",
        BitstringStatusListErrorType.StatusVerification => "STATUS_VERIFICATION_ERROR",
        BitstringStatusListErrorType.StatusListLength => "STATUS_LIST_LENGTH_ERROR",
        BitstringStatusListErrorType.Range => "RANGE_ERROR",
        BitstringStatusListErrorType.MalformedValue => "MALFORMED_VALUE_ERROR",
        _ => "STATUS_VERIFICATION_ERROR"
    };

    /// <summary>
    /// Gets the full type URL for the error, suitable as the <c>type</c> of an RFC 9457 problem detail.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "RFC 9457 defines the problem-detail 'type' as a string URI serialized directly into JSON, not a dereferenced System.Uri.")]
    public string TypeUrl => BitstringStatusListConstants.ErrorTypeUrlPrefix + ErrorCode;

    /// <summary>
    /// Creates a new exception with the specified error category and message.
    /// </summary>
    /// <param name="errorType">The category of the failure.</param>
    /// <param name="message">A description of the failure.</param>
    public BitstringStatusListException(BitstringStatusListErrorType errorType, string message): base(message)
    {
        ErrorType = errorType;
    }

    /// <summary>
    /// Creates a new exception with the specified error category, message, and inner exception.
    /// </summary>
    /// <param name="errorType">The category of the failure.</param>
    /// <param name="message">A description of the failure.</param>
    /// <param name="innerException">The underlying exception.</param>
    public BitstringStatusListException(BitstringStatusListErrorType errorType, string message, Exception innerException): base(message, innerException)
    {
        ErrorType = errorType;
    }
}
