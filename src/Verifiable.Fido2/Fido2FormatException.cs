namespace Verifiable.Fido2;

/// <summary>
/// The exception thrown when FIDO2/WebAuthn wire input is malformed: a truncated
/// authenticator data structure, an out-of-range length field, trailing bytes where
/// none are permitted, or any other violation of the encoding rules this library
/// enforces while parsing.
/// </summary>
/// <remarks>
/// <see cref="FailureKind"/> discriminates the failure at the granularity CTAP 2.3 section 8.2's
/// status-code table distinguishes (<see cref="Fido2FormatFailureKind"/>). A <c>Verifiable.Cbor</c>
/// CTAP request reader sets it explicitly at each throw site; a constructor that omits it defaults to
/// <see cref="Fido2FormatFailureKind.MalformedCbor"/>, the correct classification for every non-CTAP
/// caller of this type (attestation object/statement parsing, response decoding) that has no CTAP
/// command-boundary status code to choose between.
/// </remarks>
public sealed class Fido2FormatException: Exception
{
    /// <summary>Gets the failure classification a CTAP command decode boundary maps to a status byte.</summary>
    public Fido2FormatFailureKind FailureKind { get; }


    /// <summary>
    /// Initializes a new instance of the <see cref="Fido2FormatException"/> class, classified
    /// <see cref="Fido2FormatFailureKind.MalformedCbor"/>.
    /// </summary>
    public Fido2FormatException(): this(Fido2FormatFailureKind.MalformedCbor)
    {
    }


    /// <summary>
    /// Initializes a new instance of the <see cref="Fido2FormatException"/> class with an explicit
    /// <paramref name="failureKind"/>.
    /// </summary>
    /// <param name="failureKind">The failure classification.</param>
    public Fido2FormatException(Fido2FormatFailureKind failureKind)
    {
        FailureKind = failureKind;
    }


    /// <summary>
    /// Initializes a new instance of the <see cref="Fido2FormatException"/> class with a message,
    /// classified <see cref="Fido2FormatFailureKind.MalformedCbor"/>.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public Fido2FormatException(string message): this(Fido2FormatFailureKind.MalformedCbor, message)
    {
    }


    /// <summary>
    /// Initializes a new instance of the <see cref="Fido2FormatException"/> class with an explicit
    /// <paramref name="failureKind"/> and a message.
    /// </summary>
    /// <param name="failureKind">The failure classification.</param>
    /// <param name="message">The message that describes the error.</param>
    public Fido2FormatException(Fido2FormatFailureKind failureKind, string message): base(message)
    {
        FailureKind = failureKind;
    }


    /// <summary>
    /// Initializes a new instance of the <see cref="Fido2FormatException"/> class with a message and an
    /// inner exception, classified <see cref="Fido2FormatFailureKind.MalformedCbor"/>.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="innerException">The exception that is the cause of this exception.</param>
    public Fido2FormatException(string message, Exception innerException): this(Fido2FormatFailureKind.MalformedCbor, message, innerException)
    {
    }


    /// <summary>
    /// Initializes a new instance of the <see cref="Fido2FormatException"/> class with an explicit
    /// <paramref name="failureKind"/>, a message, and an inner exception.
    /// </summary>
    /// <param name="failureKind">The failure classification.</param>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="innerException">The exception that is the cause of this exception.</param>
    public Fido2FormatException(Fido2FormatFailureKind failureKind, string message, Exception innerException): base(message, innerException)
    {
        FailureKind = failureKind;
    }
}
