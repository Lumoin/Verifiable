namespace Verifiable.Cesr;

/// <summary>
/// The exception thrown when CESR-encoded material is malformed: an unknown code, a wrong size, non-zero
/// pad or lead bits, or any other violation of the encoding scheme.
/// </summary>
public sealed class CesrFormatException: Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CesrFormatException"/> class.
    /// </summary>
    public CesrFormatException()
    {
    }


    /// <summary>
    /// Initializes a new instance of the <see cref="CesrFormatException"/> class with a message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public CesrFormatException(string message): base(message)
    {
    }


    /// <summary>
    /// Initializes a new instance of the <see cref="CesrFormatException"/> class with a message and an
    /// inner exception.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="innerException">The exception that is the cause of this exception.</param>
    public CesrFormatException(string message, Exception innerException): base(message, innerException)
    {
    }
}
