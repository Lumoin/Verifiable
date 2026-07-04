namespace Verifiable.Keri;

/// <summary>
/// The exception thrown when a KERI key event log violates a key-state invariant: an inception that is not the
/// first event, an event whose sequence number does not follow the current state, an event for the wrong
/// identifier, or any other break in the rules that fold key events into key state.
/// </summary>
public sealed class KeriException: Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="KeriException"/> class.
    /// </summary>
    public KeriException()
    {
    }


    /// <summary>
    /// Initializes a new instance of the <see cref="KeriException"/> class with a message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public KeriException(string message): base(message)
    {
    }


    /// <summary>
    /// Initializes a new instance of the <see cref="KeriException"/> class with a message and an inner exception.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="innerException">The exception that is the cause of this exception.</param>
    public KeriException(string message, Exception innerException): base(message, innerException)
    {
    }
}
