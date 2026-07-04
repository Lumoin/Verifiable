using System;

namespace Verifiable.Acdc;

/// <summary>
/// The exception raised when an ACDC message violates a structural rule the ACDC specification fixes: a missing or
/// unexpected top-level field, fields out of their canonical order, the mutually exclusive attribute and aggregate
/// sections both present, an unmodeled message type, or a SAID that does not verify against its block.
/// </summary>
public sealed class AcdcException: Exception
{
    /// <summary>
    /// Creates an <see cref="AcdcException"/>.
    /// </summary>
    public AcdcException()
    {
    }


    /// <summary>
    /// Creates an <see cref="AcdcException"/> with a message.
    /// </summary>
    /// <param name="message">The message describing the violation.</param>
    public AcdcException(string message): base(message)
    {
    }


    /// <summary>
    /// Creates an <see cref="AcdcException"/> with a message and an inner exception.
    /// </summary>
    /// <param name="message">The message describing the violation.</param>
    /// <param name="innerException">The underlying cause.</param>
    public AcdcException(string message, Exception innerException): base(message, innerException)
    {
    }
}
