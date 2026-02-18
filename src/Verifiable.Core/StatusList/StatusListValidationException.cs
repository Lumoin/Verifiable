using System;

namespace Verifiable.Core.StatusList;

/// <summary>
/// Exception thrown when Status List Token validation fails.
/// </summary>
public sealed class StatusListValidationException: Exception
{
    /// <summary>
    /// Creates a new validation exception.
    /// </summary>
    public StatusListValidationException() { }

    /// <summary>
    /// Creates a new validation exception with the specified message.
    /// </summary>
    /// <param name="message">A description of the validation failure.</param>
    public StatusListValidationException(string message) : base(message) { }

    /// <summary>
    /// Creates a new validation exception with the specified message and inner exception.
    /// </summary>
    /// <param name="message">A description of the validation failure.</param>
    /// <param name="innerException">The underlying exception.</param>
    public StatusListValidationException(string message, Exception innerException): base(message, innerException) { }
}
