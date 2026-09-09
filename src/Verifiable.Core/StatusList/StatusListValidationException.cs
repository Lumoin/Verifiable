using System;

namespace Verifiable.Core.StatusList;

/// <summary>
/// Exception thrown when Status List Token validation fails — the token's subject mismatches the
/// credential's reference, the list has expired, or the index is out of bounds. Not sealed:
/// <see cref="StatusListResolutionException"/> derives from it so a resolver's own failure to obtain
/// the Status List Token in the first place flows through the same "no statement about the status can
/// be made" classification callers already catch this type for.
/// </summary>
public class StatusListValidationException: Exception
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
    /// <param name="innerException">The underlying exception, or <see langword="null"/> when there is none.</param>
    public StatusListValidationException(string message, Exception? innerException): base(message, innerException) { }
}
