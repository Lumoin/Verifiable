using System;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Result of parsing a TPM command buffer.
/// </summary>
public readonly struct TpmParsedCommand: IEquatable<TpmParsedCommand>
{
    /// <summary>
    /// Gets the command header.
    /// </summary>
    public TpmHeader Header { get; }

    /// <summary>
    /// Gets the parsed input parameters, or <c>null</c> if parsing failed.
    /// </summary>
    public object? Input { get; }

    /// <summary>
    /// Gets the total number of bytes consumed.
    /// </summary>
    public int TotalBytesConsumed { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="TpmParsedCommand"/> struct.
    /// </summary>
    /// <param name="header">The command header.</param>
    /// <param name="input">The parsed input.</param>
    /// <param name="totalBytesConsumed">The total bytes consumed.</param>
    public TpmParsedCommand(TpmHeader header, object? input, int totalBytesConsumed)
    {
        Header = header;
        Input = input;
        TotalBytesConsumed = totalBytesConsumed;
    }

    /// <summary>
    /// Gets the input as a specific type.
    /// </summary>
    /// <typeparam name="T">The expected input type.</typeparam>
    /// <returns>The typed input.</returns>
    public T GetInput<T>() where T : ITpmCommandInput<T> => (T)Input!;

    /// <summary>
    /// Tries to get the input as a specific type.
    /// </summary>
    /// <typeparam name="T">The expected input type.</typeparam>
    /// <param name="input">The typed input if successful.</param>
    /// <returns><c>true</c> if the input is of the specified type; otherwise, <c>false</c>.</returns>
    public bool TryGetInput<T>(out T? input) where T : ITpmCommandInput<T>
    {
        if(Input is T typedInput)
        {
            input = typedInput;
            return true;
        }

        input = default;
        return false;
    }

    /// <inheritdoc/>
    public bool Equals(TpmParsedCommand other)
    {
        return Header.Equals(other.Header) &&
               Equals(Input, other.Input) &&
               TotalBytesConsumed == other.TotalBytesConsumed;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is TpmParsedCommand other && Equals(other);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Header, Input, TotalBytesConsumed);
    }

    /// <summary>
    /// Determines whether two parsed commands are equal.
    /// </summary>
    public static bool operator ==(TpmParsedCommand left, TpmParsedCommand right)
    {
        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two parsed commands are not equal.
    /// </summary>
    public static bool operator !=(TpmParsedCommand left, TpmParsedCommand right)
    {
        return !left.Equals(right);
    }
}