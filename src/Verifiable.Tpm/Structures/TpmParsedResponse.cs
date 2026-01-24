using System;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Result of parsing a TPM response buffer.
/// </summary>
public readonly struct TpmParsedResponse: IEquatable<TpmParsedResponse>
{
    /// <summary>
    /// Gets the response header.
    /// </summary>
    public TpmHeader Header { get; }

    /// <summary>
    /// Gets the parsed output, or <c>null</c> if parsing failed or response was an error.
    /// </summary>
    public object? Output { get; }

    /// <summary>
    /// Gets the total number of bytes consumed.
    /// </summary>
    public int TotalBytesConsumed { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="TpmParsedResponse"/> struct.
    /// </summary>
    /// <param name="header">The response header.</param>
    /// <param name="output">The parsed output.</param>
    /// <param name="totalBytesConsumed">The total bytes consumed.</param>
    public TpmParsedResponse(TpmHeader header, object? output, int totalBytesConsumed)
    {
        Header = header;
        Output = output;
        TotalBytesConsumed = totalBytesConsumed;
    }

    /// <summary>
    /// Gets a value indicating whether the response indicates success.
    /// </summary>
    public bool IsSuccess => Header.IsSuccess;

    /// <summary>
    /// Gets the response code.
    /// </summary>
    public TpmRc ResponseCode => Header.ResponseCode;

    /// <summary>
    /// Gets the output as a specific type.
    /// </summary>
    /// <typeparam name="T">The expected output type.</typeparam>
    /// <returns>The typed output.</returns>
    public T GetOutput<T>() where T : ITpmCommandOutput<T> => (T)Output!;

    /// <summary>
    /// Tries to get the output as a specific type.
    /// </summary>
    /// <typeparam name="T">The expected output type.</typeparam>
    /// <param name="output">The typed output if successful.</param>
    /// <returns><c>true</c> if the output is of the specified type; otherwise, <c>false</c>.</returns>
    public bool TryGetOutput<T>(out T? output) where T : ITpmCommandOutput<T>
    {
        if(Output is T typedOutput)
        {
            output = typedOutput;
            return true;
        }

        output = default;
        return false;
    }

    /// <inheritdoc/>
    public bool Equals(TpmParsedResponse other)
    {
        return Header.Equals(other.Header) &&
               Equals(Output, other.Output) &&
               TotalBytesConsumed == other.TotalBytesConsumed;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is TpmParsedResponse other && Equals(other);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Header, Output, TotalBytesConsumed);
    }

    /// <summary>
    /// Determines whether two parsed responses are equal.
    /// </summary>
    public static bool operator ==(TpmParsedResponse left, TpmParsedResponse right)
    {
        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two parsed responses are not equal.
    /// </summary>
    public static bool operator !=(TpmParsedResponse left, TpmParsedResponse right)
    {
        return !left.Equals(right);
    }
}