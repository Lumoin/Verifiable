using System;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Interface for types that can be serialized to and parsed from TPM byte buffers.
/// </summary>
/// <typeparam name="TSelf">The implementing type.</typeparam>
public interface ITpmParseable<TSelf> where TSelf : ITpmParseable<TSelf>
{
    /// <summary>
    /// Parses an instance from a byte buffer.
    /// </summary>
    /// <param name="source">The source bytes.</param>
    /// <returns>The parsed value and number of bytes consumed.</returns>
    static abstract TpmParseResult<TSelf> Parse(ReadOnlySpan<byte> source);

    /// <summary>
    /// Gets the serialized size in bytes.
    /// </summary>
    int SerializedSize { get; }

    /// <summary>
    /// Writes the instance to a byte buffer.
    /// </summary>
    /// <param name="destination">The destination buffer.</param>
    void WriteTo(Span<byte> destination);
}
