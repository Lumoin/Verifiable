using System;
using System.Collections.Generic;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Result of parsing a TPM structure from bytes.
/// </summary>
/// <typeparam name="T">The type that was parsed.</typeparam>
public readonly struct TpmParseResult<T>: IEquatable<TpmParseResult<T>>
{
    /// <summary>
    /// Gets the parsed value.
    /// </summary>
    public T Value { get; }

    /// <summary>
    /// Gets the number of bytes consumed during parsing.
    /// </summary>
    public int BytesConsumed { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="TpmParseResult{T}"/> struct.
    /// </summary>
    /// <param name="value">The parsed value.</param>
    /// <param name="bytesConsumed">The number of bytes consumed.</param>
    public TpmParseResult(T value, int bytesConsumed)
    {
        Value = value;
        BytesConsumed = bytesConsumed;
    }

    /// <summary>
    /// Deconstructs the result into value and bytes consumed.
    /// </summary>
    /// <param name="value">The parsed value.</param>
    /// <param name="bytesConsumed">The number of bytes consumed.</param>
    public void Deconstruct(out T value, out int bytesConsumed)
    {
        value = Value;
        bytesConsumed = BytesConsumed;
    }

    /// <inheritdoc/>
    public bool Equals(TpmParseResult<T> other)
    {
        return BytesConsumed == other.BytesConsumed &&
               EqualityComparer<T>.Default.Equals(Value, other.Value);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is TpmParseResult<T> other && Equals(other);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Value, BytesConsumed);
    }

    /// <summary>
    /// Determines whether two parse results are equal.
    /// </summary>
    public static bool operator ==(TpmParseResult<T> left, TpmParseResult<T> right)
    {
        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two parse results are not equal.
    /// </summary>
    public static bool operator !=(TpmParseResult<T> left, TpmParseResult<T> right)
    {
        return !left.Equals(right);
    }
}