using System;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// A labeled byte range within a buffer.
/// </summary>
/// <remarks>
/// <para>
/// Slices enable debugger inspection and visualization of how TPM request
/// and response buffers are structured. Each slice identifies a named region
/// (header, handles, auth, parameters) with its offset and length.
/// </para>
/// <para>
/// <b>Usage:</b>
/// </para>
/// <code>
/// var slice = new TpmSlice("response.parameters", offset: 14, length: 128);
/// ReadOnlySpan&lt;byte&gt; data = responseBuffer.Span.Slice(slice.Offset, slice.Length);
/// </code>
/// <para>
/// <b>Standard slice names:</b>
/// </para>
/// <list type="bullet">
///   <item><description><c>request.header</c></description></item>
///   <item><description><c>request.handles</c></description></item>
///   <item><description><c>request.auth</c></description></item>
///   <item><description><c>request.parameters</c></description></item>
///   <item><description><c>response.header</c></description></item>
///   <item><description><c>response.handles</c></description></item>
///   <item><description><c>response.auth</c></description></item>
///   <item><description><c>response.parameters</c></description></item>
/// </list>
/// </remarks>
/// <param name="Name">The slice name.</param>
/// <param name="Offset">The byte offset into the buffer.</param>
/// <param name="Length">The length in bytes.</param>
public readonly record struct TpmSlice(string Name, int Offset, int Length)
{
    /// <summary>
    /// Gets a value indicating whether this slice is empty.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Gets the end offset (exclusive).
    /// </summary>
    public int End => Offset + Length;

    /// <summary>
    /// Extracts this slice from a buffer.
    /// </summary>
    /// <param name="buffer">The source buffer.</param>
    /// <returns>The slice data.</returns>
    public ReadOnlySpan<byte> SliceFrom(ReadOnlySpan<byte> buffer) => buffer.Slice(Offset, Length);

    /// <summary>
    /// Extracts this slice from a buffer (alias for SliceFrom).
    /// </summary>
    /// <param name="buffer">The source buffer.</param>
    /// <returns>The slice data.</returns>
    public ReadOnlySpan<byte> AsSpan(ReadOnlySpan<byte> buffer) => buffer.Slice(Offset, Length);

    /// <summary>
    /// Extracts this slice from a byte array.
    /// </summary>
    /// <param name="buffer">The source buffer.</param>
    /// <returns>The slice data.</returns>
    public ReadOnlySpan<byte> AsSpan(byte[] buffer) => buffer.AsSpan(Offset, Length);

    /// <summary>
    /// Extracts this slice from a memory buffer.
    /// </summary>
    /// <param name="buffer">The source buffer.</param>
    /// <returns>The slice data.</returns>
    public ReadOnlyMemory<byte> SliceFrom(ReadOnlyMemory<byte> buffer) => buffer.Slice(Offset, Length);

    /// <inheritdoc/>
    public override string ToString() => $"{Name}[{Offset}..{End}] ({Length} bytes)";
}