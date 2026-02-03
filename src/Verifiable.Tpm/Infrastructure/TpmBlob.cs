using System;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// A zero-copy reference to a byte range within a backing buffer.
/// </summary>
/// <remarks>
/// <para>
/// <c>TpmBlob</c> stores only offset and length, not the bytes themselves.
/// The actual bytes are accessed by providing the backing buffer (typically
/// <see cref="TpmParseContext.ResponseBytes"/>).
/// </para>
/// <para>
/// <b>Lifetime rule:</b> The backing buffer must remain valid for as long as
/// the blob is used. In the executor design, <see cref="TpmParseContext"/>
/// retains the response buffer, so wire types containing blobs remain valid
/// for the lifetime of the context.
/// </para>
/// <para>
/// <b>Usage:</b>
/// </para>
/// <code>
/// Tpm2bDigest digest = context.Wire.OfType&lt;Tpm2bDigest&gt;().First();
/// ReadOnlySpan&lt;byte&gt; bytes = digest.Buffer.AsSpan(context.ResponseBytes.Span);
/// </code>
/// </remarks>
/// <param name="Offset">The byte offset into the backing buffer.</param>
/// <param name="Length">The length in bytes.</param>
public readonly record struct TpmBlob(int Offset, int Length)
{
    /// <summary>
    /// An empty blob.
    /// </summary>
    public static TpmBlob Empty { get; } = new(0, 0);

    /// <summary>
    /// Gets a value indicating whether this blob is empty.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Extracts this blob's bytes from a backing buffer.
    /// </summary>
    /// <param name="backing">The backing buffer.</param>
    /// <returns>The blob's bytes.</returns>
    public ReadOnlySpan<byte> AsSpan(ReadOnlySpan<byte> backing)
    {
        return backing.Slice(Offset, Length);
    }

    /// <summary>
    /// Extracts this blob's bytes from a backing memory buffer.
    /// </summary>
    /// <param name="backing">The backing buffer.</param>
    /// <returns>The blob's bytes.</returns>
    public ReadOnlyMemory<byte> AsMemory(ReadOnlyMemory<byte> backing)
    {
        return backing.Slice(Offset, Length);
    }

    /// <inheritdoc/>
    public override string ToString() => $"TpmBlob({Offset}, {Length})";
}