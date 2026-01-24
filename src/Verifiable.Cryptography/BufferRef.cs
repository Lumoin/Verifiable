namespace Verifiable.Cryptography;

/// <summary>
/// A read-only view into owned memory buffer.
/// </summary>
/// <remarks>
/// <para>
/// This ref struct provides a lightweight, stack-only view into memory owned by
/// <see cref="SensitiveMemory"/>. It does not transfer or affect ownership - the
/// caller remains responsible for the lifetime of the underlying memory.
/// </para>
/// <para>
/// <strong>Ownership semantics:</strong>
/// </para>
/// <para>
/// Creating a <see cref="BufferRef"/> does not transfer ownership. The underlying
/// memory must remain valid for the lifetime of this ref. Since this is a ref struct,
/// it cannot escape the stack frame, which helps prevent use-after-free errors.
/// </para>
/// <para>
/// <strong>Usage pattern:</strong>
/// </para>
/// <code>
/// //Owner holds the data.
/// using Tpm2bNonce nonce = Tpm2bNonce.CreateRandom(32, pool);
///
/// //Create a view for serialization.
/// var bufferRef = new BufferRef(nonce);
///
/// //Use the view - tag metadata is preserved.
/// Console.WriteLine(bufferRef.Tag);
/// writer.Write(bufferRef.AsSpan());
///
/// //bufferRef goes out of scope, nonce still owns the data.
/// </code>
/// </remarks>
/// <seealso cref="SensitiveMemory"/>
/// <seealso cref="Tag"/>
public readonly ref struct BufferRef
{
    /// <summary>
    /// Gets the content of the data as a read-only span of bytes.
    /// </summary>
    /// <remarks>This property provides access to the underlying byte data without allowing modifications. It
    /// is useful for scenarios where data integrity is critical and modifications should be prevented.</remarks>
    private ReadOnlySpan<byte> Data { get; }

    /// <summary>
    /// Gets the tag describing the buffer contents.
    /// </summary>
    public Tag Tag { get; }

    /// <summary>
    /// Creates a view into sensitive memory.
    /// </summary>
    /// <param name="memory">The sensitive memory to view. Ownership is not transferred.</param>
    /// <remarks>
    /// The <paramref name="memory"/> must remain valid and undisposed for the
    /// lifetime of this <see cref="BufferRef"/>.
    /// </remarks>
    public BufferRef(SensitiveMemory memory)
    {
        ArgumentNullException.ThrowIfNull(memory);

        Data = memory.AsReadOnlySpan();
        Tag = memory.Tag;
    }

    /// <summary>
    /// Gets the underlying data as a read-only span.
    /// </summary>
    /// <returns>A read-only span over the buffer data.</returns>
    public ReadOnlySpan<byte> AsSpan() => Data;

    /// <summary>
    /// Gets the length of the buffer in bytes.
    /// </summary>
    public int Length => Data.Length;

    /// <summary>
    /// Gets a value indicating whether this buffer is empty.
    /// </summary>
    public bool IsEmpty => Data.IsEmpty;
}