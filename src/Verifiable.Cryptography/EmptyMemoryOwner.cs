using System.Buffers;

namespace Verifiable.Cryptography;

/// <summary>
/// A singleton memory owner representing an empty buffer.
/// </summary>
/// <remarks>
/// <para>
/// This type provides a shared, no-allocation solution for representing zero-length
/// buffers in APIs that require <see cref="IMemoryOwner{T}"/>. It is particularly
/// useful when:
/// </para>
/// <list type="bullet">
///   <item><description>Parsing wire formats that allow zero-length fields.</description></item>
///   <item><description>Representing "empty" or "null" values in buffer-based types.</description></item>
///   <item><description>Avoiding memory pool allocations for trivially empty data.</description></item>
/// </list>
/// <para>
/// <strong>Thread safety:</strong> This type is immutable and thread-safe. The shared
/// <see cref="Instance"/> can be used concurrently from any thread.
/// </para>
/// <para>
/// <strong>Disposal:</strong> The <see cref="Dispose"/> method is a no-op. It is safe
/// to call multiple times or not at all. This allows the singleton to be shared across
/// multiple owners without lifetime concerns.
/// </para>
/// <para>
/// <strong>Memory pool compatibility:</strong> Some memory pools (such as
/// <see cref="SensitiveMemoryPool{T}"/>) do not support zero-size rentals. This type
/// provides a compatible alternative for empty buffers without requiring special-case
/// handling in the pool implementation.
/// </para>
/// <para>
/// <strong>Usage example:</strong>
/// </para>
/// <code>
/// public static MyBufferType CreateEmpty()
/// {
///     //Use the shared empty owner instead of allocating from pool.
///     return new MyBufferType(EmptyMemoryOwner.Instance);
/// }
///
/// public static MyBufferType Parse(ref Reader reader, MemoryPool&lt;byte&gt; pool)
/// {
///     int length = reader.ReadLength();
///     
///     if(length == 0)
///     {
///         return new MyBufferType(EmptyMemoryOwner.Instance);
///     }
///     
///     IMemoryOwner&lt;byte&gt; storage = pool.Rent(length);
///     //... copy data ...
///     return new MyBufferType(storage);
/// }
/// </code>
/// </remarks>
public sealed class EmptyMemoryOwner: IMemoryOwner<byte>
{
    /// <summary>
    /// Gets the shared singleton instance.
    /// </summary>
    /// <remarks>
    /// This instance is immutable and can be safely shared across all consumers
    /// requiring an empty <see cref="IMemoryOwner{T}"/>.
    /// </remarks>
    public static EmptyMemoryOwner Instance { get; } = new();

    /// <summary>
    /// Prevents external instantiation. Use <see cref="Instance"/> instead.
    /// </summary>
    private EmptyMemoryOwner()
    {
    }

    /// <summary>
    /// Gets an empty memory region.
    /// </summary>
    /// <value>Always returns <see cref="Memory{T}.Empty"/>.</value>
    public Memory<byte> Memory => Memory<byte>.Empty;

    /// <summary>
    /// No-op disposal. Safe to call multiple times.
    /// </summary>
    /// <remarks>
    /// Since this is a shared singleton with no resources to release,
    /// disposal has no effect. This allows the instance to be used in
    /// <c>using</c> statements without concern for premature disposal
    /// affecting other consumers.
    /// </remarks>
    public void Dispose()
    {
        //Intentionally empty: singleton with no resources.
    }
}