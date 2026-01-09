using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography;

#pragma warning disable RS0030 // Do not use banned APIs
/// <summary>
/// A tagged memory wrapper that associates metadata with a memory buffer without copying.
/// </summary>
/// <typeparam name="T">The element type of the memory.</typeparam>
/// <remarks>
/// <para>
/// <strong>Purpose</strong>
/// </para>
/// <para>
/// Many .NET libraries (such as <see cref="System.Text.Json.JsonSerializer"/>) allocate
/// arrays internally when serializing data. Rather than copying these allocations into
/// pooled memory (which adds CPU overhead), this wrapper provides a lightweight way to
/// associate metadata with the existing allocation via a <see cref="Tag"/>.
/// </para>
/// <para>
/// <strong>Why Not Copy to Pooled Memory?</strong>
/// </para>
/// <para>
/// While pooled memory can reduce GC pressure for long-lived allocations, copying
/// has costs:
/// </para>
/// <list type="bullet">
/// <item><description>CPU time for the copy operation itself.</description></item>
/// <item><description>Memory pressure during the copy (both buffers exist simultaneously).</description></item>
/// <item><description>Complexity of lifetime management for pooled memory.</description></item>
/// </list>
/// <para>
/// For short-lived buffers used in request/response patterns (like JWT signing),
/// wrapping the original allocation is often more efficient.
/// </para>
/// <para>
/// <strong>GC Considerations</strong>
/// </para>
/// <para>
/// By wrapping the original allocation directly, the underlying memory remains eligible
/// for garbage collection based on this wrapper's lifetime. When the <see cref="TaggedMemory{T}"/>
/// goes out of scope and no other references exist, the memory can be collected.
/// This is typically desirable for transient serialization buffers.
/// </para>
/// <para>
/// <strong>Distinction from SensitiveMemory</strong>
/// </para>
/// <para>
/// This type is distinct from <c>SensitiveMemory</c> hierarchy which is designed for
/// cryptographic key material and secrets requiring secure handling (zeroing on disposal,
/// pinning, etc.). <see cref="TaggedMemory{T}"/> is intended for general buffers where
/// the data is not secret but benefits from metadata tagging.
/// </para>
/// <para>
/// <strong>Usage</strong>
/// </para>
/// <code>
/// //Wrap serialized JSON with a tag.
/// byte[] json = JsonSerializer.SerializeToUtf8Bytes(credential);
/// var buffer = new TaggedMemory&lt;byte&gt;(json, BufferTags.JwtPayload);
///
/// //Access the memory and metadata.
/// ReadOnlySpan&lt;byte&gt; span = buffer.Span;
/// BufferKind kind = buffer.Tag.Get&lt;BufferKind&gt;();
/// </code>
/// </remarks>
/// <seealso cref="Tag"/>
/// <seealso cref="BufferKind"/>
/// <seealso cref="BufferTags"/>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
#pragma warning restore RS0030 // Do not use banned APIs
public readonly struct TaggedMemory<T>: IEquatable<TaggedMemory<T>>
{
    /// <summary>
    /// The underlying memory buffer.
    /// </summary>
    public ReadOnlyMemory<T> Memory { get; }

    /// <summary>
    /// Metadata describing the buffer contents.
    /// </summary>
    public Tag Tag { get; }


    /// <summary>
    /// Creates a new tagged memory from a <see cref="ReadOnlyMemory{T}"/>.
    /// </summary>
    /// <param name="memory">The memory buffer.</param>
    /// <param name="tag">Metadata describing the buffer.</param>
    public TaggedMemory(ReadOnlyMemory<T> memory, Tag tag)
    {
        Memory = memory;
        Tag = tag ?? throw new ArgumentNullException(nameof(tag));
    }


    /// <summary>
    /// Creates a new tagged memory from an array.
    /// </summary>
    /// <param name="array">The array to wrap.</param>
    /// <param name="tag">Metadata describing the buffer.</param>
    public TaggedMemory(T[] array, Tag tag)
    {
        ArgumentNullException.ThrowIfNull(array);
        Memory = array;
        Tag = tag ?? throw new ArgumentNullException(nameof(tag));
    }


    /// <summary>
    /// Gets a span over the memory buffer.
    /// </summary>
    public ReadOnlySpan<T> Span => Memory.Span;


    /// <summary>
    /// Gets the length of the memory buffer.
    /// </summary>
    public int Length => Memory.Length;


    /// <summary>
    /// Gets whether the memory buffer is empty.
    /// </summary>
    public bool IsEmpty => Memory.IsEmpty;


    /// <summary>
    /// An empty tagged memory with an empty tag.
    /// </summary>
    public static TaggedMemory<T> Empty { get; } = new(ReadOnlyMemory<T>.Empty, Tag.Empty);


    private string DebuggerDisplay
    {
        get
        {
            string tagInfo = Tag.TryGet<BufferKind>(out var kind)
                ? kind.ToString()
                : Tag.Data.Count > 0 ? "Tagged" : "Untagged";
            return $"TaggedMemory<{typeof(T).Name}>[{Length}] ({tagInfo})";
        }
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(TaggedMemory<T> other)
    {
        return Memory.Equals(other.Memory) && Tag.Equals(other.Tag);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj is TaggedMemory<T> other && Equals(other);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        return HashCode.Combine(Memory.GetHashCode(), Tag.GetHashCode());
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(TaggedMemory<T> left, TaggedMemory<T> right)
    {
        return left.Equals(right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(TaggedMemory<T> left, TaggedMemory<T> right)
    {
        return !left.Equals(right);
    }
}