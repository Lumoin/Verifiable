using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography;

/// <summary>
/// Identifies the kind of content stored in a buffer.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Purpose</strong>
/// </para>
/// <para>
/// When working with serialized data, the raw bytes are opaque without context.
/// <see cref="BufferKind"/> provides a lightweight discriminator to identify
/// what the buffer contains (JWT header, JSON payload, CBOR data, etc.).
/// </para>
/// <para>
/// <strong>Why This Exists: Library Allocation Patterns</strong>
/// </para>
/// <para>
/// Many .NET libraries allocate internally and do not accept a <see cref="System.Buffers.MemoryPool{T}"/>
/// or <see cref="System.Buffers.ArrayPool{T}"/>. For example, <see cref="System.Text.Json.JsonSerializer.SerializeToUtf8Bytes{TValue}(TValue, System.Text.Json.JsonSerializerOptions?)"/>
/// allocates and returns a <c>byte[]</c>. This is a common pattern across serialization libraries.
/// </para>
/// <para>
/// <strong>Wrapping vs. Copying Trade-offs</strong>
/// </para>
/// <para>
/// When a library returns an allocated array, there are two options:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Copy to pooled memory</strong> - Rent from a pool, copy the bytes, return the original
/// to GC. This can make the original array shorter-lived and eligible for collection sooner,
/// potentially reducing memory pressure. However, copying has CPU cost and during the copy
/// both buffers exist in memory simultaneously.
/// </description></item>
/// <item><description>
/// <strong>Wrap directly</strong> - Use the allocated array as-is with metadata tagging.
/// No copy overhead, but the array lifetime is tied to usage. For short-lived request/response
/// patterns (like JWT signing), this is often more efficient.
/// </description></item>
/// </list>
/// <para>
/// <see cref="TaggedMemory{T}"/> with <see cref="BufferKind"/> takes the wrapping approach,
/// avoiding copy overhead while still providing meaningful context about the buffer contents.
/// </para>
/// <para>
/// <strong>Design</strong>
/// </para>
/// <para>
/// This type follows the same "extensible discriminator" pattern as <see cref="Context.CryptoAlgorithm"/>.
/// Predefined values cover common cases, and custom values can be added via <see cref="Create"/>
/// for application-specific buffer types.
/// </para>
/// <para>
/// <strong>Usage with TaggedMemory</strong>
/// </para>
/// <para>
/// <see cref="BufferKind"/> is typically used as part of a <see cref="Tag"/> associated
/// with <see cref="TaggedMemory{T}"/> to describe buffer contents:
/// </para>
/// <code>
/// //Serializer allocates internally - we wrap without copying.
/// byte[] json = JsonSerializer.SerializeToUtf8Bytes(credential);
/// var tag = Tag.Create((typeof(BufferKind), BufferKind.JwtPayload));
/// var buffer = new TaggedMemory&lt;byte&gt;(json, tag);
/// </code>
/// <para>
/// <strong>Extending with Custom Values</strong>
/// </para>
/// <para>
/// Use code values above 1000 to avoid collisions with future library additions:
/// </para>
/// <code>
/// public static class CustomBufferKinds
/// {
///     public static BufferKind ProtobufMessage { get; } = BufferKind.Create(1001);
///     public static BufferKind AvroRecord { get; } = BufferKind.Create(1002);
/// }
/// </code>
/// <para>
/// <strong>Thread Safety</strong>
/// </para>
/// <para>
/// The <see cref="Create"/> method is not thread-safe. Call it only during
/// application startup before concurrent access begins.
/// </para>
/// </remarks>
/// <seealso cref="TaggedMemory{T}"/>
/// <seealso cref="Tag"/>
/// <seealso cref="BufferTags"/>
[DebuggerDisplay("{BufferKindNames.GetName(this),nq}")]
public readonly struct BufferKind: IEquatable<BufferKind>
{
    /// <summary>
    /// Gets the numeric code for this buffer kind.
    /// </summary>
    public int Kind { get; }


    private BufferKind(int kind)
    {
        Kind = kind;
    }


    /// <summary>
    /// The buffer kind is unknown or unspecified.
    /// </summary>
    public static BufferKind Unknown { get; } = new BufferKind(-1);

    /// <summary>
    /// JWT protected header bytes (typically JSON).
    /// </summary>
    public static BufferKind JwtHeader { get; } = new BufferKind(0);

    /// <summary>
    /// JWT payload bytes (typically JSON).
    /// </summary>
    public static BufferKind JwtPayload { get; } = new BufferKind(1);

    /// <summary>
    /// General JSON-encoded bytes.
    /// </summary>
    public static BufferKind Json { get; } = new BufferKind(2);

    /// <summary>
    /// CBOR-encoded bytes.
    /// </summary>
    public static BufferKind Cbor { get; } = new BufferKind(3);

    /// <summary>
    /// CWT (CBOR Web Token) protected header bytes.
    /// </summary>
    public static BufferKind CwtHeader { get; } = new BufferKind(4);

    /// <summary>
    /// CWT payload bytes.
    /// </summary>
    public static BufferKind CwtPayload { get; } = new BufferKind(5);

    /// <summary>
    /// Serialized Verifiable Credential bytes.
    /// </summary>
    public static BufferKind Credential { get; } = new BufferKind(6);

    /// <summary>
    /// Serialized Verifiable Presentation bytes.
    /// </summary>
    public static BufferKind Presentation { get; } = new BufferKind(7);


    private static readonly List<BufferKind> s_kinds =
    [
        Unknown, JwtHeader, JwtPayload, Json, Cbor, CwtHeader, CwtPayload, Credential, Presentation
    ];


    /// <summary>
    /// Gets all registered buffer kind values.
    /// </summary>
    public static IReadOnlyList<BufferKind> All => s_kinds.AsReadOnly();


    /// <summary>
    /// Creates a new buffer kind value for custom buffer types.
    /// </summary>
    /// <param name="kind">The unique numeric code for this buffer kind.</param>
    /// <returns>The newly created buffer kind.</returns>
    /// <exception cref="ArgumentException">Thrown when the code already exists.</exception>
    /// <remarks>
    /// <para>
    /// This method is not thread-safe. Call it only during application startup.
    /// Use code values above 1000 to avoid collisions with future library additions.
    /// </para>
    /// </remarks>
    public static BufferKind Create(int kind)
    {
        for(int i = 0; i < s_kinds.Count; ++i)
        {
            if(s_kinds[i].Kind == kind)
            {
                throw new ArgumentException($"Buffer kind code '{kind}' already exists.", nameof(kind));
            }
        }

        var newKind = new BufferKind(kind);
        s_kinds.Add(newKind);

        return newKind;
    }


    /// <inheritdoc />
    public override string ToString() => BufferKindNames.GetName(this);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(BufferKind other) => Kind == other.Kind;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is BufferKind other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Kind;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(BufferKind left, BufferKind right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(BufferKind left, BufferKind right) => !left.Equals(right);
}


/// <summary>
/// Provides human-readable names for <see cref="BufferKind"/> values.
/// </summary>
public static class BufferKindNames
{
    /// <summary>
    /// Gets the name for the specified buffer kind.
    /// </summary>
    /// <param name="kind">The buffer kind.</param>
    /// <returns>The human-readable name.</returns>
    public static string GetName(BufferKind kind) => GetName(kind.Kind);


    /// <summary>
    /// Gets the name for the specified buffer kind code.
    /// </summary>
    /// <param name="kind">The numeric code.</param>
    /// <returns>The human-readable name.</returns>
    public static string GetName(int kind) => kind switch
    {
        -1 => nameof(BufferKind.Unknown),
        0 => nameof(BufferKind.JwtHeader),
        1 => nameof(BufferKind.JwtPayload),
        2 => nameof(BufferKind.Json),
        3 => nameof(BufferKind.Cbor),
        4 => nameof(BufferKind.CwtHeader),
        5 => nameof(BufferKind.CwtPayload),
        6 => nameof(BufferKind.Credential),
        7 => nameof(BufferKind.Presentation),
        _ => $"Custom({kind})"
    };
}