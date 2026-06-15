namespace Verifiable.Foundation;

/// <summary>
/// Pre-built <see cref="Tag"/> instances for the domain-neutral buffer content types.
/// </summary>
/// <remarks>
/// <para>
/// This static class provides ready-to-use tags for identifying buffer contents.
/// Each tag contains the appropriate <see cref="BufferKind"/> metadata. Domain-specific buffer tags
/// (JWT/CWT, Verifiable Credential / Presentation, ...) are defined by the layer that owns those
/// formats, on top of a <see cref="BufferKind"/> created through <see cref="BufferKind.Create"/>.
/// </para>
/// <para>
/// <strong>Usage</strong>
/// </para>
/// <code>
/// //Use a pre-built tag when creating tagged memory.
/// var buffer = new TaggedMemory&lt;byte&gt;(jsonBytes, BufferTags.Json);
///
/// //Or retrieve the buffer kind from a tag.
/// var kind = BufferTags.Json.Get&lt;BufferKind&gt;();
/// </code>
/// </remarks>
/// <seealso cref="Tag"/>
/// <seealso cref="BufferKind"/>
/// <seealso cref="TaggedMemory{T}"/>
public static class BufferTags
{
    /// <summary>
    /// Tag for general JSON-encoded bytes.
    /// </summary>
    public static Tag Json { get; } = Tag.Create(
        (typeof(BufferKind), BufferKind.Json));

    /// <summary>
    /// Tag for CBOR-encoded bytes.
    /// </summary>
    public static Tag Cbor { get; } = Tag.Create(
        (typeof(BufferKind), BufferKind.Cbor));
}
