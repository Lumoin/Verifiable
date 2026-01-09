namespace Verifiable.Cryptography;

/// <summary>
/// Pre-built <see cref="Tag"/> instances for common buffer content types.
/// </summary>
/// <remarks>
/// <para>
/// This static class provides ready-to-use tags for identifying buffer contents.
/// Each tag contains the appropriate <see cref="BufferKind"/> metadata.
/// </para>
/// <para>
/// <strong>Usage</strong>
/// </para>
/// <code>
/// //Use a pre-built tag when creating tagged memory.
/// var buffer = new TaggedMemory&lt;byte&gt;(headerBytes, BufferTags.JwtHeader);
///
/// //Or retrieve the buffer kind from a tag.
/// var kind = BufferTags.JwtPayload.Get&lt;BufferKind&gt;();
/// </code>
/// </remarks>
/// <seealso cref="Tag"/>
/// <seealso cref="BufferKind"/>
/// <seealso cref="TaggedMemory{T}"/>
public static class BufferTags
{
    /// <summary>
    /// Tag for JWT protected header bytes.
    /// </summary>
    public static Tag JwtHeader { get; } = Tag.Create(
        (typeof(BufferKind), BufferKind.JwtHeader));

    /// <summary>
    /// Tag for JWT payload bytes.
    /// </summary>
    public static Tag JwtPayload { get; } = Tag.Create(
        (typeof(BufferKind), BufferKind.JwtPayload));

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

    /// <summary>
    /// Tag for CWT protected header bytes.
    /// </summary>
    public static Tag CwtHeader { get; } = Tag.Create(
        (typeof(BufferKind), BufferKind.CwtHeader));

    /// <summary>
    /// Tag for CWT payload bytes.
    /// </summary>
    public static Tag CwtPayload { get; } = Tag.Create(
        (typeof(BufferKind), BufferKind.CwtPayload));

    /// <summary>
    /// Tag for serialized Verifiable Credential bytes.
    /// </summary>
    public static Tag Credential { get; } = Tag.Create(
        (typeof(BufferKind), BufferKind.Credential));

    /// <summary>
    /// Tag for serialized Verifiable Presentation bytes.
    /// </summary>
    public static Tag Presentation { get; } = Tag.Create(
        (typeof(BufferKind), BufferKind.Presentation));
}