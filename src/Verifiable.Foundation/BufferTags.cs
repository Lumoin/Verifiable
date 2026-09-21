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
/// <see cref="Tag"/> is declared in <c>Lumoin.Base</c>; a consumer that imports only
/// <c>Verifiable.Foundation</c> and writes the bare <see cref="Tag"/> name needs its own
/// <c>using Lumoin.Base;</c> as well, since a <c>global using</c> inside this project's own
/// compilation is not re-exported to a downstream consumer.
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
    public static Tag Json { get; } = Tag.Create(BufferKind.Json);

    /// <summary>
    /// Tag for CBOR-encoded bytes.
    /// </summary>
    public static Tag Cbor { get; } = Tag.Create(BufferKind.Cbor);

    /// <summary>
    /// Tag for canonical XML octets produced by a canonicalization algorithm.
    /// </summary>
    public static Tag XmlCanonical { get; } = Tag.Create(BufferKind.XmlCanonical);

    /// <summary>
    /// Tag for XML Signature reference-processing output octets: the final octet stream a
    /// <c>ds:Reference</c>'s dereference-then-transform-chain produces, which <c>DigestMethod</c> digests.
    /// </summary>
    public static Tag XmlDigestInput { get; } = Tag.Create(BufferKind.XmlDigestInput);

    /// <summary>
    /// Tag for octets decoded from XSD <c>base64Binary</c> element content, such as <c>DigestValue</c>,
    /// <c>SignatureValue</c> and <c>X509Certificate</c>.
    /// </summary>
    public static Tag XmlDecodedContent { get; } = Tag.Create(BufferKind.XmlDecodedContent);
}
