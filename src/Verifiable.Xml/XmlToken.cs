namespace Verifiable.Xml;

/// <summary>
/// One token produced by <see cref="XmlSpanReader"/>: the token kind, the name and value spans into the
/// document octets and the byte offsets those spans start at.
/// </summary>
/// <remarks>
/// The spans alias the UTF-8 document the reader was constructed over and are valid only while that memory
/// is. Which spans are populated depends on <see cref="Kind"/>: element and attribute tokens carry the
/// qualified name in <see cref="Name"/>; attribute, text, CDATA, comment and XML declaration tokens carry
/// content in <see cref="Value"/>; processing instructions carry the target in <see cref="Name"/> and the
/// instruction content in <see cref="Value"/>. Values are raw document octets: references are unresolved
/// and no line-end or attribute-value normalization has been applied, per the layering of
/// <see cref="XmlNodeTable"/>, which performs the normalizations of
/// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> sections 2.11
/// and 3.3.3 when it builds the document table.
/// </remarks>
public readonly ref struct XmlToken
{
    /// <summary>
    /// The kind of markup or character data this token represents.
    /// </summary>
    public XmlTokenKind Kind { get; }

    /// <summary>
    /// The qualified name of an element or attribute, or the target of a processing instruction. Empty for
    /// kinds that carry no name.
    /// </summary>
    public ReadOnlySpan<byte> Name { get; }

    /// <summary>
    /// The raw content of the token: an attribute's literal between its quotes, a run of character data,
    /// CDATA or comment content, processing instruction content or the XML declaration's interior. Empty
    /// for kinds that carry no value.
    /// </summary>
    public ReadOnlySpan<byte> Value { get; }

    /// <summary>
    /// The byte offset the token starts at, in the coordinate space the reader was constructed with.
    /// </summary>
    public long ByteOffset { get; }

    /// <summary>
    /// The byte offset <see cref="Value"/> starts at, in the coordinate space the reader was constructed
    /// with. Equal to <see cref="ByteOffset"/> when the token has no value.
    /// </summary>
    public long ValueByteOffset { get; }


    /// <summary>
    /// Creates a token.
    /// </summary>
    /// <param name="kind">The kind of the token.</param>
    /// <param name="name">The name span, or empty.</param>
    /// <param name="value">The value span, or empty.</param>
    /// <param name="byteOffset">The byte offset the token starts at.</param>
    /// <param name="valueByteOffset">The byte offset the value starts at.</param>
    internal XmlToken(XmlTokenKind kind, ReadOnlySpan<byte> name, ReadOnlySpan<byte> value, long byteOffset, long valueByteOffset)
    {
        Kind = kind;
        Name = name;
        Value = value;
        ByteOffset = byteOffset;
        ValueByteOffset = valueByteOffset;
    }
}
