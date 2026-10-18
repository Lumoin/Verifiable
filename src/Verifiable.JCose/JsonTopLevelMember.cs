namespace Verifiable.JCose;

/// <summary>
/// One member at a JSON object's top level, as <see cref="JwkJsonReader.ReadTopLevelMembers"/> reads it from the object the
/// document is: its name decoded once (RFC 8259 section 7), the kind of its value, and the value's text.
/// </summary>
/// <param name="Name">The member's name, decoded.</param>
/// <param name="Kind">The kind of the member's value.</param>
/// <param name="Text">
/// For a <see cref="JsonTopLevelValueKind.String"/>, the string decoded once; for every other kind, the value's JSON text as
/// written.
/// </param>
public sealed record JsonTopLevelMember(string Name, JsonTopLevelValueKind Kind, string Text)
{
    /// <summary>
    /// The elements of the array the member's value is, in document order, each as one typed answer
    /// (<see cref="JsonMemberLookup"/>): a string with its decoded text, a number with its spelling, or a value of another kind
    /// naming which. A reader of a member defined as an array of strings - a JWK's <c>key_ops</c> or <c>x5c</c> (RFC 7517
    /// sections 4.3 and 4.7) - judges each element's kind from this answer, read by the reader that read the member, never by a
    /// scan of its own. <see langword="null"/> when the member is no array, or its text is no one well-formed array of Unicode
    /// text, as a member the reader answered never is.
    /// </summary>
    /// <returns>The elements, or <see langword="null"/>.</returns>
    public IReadOnlyList<JsonMemberLookup>? ArrayElements() =>
        Kind is JsonTopLevelValueKind.Array ? JwkJsonReader.ReadArrayElements(Text) : null;
}
