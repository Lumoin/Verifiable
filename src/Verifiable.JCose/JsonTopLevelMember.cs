namespace Verifiable.JCose;

/// <summary>
/// One member at a JSON object's top level, as <see cref="JwkJsonReader.ReadTopLevelMembers"/> reads it from the object the
/// document is: its name decoded once (RFC 8259 section 7), the kind of its value, and the value's text.
/// </summary>
/// <param name="Name">The member's name, decoded.</param>
/// <param name="Kind">The kind of the member's value.</param>
/// <param name="Text">
/// For a <see cref="JsonTopLevelValueKind.String"/>, the string decoded once; for an
/// <see cref="JsonTopLevelValueKind.UndecodableString"/>, empty; for every other kind, the value's JSON text as written.
/// </param>
public sealed record JsonTopLevelMember(string Name, JsonTopLevelValueKind Kind, string Text);
