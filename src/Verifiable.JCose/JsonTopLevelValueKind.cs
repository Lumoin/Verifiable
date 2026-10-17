namespace Verifiable.JCose;

/// <summary>
/// The kind of value a member at a JSON object's top level carries (RFC 8259 section 3), as
/// <see cref="JwkJsonReader.ReadTopLevelMembers"/> reads it.
/// </summary>
public enum JsonTopLevelValueKind
{
    /// <summary>A string whose escapes name Unicode text, read decoded once (RFC 8259 section 7).</summary>
    String,

    /// <summary>
    /// A string whose escapes name no Unicode text - an unpaired surrogate, which the grammar admits and of which RFC 8259
    /// section 8.2 says receivers "might ... even suffer fatal runtime exceptions" - so no text is read from it.
    /// </summary>
    UndecodableString,

    /// <summary>A number (RFC 8259 section 6), its text as written.</summary>
    Number,

    /// <summary>The literal <c>true</c>.</summary>
    True,

    /// <summary>The literal <c>false</c>.</summary>
    False,

    /// <summary>The literal <c>null</c>.</summary>
    Null,

    /// <summary>An object nested beneath the top level, its JSON text as written; none of its members is the top level's own.</summary>
    Object,

    /// <summary>An array, its JSON text as written.</summary>
    Array
}
