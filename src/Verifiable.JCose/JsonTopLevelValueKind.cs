namespace Verifiable.JCose;

/// <summary>
/// The kind of value a member at a JSON object's top level carries (RFC 8259 section 3), as
/// <see cref="JwkJsonReader.ReadTopLevelMembers"/> reads it.
/// </summary>
public enum JsonTopLevelValueKind
{
    /// <summary>
    /// A string, read decoded once (RFC 8259 section 7); a document holding a string naming no Unicode text is refused whole
    /// (<see cref="JsonUndecodableMember"/>), so every string read is Unicode text.
    /// </summary>
    String,

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
