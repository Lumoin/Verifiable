namespace Verifiable.JCose;

/// <summary>
/// Which part of a member, as <see cref="JwkJsonReader.ReadTopLevelMembers"/> reads a document, is a string naming no Unicode
/// text (RFC 8259 section 8.2): its name, or a string its value is or holds.
/// </summary>
public enum JsonUndecodableMemberPart
{
    /// <summary>
    /// The member's value: a string the value is, or a string an array the value is holds, at any depth of arrays within it.
    /// </summary>
    Value,

    /// <summary>The member's name.</summary>
    Name
}
