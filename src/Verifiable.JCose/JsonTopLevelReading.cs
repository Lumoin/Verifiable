namespace Verifiable.JCose;

/// <summary>
/// The reading of a document as the one JSON object whose top-level members it carries, as
/// <see cref="JwkJsonReader.ReadTopLevelMembers"/> answers it: the members (<see cref="JsonTopLevelMembers"/>), or the
/// refusal of a document that is not one well-formed JSON object (<see cref="JsonNotOneObject"/>), of a well-formed object one
/// of whose objects repeats a member name (<see cref="JsonRepeatedMemberName"/>), or of a well-formed object one of whose
/// members has a name or a string value naming no Unicode text (<see cref="JsonUndecodableMember"/>), each a reason of its own.
/// </summary>
public abstract record JsonTopLevelReading;


/// <summary>
/// The members at the top level of the one JSON object the document is, in document order, each name and string value
/// decoded once (RFC 8259 section 7), every one of them Unicode text.
/// </summary>
/// <param name="Members">The object's top-level members.</param>
public sealed record JsonTopLevelMembers(IReadOnlyList<JsonTopLevelMember> Members) : JsonTopLevelReading;


/// <summary>
/// The document is not one well-formed JSON object: it is not exactly one well-formed JSON value (RFC 8259 section 2) - an
/// object never closed, a value followed by another, a name or a string that is no well-formed UTF-8 (RFC 8259 section 8.1),
/// a document past the reader's bounds - or it is one such value that is no object, an array or a string among them.
/// </summary>
public sealed record JsonNotOneObject : JsonTopLevelReading;


/// <summary>
/// The document is one well-formed JSON object, but one of its objects, its own or one nested within it, names a member more
/// than once, where RFC 8259 section 4 says the names within an object SHOULD be unique and "the behavior of software that
/// receives such an object is unpredictable": readers of a repeated name differ in which value they take, so the document
/// names no member one way. The first repetition in document order is the one answered.
/// </summary>
/// <param name="Name">
/// The repeated name, decoded once (RFC 8259 section 7). It is always Unicode text: a name naming none is answered at its
/// first occurrence as <see cref="JsonUndecodableMember"/>, which comes before any repetition of it.
/// </param>
/// <param name="ObjectDepth">
/// The nesting depth of the object that repeats it: one for the document's own object, one more for each object or array it
/// is nested within beneath that.
/// </param>
public sealed record JsonRepeatedMemberName(string Name, int ObjectDepth) : JsonTopLevelReading;


/// <summary>
/// The document is one well-formed JSON object, but a member of one of its objects, its own or one nested within it, has a
/// name or a string value whose escapes name an unpaired surrogate: the grammar admits it, but it names no Unicode text, and
/// RFC 8259 section 8.2 says the behavior of software receiving it is unpredictable, so no reader agrees on its text. The first
/// such member in document order is the one answered, whether or not any reader of the document reads that member. No value
/// the document carries is answered.
/// </summary>
/// <param name="Name">
/// When <paramref name="Part"/> is <see cref="JsonUndecodableMemberPart.Value"/>, the member's name decoded once (RFC 8259
/// section 7), which is Unicode text. When it is <see cref="JsonUndecodableMemberPart.Name"/>, the name as the document spells
/// it, its escapes as written (<c>\uDC00</c> as those six characters), which is text that can be written, as the decoded name
/// is not.
/// </param>
/// <param name="ObjectDepth">
/// The nesting depth of the object carrying the member: one for the document's own object, one more for each object or array
/// it is nested within beneath that.
/// </param>
/// <param name="Part">Whether the member's name or its value names no Unicode text.</param>
public sealed record JsonUndecodableMember(string Name, int ObjectDepth, JsonUndecodableMemberPart Part) : JsonTopLevelReading;
