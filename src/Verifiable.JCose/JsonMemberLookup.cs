namespace Verifiable.JCose;

/// <summary>
/// What a member asked for by name at the top level of the one JSON object a document is answers
/// (<see cref="JsonTopLevelMembers.Find"/>): the member carried as a string, with its decoded text; carried as a number, with its
/// spelling; carried as a value of another kind, naming which; or no such member. A reader of a parameter consumes this answer,
/// so the kind of a member's value is judged once, by the reader of the document, and never again by each of its readers.
/// </summary>
public abstract record JsonMemberLookup;


/// <summary>The member is carried as a string, decoded once (RFC 8259 section 7), which is Unicode text.</summary>
/// <param name="Text">The decoded string.</param>
public sealed record JsonMemberString(string Text) : JsonMemberLookup;


/// <summary>
/// The member is carried as a number (RFC 8259 section 6), its spelling as the document writes it, which the grammar admitted, so
/// a reader converts it to the range it needs and refuses one outside it.
/// </summary>
/// <param name="Spelling">The number as the document writes it.</param>
public sealed record JsonMemberNumber(string Spelling) : JsonMemberLookup;


/// <summary>The member is carried as a value that is neither a string nor a number: a literal, an object or an array.</summary>
/// <param name="Kind">Which kind of value it is.</param>
public sealed record JsonMemberOfOtherKind(JsonTopLevelValueKind Kind) : JsonMemberLookup;


/// <summary>The object carries no member of that name at its top level.</summary>
public sealed record JsonMemberAbsent : JsonMemberLookup;
