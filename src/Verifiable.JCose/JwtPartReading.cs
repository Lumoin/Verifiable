namespace Verifiable.JCose;

/// <summary>
/// The reading of one decoded part of a JWS, its protected header (<see cref="JwtHeader.Read"/>) or its claims set
/// (<see cref="JwtPayload.Read"/>), read once through the library's one strict judgement of a document a protocol reads as one JSON
/// object (<see cref="JwkJsonReader.ReadTopLevelMembers"/>): the part, every member at every depth held as a claims set holds it
/// (<see cref="JwtPartRead{TPart}"/>), or the reader's refusal of the document (<see cref="JwtPartRefused{TPart}"/>). No reading
/// throws on the bytes it is handed, and none judges what the members name: a required member's absence, a member of another kind
/// than its claim defines and every date's bound are judged by the validator reading the part.
/// </summary>
/// <typeparam name="TPart">The part read: <see cref="JwtHeader"/> or <see cref="JwtPayload"/>.</typeparam>
public abstract record JwtPartReading<TPart> where TPart : JoseDictionary;


/// <summary>The part, every member of the one JSON object it is held at every depth.</summary>
/// <typeparam name="TPart">The part read.</typeparam>
/// <param name="Part">The part.</param>
public sealed record JwtPartRead<TPart>(TPart Part) : JwtPartReading<TPart> where TPart : JoseDictionary;


/// <summary>
/// The JSON reader refused the document the part is: no one well-formed JSON object (<see cref="JsonNotOneObject"/>), an object
/// repeating a member name at any depth (<see cref="JsonRepeatedMemberName"/>), or one holding a name or a string naming no Unicode
/// text (<see cref="JsonUndecodableMember"/>), carried as the reader answered it.
/// </summary>
/// <typeparam name="TPart">The part read.</typeparam>
/// <param name="Refusal">The reader's refusal.</param>
public sealed record JwtPartRefused<TPart>(JsonTopLevelReading Refusal) : JwtPartReading<TPart> where TPart : JoseDictionary;
