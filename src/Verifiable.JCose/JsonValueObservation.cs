namespace Verifiable.JCose;

/// <summary>
/// What one occurrence of a member at the top level of a well-formed JSON object holds, observed without its value: a string
/// naming Unicode text and the length of that text, a string naming none, or a value that is no string. No observation carries
/// the text it observed, so a member carrying a credential is observed without the credential.
/// </summary>
public abstract record JsonValueObservation;


/// <summary>
/// A string naming Unicode text (RFC 8259 section 8.2), of the length its text has once decoded (RFC 8259 section 7), in UTF-16
/// code units, the measure of a decoded <see cref="string"/>'s <see cref="string.Length"/>.
/// </summary>
/// <param name="Utf16Length">The length of the decoded text in UTF-16 code units.</param>
public sealed record JsonReadableString(int Utf16Length) : JsonValueObservation;


/// <summary>
/// A string whose escapes name an unpaired surrogate: the grammar admits it, but it names no Unicode text (RFC 8259 section 8.2),
/// so it has no length a reader agrees on.
/// </summary>
public sealed record JsonUndecodableString : JsonValueObservation;


/// <summary>A value that is no string: a number, a literal, an object or an array.</summary>
/// <param name="Kind">Which kind of value it is.</param>
public sealed record JsonNonStringValue(JsonTopLevelValueKind Kind) : JsonValueObservation;
