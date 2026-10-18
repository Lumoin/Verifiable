using Verifiable.JCose;

namespace Verifiable.OAuth.Validation;

/// <summary>
/// The one reading of a NumericDate claim (RFC 7519 section 2) off a claims set read as the one JSON object it is
/// (<see cref="JwkJsonReader.ReadTopLevelMembers"/>): the claim as the reader answered it (<see cref="JsonTopLevelMembers.Find"/>),
/// a JSON number read as the date it names with every digit kept (<see cref="JsonMemberNumber.ToNumericDate"/>). A claim the
/// claims set omits is absent; one it carries that names no date - a string of digits, another kind of value, a number naming an
/// instant no clock represents - is malformed, never read as absent, so a validator that treats an omitted claim as no constraint
/// never treats an unreadable one the same way.
/// </summary>
internal static class NumericDateClaims
{
    /// <summary>Reads one NumericDate claim off a claims set's top-level members.</summary>
    /// <param name="members">The claims set's top-level members.</param>
    /// <param name="name">The claim's name.</param>
    /// <param name="date">The date as written when the result is <see cref="NumericDateReadResult.Value"/>; otherwise <see langword="null"/>.</param>
    /// <returns>Whether the claim is absent, names a date, or is malformed.</returns>
    internal static NumericDateReadResult Read(JsonTopLevelMembers members, string name, out NumericDate? date)
    {
        var carried = members.Find(name);
        date = carried is JsonMemberNumber number ? number.ToNumericDate() : null;

        if(carried is JsonMemberAbsent)
        {
            return NumericDateReadResult.Absent;
        }

        return date is null ? NumericDateReadResult.Malformed : NumericDateReadResult.Value;
    }
}
