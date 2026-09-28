namespace Verifiable.OAuth.Validation;

/// <summary>
/// What reading a NumericDate claim (<see href="https://www.rfc-editor.org/rfc/rfc7519#section-2">RFC
/// 7519 §2</see>: "A JSON numeric value representing the number of seconds from
/// 1970-01-01T00:00:00Z UTC until the specified UTC date/time") off a verified payload found. An absent
/// claim and a present claim no instant can be read from are distinct outcomes, so a validator that
/// treats an optional claim's absence as "no constraint" never treats an unreadable value the same way.
/// </summary>
internal enum NumericDateReadResult
{
    /// <summary>The claim is not present.</summary>
    Absent,

    /// <summary>The claim is present and names an instant a <see cref="DateTimeOffset"/> holds.</summary>
    Value,

    /// <summary>
    /// The claim is present but is not a number, or names no instant a <see cref="DateTimeOffset"/>
    /// holds (<see cref="JwtTemporalChecks.TryFromUnixSeconds(double, out DateTimeOffset)"/>).
    /// </summary>
    Malformed
}
