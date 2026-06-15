namespace Verifiable.Server;

/// <summary>
/// The character-set restriction RFC 6749 §4.1.2.1 / §5.2 place on the OAuth
/// <c>error_description</c>, which OID4VCI 1.0 §8.3.1.2 (Credential Error Response) and §11.1
/// (Notification <c>event_description</c>) restate verbatim:
/// "The values for the error_description parameter MUST NOT include characters outside the set
/// <c>%x20-21 / %x23-5B / %x5D-7E</c>." That set is printable US-ASCII with the JSON-significant
/// <c>"</c> (0x22) and <c>\</c> (0x5C) — and every control character — removed.
/// </summary>
/// <remarks>
/// The value is issuer-emitted (a developer-facing diagnostic the application supplies), so the
/// library sanitizes it to the allowed set on emit rather than refusing the whole response: a
/// description carrying an out-of-charset character is reduced to its conformant subset so the
/// emitted <c>error_description</c> never violates §8.3.1.2, and the same restriction the library
/// guarantees the response side also leaves a §11.1 <c>event_description</c> conformant before the
/// notification reaches the application seam.
/// </remarks>
public static class ErrorDescriptionCharset
{
    /// <summary>
    /// Whether <paramref name="value"/> contains only characters in the
    /// <c>%x20-21 / %x23-5B / %x5D-7E</c> set.
    /// </summary>
    /// <param name="value">The candidate <c>error_description</c> / <c>event_description</c>.</param>
    /// <returns><see langword="true"/> when every character is in the allowed set.</returns>
    public static bool IsConformant(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        foreach(char c in value)
        {
            if(!IsAllowed(c))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Returns <paramref name="value"/> with every character outside the
    /// <c>%x20-21 / %x23-5B / %x5D-7E</c> set removed, so the result is a §8.3.1.2 / §11.1
    /// conformant <c>error_description</c>. A <see langword="null"/> input returns
    /// <see langword="null"/>; an already-conformant input is returned unchanged.
    /// </summary>
    /// <param name="value">The candidate description, or <see langword="null"/>.</param>
    /// <returns>The sanitized description, or <see langword="null"/> when the input was null.</returns>
    public static string? Sanitize(string? value)
    {
        if(value is null || IsConformant(value))
        {
            return value;
        }

        char[] buffer = new char[value.Length];
        int length = 0;
        foreach(char c in value)
        {
            if(IsAllowed(c))
            {
                buffer[length++] = c;
            }
        }

        return new string(buffer, 0, length);
    }


    private static bool IsAllowed(char c) =>
        c is (>= ' ' and <= '!') or (>= '#' and <= '[') or (>= ']' and <= '~');
}
