using System;

namespace Verifiable.Cryptography.Cbom;

/// <summary>
/// Helpers for building CycloneDX bom-ref identifiers. These identifiers are lowercase
/// machine slugs, not culture-sensitive display text, so casing is normalized with an
/// explicit ASCII fold rather than a culture-aware lowercasing routine.
/// </summary>
internal static class CbomIdentifiers
{
    /// <summary>
    /// Folds ASCII <c>A</c>-<c>Z</c> to lowercase and leaves all other characters intact.
    /// Used to slugify algorithm and library names into stable bom-refs.
    /// </summary>
    /// <param name="value">The value to fold.</param>
    /// <returns>The ASCII-lowercased value.</returns>
    public static string AsciiLower(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        Span<char> buffer = value.Length <= 128 ? stackalloc char[value.Length] : new char[value.Length];
        for(int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            buffer[i] = c is >= 'A' and <= 'Z' ? (char)(c + 32) : c;
        }

        return new string(buffer);
    }
}
