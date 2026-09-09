using System.Globalization;

namespace Verifiable.Tests.TestInfrastructure
{
    /// <summary>
    /// Extension methods for <see cref="string"/> to help with testing.
    /// </summary>
    internal static class StringExtensions
    {
        /// <summary>
        /// Toggles the case of the character at the given index.
        /// </summary>
        /// <param name="str">The string in which to toggle a character.</param>
        /// <param name="index">The index at which to toggle the character.</param>
        /// <returns>A new string with toggled letter.</returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <remarks>Allocates a new string.</remarks>
        public static string ToggleCaseForLetterAt(this string str, int index)
        {
            if(index < 0 || index >= str.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(index));
            }

            return string.Create(str.Length, str, (chars, original) =>
            {
                ReadOnlySpan<char> span = original.AsSpan();
                span[..index].CopyTo(chars);
                chars[index] = ToggleCase(span[index]);
                span[(index + 1)..].CopyTo(chars[(index + 1)..]);
            });
        }


        /// <summary>
        /// Toggles the case of the character at the given index.
        /// </summary>
        /// <param name="character">The character to toggle.</param>
        /// <returns>The character toggled.</returns>
        private static char ToggleCase(this char character)
        {
            return char.IsUpper(character) ? char.ToLower(character, CultureInfo.CurrentCulture) : char.ToUpper(character, CultureInfo.CurrentCulture);
        }


        /// <summary>
        /// Inserts a soft hyphen (U+00AD) at the given index.
        /// </summary>
        /// <param name="str">The string into which to insert the soft hyphen.</param>
        /// <param name="index">The index at which to insert the soft hyphen.</param>
        /// <returns>A new string with the soft hyphen inserted at <paramref name="index"/>.</returns>
        /// <remarks>
        /// U+00AD is a Unicode default-ignorable code point: a culture-aware string comparison
        /// (for example <see cref="StringComparison.InvariantCulture"/>) can treat the result as
        /// equal to <paramref name="str"/> even though the two strings are byte-different. This is
        /// used to prove that a comparison is ordinal, which never ignores it.
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="index"/> is negative or greater than <paramref name="str"/>'s length.</exception>
        public static string InsertIgnorableCodePointAt(this string str, int index)
        {
            if(index < 0 || index > str.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(index));
            }

            //Named by code point cast rather than as an invisible literal character in source, which
            //editors and diff/patch tooling can silently drop or alter.
            const char SoftHyphen = (char)0x00AD;

            return string.Create(str.Length + 1, str, (chars, original) =>
            {
                ReadOnlySpan<char> span = original.AsSpan();
                span[..index].CopyTo(chars);
                chars[index] = SoftHyphen;
                span[index..].CopyTo(chars[(index + 1)..]);
            });
        }
    }
}
