using System;

namespace Verifiable.Tests.TestInfrastructure
{
    /// <summary>
    /// Extension methods for <see cref="string"/> to help with testing.
    /// </summary>
    public static class StringExtensions
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
            return char.IsUpper(character) ? char.ToLower(character) : char.ToUpper(character);
        }
    }
}
