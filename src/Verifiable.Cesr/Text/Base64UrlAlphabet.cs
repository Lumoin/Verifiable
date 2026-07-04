namespace Verifiable.Cesr.Text;

/// <summary>
/// The Base64URL alphabet of the CESR text domain: the bijection between a character and its six-bit sextet
/// value. The forward alphabet and the reverse lookup are encapsulated here so the codecs never handle a raw
/// lookup table, and so this is the single seam where a vectorized backend can later replace the scalar
/// lookup without touching callers.
/// </summary>
/// <remarks>
/// <para>
/// The alphabet is the URL- and filename-safe Base64 alphabet (IETF RFC 4648 §5). CESR never uses the Base64
/// <c>=</c> pad character; see the CESR specification's
/// <see href="https://trustoverip.github.io/kswg-cesr-specification/#concrete-domain-representations">Concrete
/// Domain representations</see>.
/// </para>
/// </remarks>
public static class Base64UrlAlphabet
{
    /// <summary>
    /// The 64 Base64URL characters in sextet order: index 0-63 maps to the encoded character.
    /// </summary>
    private const string Characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// <summary>
    /// Reverse lookup from an ASCII character to its sextet value, or <c>-1</c> when the character is not in
    /// the alphabet. Indexed by the character's byte value (0-127).
    /// </summary>
    private static sbyte[] Inverse { get; } = BuildInverse();


    /// <summary>
    /// The Base64URL character that encodes the sextet value zero (<c>A</c>). CESR prepends this character to
    /// align a value on a 24-bit boundary — a zero net-pad or lead — so it is the character a decoder fills the
    /// pad position with, or strips from the front of a padded value. This is distinct from the soft extra-pad
    /// character <see cref="CesrTextCodec.Pad"/> (<c>_</c>, the sextet value 63).
    /// </summary>
    public static char Zero { get; } = Characters[0];


    /// <summary>
    /// Gets the Base64URL character that encodes a sextet value.
    /// </summary>
    /// <param name="sextet">The sextet value, in the range 0-63.</param>
    /// <returns>The encoded character.</returns>
    public static char CharOf(int sextet) => Characters[sextet];


    /// <summary>
    /// Gets the sextet value (0-63) of a Base64URL character.
    /// </summary>
    /// <param name="character">The character to convert.</param>
    /// <returns>The sextet value in the range 0-63.</returns>
    /// <exception cref="CesrFormatException">The character is not a valid Base64URL character.</exception>
    public static int SextetOf(char character)
    {
        int value = character < 128 ? Inverse[character] : -1;
        if(value < 0)
        {
            throw new CesrFormatException($"Character '{character}' is not a valid Base64URL character.");
        }

        return value;
    }


    /// <summary>
    /// Whether a character is in the Base64URL alphabet, and so a valid character of a CESR text-domain
    /// primitive. Unlike <see cref="SextetOf(char)"/> this does not throw for a non-alphabet character; it
    /// returns <see langword="false"/>, for a caller validating untrusted input by shape rather than decoding it.
    /// </summary>
    /// <param name="character">The character to test.</param>
    /// <returns><see langword="true"/> when the character is a Base64URL character.</returns>
    public static bool IsBase64Url(char character) => character < 128 && Inverse[character] >= 0;


    private static sbyte[] BuildInverse()
    {
        var inverse = new sbyte[128];
        for(int i = 0; i < inverse.Length; i++)
        {
            inverse[i] = -1;
        }

        for(int i = 0; i < Characters.Length; i++)
        {
            inverse[Characters[i]] = (sbyte)i;
        }

        return inverse;
    }
}
