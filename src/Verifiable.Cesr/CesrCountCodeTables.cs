namespace Verifiable.Cesr;

/// <summary>
/// The CESR count (group/framing) code table rules: the nested selector scheme that determines a count
/// code's sizing, the count bounds for a given soft size, and the protocol genus/version helpers.
/// </summary>
/// <remarks>
/// <para>
/// Unlike the fixed and variable primitive tables, a count code's sizing is a pure function of its
/// selector structure rather than a per-type entry, so it is computed rather than enumerated. Anchored on
/// the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#count-code-tables">
/// Count Code tables</see> and the <see href="https://trustoverip.github.io/kswg-cesr-specification/#encoding-scheme-table">
/// Encoding Scheme Table</see>: the first selector is always <c>-</c>; a second character of <c>A-Z a-z</c>
/// is a small count code, <c>-</c> is the large count code table, and <c>_</c> is the protocol genus/version
/// table. A second character of <c>0-9</c> selects a reserved (unspecified) count code table.
/// </para>
/// </remarks>
public static class CesrCountCodeTables
{
    /// <summary>
    /// The initial selector character of every count code ("-").
    /// </summary>
    public const char CountSelector = '-';

    /// <summary>
    /// The selector character reserved for the (yet-to-be-specified) op code tables ("_").
    /// </summary>
    public const char OpCodeSelector = '_';

    /// <summary>
    /// The two-character prefix of a protocol genus/version code ("-_"), whose remaining three hard
    /// characters are the protocol genus.
    /// </summary>
    public const string GenusVersionPrefix = "-_";

    /// <summary>
    /// The number of soft characters that carry the version in a protocol genus/version code: one for the
    /// major version and two for the minor version.
    /// </summary>
    public const int VersionSoftSize = 3;


    /// <summary>
    /// Computes the sizing of the count code that begins with the given two selector characters.
    /// </summary>
    /// <param name="first">The first character; for a count code this MUST be <see cref="CountSelector"/>.</param>
    /// <param name="second">The second character, which selects between the small, large, and genus/version tables.</param>
    /// <returns>The sizing for the selected count code table.</returns>
    /// <exception cref="CesrFormatException">The two characters do not begin a specified count code.</exception>
    public static CesrCountCodeSizing SizingForSelector(char first, char second)
    {
        if(first != CountSelector)
        {
            throw new CesrFormatException(first == OpCodeSelector
                ? "Unexpected op code where a CESR count code was expected."
                : $"Unsupported CESR count code selector '{first}'.");
        }

        return second switch
        {
            //Small count code: selector '-', type letter, two-character count. Code size 4.
            >= 'A' and <= 'Z' => new CesrCountCodeSizing(2, 2, 4),
            >= 'a' and <= 'z' => new CesrCountCodeSizing(2, 2, 4),

            //Large count code table: selectors '--', one type character, five-character count. Code size 8.
            CountSelector => new CesrCountCodeSizing(3, 5, 8),

            //Protocol genus/version table: selectors '-_', three genus characters, three version characters. Code size 8.
            OpCodeSelector => new CesrCountCodeSizing(5, VersionSoftSize, 8),

            //Numeral sub-selectors are reserved for as-yet-unspecified count code tables.
            >= '0' and <= '9' => throw new CesrFormatException($"CESR count code sub-selector '{second}' selects a reserved count code table."),

            _ => throw new CesrFormatException($"Unsupported CESR count code sub-selector '{second}'.")
        };
    }


    /// <summary>
    /// The largest count (or version) value a soft part of the given character width can hold, that is
    /// <c>64^softSize - 1</c>.
    /// </summary>
    /// <param name="softSize">The number of soft characters.</param>
    /// <returns>The inclusive maximum value.</returns>
    public static long MaxCount(int softSize)
    {
        long max = 1;
        for(int i = 0; i < softSize; i++)
        {
            max *= 64;
        }

        return max - 1;
    }


    /// <summary>
    /// Whether the given stable code is a protocol genus/version code (begins with <see cref="GenusVersionPrefix"/>
    /// and so does not count quadlets/triplets but instead modifies the protocol genus and version of the
    /// count codes that follow it).
    /// </summary>
    /// <param name="code">The stable (hard) code.</param>
    /// <returns><see langword="true"/> when the code is a genus/version code.</returns>
    public static bool IsGenusVersionCode(string code)
    {
        ArgumentNullException.ThrowIfNull(code);

        return code.Length == 5 && code.StartsWith(GenusVersionPrefix, StringComparison.Ordinal);
    }


    /// <summary>
    /// Packs a major and minor version into the soft value of a protocol genus/version code: the major
    /// version occupies the leading soft character and the minor version the trailing two.
    /// </summary>
    /// <param name="major">The major version, in the range 0 to 63.</param>
    /// <param name="minor">The minor version, in the range 0 to 4095.</param>
    /// <returns>The integer soft value (<c>major * 4096 + minor</c>).</returns>
    /// <exception cref="CesrFormatException">A version component is out of range.</exception>
    public static int PackVersion(int major, int minor)
    {
        if(major is < 0 or > 63)
        {
            throw new CesrFormatException($"Major version {major} is out of the range 0 to 63 for a genus/version code.");
        }

        if(minor is < 0 or > 4095)
        {
            throw new CesrFormatException($"Minor version {minor} is out of the range 0 to 4095 for a genus/version code.");
        }

        return (major * 4096) + minor;
    }


    /// <summary>
    /// Unpacks the soft value of a protocol genus/version code into its major and minor version components.
    /// </summary>
    /// <param name="version">The integer soft value, as produced by <see cref="PackVersion(int, int)"/>.</param>
    /// <returns>The major and minor version.</returns>
    public static (int Major, int Minor) UnpackVersion(int version)
    {
        return (version >> 12, version & 0xFFF);
    }
}
