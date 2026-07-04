using System.Globalization;
using System.Text.RegularExpressions;
using Verifiable.Cesr.Text;

namespace Verifiable.Cesr;

/// <summary>
/// Finds and decodes the version string that prefixes a non-native (JSON, CBOR, or MGPK) field map interleaved
/// in a CESR stream. The version string is the value of the leading <c>v</c> field; it is a fixed-width ASCII
/// run a parser locates by regular expression, and it carries the serialization kind and the total length of
/// the serialization, so a parser can offload a whole non-native message without first deserializing it.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#version-string-field">
/// Version String field</see>. Two formats are supported: the version 2.XX format <c>PPPPMmmGggKKKKBBBB.</c>
/// (19 characters, total length <c>BBBB</c> as a four-character base-64 number, terminator <c>.</c>) and the
/// legacy version 1.XX format <c>PPPPvvKKKKllllll_</c> (17 characters, total length <c>llllll</c> as six
/// lowercase hexadecimal characters, terminator <c>_</c>). Only the serialization kind and total length are
/// read; the opaque protocol and version parts are left for a protocol-genus-aware consumer to interpret. The
/// length is inclusive of the version string and any framing that precedes it, so it is the full byte count of
/// the interleaved serialization.
/// </para>
/// </remarks>
public static partial class CesrVersionString
{
    /// <summary>
    /// The character offset of the <c>KKKK</c> serialization-kind part within a version 2.XX match
    /// (after <c>PPPP</c>, <c>Mmm</c>, and <c>Ggg</c>).
    /// </summary>
    private const int Version2KindOffset = 10;

    /// <summary>
    /// The character offset of the <c>BBBB</c> length part within a version 2.XX match.
    /// </summary>
    private const int Version2LengthOffset = 14;

    /// <summary>
    /// The character offset of the <c>KKKK</c> serialization-kind part within a legacy version 1.XX match
    /// (after <c>PPPP</c> and <c>vv</c>).
    /// </summary>
    private const int Version1KindOffset = 6;

    /// <summary>
    /// The character offset of the <c>llllll</c> length part within a legacy version 1.XX match.
    /// </summary>
    private const int Version1LengthOffset = 10;

    /// <summary>
    /// The number of characters in the <c>llllll</c> length part of a legacy version 1.XX version string.
    /// </summary>
    private const int Version1LengthSize = 6;

    /// <summary>
    /// The number of characters in the <c>BBBB</c> length part of a version 2.XX version string.
    /// </summary>
    private const int Version2LengthSize = 4;

    /// <summary>
    /// The number of characters in the <c>KKKK</c> serialization-kind part of either version string format.
    /// </summary>
    private const int KindSize = 4;


    /// <summary>
    /// The version 2.XX version string pattern: protocol, protocol version, genus version, serialization kind,
    /// and base-64 length, terminated by <c>.</c> (CESR specification, Version String field, version 2.XX).
    /// </summary>
    [GeneratedRegex("[A-Z]{4}[A-Za-z0-9_-]{6}(JSON|CBOR|MGPK)[A-Za-z0-9_-]{4}\\.")]
    private static partial Regex Version2Pattern();


    /// <summary>
    /// The legacy version 1.XX version string pattern: protocol, version, serialization kind, and hexadecimal
    /// length, terminated by <c>_</c> (CESR specification, Version String field, legacy version 1.XX).
    /// </summary>
    [GeneratedRegex("[A-Z]{4}[0-9a-f]{2}(JSON|CBOR|MGPK)[0-9a-f]{6}_")]
    private static partial Regex Version1Pattern();


    /// <summary>
    /// Tries to find the leading version string in the start of a non-native serialization and read the
    /// serialization kind and total length it conveys.
    /// </summary>
    /// <param name="text">The start of the serialization, as ASCII characters; the version string is the first field.</param>
    /// <param name="kind">The serialization kind, when found.</param>
    /// <param name="totalLength">The total length of the serialization in bytes (inclusive of the version string), when found.</param>
    /// <param name="matchStart">The character offset at which the version string begins, when found. A caller MUST verify
    /// this offset is where its serialization's leading version field's value sits; this method only locates a version
    /// string by shape and does not confirm it is the leading field rather than a look-alike in a later field's value.</param>
    /// <returns><see langword="true"/> when a version string is found; otherwise <see langword="false"/>.</returns>
    /// <exception cref="CesrFormatException">A version string is found but carries an unsupported serialization kind.</exception>
    public static bool TryFind(ReadOnlySpan<char> text, out CesrSerializationKind kind, out int totalLength, out int matchStart)
    {
        foreach(ValueMatch match in Version2Pattern().EnumerateMatches(text))
        {
            ReadOnlySpan<char> matched = text.Slice(match.Index, match.Length);
            kind = KindOf(matched.Slice(Version2KindOffset, KindSize));
            totalLength = (int)CesrTextCodec.Base64ToInt(matched.Slice(Version2LengthOffset, Version2LengthSize));
            matchStart = match.Index;

            return true;
        }

        foreach(ValueMatch match in Version1Pattern().EnumerateMatches(text))
        {
            ReadOnlySpan<char> matched = text.Slice(match.Index, match.Length);
            kind = KindOf(matched.Slice(Version1KindOffset, KindSize));
            totalLength = int.Parse(matched.Slice(Version1LengthOffset, Version1LengthSize), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            matchStart = match.Index;

            return true;
        }

        kind = CesrSerializationKind.None;
        totalLength = 0;
        matchStart = 0;

        return false;
    }


    /// <summary>
    /// Returns the version string with its total-length field set to the given byte count, leaving the protocol,
    /// version, genus, serialization kind, and terminator unchanged. This is the inverse of the length
    /// <see cref="TryFind(ReadOnlySpan{char}, out CesrSerializationKind, out int, out int)"/> reads, used to stamp the size
    /// of a serialization back into its own leading version string (the size is part of the bytes the size counts).
    /// </summary>
    /// <param name="versionString">A complete version string in either the version 2.XX or legacy version 1.XX format.</param>
    /// <param name="totalLength">The total length of the serialization in bytes, inclusive of the version string.</param>
    /// <returns>The version string with its length field replaced.</returns>
    /// <exception cref="CesrFormatException">The input is not a recognized CESR version string.</exception>
    public static string WithLength(ReadOnlySpan<char> versionString, int totalLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(totalLength);

        foreach(ValueMatch match in Version2Pattern().EnumerateMatches(versionString))
        {
            if(match.Index == 0 && match.Length == versionString.Length)
            {
                return Stamp(versionString, Version2LengthOffset, CesrTextCodec.IntToBase64(totalLength, Version2LengthSize));
            }
        }

        foreach(ValueMatch match in Version1Pattern().EnumerateMatches(versionString))
        {
            if(match.Index == 0 && match.Length == versionString.Length)
            {
                return Stamp(versionString, Version1LengthOffset, totalLength.ToString("x6", CultureInfo.InvariantCulture));
            }
        }

        throw new CesrFormatException($"'{new string(versionString)}' is not a recognized CESR version string.");

        static string Stamp(ReadOnlySpan<char> source, int offset, string lengthField)
        {
            Span<char> result = stackalloc char[source.Length];
            source.CopyTo(result);
            lengthField.CopyTo(result.Slice(offset, lengthField.Length));

            return new string(result);
        }
    }


    private static CesrSerializationKind KindOf(ReadOnlySpan<char> kind) => kind switch
    {
        "JSON" => CesrSerializationKind.Json,
        "CBOR" => CesrSerializationKind.Cbor,
        "MGPK" => CesrSerializationKind.Mgpk,
        _ => throw new CesrFormatException($"Unsupported non-native serialization kind '{new string(kind)}' in a CESR version string.")
    };
}
