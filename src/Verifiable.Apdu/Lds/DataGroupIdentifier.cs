using System;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// Maps between the three ways an ICAO Doc 9303 eMRTD data group is named: its number (1-16), its
/// BER-TLV presence tag (as listed in EF.COM's tag list and used as the data group's template tag),
/// and its elementary file identifier (read from the chip).
/// </summary>
/// <remarks>
/// <para>
/// The file identifier is <c>0x0100 + number</c> (DG1 = <c>0x0101</c> … DG16 = <c>0x0110</c>). The
/// presence tag is mostly <c>0x60 + number</c>, but DG2 and DG4 — the face and iris biometric groups —
/// use the special tags <c>0x75</c> and <c>0x76</c> (Doc 9303 Part 10). This type bridges EF.COM's
/// tag list to the file identifiers a reader selects.
/// </para>
/// </remarks>
public static class DataGroupIdentifier
{
    /// <summary>The lowest data-group number.</summary>
    public const int MinimumNumber = 1;

    /// <summary>The highest data-group number.</summary>
    public const int MaximumNumber = 16;

    //Presence/template tag per data-group number, index = DG number.
    private static readonly byte[] TagByNumber =
    [
        0x00,                                                       // unused (index 0)
        0x61, 0x75, 0x63, 0x76, 0x65, 0x66, 0x67, 0x68,             // DG1..DG8
        0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70              // DG9..DG16
    ];


    /// <summary>
    /// The elementary file identifier of a data group (<c>0x0100 + number</c>).
    /// </summary>
    /// <param name="number">The data-group number, 1-16.</param>
    /// <returns>The two-byte elementary file identifier.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="number"/> is out of range.</exception>
    public static ushort FileIdentifierFromNumber(int number)
    {
        ThrowIfOutOfRange(number);

        return (ushort)(0x0100 + number);
    }


    /// <summary>
    /// The BER-TLV presence/template tag of a data group.
    /// </summary>
    /// <param name="number">The data-group number, 1-16.</param>
    /// <returns>The single-byte tag.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="number"/> is out of range.</exception>
    public static byte TagFromNumber(int number)
    {
        ThrowIfOutOfRange(number);

        return TagByNumber[number];
    }


    /// <summary>
    /// The data-group number for a BER-TLV presence tag, or <see langword="null"/> when the tag is not
    /// a known data-group tag.
    /// </summary>
    /// <param name="tag">The single-byte presence tag (for example from EF.COM's tag list).</param>
    /// <returns>The data-group number, or <see langword="null"/>.</returns>
    public static int? NumberFromTag(byte tag)
    {
        for(int number = MinimumNumber; number <= MaximumNumber; number++)
        {
            if(TagByNumber[number] == tag)
            {
                return number;
            }
        }

        return null;
    }


    /// <summary>
    /// Throws when <paramref name="number"/> is outside the valid data-group range.
    /// </summary>
    private static void ThrowIfOutOfRange(int number)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(number, MinimumNumber);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(number, MaximumNumber);
    }
}
