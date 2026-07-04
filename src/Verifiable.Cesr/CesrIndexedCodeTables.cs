using System.Collections.Frozen;
using System.Collections.Generic;

namespace Verifiable.Cesr;

/// <summary>
/// The CESR indexed-signature code tables: the selector-to-hard-size map, the per-code size table, and the
/// set of codes whose signature appears in the current key list only (so their other-index is absent).
/// </summary>
/// <remarks>
/// <para>
/// The size entries are the REQUIRED indexed codes of the KERI/ACDC protocol stack genus, version 2.00,
/// anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#indexed-code-table-for-genusversion---aaacaa-keriacdc-protocol-stack-version-200">
/// Indexed code table</see>. The partitioning follows the unambiguous hard/soft/ondex/full/lead scheme and is
/// verified against the published conformance vectors.
/// </para>
/// </remarks>
public static class CesrIndexedCodeTables
{
    /// <summary>
    /// Maps the first (selector) character of an indexed code to the number of stable hard characters.
    /// </summary>
    public static FrozenDictionary<char, int> HardSizes { get; } = BuildHardSizes();

    /// <summary>
    /// Maps an indexed code's hard part to its <see cref="CesrIndexedCodeSizing"/>.
    /// </summary>
    public static FrozenDictionary<string, CesrIndexedCodeSizing> Sizes { get; } = BuildSizes();

    /// <summary>
    /// The codes whose signature appears in the current key list only; for these the other-index is always
    /// absent (decoded as <see langword="null"/>) and any stored other-index must be zero.
    /// </summary>
    public static FrozenSet<string> CurrentOnlyCodes { get; } = new[] { "B", "D", "F", "0B", "2B", "2D", "2F", "3B" }.ToFrozenSet();


    private static FrozenDictionary<char, int> BuildHardSizes()
    {
        var hards = new Dictionary<char, int>();
        for(char c = 'A'; c <= 'Z'; c++)
        {
            hards[c] = 1;
        }

        for(char c = 'a'; c <= 'z'; c++)
        {
            hards[c] = 1;
        }

        hards['0'] = 2;
        hards['1'] = 2;
        hards['2'] = 2;
        hards['3'] = 2;
        hards['4'] = 2;

        return hards.ToFrozenDictionary();
    }


    private static FrozenDictionary<string, CesrIndexedCodeSizing> BuildSizes()
    {
        //CesrIndexedCodeSizing is (HardSize, SoftSize, OndexSize, FullSize, LeadSize); FullSize null means variable.
        var sizes = new Dictionary<string, CesrIndexedCodeSizing>
        {
            //Indexed two-character codes (64-byte signatures, single index).
            ["A"] = new(1, 1, 0, 88, 0),
            ["B"] = new(1, 1, 0, 88, 0),
            ["C"] = new(1, 1, 0, 88, 0),
            ["D"] = new(1, 1, 0, 88, 0),
            ["E"] = new(1, 1, 0, 88, 0),
            ["F"] = new(1, 1, 0, 88, 0),

            //Indexed four-character codes (114-byte signatures, dual index).
            ["0A"] = new(2, 2, 1, 156, 0),
            ["0B"] = new(2, 2, 1, 156, 0),

            //Indexed six-character codes (64-byte signatures, big dual index).
            ["2A"] = new(2, 4, 2, 92, 0),
            ["2B"] = new(2, 4, 2, 92, 0),
            ["2C"] = new(2, 4, 2, 92, 0),
            ["2D"] = new(2, 4, 2, 92, 0),
            ["2E"] = new(2, 4, 2, 92, 0),
            ["2F"] = new(2, 4, 2, 92, 0),

            //Indexed eight-character codes (114-byte signatures, big dual index).
            ["3A"] = new(2, 6, 3, 160, 0),
            ["3B"] = new(2, 6, 3, 160, 0),

            //Variable and lead-bearing indexed codes.
            ["0z"] = new(2, 2, 0, null, 0),
            ["1z"] = new(2, 2, 1, 76, 1),
            ["4z"] = new(2, 6, 3, 80, 1),
        };

        return sizes.ToFrozenDictionary();
    }
}
