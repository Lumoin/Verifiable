using System.Collections.Frozen;
using System.Collections.Generic;

namespace Verifiable.Cesr;

/// <summary>
/// The CESR master code tables: the selector-to-hard-size map and the per-code size table. These are the
/// static, genus-specific data that tell a parser how to partition a code, and they drive both the text and
/// binary domain transcoders. The Base64URL mechanics those transcoders use live in
/// <see cref="Text.Base64UrlAlphabet"/> and <see cref="Text.CesrTextCodec"/>.
/// </summary>
/// <remarks>
/// <para>
/// The size entries are the REQUIRED codes of the KERI/ACDC protocol stack genus, version 2.00, anchored on
/// the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#master-code-table-for-genusversion--_aaacaa-keriacdc-protocol-stack-version-200">
/// Master code table for genus/version <c>-_AAACAA</c></see>. The specification's prose "Code Length" column
/// is inconsistent between fixed and soft-bearing rows, so the partitioning here follows the unambiguous
/// hard/soft/extra/full/lead scheme of the <see href="https://trustoverip.github.io/kswg-cesr-specification/#summary-of-selector-code-tables-and-encoding-scheme-design">
/// Encoding Scheme Table</see> and is verified against the published conformance vectors.
/// </para>
/// </remarks>
public static class CesrCodeTables
{
    /// <summary>
    /// Maps the first (selector) character of a code to the number of stable hard characters in that code.
    /// </summary>
    /// <remarks>
    /// Per the Encoding Scheme Table: the letters <c>A-Z a-z</c> are one-character codes; selector <c>0</c>
    /// is a two-character code; selectors <c>1 2 3</c> are four-character large fixed codes; selectors
    /// <c>4 5 6</c> are four-character small variable codes (two hard, two soft); selectors <c>7 8 9</c> are
    /// eight-character large variable codes (four hard, four soft).
    /// </remarks>
    public static FrozenDictionary<char, int> HardSizes { get; } = BuildHardSizes();

    /// <summary>
    /// Maps a code's hard part to its <see cref="CesrCodeSizing"/>.
    /// </summary>
    public static FrozenDictionary<string, CesrCodeSizing> Sizes { get; } = BuildSizes();


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
        hards['1'] = 4;
        hards['2'] = 4;
        hards['3'] = 4;
        hards['4'] = 2;
        hards['5'] = 2;
        hards['6'] = 2;
        hards['7'] = 4;
        hards['8'] = 4;
        hards['9'] = 4;

        return hards.ToFrozenDictionary();
    }


    private static FrozenDictionary<string, CesrCodeSizing> BuildSizes()
    {
        //CesrCodeSizing is (HardSize, SoftSize, ExtraSize, FullSize, LeadSize); FullSize null means variable.
        var sizes = new Dictionary<string, CesrCodeSizing>
        {
            //Basic one-character codes (selector is also the type; pad size 1).
            ["A"] = new(1, 0, 0, 44, 0),
            ["B"] = new(1, 0, 0, 44, 0),
            ["C"] = new(1, 0, 0, 44, 0),
            ["D"] = new(1, 0, 0, 44, 0),
            ["E"] = new(1, 0, 0, 44, 0),
            ["F"] = new(1, 0, 0, 44, 0),
            ["G"] = new(1, 0, 0, 44, 0),
            ["H"] = new(1, 0, 0, 44, 0),
            ["I"] = new(1, 0, 0, 44, 0),
            ["J"] = new(1, 0, 0, 44, 0),
            ["K"] = new(1, 0, 0, 76, 0),
            ["L"] = new(1, 0, 0, 76, 0),
            ["M"] = new(1, 0, 0, 4, 0),
            ["N"] = new(1, 0, 0, 12, 0),
            ["O"] = new(1, 0, 0, 44, 0),
            ["P"] = new(1, 0, 0, 124, 0),
            ["Q"] = new(1, 0, 0, 44, 0),
            ["R"] = new(1, 0, 0, 8, 0),
            ["S"] = new(1, 0, 0, 16, 0),
            ["T"] = new(1, 0, 0, 20, 0),
            ["U"] = new(1, 0, 0, 24, 0),
            ["V"] = new(1, 0, 0, 4, 1),
            ["W"] = new(1, 0, 0, 4, 0),
            ["X"] = new(1, 3, 0, 4, 0),
            ["Y"] = new(1, 7, 0, 8, 0),
            ["Z"] = new(1, 11, 0, 12, 0),
            ["a"] = new(1, 0, 0, 44, 0),
            ["b"] = new(1, 3, 0, 8, 0),

            //Basic two-character codes (selector 0; pad size 2).
            ["0A"] = new(2, 0, 0, 24, 0),
            ["0B"] = new(2, 0, 0, 88, 0),
            ["0C"] = new(2, 0, 0, 88, 0),
            ["0D"] = new(2, 0, 0, 88, 0),
            ["0E"] = new(2, 0, 0, 88, 0),
            ["0F"] = new(2, 0, 0, 88, 0),
            ["0G"] = new(2, 0, 0, 88, 0),
            ["0H"] = new(2, 0, 0, 8, 0),
            ["0I"] = new(2, 0, 0, 88, 0),
            ["0J"] = new(2, 2, 1, 4, 0),
            ["0K"] = new(2, 2, 0, 4, 0),
            ["0L"] = new(2, 6, 1, 8, 0),
            ["0M"] = new(2, 6, 0, 8, 0),
            ["0N"] = new(2, 10, 1, 12, 0),
            ["0O"] = new(2, 10, 0, 12, 0),

            //Large fixed four-character codes (selectors 1/2/3 encode lead size 0/1/2).
            ["1AAA"] = new(4, 0, 0, 48, 0),
            ["1AAB"] = new(4, 0, 0, 48, 0),
            ["1AAC"] = new(4, 0, 0, 80, 0),
            ["1AAD"] = new(4, 0, 0, 80, 0),
            ["1AAE"] = new(4, 0, 0, 156, 0),
            ["1AAF"] = new(4, 4, 0, 8, 0),
            ["1AAG"] = new(4, 0, 0, 36, 0),
            ["1AAH"] = new(4, 0, 0, 100, 0),
            ["1AAI"] = new(4, 0, 0, 48, 0),
            ["1AAJ"] = new(4, 0, 0, 48, 0),
            ["1AAK"] = new(4, 0, 0, 4, 0),
            ["1AAL"] = new(4, 0, 0, 4, 0),
            ["1AAM"] = new(4, 0, 0, 4, 0),
            ["1AAN"] = new(4, 8, 0, 12, 0),
            ["1AAO"] = new(4, 0, 0, 4, 0),
            ["1AAP"] = new(4, 0, 0, 4, 0),

            //Version-string codes.
            ["1__-"] = new(4, 2, 0, 12, 0),
            ["1___"] = new(4, 0, 0, 8, 0),
            ["2__-"] = new(4, 2, 0, 12, 1),
            ["2___"] = new(4, 0, 0, 8, 1),
            ["3__-"] = new(4, 2, 0, 12, 2),
            ["3___"] = new(4, 0, 0, 8, 2),

            //Small variable-length codes (selectors 4/5/6 encode lead size 0/1/2).
            ["4A"] = new(2, 2, 0, null, 0),
            ["5A"] = new(2, 2, 0, null, 1),
            ["6A"] = new(2, 2, 0, null, 2),
            ["4B"] = new(2, 2, 0, null, 0),
            ["5B"] = new(2, 2, 0, null, 1),
            ["6B"] = new(2, 2, 0, null, 2),
            ["4C"] = new(2, 2, 0, null, 0),
            ["5C"] = new(2, 2, 0, null, 1),
            ["6C"] = new(2, 2, 0, null, 2),
            ["4D"] = new(2, 2, 0, null, 0),
            ["5D"] = new(2, 2, 0, null, 1),
            ["6D"] = new(2, 2, 0, null, 2),
            ["4E"] = new(2, 2, 0, null, 0),
            ["5E"] = new(2, 2, 0, null, 1),
            ["6E"] = new(2, 2, 0, null, 2),
            ["4F"] = new(2, 2, 0, null, 0),
            ["5F"] = new(2, 2, 0, null, 1),
            ["6F"] = new(2, 2, 0, null, 2),
            ["4H"] = new(2, 2, 0, null, 0),
            ["5H"] = new(2, 2, 0, null, 1),
            ["6H"] = new(2, 2, 0, null, 2),

            //Large variable-length codes (selectors 7/8/9 encode lead size 0/1/2).
            ["7AAA"] = new(4, 4, 0, null, 0),
            ["8AAA"] = new(4, 4, 0, null, 1),
            ["9AAA"] = new(4, 4, 0, null, 2),
            ["7AAB"] = new(4, 4, 0, null, 0),
            ["8AAB"] = new(4, 4, 0, null, 1),
            ["9AAB"] = new(4, 4, 0, null, 2),
            ["7AAC"] = new(4, 4, 0, null, 0),
            ["8AAC"] = new(4, 4, 0, null, 1),
            ["9AAC"] = new(4, 4, 0, null, 2),
            ["7AAD"] = new(4, 4, 0, null, 0),
            ["8AAD"] = new(4, 4, 0, null, 1),
            ["9AAD"] = new(4, 4, 0, null, 2),
            ["7AAE"] = new(4, 4, 0, null, 0),
            ["8AAE"] = new(4, 4, 0, null, 1),
            ["9AAE"] = new(4, 4, 0, null, 2),
            ["7AAF"] = new(4, 4, 0, null, 0),
            ["8AAF"] = new(4, 4, 0, null, 1),
            ["9AAF"] = new(4, 4, 0, null, 2),
            ["7AAH"] = new(4, 4, 0, null, 0),
            ["8AAH"] = new(4, 4, 0, null, 1),
            ["9AAH"] = new(4, 4, 0, null, 2),
        };

        return sizes.ToFrozenDictionary();
    }
}
