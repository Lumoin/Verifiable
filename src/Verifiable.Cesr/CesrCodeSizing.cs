namespace Verifiable.Cesr;

/// <summary>
/// The size descriptor for a single CESR code: how the fully qualified primitive is partitioned into a
/// stable code part, an optional variable size or special-value part, and the converted raw value.
/// </summary>
/// <param name="HardSize">
/// The number of stable text characters in the code (the selector and type, "hs"). These characters are
/// fixed for a given code and are what a parser reads first to look the code up.
/// </param>
/// <param name="SoftSize">
/// The number of variable text characters following the hard part (the size or special-value characters,
/// "ss"). Zero for ordinary fixed primitives; non-zero for variable-length codes (a Base64URL count of
/// quadlets/triplets) and for special fixed codes that carry a value in the code itself.
/// </param>
/// <param name="ExtraSize">
/// The number of leading pad characters within the soft part ("xs"), present only for certain special
/// codes whose value would otherwise straddle a character boundary. These pad characters MUST be the
/// Base64URL <c>_</c> character and are not part of the conveyed soft value.
/// </param>
/// <param name="FullSize">
/// The total number of text characters in the fully qualified primitive ("fs") for a fixed-size code, or
/// <see langword="null"/> for a variable-size code whose full size is computed at parse time from the soft
/// count. For fixed codes this is always a multiple of four (the 24-bit composability boundary).
/// </param>
/// <param name="LeadSize">
/// The number of zero-valued lead bytes ("ls", 0, 1, or 2) prepended to the raw value in the binary domain
/// so that the lead-plus-raw length aligns on a 24-bit (three-byte) boundary.
/// </param>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#summary-of-selector-code-tables-and-encoding-scheme-design">
/// Summary of Selector code tables and encoding scheme design</see> (the Encoding Scheme Table) and the
/// <see href="https://trustoverip.github.io/kswg-cesr-specification/#master-code-table-for-genusversion--_aaacaa-keriacdc-protocol-stack-version-200">
/// Master code table</see>. The naming hard/soft/full/lead mirrors the specification's own terminology.
/// </para>
/// </remarks>
public readonly record struct CesrCodeSizing(int HardSize, int SoftSize, int ExtraSize, int? FullSize, int LeadSize)
{
    /// <summary>
    /// The combined size of the code (hard plus soft characters, "cs"). This is where the converted raw
    /// value begins in the text domain.
    /// </summary>
    public int CodeSize => HardSize + SoftSize;

    /// <summary>
    /// Whether this code is variable-sized (its full size is determined by the soft count at parse time
    /// rather than fixed by the code).
    /// </summary>
    public bool IsVariable => FullSize is null;

    /// <summary>
    /// Whether this code is a special fixed code that carries its value in the soft part of the code while
    /// having an empty raw value (a fixed full size together with a non-zero soft size).
    /// </summary>
    public bool IsSpecial => FullSize is not null && SoftSize > 0;

    /// <summary>
    /// The number of raw value bytes a fixed-size code carries — the value recovered after removing the code
    /// characters, the net pad, and the lead bytes — or <see langword="null"/> for a variable-size code whose
    /// raw size is not fixed by the code. For a digest code this is the digest length (for example 32 bytes
    /// for the 44-character Blake3-256 code <c>E</c>).
    /// </summary>
    public int? RawSize
    {
        get
        {
            if(FullSize is not int fullSize)
            {
                return null;
            }

            int padSize = CodeSize % 4;
            int valueChars = fullSize - CodeSize;

            return (((padSize + valueChars) * 3) / 4) - padSize - LeadSize;
        }
    }
}
