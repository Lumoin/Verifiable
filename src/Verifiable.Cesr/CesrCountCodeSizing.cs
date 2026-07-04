namespace Verifiable.Cesr;

/// <summary>
/// The size descriptor for a CESR count (group/framing) code. A count code is a special primitive that
/// carries no raw value: its soft part holds a count of the quadlets/triplets in the group that follows
/// (or, for the genus/version code, a protocol version), and its full size equals the code size.
/// </summary>
/// <param name="HardSize">
/// The number of stable text characters in the code ("hs"): two for a small count code (<c>-X</c>), three
/// for a large count code (<c>--X</c>), and five for a protocol genus/version code (<c>-_GGG</c>).
/// </param>
/// <param name="SoftSize">
/// The number of variable text characters following the hard part ("ss"): the count (or version) as a
/// Base64URL integer. Two for small, five for large, three for genus/version.
/// </param>
/// <param name="FullSize">
/// The total number of text characters in the code ("fs"). For a count code this always equals
/// <see cref="CodeSize"/> (there is no raw value) and is always a multiple of four.
/// </param>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#count-code-tables">
/// Count Code tables</see>: "Count Codes MUST NOT have a value component but MUST have only type and size
/// components", and each count code "MUST be aligned on a 24-bit boundary" so its pad size is always zero.
/// </para>
/// </remarks>
public readonly record struct CesrCountCodeSizing(int HardSize, int SoftSize, int FullSize)
{
    /// <summary>
    /// The combined size of the code (hard plus soft characters, "cs"). For a count code this equals
    /// <see cref="FullSize"/> because there is no raw value beyond the code.
    /// </summary>
    public int CodeSize => HardSize + SoftSize;
}
