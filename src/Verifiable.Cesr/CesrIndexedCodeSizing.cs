namespace Verifiable.Cesr;

/// <summary>
/// The size descriptor for a CESR indexed-signature code. Indexed codes are a context-specific coding scheme
/// whose soft part carries one or two indices (an index, and optionally an other-index "ondex" for dual
/// indexing) rather than a length or special value.
/// </summary>
/// <param name="HardSize">The number of stable text characters in the code ("hs").</param>
/// <param name="SoftSize">The total number of soft characters, covering the index and any ondex ("ss").</param>
/// <param name="OndexSize">The number of characters dedicated to the other-index ("os"); zero when single-indexed.</param>
/// <param name="FullSize">The total text size for a fixed-size code, or <see langword="null"/> when variable.</param>
/// <param name="LeadSize">The number of zero-valued lead bytes prepended to the raw value ("ls").</param>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#indexed-codes">
/// Indexed codes</see> section and the indexed code table. The common use is thresholded multi-signatures,
/// where each signature is associated with its public key by index; dual indexing (index and ondex) supports
/// pre-rotation with partial rotation, where a signature contributes to two key lists at different positions.
/// </para>
/// </remarks>
public readonly record struct CesrIndexedCodeSizing(int HardSize, int SoftSize, int OndexSize, int? FullSize, int LeadSize)
{
    /// <summary>
    /// The combined size of the code (hard plus soft characters, "cs").
    /// </summary>
    public int CodeSize => HardSize + SoftSize;

    /// <summary>
    /// The number of characters dedicated to the main index ("ms"), that is the soft size less the ondex size.
    /// </summary>
    public int MainIndexSize => SoftSize - OndexSize;

    /// <summary>
    /// Whether this code is variable-sized (its full size is determined by the index used as a length).
    /// </summary>
    public bool IsVariable => FullSize is null;
}
