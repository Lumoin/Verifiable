namespace Verifiable.Core.Text;

/// <summary>
/// A location and category reported by <see cref="TextHygiene"/>.
/// <see cref="Offset"/> is a UTF-16 code-unit index for character input and a byte offset for UTF-8 input.
/// Categories follow <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44,
/// Table 12</see>, which calls Cs "a surrogate code point". Unicode data is the running runtime's;
/// Unassigned and PrivateUse answers can differ between runtimes.
/// </summary>
public readonly record struct TextHygieneFinding
{
    /// <summary>
    /// Creates the data for one <see cref="TextHygieneClass"/> occurrence without interpreting its offset unit.
    /// Cs is "a surrogate code point" in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
    /// </summary>
    /// <param name="offset">The input-relative UTF-16 code-unit index or UTF-8 byte offset.</param>
    /// <param name="codePoint">The scalar, lone surrogate code unit, or -1 for ill-formed UTF-8.</param>
    /// <param name="class">The category selected by the caller's rule.</param>
    public TextHygieneFinding(int offset, int codePoint, TextHygieneClass @class)
    {
        Offset = offset;
        CodePoint = codePoint;
        Class = @class;
    }

    /// <summary>
    /// Gets the input-relative UTF-16 code-unit index for character input or byte offset for UTF-8 input.
    /// The <see cref="TextHygiene"/> overload determines the unit; Cs, "a surrogate code point", in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>
    /// occupies one UTF-16 code unit when unpaired.
    /// </summary>
    public int Offset { get; }

    /// <summary>
    /// Gets the scalar or lone UTF-16 code unit; -1 means no code point exists because
    /// <see cref="Class"/> is <see cref="TextHygieneClass.IllFormedEncoding"/>.
    /// Cs means "a surrogate code point" in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
    /// </summary>
    public int CodePoint { get; }

    /// <summary>
    /// Gets the category selected by the <see cref="TextHygieneRule"/> that produced this occurrence.
    /// Cf is "a format control character" in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
    /// </summary>
    public TextHygieneClass Class { get; }
}
