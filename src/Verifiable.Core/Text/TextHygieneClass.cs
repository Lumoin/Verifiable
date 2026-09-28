namespace Verifiable.Core.Text;

/// <summary>
/// A display-relevant category reported by <see cref="TextHygiene"/>.
/// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>
/// calls Cf "a format control character". Categories use the running runtime's Unicode data;
/// <see cref="Unassigned"/> and <see cref="PrivateUse"/> answers can differ between runtimes.
/// </summary>
public enum TextHygieneClass
{
    /// <summary>
    /// Cc, "a C0 or C1 control code", in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
    /// </summary>
    Control,

    /// <summary>
    /// Cf, "a format control character", in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
    /// This includes embeddings, overrides and isolates in
    /// <see href="https://www.unicode.org/reports/tr9/#Explicit_Directional_Embeddings">UAX #9, Sections 2.1-2.5</see>
    /// and marks in <see href="https://www.unicode.org/reports/tr9/#Implicit_Directional_Marks">Section 2.6</see>.
    /// </summary>
    Format,

    /// <summary>
    /// Zl, "U+2028 LINE SEPARATOR only", in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
    /// </summary>
    LineSeparator,

    /// <summary>
    /// Zp, "U+2029 PARAGRAPH SEPARATOR only", in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
    /// </summary>
    ParagraphSeparator,

    /// <summary>
    /// Any code point in "E0000..E007F; Tags", assigned or unassigned, from
    /// <see href="https://www.unicode.org/Public/UCD/latest/ucd/Blocks.txt">the Tags block</see>.
    /// This block takes precedence over the general category.
    /// </summary>
    Tag,

    /// <summary>
    /// A lone UTF-16 code unit in Cs, "a surrogate code point", from
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
    /// A paired surrogate instead contributes to its scalar's category.
    /// </summary>
    UnpairedSurrogate,

    /// <summary>
    /// Co, "a private-use character", in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>,
    /// as classified by the running runtime's Unicode data.
    /// </summary>
    PrivateUse,

    /// <summary>
    /// Cn, "a reserved unassigned code point or a noncharacter", in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>,
    /// as classified by the running runtime's Unicode data.
    /// </summary>
    Unassigned,

    /// <summary>
    /// An ill-formed UTF-8 sequence for which <see cref="System.Text.Rune.DecodeFromUtf8"/>
    /// yields no scalar. This is an encoding failure, separate from the categories in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>,
    /// which defines Cs as "a surrogate code point".
    /// </summary>
    IllFormedEncoding
}
