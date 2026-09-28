namespace Verifiable.Core.Text;

/// <summary>
/// What a code point does when shown, as <see cref="TextHygiene"/> reports it: the class a
/// <see cref="TextHygieneRule"/> selects to refuse or escape. <see cref="Tag"/> is a fixed range and is classified
/// first; every other scalar takes its general category from the running runtime's Unicode data, so a code point
/// assigned in a later Unicode version (a new Cf, for example) reads as Cn on an older runtime: it passes
/// <see cref="TextHygieneRule.Default"/> unflagged and <see cref="TextHygieneRule.Strict"/> reports it as
/// <see cref="Unassigned"/>.
/// </summary>
/// <remarks>
/// <para>
/// No class covers these code points, which act when shown without being controls or format characters, so every
/// rule, <see cref="TextHygieneRule.Strict"/> included, passes them and <see cref="TextHygiene.EscapeVisibly"/>
/// writes them unchanged:
/// </para>
/// <list type="bullet">
/// <item><description>The variation selectors U+180B..U+180D, U+180F, U+FE00..U+FE0F and U+E0100..U+E01EF. They
/// render as nothing, and a run of the 240 supplementary selectors after a base character carries a hidden payload
/// the way the Tags block does.</description></item>
/// <item><description>The assigned default-ignorable code points outside Cf: U+034F, U+115F, U+1160, U+17B4,
/// U+17B5, U+3164 and U+FFA0, which also render as nothing.</description></item>
/// <item><description>Combining marks, stacked or not; whitespace look-alikes (Zs such as U+2000..U+200A and
/// U+3000); U+2800 BRAILLE PATTERN BLANK; and confusable characters.</description></item>
/// </list>
/// <para>
/// The reserved default-ignorable code points (U+2065, U+FFF0..U+FFF8, U+E0080..U+E00FF and U+E01F0..U+E0FFF) are
/// <see cref="Unassigned"/> while the running runtime has not assigned them, so only
/// <see cref="TextHygieneRule.Strict"/> reports them.
/// </para>
/// </remarks>
public enum TextHygieneClass
{
    /// <summary>
    /// Cc, "a C0 or C1 control code", in
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see>.
    /// </summary>
    Control,

    /// <summary>
    /// Cf, "a format control character", in
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see>.
    /// This includes embeddings, overrides and isolates in
    /// <see href="https://www.unicode.org/reports/tr9/#Explicit_Directional_Embeddings">UAX #9, Sections 2.1-2.5</see>
    /// and marks in <see href="https://www.unicode.org/reports/tr9/#Implicit_Directional_Marks">Section 2.6</see>.
    /// The category is the running runtime's: a Cf character assigned in a later Unicode version reads as
    /// <see cref="Unassigned"/> on an older runtime.
    /// </summary>
    Format,

    /// <summary>
    /// Zl, "U+2028 LINE SEPARATOR only", in
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see>.
    /// </summary>
    LineSeparator,

    /// <summary>
    /// Zp, "U+2029 PARAGRAPH SEPARATOR only", in
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see>.
    /// </summary>
    ParagraphSeparator,

    /// <summary>
    /// Any code point in "E0000..E007F; Tags", assigned or unassigned, from
    /// <see href="https://www.unicode.org/Public/UCD/latest/ucd/Blocks.txt">the Tags block</see>.
    /// The range is fixed, so the class does not depend on the runtime's Unicode data, and it takes
    /// precedence over the general category.
    /// </summary>
    Tag,

    /// <summary>
    /// A lone UTF-16 code unit in D800..DFFF. Unicode core
    /// <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G25660">D91</see> states
    /// "Because surrogate code points are not Unicode scalar values, isolated UTF-16 code units in the range"
    /// D800 to DFFF (hexadecimal) "are ill-formed." A paired surrogate instead contributes to its scalar's class.
    /// </summary>
    UnpairedSurrogate,

    /// <summary>
    /// Co, "a private-use character", in
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see>.
    /// </summary>
    PrivateUse,

    /// <summary>
    /// Cn, "a reserved unassigned code point or a noncharacter", in
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see>,
    /// as the running runtime's Unicode data reports it. The noncharacters (U+FDD0..U+FDEF and the last two code
    /// points of every plane) are Cn in every Unicode version; a reserved code point leaves this class on a runtime
    /// whose Unicode data assigns it.
    /// </summary>
    Unassigned,

    /// <summary>
    /// A maximal subpart of an ill-formed UTF-8 sequence, which has no code point.
    /// <see href="https://www.rfc-editor.org/rfc/rfc3629#section-3">RFC 3629, Section 3</see> states:
    /// "Implementations of the decoding algorithm above MUST protect against decoding invalid sequences."
    /// Unicode core <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G55471">D93b</see>
    /// defines the maximal subpart as "The longest code unit subsequence starting at an unconvertible offset that is
    /// either: a. the initial subsequence of a well-formed code unit sequence, or b. a subsequence of length one."
    /// </summary>
    IllFormedEncoding
}
