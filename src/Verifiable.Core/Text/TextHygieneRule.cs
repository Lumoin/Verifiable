using System.Collections.Frozen;

namespace Verifiable.Core.Text;

/// <summary>
/// An immutable selection of <see cref="TextHygieneClass"/> values to report or escape,
/// with code-point exceptions. <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44,
/// Table 12</see> defines Cf as "a format control character"; selecting categories is the caller's policy.
/// The running runtime supplies Unicode data, so Unassigned and PrivateUse answers can differ between runtimes.
/// </summary>
public sealed class TextHygieneRule
{
    /// <summary>
    /// Creates a rule by snapshotting the selected <see cref="TextHygieneClass"/> values and exceptions.
    /// The categories are those of <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44,
    /// Table 12</see>, including Cf, "a format control character"; an allowed code point takes precedence.
    /// </summary>
    /// <param name="classes">The classes to report or escape.</param>
    /// <param name="allowedCodePoints">Allowed scalar values or lone UTF-16 code units.</param>
    /// <exception cref="ArgumentNullException">Either collection is null.</exception>
    public TextHygieneRule(IEnumerable<TextHygieneClass> classes, IEnumerable<int> allowedCodePoints)
    {
        ArgumentNullException.ThrowIfNull(classes);
        ArgumentNullException.ThrowIfNull(allowedCodePoints);
        Classes = classes.ToFrozenSet();
        AllowedCodePoints = allowedCodePoints.ToFrozenSet();
    }

    /// <summary>
    /// Gets the classes selected for reporting by <see cref="TextHygiene"/>, including any encoding failures.
    /// Cf is "a format control character" in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
    /// </summary>
    public FrozenSet<TextHygieneClass> Classes { get; }

    /// <summary>
    /// Gets code points exempt from <see cref="Classes"/>. Ill-formed UTF-8 has no code point
    /// and cannot be exempted through this set. A code point can exempt a selected Cc,
    /// "a C0 or C1 control code", from
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
    /// </summary>
    public FrozenSet<int> AllowedCodePoints { get; }

    /// <summary>
    /// Gets the rule selecting controls, formatting, line and paragraph separators, the Tags block,
    /// unpaired surrogates and ill-formed UTF-8. Cf is "a format control character" in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
    /// </summary>
    public static TextHygieneRule Default { get; } = new(
        [TextHygieneClass.Control, TextHygieneClass.Format, TextHygieneClass.LineSeparator,
         TextHygieneClass.ParagraphSeparator, TextHygieneClass.Tag, TextHygieneClass.UnpairedSurrogate,
         TextHygieneClass.IllFormedEncoding], []);

    /// <summary>
    /// Gets <see cref="Default"/> with tab, line feed and carriage return allowed for display layout.
    /// Each is "a C0 or C1 control code" under
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
    /// </summary>
    public static TextHygieneRule DisplayText { get; } = new(Default.Classes, [0x0009, 0x000A, 0x000D]);

    /// <summary>
    /// Gets <see cref="Default"/> plus Co, "a private-use character", and Cn,
    /// "a reserved unassigned code point or a noncharacter", from
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
    /// These categories depend on the running runtime's Unicode data.
    /// </summary>
    public static TextHygieneRule Strict { get; } = new(
        [.. Default.Classes, TextHygieneClass.PrivateUse, TextHygieneClass.Unassigned], []);
}
