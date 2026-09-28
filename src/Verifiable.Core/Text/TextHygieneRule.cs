using System.Collections.Frozen;

namespace Verifiable.Core.Text;

/// <summary>
/// An immutable selection of <see cref="TextHygieneClass"/> values that <see cref="TextHygiene"/> reports or escapes,
/// with code points exempt from that selection. Which classes a reader must not be shown is the caller's policy;
/// <see cref="Default"/>, <see cref="DisplayText"/> and <see cref="Strict"/> are the presets, and
/// <see cref="Create"/> builds any other rule after refusing one that could never select anything it names.
/// A rule selects only what its classes cover: the remarks of <see cref="TextHygieneClass"/> list the code points
/// that act when shown and that no class covers, so no rule is a complete display sanitizer.
/// </summary>
public sealed class TextHygieneRule
{
    /// <summary>
    /// The largest value in the Unicode codespace. Unicode core
    /// <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G22696">D9</see> defines the
    /// codespace as "A range of integers from 0 to" 10FFFF (hexadecimal), and an exception outside it can match nothing.
    /// </summary>
    private static int MaximumCodePoint { get; } = 0x10FFFF;

    /// <summary>
    /// Stores the snapshots of a rule whose values are already known to be usable.
    /// </summary>
    /// <param name="classes">The classes to report or escape.</param>
    /// <param name="allowedCodePoints">The exempt code points.</param>
    private TextHygieneRule(FrozenSet<TextHygieneClass> classes, FrozenSet<int> allowedCodePoints)
    {
        Classes = classes;
        AllowedCodePoints = allowedCodePoints;
    }

    /// <summary>
    /// Gets the classes <see cref="TextHygiene"/> reports or escapes. The set is an immutable snapshot.
    /// </summary>
    public IReadOnlySet<TextHygieneClass> Classes { get; }

    /// <summary>
    /// Gets the code points exempt from <see cref="Classes"/>. An exception overrides every class, including
    /// <see cref="TextHygieneClass.Format"/>, <see cref="TextHygieneClass.Tag"/> and
    /// <see cref="TextHygieneClass.UnpairedSurrogate"/> (a value in D800..DFFF exempts that lone UTF-16 code unit),
    /// and exempting U+2028 or U+2029 exempts a whole class; these are the caller's choice, so a caller that exempts
    /// U+202E shows the reader a real override. A carriage return directly followed by a line feed is one line break
    /// and is exempt whenever the line feed is. An ill-formed UTF-8 subpart has no code point, so no exception
    /// reaches <see cref="TextHygieneClass.IllFormedEncoding"/>. The set is an immutable snapshot.
    /// </summary>
    public IReadOnlySet<int> AllowedCodePoints { get; }

    /// <summary>
    /// Gets the rule for text a reader must not be misled by: controls, format characters, line and paragraph
    /// separators, the Tags block, unpaired surrogates and ill-formed UTF-8. It passes the variation selectors, the
    /// default-ignorable code points outside Cf, combining marks, whitespace look-alikes, U+2800 and confusable
    /// characters, which no class covers (see <see cref="TextHygieneClass"/>), and a code point assigned after the
    /// running runtime's Unicode version, which reads as Cn.
    /// </summary>
    public static TextHygieneRule Default { get; } = new(
        new[]
        {
            TextHygieneClass.Control, TextHygieneClass.Format, TextHygieneClass.LineSeparator,
            TextHygieneClass.ParagraphSeparator, TextHygieneClass.Tag, TextHygieneClass.UnpairedSurrogate,
            TextHygieneClass.IllFormedEncoding
        }.ToFrozenSet(),
        FrozenSet<int>.Empty);

    /// <summary>
    /// Gets <see cref="Default"/> with tab and line feed allowed for display layout, and a carriage return allowed
    /// only as the first half of a CRLF line break. A lone carriage return stays a
    /// <see cref="TextHygieneClass.Control"/> finding: shown on a terminal or any line-oriented display it returns to
    /// the start of the line, and the text after it overwrites what the reader saw. A line feed starts a new line, so a
    /// partner's text can begin a line that reads as a separate record; a caller that frames records by line uses
    /// <see cref="Default"/>.
    /// </summary>
    public static TextHygieneRule DisplayText { get; } = new(Default.Classes.ToFrozenSet(), new[] { 0x0009, 0x000A }.ToFrozenSet());

    /// <summary>
    /// Gets <see cref="Default"/> plus <see cref="TextHygieneClass.PrivateUse"/> and
    /// <see cref="TextHygieneClass.Unassigned"/>, so a code point assigned after the running runtime's Unicode version,
    /// a reserved default-ignorable code point and a noncharacter are reported as Cn. It still passes the variation
    /// selectors, the assigned default-ignorable code points outside Cf, combining marks, whitespace look-alikes,
    /// U+2800 and confusable characters: no class covers them (see <see cref="TextHygieneClass"/>).
    /// </summary>
    public static TextHygieneRule Strict { get; } = new(
        Default.Classes.Concat([TextHygieneClass.PrivateUse, TextHygieneClass.Unassigned]).ToFrozenSet(),
        FrozenSet<int>.Empty);

    /// <summary>
    /// Creates a rule from the caller's classes and exceptions, or refuses a rule that could not select what it names:
    /// an empty class set, a value that is not a defined <see cref="TextHygieneClass"/>, or an exception outside the
    /// Unicode codespace 0..10FFFF. The classes are checked before the exceptions, and the first offending value in
    /// input order is named in the refusal. Exceptions that exempt a selected code point, or a whole class, are the
    /// caller's choice and are kept (see <see cref="AllowedCodePoints"/>).
    /// </summary>
    /// <param name="classes">The classes to report or escape.</param>
    /// <param name="allowedCodePoints">Exempt scalar values, or lone UTF-16 code units in D800..DFFF.</param>
    /// <returns>The rule, or the <see cref="TextHygieneRuleRefusal"/> naming why it cannot be built.</returns>
    /// <exception cref="ArgumentNullException">Either collection is null.</exception>
    public static Result<TextHygieneRule, TextHygieneRuleRefusal> Create(IEnumerable<TextHygieneClass> classes, IEnumerable<int> allowedCodePoints)
    {
        ArgumentNullException.ThrowIfNull(classes);
        ArgumentNullException.ThrowIfNull(allowedCodePoints);
        TextHygieneClass[] classList = [.. classes];
        int[] allowedList = [.. allowedCodePoints];
        if(classList.Length == 0)
        {
            return Result.Failure<TextHygieneRule, TextHygieneRuleRefusal>(new TextHygieneRuleRefusal(TextHygieneRuleRefusalReason.EmptyClassSet, null));
        }

        foreach(TextHygieneClass selected in classList)
        {
            if(!Enum.IsDefined(selected))
            {
                return Result.Failure<TextHygieneRule, TextHygieneRuleRefusal>(new TextHygieneRuleRefusal(TextHygieneRuleRefusalReason.UndefinedClass, (int)selected));
            }
        }

        foreach(int allowed in allowedList)
        {
            if(allowed < 0 || allowed > MaximumCodePoint)
            {
                return Result.Failure<TextHygieneRule, TextHygieneRuleRefusal>(new TextHygieneRuleRefusal(TextHygieneRuleRefusalReason.CodePointOutsideCodespace, allowed));
            }
        }

        return Result.Success<TextHygieneRule, TextHygieneRuleRefusal>(new TextHygieneRule(classList.ToFrozenSet(), allowedList.ToFrozenSet()));
    }
}

/// <summary>
/// Why <see cref="TextHygieneRule.Create"/> refused to build a rule.
/// </summary>
public enum TextHygieneRuleRefusalReason
{
    /// <summary>
    /// No class was given, so the rule would pass every input.
    /// </summary>
    EmptyClassSet,

    /// <summary>
    /// A value is not a defined <see cref="TextHygieneClass"/>, so no occurrence can ever carry it.
    /// </summary>
    UndefinedClass,

    /// <summary>
    /// An exception lies outside the Unicode codespace 0..10FFFF, so no input can ever hold it.
    /// </summary>
    CodePointOutsideCodespace
}

/// <summary>
/// The refusal <see cref="TextHygieneRule.Create"/> returns: the reason and the offending value it names.
/// </summary>
public readonly record struct TextHygieneRuleRefusal
{
    /// <summary>
    /// Stores the reason and the offending value.
    /// </summary>
    /// <param name="reason">Why the rule was refused.</param>
    /// <param name="value">The offending class or code point value, or null for an empty class set.</param>
    internal TextHygieneRuleRefusal(TextHygieneRuleRefusalReason reason, int? value)
    {
        Reason = reason;
        Value = value;
    }

    /// <summary>
    /// Gets why the rule was refused.
    /// </summary>
    public TextHygieneRuleRefusalReason Reason { get; }

    /// <summary>
    /// Gets the offending value: the undefined class's numeric value or the exception outside the codespace;
    /// null for <see cref="TextHygieneRuleRefusalReason.EmptyClassSet"/>, which has no single offending value.
    /// </summary>
    public int? Value { get; }
}
